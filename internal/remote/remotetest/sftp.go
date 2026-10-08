// Package remotetest runs the remote hosts the tests of go-fs send to.
package remotetest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTPHost is an SFTP server a test sends to. It serves Dir, which is also
// where a login starts, and takes one login.
type SFTPHost struct {
	Host        string
	Port        int
	Dir         string
	Fingerprint string
	// Logins counts the logins offered to it, right or wrong.
	Logins atomic.Int32
	// Slow is how long every read of what a client sent waits, which holds a
	// send up for a test that stops it.
	Slow atomic.Int64
}

// NewSFTPHost starts an SFTP server that takes the login of username with
// password, and stops it when the test ends.
func NewSFTPHost(t testing.TB, username, password string) *SFTPHost {
	t.Helper()
	return NewSFTPHostWith(t, username, password, nil)
}

// NewSFTPHostWith is NewSFTPHost with the host's SSH configuration tuned, to
// offer only some algorithms.
func NewSFTPHostWith(t testing.TB, username, password string, tune func(*ssh.ServerConfig)) *SFTPHost {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	host := &SFTPHost{Dir: t.TempDir(), Fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, given []byte) (*ssh.Permissions, error) {
			host.Logins.Add(1)
			if meta.User() == username && string(given) == password {
				return nil, nil
			}
			return nil, errors.New("wrong login")
		},
	}
	serverConfig.AddHostKey(signer)
	if tune != nil {
		tune(serverConfig)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	host.Host, host.Port = addr.IP.String(), addr.Port

	var mu sync.Mutex
	var conns []net.Conn
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				host.serve(conn, serverConfig)
			}()
		}
	}()
	return host
}

func (h *SFTPHost) serve(conn net.Conn, serverConfig *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	_, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for incoming := range chans {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range requests {
				ok := req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
				_ = req.Reply(ok, nil)
				if !ok {
					continue
				}
				go func() {
					defer func() { _ = channel.Close() }()
					server, err := sftp.NewServer(slowChannel{channel, h}, sftp.WithServerWorkingDirectory(h.Dir))
					if err != nil {
						return
					}
					_ = server.Serve()
				}()
			}
		}()
	}
}

// slowChannel is the channel of an SFTP session, which reads as slowly as the
// host is told to.
type slowChannel struct {
	ssh.Channel
	host *SFTPHost
}

func (c slowChannel) Read(b []byte) (int, error) {
	if wait := time.Duration(c.host.Slow.Load()); wait > 0 {
		time.Sleep(wait)
	}
	return c.Channel.Read(b)
}

// Path is a local path as an SFTP server names it: with slashes, and on
// Windows with a slash before the drive letter.
func Path(p string) string {
	p = filepath.ToSlash(p)
	if len(p) > 1 && p[1] == ':' {
		p = "/" + p
	}
	return p
}

// Write puts a file on the host, with the folders leading up to it.
func (h *SFTPHost) Write(t testing.TB, name, content string) {
	t.Helper()
	full := filepath.Join(h.Dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Leftovers are the files of a folder of the host a send writes under a name
// of its own.
func (h *SFTPHost) Leftovers(t testing.TB, name string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(h.Dir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".part") {
			found = append(found, entry.Name())
		}
	}
	return found
}

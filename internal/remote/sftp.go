package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
)

// HandshakeTimeout bounds the connection and the handshake with a host, which
// one that does not answer would hold.
const HandshakeTimeout = 30 * time.Second

// errHostKeyShown ends the handshake that only asks for the key of a host.
var errHostKeyShown = errors.New("host key shown")

// ErrHostKeyChanged is a host that shows a key other than the one accepted.
var ErrHostKeyChanged = errors.New("the host key is not the one that was accepted")

// sshConnect dials a host and runs the handshake, within HandshakeTimeout.
// The connection is cut as soon as ctx ends, which is what stops whatever
// waits on it.
func sshConnect(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// sshHostKey asks an SSH host for its key, with the same algorithms as the
// login that follows, so that the key shown is the kind the login is shown too.
func sshHostKey(ctx context.Context, l Login, sshCfg config.SSH) (string, string, error) {
	var seen ssh.PublicKey
	conn, err := sshConnect(ctx, l.Address(), &ssh.ClientConfig{
		Config:            sshCfg.ClientTransport(),
		HostKeyAlgorithms: sshCfg.HostKeys(),
		User:              "go-fs",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errHostKeyShown
		},
	})
	if conn != nil {
		_ = conn.Close()
	}
	if seen == nil {
		if err == nil {
			err = errors.New("no host key was shown")
		}
		return "", "", Failure(l, err)
	}
	return seen.Type(), ssh.FingerprintSHA256(seen), nil
}

// OpenSFTP logs in to a host, provided it shows the key that was accepted,
// and opens its SFTP, with the algorithms [general.ssh] allows. The
// connection lives as long as ctx.
func OpenSFTP(ctx context.Context, l Login, sshCfg config.SSH) (*ssh.Client, *sftp.Client, error) {
	password := l.Password
	login := &ssh.ClientConfig{
		Config:            sshCfg.ClientTransport(),
		HostKeyAlgorithms: sshCfg.HostKeys(),
		User:              l.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			// what many hosts ask a password by instead
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != l.HostKey {
				return ErrHostKeyChanged
			}
			return nil
		},
	}
	conn, err := sshConnect(ctx, l.Address(), login)
	if err != nil {
		return nil, nil, Failure(l, err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("%s offers no SFTP: %w", l.Shown(), err)
	}
	return conn, client, nil
}

// Failure says why a host could not be reached or logged in to, in the words
// a page shows.
func Failure(l Login, err error) error {
	var negotiation *ssh.AlgorithmNegotiationError
	switch {
	case errors.As(err, &negotiation):
		return fmt.Errorf("%s offers no %s that general.ssh allows; it offers %s",
			l.Shown(), negotiation.What, strings.Join(negotiation.RequestedAlgorithms, ", "))
	case errors.Is(err, ErrHostKeyChanged) && l.Server != "":
		return fmt.Errorf("the key of %s is not the one saved for the server %s; "+
			"an administrator has to edit the server and accept the key it shows now", l.Shown(), l.Server)
	case errors.Is(err, ErrHostKeyChanged):
		return fmt.Errorf("the key of %s is not the one that was accepted; connect again to see the one it shows now", l.Shown())
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%s refused the login of %s", l.Shown(), l.Username)
	}
	return fmt.Errorf("%s: %w", l.Shown(), err)
}

// sftpFS is a host logged in to by SFTP.
type sftpFS struct {
	conn   *ssh.Client
	client *sftp.Client
}

func openSFTPFS(ctx context.Context, l Login, sshCfg config.SSH) (FS, error) {
	conn, client, err := OpenSFTP(ctx, l, sshCfg)
	if err != nil {
		return nil, err
	}
	return &sftpFS{conn: conn, client: client}, nil
}

func (s *sftpFS) Resolve(p string) (string, error) {
	if p == "" {
		return s.client.Getwd()
	}
	return s.client.RealPath(p)
}

func (s *sftpFS) Stat(p string) (fs.FileInfo, error)  { return s.client.Stat(p) }
func (s *sftpFS) Lstat(p string) (fs.FileInfo, error) { return s.client.Lstat(p) }

func (s *sftpFS) ReadDir(folder string) ([]fs.FileInfo, error) {
	infos, err := s.client.ReadDir(folder)
	if err != nil {
		return nil, err
	}
	found := infos[:0]
	for _, info := range infos {
		name := info.Name()
		if name == "." || name == ".." {
			continue
		}
		// a link is listed as one, and is what it leads to where that can
		// be read
		if info.Mode()&fs.ModeSymlink != 0 {
			if target, err := s.client.Stat(path.Join(folder, name)); err == nil {
				info = linkInfo{FileInfo: target, name: name}
			}
		}
		found = append(found, info)
	}
	return found, nil
}

func (s *sftpFS) Open(p string) (io.ReadSeekCloser, error) { return s.client.Open(p) }

// Put writes the file under a hidden name beside where it goes and renames it
// once all of it is there, so that a write that is stopped or fails never
// leaves half a file under the real name. What was written is taken away
// again when anything fails.
func (s *sftpFS) Put(final string, body io.Reader, _ int64) (int64, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return 0, err
	}
	part := path.Join(path.Dir(final), "."+path.Base(final)+".go-fs-"+hex.EncodeToString(suffix)+".part")
	out, err := s.client.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return 0, err
	}
	written, err := out.ReadFromWithConcurrency(body, 0)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = s.replace(part, final)
	}
	if err != nil {
		_ = s.client.Remove(part)
	}
	return written, err
}

// replace puts a file that was written in place, replacing whatever is
// there: at once where the host can, and else by removing it first. A host
// may offer the rename that replaces and still refuse to replace with it, as
// a server that hands it on to a plain SFTP rename does, so a refusal is
// tried again the other way.
func (s *sftpFS) replace(from, to string) error {
	if _, ok := s.client.HasExtension("posix-rename@openssh.com"); ok {
		if err := s.client.PosixRename(from, to); err == nil {
			return nil
		}
	}
	if err := s.client.Remove(to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return s.client.Rename(from, to)
}

func (s *sftpFS) Mkdir(p string) error         { return s.client.Mkdir(p) }
func (s *sftpFS) Rename(from, to string) error { return s.client.Rename(from, to) }
func (s *sftpFS) Remove(p string) error        { return s.client.Remove(p) }
func (s *sftpFS) RemoveDir(p string) error     { return s.client.RemoveDirectory(p) }

func (s *sftpFS) Close() error {
	err := s.client.Close()
	if closeErr := s.conn.Close(); err == nil {
		err = closeErr
	}
	return err
}

// linkInfo is what a link leads to, under the name of the link.
type linkInfo struct {
	fs.FileInfo
	name string
}

func (l linkInfo) Name() string { return l.name }

// IsLink reports an entry of ReadDir that is a link, listed as what it leads
// to: a walk that goes into it might never come out again.
func IsLink(info fs.FileInfo) bool {
	_, ok := info.(linkInfo)
	return ok
}

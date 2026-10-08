package sftp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/service"
)

// dialWith opens an SSH connection as john with a client configuration of the
// test's own, filling in what it leaves out.
func dialWith(t testing.TB, server *testServer, client *ssh.ClientConfig) (*ssh.Client, error) {
	t.Helper()
	if client.User == "" {
		client.User = "john"
	}
	if client.Auth == nil {
		client.Auth = []ssh.AuthMethod{ssh.Password("doe")}
	}
	if client.HostKeyCallback == nil {
		client.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	conn, err := ssh.Dial("tcp", server.address(), client)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

func (s *testServer) address() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port()))
}

// eventually waits for cond, which the server reaches on a goroutine of its
// own after the client has already seen the result.
func eventually(t *testing.T, within time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// closedWithin reports whether the server closed the connection within d.
func closedWithin(conn ssh.Conn, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = conn.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// sha1Only signs with ssh-rsa alone, the way a client from before RSA SHA-2
// signatures does.
func sha1Only(t *testing.T, key *rsa.PrivateKey) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ssh.NewSignerWithAlgorithms(signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	return legacy
}

func TestALegacyKeyExchangeIsOfferedOnlyWhenListed(t *testing.T) {
	old := &ssh.ClientConfig{}
	old.KeyExchanges = []string{ssh.InsecureKeyExchangeDH14SHA1}

	server := newServer(t, nil)
	if _, err := dialWith(t, server, old); err == nil {
		t.Fatal("diffie-hellman-group14-sha1 is not in the secure default")
	}
	if !eventually(t, time.Second, func() bool { return server.logs.find("sftp client has no algorithm in common") != nil }) {
		t.Error("a client turned away for its algorithms has to be reported")
	}

	server = newServer(t, func(c *sftpConfig) {
		c.SSH.KeyExchanges = []string{ssh.KeyExchangeCurve25519, ssh.InsecureKeyExchangeDH14SHA1}
	})
	old = &ssh.ClientConfig{}
	old.KeyExchanges = []string{ssh.InsecureKeyExchangeDH14SHA1}
	if _, err := dialWith(t, server, old); err != nil {
		t.Fatalf("listed, it has to be offered: %v", err)
	}
}

func TestAnRSAKeySignedWithSHA1IsAcceptedOnlyWhenListed(t *testing.T) {
	key := newRSAKey(t)
	signer := sha1Only(t, key)
	authorized := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	withKey := func(c *sftpConfig) {
		user := fullUser("john", "")
		user.AuthorizedKeys = []string{authorized}
		c.Users = []config.User{user}
	}

	server := newServer(t, withKey)
	if _, err := dialWith(t, server, &ssh.ClientConfig{Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}}); err == nil {
		t.Fatal("an ssh-rsa signature is not in the secure default")
	}

	server = newServer(t, func(c *sftpConfig) {
		withKey(c)
		c.SSH.PublicKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	})
	if _, err := dialWith(t, server, &ssh.ClientConfig{Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}}); err != nil {
		t.Fatalf("listed, ssh-rsa has to be accepted: %v", err)
	}
}

func TestTheCiphersAreTheListedOnes(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) {
		c.SSH.Ciphers = []string{ssh.CipherAES256GCM}
	})

	chacha := &ssh.ClientConfig{}
	chacha.Ciphers = []string{ssh.CipherChaCha20Poly1305}
	if _, err := dialWith(t, server, chacha); err == nil {
		t.Error("chacha20-poly1305 is not listed, so it cannot be negotiated")
	}
	aes := &ssh.ClientConfig{}
	aes.Ciphers = []string{ssh.CipherAES256GCM}
	if _, err := dialWith(t, server, aes); err != nil {
		t.Errorf("the listed cipher has to work: %v", err)
	}
}

func TestReloadChangesTheAlgorithmsForTheNextConnection(t *testing.T) {
	server := newServer(t, nil)
	chacha := func() *ssh.ClientConfig {
		client := &ssh.ClientConfig{}
		client.Ciphers = []string{ssh.CipherChaCha20Poly1305}
		return client
	}
	if _, err := dialWith(t, server, chacha()); err != nil {
		t.Fatalf("chacha20-poly1305 is in the default: %v", err)
	}

	next := server.settings().ssh
	next.Ciphers = []string{ssh.CipherAES128GCM}
	if err := server.Reload(server.settings().cfg, next, []config.User{fullUser("john", "doe")}); err != nil {
		t.Fatalf("the algorithms reload without a restart: %v", err)
	}
	if _, err := dialWith(t, server, chacha()); err == nil {
		t.Error("after the reload chacha20-poly1305 is no longer offered")
	}
}

func TestReloadRefusesHostKeyAlgorithmsTheKeyCannotSignWith(t *testing.T) {
	server := newServer(t, nil)
	next := server.settings().ssh
	next.HostKeyAlgorithms = []string{ssh.KeyAlgoRSASHA256}
	err := server.Reload(server.settings().cfg, next, []config.User{fullUser("john", "doe")})
	if err == nil || errors.Is(err, service.ErrNeedsRestart) {
		t.Fatalf("an ed25519 host key cannot sign as rsa-sha2-256, err = %v", err)
	}
	if _, err := dial(t, server, "john", ssh.Password("doe")); err != nil {
		t.Errorf("the running configuration has to stay: %v", err)
	}
}

func TestAnRSAHostKeySignsWithSHA1OnlyWhenListed(t *testing.T) {
	block, err := ssh.MarshalPrivateKey(newRSAKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	hostKey := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(block))
	old := func() *ssh.ClientConfig {
		return &ssh.ClientConfig{HostKeyAlgorithms: []string{ssh.KeyAlgoRSA}}
	}

	server := newServer(t, func(c *sftpConfig) { c.HostKey = hostKey })
	if _, err := dialWith(t, server, old()); err == nil {
		t.Error("an ssh-rsa host key signature is not in the secure default")
	}
	modern := &ssh.ClientConfig{HostKeyAlgorithms: []string{ssh.KeyAlgoRSASHA512}}
	if _, err := dialWith(t, server, modern); err != nil {
		t.Errorf("rsa-sha2-512 has to work: %v", err)
	}

	server = newServer(t, func(c *sftpConfig) {
		c.HostKey = hostKey
		c.SSH.HostKeyAlgorithms = []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	})
	if _, err := dialWith(t, server, old()); err != nil {
		t.Errorf("listed, ssh-rsa has to be signed with: %v", err)
	}
}

func TestLoginGraceTimeClosesAConnectionThatNeverLogsIn(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) { c.SSH.LoginGraceTime = 1 })

	conn, err := net.Dial("tcp", server.address())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	started := time.Now()
	// the server says its version and then waits for the client's, which
	// never comes
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("the server has to close the connection, not leave it to the deadline: %v", err)
	}
	if took := time.Since(started); took < 900*time.Millisecond || took > 5*time.Second {
		t.Errorf("closed after %v, want about a second", took)
	}
	if !eventually(t, time.Second, func() bool { return server.Connections() == 0 }) {
		t.Error("the slot has to be given back")
	}
	if server.logs.find("sftp login timed out") == nil {
		t.Error("the timeout has to be reported")
	}
}

func TestLoginGraceTimeLeavesALoggedInConnectionAlone(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) { c.SSH.LoginGraceTime = 1 })
	client := login(t, server)
	time.Sleep(1500 * time.Millisecond)
	if _, err := client.ReadDir("/"); err != nil {
		t.Errorf("a connection that logged in in time has to stay: %v", err)
	}
}

func TestMaxAuthTriesEndsTheLogin(t *testing.T) {
	// the first answer is wrong, the second right
	attempts := func() ssh.AuthMethod {
		answers := []string{"wrong", "doe"}
		return ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			answer := answers[0]
			answers = answers[1:]
			return answer, nil
		}), 2)
	}

	server := newServer(t, func(c *sftpConfig) { c.SSH.MaxAuthTries = 1 })
	if _, err := dialWith(t, server, &ssh.ClientConfig{Auth: []ssh.AuthMethod{attempts()}}); err == nil {
		t.Error("one wrong password is all maxAuthTries = 1 allows")
	}

	server = newServer(t, nil)
	if _, err := dialWith(t, server, &ssh.ClientConfig{Auth: []ssh.AuthMethod{attempts()}}); err != nil {
		t.Errorf("the default allows a second try: %v", err)
	}
}

func TestMaxSessionsLimitsTheSessionsOfAConnection(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) { c.SSH.MaxSessions = 1 })
	conn, err := dial(t, server, "john", ssh.Password("doe"))
	if err != nil {
		t.Fatal(err)
	}

	first, err := conn.NewSession()
	if err != nil {
		t.Fatalf("the first session: %v", err)
	}
	if second, err := conn.NewSession(); err == nil {
		_ = second.Close()
		t.Fatal("a second session is one more than maxSessions = 1")
	}
	_ = first.Close()
	if !eventually(t, 2*time.Second, func() bool {
		session, err := conn.NewSession()
		if err == nil {
			_ = session.Close()
		}
		return err == nil
	}) {
		t.Error("a closed session gives its place back")
	}
}

func TestMaxConnectionsPerHostLimitsOneAddress(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) { c.SSH.MaxConnectionsPerHost = 1 })
	first, err := dial(t, server, "john", ssh.Password("doe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(t, server, "john", ssh.Password("doe")); err == nil {
		t.Fatal("a second connection from 127.0.0.1 is one more than maxConnectionsPerHost = 1")
	}
	_ = first.Close()
	if !eventually(t, 2*time.Second, func() bool {
		conn, err := dial(t, server, "john", ssh.Password("doe"))
		if err == nil {
			_ = conn.Close()
		}
		return err == nil
	}) {
		t.Error("a closed connection gives its place back")
	}
}

func TestKeepAliveDropsAClientThatDoesNotAnswer(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) {
		c.SSH.KeepAliveInterval = 1
		c.SSH.KeepAliveCountMax = 1
	})
	raw, err := net.Dial("tcp", server.address())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	// the global requests are never read, so the keepalive is never answered
	conn, _, _, err := ssh.NewClientConn(raw, server.address(), &ssh.ClientConfig{
		User:            "john",
		Auth:            []ssh.AuthMethod{ssh.Password("doe")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !closedWithin(conn, 5*time.Second) {
		t.Fatal("a client that does not answer has to be dropped")
	}
	if !eventually(t, time.Second, func() bool {
		return server.logs.find("sftp client stopped answering keepalives, closing the connection") != nil
	}) {
		t.Error("the drop has to be reported")
	}
}

func TestKeepAliveLeavesAClientThatAnswersAlone(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) {
		c.SSH.KeepAliveInterval = 1
		c.SSH.KeepAliveCountMax = 1
	})
	client := login(t, server)
	time.Sleep(3 * time.Second)
	if _, err := client.ReadDir("/"); err != nil {
		t.Errorf("a client that answers has to stay: %v", err)
	}
}

func TestKeepalivesDoNotKeepAnIdleConnectionOpen(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) {
		c.IdleTimeout = 2
		c.SSH.KeepAliveInterval = 1
	})
	conn, err := dial(t, server, "john", ssh.Password("doe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sftp.NewClient(conn); err != nil {
		t.Fatal(err)
	}
	if !closedWithin(conn, 6*time.Second) {
		t.Fatal("answered keepalives are no SFTP traffic, the connection is idle")
	}
	if server.logs.find("sftp connection idle, closing it") == nil {
		t.Error("the idle timeout has to be reported")
	}
}

func TestSFTPTrafficKeepsAConnectionOpen(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) { c.IdleTimeout = 1 })
	client := login(t, server)
	for range 10 {
		if _, err := client.ReadDir("/"); err != nil {
			t.Fatalf("a connection in use is not idle: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func TestTheBannerIsShownBeforeTheLogin(t *testing.T) {
	server := newServer(t, func(c *sftpConfig) { c.SSH.Banner = []string{"Authorized use only.", "Every login is logged."} })
	var shown string
	_, err := dialWith(t, server, &ssh.ClientConfig{BannerCallback: func(message string) error {
		shown = message
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := "Authorized use only.\r\nEvery login is logged.\r\n"; shown != want {
		t.Errorf("banner = %q, want %q", shown, want)
	}
}

func TestMaxPacketSizeBoundsOneReadAnswer(t *testing.T) {
	for _, size := range []int{config.MinSFTPPacketSize, config.MaxSFTPPacketSize} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			server := newServer(t, func(c *sftpConfig) { c.SSH.MaxPacketSize = size })
			server.write(t, "large.txt", strings.Repeat("go-fs ", 100_000))
			conn, err := dial(t, server, "john", ssh.Password("doe"))
			if err != nil {
				t.Fatal(err)
			}
			// one READ for more than either size, which a client library
			// would split up or repeat; the answer says what the server allows
			if got := readOnce(t, conn, "large.txt", config.MaxSFTPPacketSize+4096); got != size {
				t.Errorf("one read was answered with %d bytes, want %d", got, size)
			}
		})
	}
}

// readOnce opens name over a bare SFTP session and sends a single READ of
// length bytes, reporting how many the answer carries.
func readOnce(t *testing.T, conn *ssh.Client, name string, length int) int {
	t.Helper()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	in, _ := session.StdinPipe()
	out, _ := session.StdoutPipe()
	if err := session.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}

	str := func(v string) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(v))), v...) }
	send := func(kind byte, payload ...[]byte) {
		body := []byte{kind}
		for _, part := range payload {
			body = append(body, part...)
		}
		if _, err := in.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(want byte) []byte {
		var size [4]byte
		if _, err := io.ReadFull(out, size[:]); err != nil {
			t.Fatal(err)
		}
		body := make([]byte, binary.BigEndian.Uint32(size[:]))
		if _, err := io.ReadFull(out, body); err != nil {
			t.Fatal(err)
		}
		if body[0] != want {
			t.Fatalf("answer type %d, want %d", body[0], want)
		}
		return body[1:]
	}
	u32 := func(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

	const (
		fxpInit, fxpVersion = 1, 2
		fxpOpen, fxpHandle  = 3, 102
		fxpRead, fxpData    = 5, 103
	)
	send(fxpInit, u32(3))
	receive(fxpVersion)
	// id, path, SSH_FXF_READ, attributes with no flags
	send(fxpOpen, u32(1), str(name), u32(1), u32(0))
	answer := receive(fxpHandle)
	handle := answer[8 : 8+binary.BigEndian.Uint32(answer[4:8])]
	send(fxpRead, u32(2), str(string(handle)), binary.BigEndian.AppendUint64(nil, 0), u32(uint32(length)))
	data := receive(fxpData)
	return int(binary.BigEndian.Uint32(data[4:8]))
}

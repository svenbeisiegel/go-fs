package sftp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
)

// logStore collects the records a server writes, so that tests can assert on
// the login and transfer reports.
type logStore struct {
	mu      sync.Mutex
	records []map[string]any
}

func (s *logStore) add(record map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, record)
}

func (s *logStore) find(message string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record["msg"] == message {
			return record
		}
	}
	return nil
}

type recorder struct {
	store *logStore
	attrs []slog.Attr
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, record slog.Record) error {
	fields := map[string]any{"msg": record.Message}
	for _, attr := range r.attrs {
		fields[attr.Key] = attr.Value.Any()
	}
	record.Attrs(func(attr slog.Attr) bool {
		fields[attr.Key] = attr.Value.Any()
		return true
	})
	r.store.add(fields)
	return nil
}

func (r *recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(r.attrs)+len(attrs))
	merged = append(merged, r.attrs...)
	merged = append(merged, attrs...)
	return &recorder{store: r.store, attrs: merged}
}

func (r *recorder) WithGroup(string) slog.Handler { return r }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

type testServer struct {
	*Server
	base string
	logs *logStore
}

// fullUser is an account with a password and every right granted. Permissions
// deny by default, so a test about one restriction starts here and takes that
// single right away.
func fullUser(name, password string) config.User {
	yes := true
	return config.User{
		Username:               name,
		Password:               password,
		SFTP:                   true,
		AllowUserFileCreate:    &yes,
		AllowUserFileRetrieve:  &yes,
		AllowUserFileOverwrite: &yes,
		AllowUserFileDelete:    &yes,
		AllowUserFolderDelete:  &yes,
		AllowUserFolderCreate:  &yes,
	}
}

// sftpConfig is the [sftp] section together with the accounts the file keeps
// under [[users]], so that one closure tunes both.
type sftpConfig struct {
	config.SFTP
	Users []config.User
}

// newServer starts a server on an ephemeral port with a single account
// "john"/"doe" that may do everything.
func newServer(t *testing.T, tune func(*sftpConfig)) *testServer {
	t.Helper()
	base := t.TempDir()
	cfg := sftpConfig{SFTP: config.Default().SFTP}
	cfg.Enabled = true
	cfg.Port = 0
	cfg.Basefolder = base
	cfg.LoginFailureDelay = 0
	cfg.Users = []config.User{fullUser("john", "doe")}
	if tune != nil {
		tune(&cfg)
	}
	if cfg.Basefolder != base {
		base = cfg.Basefolder
	}

	logs := &logStore{}
	server, err := New(cfg.SFTP, cfg.Users, slog.New(&recorder{store: logs}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
	})
	return &testServer{Server: server, base: base, logs: logs}
}

// write puts a file into the served folder, creating the folders above it.
func (s *testServer) write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(s.base, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (s *testServer) read(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(s.base, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func (s *testServer) port() int {
	if addr, ok := s.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// dial opens an SSH connection with the given authentication method.
func dial(t *testing.T, server *testServer, user string, auth ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	client, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(server.port())), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, nil
}

// connect logs in and opens the SFTP subsystem, failing the test if it cannot.
func connect(t *testing.T, server *testServer, user, password string) *sftp.Client {
	t.Helper()
	ssh, err := dial(t, server, user, ssh.Password(password))
	if err != nil {
		t.Fatalf("dial as %s: %v", user, err)
	}
	client, err := sftp.NewClient(ssh)
	if err != nil {
		t.Fatalf("sftp subsystem: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// login is connect for the account the helper configures.
func login(t *testing.T, server *testServer) *sftp.Client {
	t.Helper()
	return connect(t, server, "john", "doe")
}

// newKeyPair returns a signer for a client and the authorized_keys line that
// matches it.
func newKeyPair(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	authorized := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return signer, authorized
}

// newHostKey returns a host key in the form the configuration takes: base64 of
// its PEM encoding.
func newHostKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(block)), signer.PublicKey()
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func names(entries []os.FileInfo) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Name())
	}
	return out
}

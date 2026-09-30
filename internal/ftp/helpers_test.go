package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
)

// entry is one captured log record, flattened for easy assertions.
type entry struct {
	message string
	attrs   map[string]any
}

type logStore struct {
	mu      sync.Mutex
	entries []entry
}

func (s *logStore) all(message string) []entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []entry
	for _, e := range s.entries {
		if e.message == message {
			out = append(out, e)
		}
	}
	return out
}

// matching finds records whose message contains a fragment, for the long ones
// that are not worth repeating in full.
func (s *logStore) matching(fragment string) []entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []entry
	for _, e := range s.entries {
		if strings.Contains(e.message, fragment) {
			out = append(out, e)
		}
	}
	return out
}

// recorder is a slog handler that keeps records, including the attributes
// added with With.
type recorder struct {
	store *logStore
	attrs []slog.Attr
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) WithGroup(string) slog.Handler            { return r }

func (r *recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, 0, len(r.attrs)+len(attrs))
	combined = append(combined, r.attrs...)
	combined = append(combined, attrs...)
	return &recorder{store: r.store, attrs: combined}
}

func (r *recorder) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]any, len(r.attrs)+record.NumAttrs())
	for _, a := range r.attrs {
		attrs[a.Key] = a.Value.Any()
	}
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	r.store.entries = append(r.store.entries, entry{message: record.Message, attrs: attrs})
	return nil
}

// dataPortBase hands each test its own passive port range, so tests can run in
// parallel without fighting over ports.
var dataPortBase = struct {
	mu   sync.Mutex
	next int
}{next: 41000}

func reserveDataPorts(count int) int {
	dataPortBase.mu.Lock()
	defer dataPortBase.mu.Unlock()
	port := dataPortBase.next
	dataPortBase.next += count + 1
	return port
}

type testServer struct {
	*Server
	base string
	port int
	logs *logStore
}

// fullUser is an account that logs in without a password and has every right
// granted. Permissions deny by default, so a test that cares about one
// restriction starts here and takes that single right away.
func fullUser(name string) config.User {
	yes := true
	return config.User{
		Username:                  name,
		FTP:                       true,
		AllowLoginWithoutPassword: &yes,
		AllowUserFileCreate:       &yes,
		AllowUserFileRetrieve:     &yes,
		AllowUserFileOverwrite:    &yes,
		AllowUserFileDelete:       &yes,
		AllowUserFolderDelete:     &yes,
		AllowUserFolderCreate:     &yes,
	}
}

// ftpConfig is the [ftp] section together with the accounts the file keeps
// under [[users]], so that one closure tunes both.
type ftpConfig struct {
	config.FTP
	Users []config.User
}

// newServer starts a server on an ephemeral control port, with its own passive
// port range and a single user "john" that needs no password.
func newServer(t *testing.T, tune func(*ftpConfig)) *testServer {
	t.Helper()
	return newServerWith(t, tune, nil)
}

// newTLSServer does the same with the implicit TLS listener enabled on an
// ephemeral port and a generated certificate.
func newTLSServer(t *testing.T, tune func(*ftpConfig)) *testServer {
	t.Helper()
	return newServerWith(t, tune, func(ftps *config.FTPS) {
		ftps.Enabled = true
		ftps.Port = 0
	})
}

func newServerWith(t *testing.T, tune func(*ftpConfig), tuneTLS func(*config.FTPS)) *testServer {
	t.Helper()
	base := t.TempDir()
	cfg := ftpConfig{FTP: config.Default().FTP}
	cfg.Basefolder = base
	cfg.Port = 0
	cfg.MaxConnections = 8
	cfg.PassiveMinPort = reserveDataPorts(cfg.MaxConnections)
	cfg.PassiveMaxPort = cfg.PassiveMinPort + cfg.MaxConnections
	cfg.LoginFailureDelay = 0
	cfg.Users = []config.User{fullUser("john")}
	if tune != nil {
		tune(&cfg)
	}
	ftps := config.Default().FTPS
	if tuneTLS != nil {
		tuneTLS(&ftps)
	}
	if cfg.Basefolder != base {
		base = cfg.Basefolder
	}

	logs := &logStore{}
	server, err := New(cfg.FTP, ftps, cfg.Users, slog.New(&recorder{store: logs}))
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
	return &testServer{Server: server, base: base, port: portOf(server.Addr()), logs: logs}
}

// dataPort is the first port of the passive range, which a passive transfer
// takes when nothing else holds it.
func (s *testServer) dataPort() int {
	return s.settings().cfg.PassiveMinPort
}

func (s *testServer) write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(s.base, name)
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
	content, err := os.ReadFile(filepath.Join(s.base, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// client drives the control connection.
type client struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

// connect opens a control connection and consumes the greeting.
func connect(t *testing.T, server *testServer) *client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(server.port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &client{t: t, conn: conn, reader: bufio.NewReader(conn)}
	c.expect("220 Welcome")
	return c
}

// connectTLS opens an implicit TLS control connection.
func connectTLS(t *testing.T, server *testServer) *client {
	t.Helper()
	conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(portOf(server.SecureAddr()))),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &client{t: t, conn: conn, reader: bufio.NewReader(conn)}
	c.expect("220 Welcome")
	return c
}

// send writes a command with the CRLF terminator a real client uses.
func (c *client) send(format string, args ...any) {
	c.t.Helper()
	line := fmt.Sprintf(format, args...)
	_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.t.Fatalf("sending %q: %v", line, err)
	}
}

// raw writes bytes without adding a terminator.
func (c *client) raw(text string) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c.conn, text); err != nil {
		c.t.Fatalf("sending %q: %v", text, err)
	}
}

// line reads one reply line.
func (c *client) line() string {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	text, err := c.reader.ReadString('\n')
	if err != nil {
		c.t.Fatalf("reading a reply: %v", err)
	}
	return strings.TrimRight(text, "\r\n")
}

// reply reads a complete reply, following multi line answers to their end.
func (c *client) reply() string {
	c.t.Helper()
	first := c.line()
	if len(first) < 4 || first[3] != '-' {
		return first
	}
	code := first[:3]
	lines := []string{first}
	for {
		next := c.line()
		lines = append(lines, next)
		if strings.HasPrefix(next, code+" ") {
			return strings.Join(lines, "\r\n")
		}
	}
}

// expect reads a reply and requires it to match exactly.
func (c *client) expect(want string) string {
	c.t.Helper()
	got := c.reply()
	if got != want {
		c.t.Fatalf("got %q, want %q", got, want)
	}
	return got
}

// expectCode reads a reply and requires the given status code.
func (c *client) expectCode(code string) string {
	c.t.Helper()
	got := c.reply()
	if !strings.HasPrefix(got, code) {
		c.t.Fatalf("got %q, want a %s reply", got, code)
	}
	return got
}

// login authenticates as the default passwordless user.
func (c *client) login() {
	c.t.Helper()
	c.send("USER john")
	c.expect("232 User logged in")
}

// passive asks for a passive data channel and connects to it.
func (c *client) passive(server *testServer) net.Conn {
	c.t.Helper()
	c.send("EPSV")
	reply := c.expectCode("229")
	open := strings.Index(reply, "|||")
	closing := strings.LastIndex(reply, "|")
	if open < 0 || closing <= open+3 {
		c.t.Fatalf("cannot read the port out of %q", reply)
	}
	port, err := strconv.Atoi(reply[open+3 : closing])
	if err != nil {
		c.t.Fatalf("cannot read the port out of %q", reply)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		c.t.Fatalf("connecting to the data port: %v", err)
	}
	return conn
}

// download runs a command that sends data and returns what arrived.
func (c *client) download(server *testServer, command string) (string, string) {
	c.t.Helper()
	data := c.passive(server)
	defer func() { _ = data.Close() }()

	c.send("%s", command)
	c.expectCode("150")

	_ = data.SetReadDeadline(time.Now().Add(5 * time.Second))
	content, _ := io.ReadAll(data)
	_ = data.Close()
	return string(content), c.reply()
}

// upload runs a command that receives data.
func (c *client) upload(server *testServer, command, content string) string {
	c.t.Helper()
	data := c.passive(server)

	c.send("%s", command)
	opening := c.expectCode("150")
	_ = opening

	_ = data.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(data, content); err != nil {
		c.t.Fatalf("writing to the data connection: %v", err)
	}
	_ = data.Close()
	return c.reply()
}

// discardLogger is for tests that do not look at the output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func newReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}

// portFromEpsv reads the port out of a 229 reply.
func portFromEpsv(t *testing.T, reply string) int {
	t.Helper()
	open := strings.Index(reply, "|||")
	closing := strings.LastIndex(reply, "|")
	if open < 0 || closing <= open+3 {
		t.Fatalf("cannot read the port out of %q", reply)
	}
	port, err := strconv.Atoi(reply[open+3 : closing])
	if err != nil {
		t.Fatalf("cannot read the port out of %q", reply)
	}
	return port
}

// externalAddress finds a non loopback IPv4 address of this host, or "".
func externalAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}
	return ""
}

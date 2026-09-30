package httpd

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
)

// logStore collects the records a server writes.
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

// findLike is find for a message too long to repeat in a test.
func (s *logStore) findLike(prefix string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if message, ok := record["msg"].(string); ok && strings.HasPrefix(message, prefix) {
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
	merged := append(append([]slog.Attr{}, r.attrs...), attrs...)
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

// fullUser is an account that may reach everything and do everything.
// Permissions deny by default, so a test about one restriction starts here and
// takes that single right away.
func fullUser(name, password string) config.User {
	return config.User{
		Username:               name,
		Password:               password,
		HTTP:                   true,
		Paths:                  []string{"^/.*"},
		AllowUserFileCreate:    new(true),
		AllowUserFileRetrieve:  new(true),
		AllowUserFileOverwrite: new(true),
		AllowUserFileDelete:    new(true),
		AllowUserFolderDelete:  new(true),
		AllowUserFolderCreate:  new(true),
	}
}

// httpConfig is the [http] section together with the accounts the file keeps
// under [[users]], so that one closure tunes both.
type httpConfig struct {
	config.HTTP
	Users []config.User
	// ConfigPath is the file the admin interface edits, empty for a server
	// without one, which is what most tests want.
	ConfigPath string
}

// newServer starts a server on an ephemeral port. By default nothing is
// public: every method needs the account "john"/"doe".
func newServer(t *testing.T, tune func(*httpConfig)) *testServer {
	t.Helper()
	return newServerWith(t, tune, nil)
}

func newServerWith(t *testing.T, tune func(*httpConfig), tuneTLS func(*config.HTTPS)) *testServer {
	t.Helper()
	base := t.TempDir()
	cfg := httpConfig{HTTP: config.Default().HTTP}
	cfg.Enabled = true
	cfg.Port = 0
	cfg.Basefolder = base
	cfg.LoginFailureDelay = 0
	// every test's client is 127.0.0.1, so the login lock is off unless a
	// test is about it
	cfg.LoginAttempts = 0
	cfg.PathsRequireAuth = []string{"^/private/.*"}
	cfg.Users = []config.User{fullUser("john", "doe")}
	if tune != nil {
		tune(&cfg)
	}
	https := config.Default().HTTPS
	if tuneTLS != nil {
		https.Port = 0
		tuneTLS(&https)
	}
	if cfg.Basefolder != base {
		base = cfg.Basefolder
	}

	logs := &logStore{}
	server, err := New(cfg.HTTP, https, cfg.Users, cfg.ConfigPath, slog.New(&recorder{store: logs}))
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

// mkdir puts an empty folder into the served folder.
func (s *testServer) mkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(s.base, filepath.FromSlash(name)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (s *testServer) read(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(s.base, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func (s *testServer) url(path string) string {
	port := 0
	if addr, ok := s.Addr().(*net.TCPAddr); ok {
		port = addr.Port
	}
	return "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + path
}

// do sends a request and returns the response, leaving the body to the caller.
func do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

// get is a plain request with no credentials.
func get(t *testing.T, server *testServer, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	res := do(t, req)
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

// basic sends a request authenticated with Basic.
func basic(t *testing.T, server *testServer, method, path, name, password string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, server.url(path), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(name+":"+password)))
	return do(t, req)
}

// digestRequest answers a challenge the way a browser does: it sends the
// request once, reads the WWW-Authenticate header and sends it again.
func digestRequest(t *testing.T, server *testServer, method, path, name, password, userAgent string, body io.Reader) *http.Response {
	t.Helper()
	first, err := http.NewRequest(method, server.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	if userAgent != "" {
		first.Header.Set("User-Agent", userAgent)
	}
	challenge := do(t, first)
	if challenge.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected a challenge, got %d", challenge.StatusCode)
	}
	params := parseDigest(challenge.Header.Get("WWW-Authenticate"))

	req, err := http.NewRequest(method, server.url(path), body)
	if err != nil {
		t.Fatal(err)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	req.Header.Set("Authorization", digestHeader(t, params, method, path, name, password, true))
	return do(t, req)
}

// digestHeader builds an Authorization header for the challenge in params.
func digestHeader(t *testing.T, params map[string]string, method, uri, name, password string, withQop bool) string {
	t.Helper()
	digest, ok := hasher(params["algorithm"])
	if !ok {
		t.Fatalf("unsupported algorithm %q", params["algorithm"])
	}
	ha1 := digest(name + ":" + params["realm"] + ":" + password)
	ha2 := digest(method + ":" + uri)

	if !withQop {
		response := digest(ha1 + ":" + params["nonce"] + ":" + ha2)
		return fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q, algorithm=%s`,
			name, params["realm"], params["nonce"], uri, response, params["algorithm"])
	}

	cnonce := randomHex(8)
	response := digest(strings.Join([]string{ha1, params["nonce"], "00000001", cnonce, "auth", ha2}, ":"))
	return fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, qop=auth, nc=00000001, `+
		`cnonce=%q, response=%q, algorithm=%s`,
		name, params["realm"], params["nonce"], uri, cnonce, response, params["algorithm"])
}

func randomHex(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

func md5Hex(in string) string {
	sum := md5.Sum([]byte(in))
	return hex.EncodeToString(sum[:])
}

func sha256Hex(in string) string {
	sum := sha256.Sum256([]byte(in))
	return hex.EncodeToString(sum[:])
}

func names(entries []entry) []string {
	out := make([]string, 0, len(entries))
	for _, item := range entries {
		out = append(out, item.Name)
	}
	return out
}

var _ = url.PathEscape

// publicServer makes everything public, which is what the listing tests need:
// they are about the page rather than about who may see it.
func publicServer(cfg *httpConfig) {
	cfg.MethodsRequireAuth = nil
	cfg.PathsRequireAuth = nil
}

// readOnlyUser may reach everything and change nothing.
func readOnlyUser(name, password string) config.User {
	return config.User{
		Username:              name,
		Password:              password,
		HTTP:                  true,
		Paths:                 []string{"^/.*"},
		AllowUserFileRetrieve: new(true),
	}
}

// touch dates a file, so that an order by date is something a test can set up.
func touch(t *testing.T, server *testServer, name string, when time.Time) {
	t.Helper()
	path := filepath.Join(server.base, filepath.FromSlash(name))
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// assertOrder checks that the wanted names appear in the page in that order.
// Each is looked for after the one before it, so a name that also occurs in a
// dialog or a script further down cannot make a wrong order look right.
func assertOrder(t *testing.T, body string, wanted ...string) {
	t.Helper()
	at := 0
	for i, want := range wanted {
		needle := `data-name="` + strings.TrimSuffix(want, "/") + `"`
		found := strings.Index(body[at:], needle)
		if found < 0 {
			t.Fatalf("%q does not come after %v", want, wanted[:i])
		}
		at += found + len(needle)
	}
}

// mkcol asks for a folder as the browser page does.
func mkcol(t *testing.T, server *testServer, path, name, password string) *http.Response {
	t.Helper()
	return basic(t, server, methodMkcol, path, name, password, nil)
}

// move renames, which is a MOVE whose Destination is in the same folder.
func move(t *testing.T, server *testServer, from, to, name, password string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(methodMove, server.url(from), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Destination", to)
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(name+":"+password)))
	return do(t, req)
}

// bodyOf reads a response the caller already has, for the requests basic and
// move answer with the response rather than with its body.
func bodyOf(t *testing.T, res *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// browserGet asks for a path the way a browser does, so that the server offers
// it the login page rather than a challenge.
func browserGet(t *testing.T, server *testServer, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	return do(t, req)
}

// postLogin submits the login form for a path and returns the answer.
func postLogin(t *testing.T, server *testServer, path, name, password string) *http.Response {
	t.Helper()
	form := url.Values{"username": {name}, "password": {password}}
	req, err := http.NewRequest(http.MethodPost,
		server.url(path+"?go-fs=login"), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	return do(t, req)
}

// login logs in and returns the session cookie it was handed.
func login(t *testing.T, server *testServer, path, name, password string) *http.Cookie {
	t.Helper()
	res := postLogin(t, server, path, name, password)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", res.StatusCode)
	}
	session := cookieNamed(res, sessionCookie)
	if session == nil {
		t.Fatal("no session token was handed out")
	}
	return session
}

// cookieNamed finds one cookie in an answer, or nothing.
func cookieNamed(res *http.Response, name string) *http.Cookie {
	for _, cookie := range res.Cookies() {
		if cookie.Name == name && cookie.Value != "" {
			return cookie
		}
	}
	return nil
}

// withSession sends a request carrying nothing but a session token.
func withSession(t *testing.T, server *testServer, method, path string, session *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, server.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	return do(t, req)
}

// fixClock pins the login tracker's clock and returns a way to move it, so a
// test about the lock never waits. It has to be called before any request.
func fixClock(server *testServer) func(time.Duration) {
	var mu sync.Mutex
	now := time.Now()
	server.logins.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	return func(by time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(by)
	}
}

// forwarded sends a request with the headers a reverse proxy would add, and
// Basic credentials when a name is given.
func forwarded(t *testing.T, server *testServer, method, path string, headers map[string]string, name, password string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, server.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if name != "" {
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(name+":"+password)))
	}
	return do(t, req)
}

package supervisor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/httpd"
)

// logStore collects what the supervisor reports.
type logStore struct {
	mu      sync.Mutex
	records []string
}

func (s *logStore) Enabled(context.Context, slog.Level) bool { return true }
func (s *logStore) WithAttrs([]slog.Attr) slog.Handler       { return s }
func (s *logStore) WithGroup(string) slog.Handler            { return s }

func (s *logStore) Handle(_ context.Context, record slog.Record) error {
	line := record.Message
	record.Attrs(func(attr slog.Attr) bool {
		line += fmt.Sprintf(" %s=%v", attr.Key, attr.Value.Any())
		return true
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, line)
	return nil
}

func (s *logStore) has(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range s.records {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

func (s *logStore) waitFor(t *testing.T, fragment string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.has(fragment) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("never saw %q in:\n%s", fragment, strings.Join(s.records, "\n"))
}

// baseConfig is a configuration with the HTTP and TFTP servers on ephemeral
// ports and one account.
func baseConfig(t *testing.T) config.Config {
	t.Helper()
	folder := t.TempDir()
	cfg := config.Default()
	cfg.General.Basefolder = folder
	cfg.FTP.Enabled = false
	cfg.SFTP.Enabled = false
	cfg.TFTP.Enabled = false
	cfg.HTTP.Enabled = true
	cfg.HTTP.Port = 0
	cfg.HTTP.Basefolder = folder
	cfg.HTTP.LoginFailureDelay = 0
	cfg.HTTP.PathsRequireAuth = []string{"^/private/.*"}
	cfg.Users = []config.User{{
		Username: "john", Password: "doe", HTTP: true, Paths: []string{"^/.*"},
		AllowUserFileRetrieve: new(true),
	}}
	cfg.TFTP.Basefolder = folder
	return cfg
}

func newSupervisor(t *testing.T) (*Supervisor, *logStore, context.Context) {
	t.Helper()
	logs := &logStore{}
	// the path only has to name the file the admin interface would edit; the
	// interface reads it when a request asks for it, not when it is built
	sup := New(slog.New(logs), filepath.Join(t.TempDir(), "go-fs.toml"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		sup.Shutdown(context.Background())
	})
	return sup, logs, ctx
}

// httpPort digs the bound port out of the running HTTP server.
func httpPort(t *testing.T, sup *Supervisor) int {
	t.Helper()
	sup.mu.Lock()
	defer sup.mu.Unlock()
	server, ok := sup.running["http"].(*httpd.Server)
	if !ok {
		t.Fatal("the http server is not running")
	}
	addr, ok := server.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("the http server has no address")
	}
	return addr.Port
}

func fetch(t *testing.T, port int, path, name, password string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		"http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		req.SetBasicAuth(name, password)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func TestApplyStartsStopsAndRestarts(t *testing.T) {
	sup, logs, ctx := newSupervisor(t)
	cfg := baseConfig(t)

	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := sup.Running(); len(got) != 1 || got[0] != "http" {
		t.Fatalf("running = %v, want just http", got)
	}
	logs.waitFor(t, "server started server=http")

	// switching another server on starts only that one
	cfg.TFTP.Enabled = true
	cfg.TFTP.Port = 0
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := sup.Running(); len(got) != 2 {
		t.Fatalf("running = %v, want http and tftp", got)
	}
	logs.waitFor(t, "server started server=tftp")

	// switching it off again stops it
	cfg.TFTP.Enabled = false
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := sup.Running(); len(got) != 1 || got[0] != "http" {
		t.Fatalf("running = %v, want just http", got)
	}
	logs.waitFor(t, "server stopped server=tftp")
}

// An account change is applied to the running server; a port change rebinds it.
func TestApplyReloadsOrRestarts(t *testing.T) {
	sup, logs, ctx := newSupervisor(t)
	cfg := baseConfig(t)
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	port := httpPort(t, sup)

	cfg.Users = append(cfg.Users, config.User{
		Username: "jane", Password: "secret", HTTP: true, Paths: []string{"^/.*"},
		AllowUserFileRetrieve: new(true),
	})
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	logs.waitFor(t, "server reloaded server=http")
	if got := httpPort(t, sup); got != port {
		t.Errorf("the listener was rebound: %d -> %d", port, got)
	}

	// a base folder change cannot be applied to a bound listener
	cfg.HTTP.Basefolder = t.TempDir()
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	logs.waitFor(t, "server restarted server=http")
}

// Each server is handed the accounts that switch it on, and a switch flipped
// in the file reaches it on the next reload.
func TestAccountsReachOnlyTheServersTheySwitchOn(t *testing.T) {
	sup, logs, ctx := newSupervisor(t)
	cfg := baseConfig(t)
	if err := os.MkdirAll(filepath.Join(cfg.HTTP.Basefolder, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	port := httpPort(t, sup)

	if res := fetch(t, port, "/private/", "john", "doe"); res.StatusCode != http.StatusOK {
		t.Fatalf("john is switched on for http, got %d", res.StatusCode)
	}

	cfg.Users[0].HTTP = false
	cfg.Users[0].FTP = true
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	logs.waitFor(t, "server reloaded server=http")
	if res := fetch(t, port, "/private/", "john", "doe"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("john is switched off for http, got %d", res.StatusCode)
	}
}

// The whole point: an account change must not disturb a transfer in flight.
func TestReloadDoesNotDisturbATransfer(t *testing.T) {
	sup, logs, ctx := newSupervisor(t)
	cfg := baseConfig(t)

	// a file big enough that the read takes a moment
	payload := strings.Repeat("go-fs payload ", 400000) // about 5.6 MB
	if err := os.WriteFile(filepath.Join(cfg.HTTP.Basefolder, "big.bin"), []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	port := httpPort(t, sup)

	res := fetch(t, port, "/big.bin", "", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	// read the first bytes, then reload while the rest is still coming
	head := make([]byte, 1024)
	if _, err := io.ReadFull(res.Body, head); err != nil {
		t.Fatal(err)
	}

	cfg.Users = append(cfg.Users, config.User{
		Username: "jane", Password: "secret", HTTP: true, Paths: []string{"^/.*"},
		AllowUserFileRetrieve: new(true),
	})
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	logs.waitFor(t, "server reloaded server=http")

	rest, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("the download was cut short: %v", err)
	}
	if got := string(head) + string(rest); got != payload {
		t.Errorf("the download came back changed: %d bytes instead of %d", len(got), len(payload))
	}

	// and the account added mid-transfer works
	if res := fetch(t, port, "/private/", "jane", "secret"); res.StatusCode == http.StatusUnauthorized {
		t.Error("jane should have been accepted")
	}
}

// TestAdminInterfaceIsServedByTheHTTPServer checks that the supervisor hands
// the http server the configuration file, so that the interface that edits it
// is there, and that it opens to nobody but a session of an admin account.
func TestAdminInterfaceIsServedByTheHTTPServer(t *testing.T) {
	sup, _, ctx := newSupervisor(t)

	cfg := baseConfig(t)
	cfg.Users = append(cfg.Users, config.User{
		Username: "root", Password: "secret", HTTP: true, IsAdmin: true,
		Paths: []string{"^/.*"},
	})
	// the file the interface reads back has to exist and validate
	if err := config.Save(sup.path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(sup.Running(), "admin") {
		t.Fatalf("the admin interface is a server of its own: %v", sup.Running())
	}
	port := httpPort(t, sup)

	// a header, even the admin's own, is not a session
	if res := fetch(t, port, "/?go-fs=admin-config", "root", "secret"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("basic authentication was answered %d, want 401", res.StatusCode)
	}

	form := url.Values{"username": {"root"}, "password": {"secret"}}
	req, err := http.NewRequest(http.MethodPost,
		"http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/?go-fs=login",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var session *http.Cookie
	for _, cookie := range res.Cookies() {
		if cookie.Name == "goFsSessionToken" {
			session = cookie
		}
	}
	if session == nil {
		t.Fatalf("the login handed out no session: %s", res.Status)
	}

	req, err = http.NewRequest(http.MethodGet,
		"http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/?go-fs=admin-config", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the admin session was answered %d: %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), sup.path) {
		t.Errorf("the state does not name the file the supervisor was given: %s", body)
	}

	// the switch is applied by a reload, not a restart
	cfg.HTTP.EnableAdminInterface = false
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("the disabled interface was answered %d, want 404", res.StatusCode)
	}
}

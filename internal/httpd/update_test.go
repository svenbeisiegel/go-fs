package httpd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/selfupdate"
)

// stubUpdater stands in for selfupdate.Updater: it keeps what it was sent,
// answers with err, and replaces no binary.
type stubUpdater struct {
	err error

	mu        sync.Mutex
	staged    []byte
	calls     int
	requested chan struct{}
	once      sync.Once
}

func newStubUpdater() *stubUpdater {
	return &stubUpdater{requested: make(chan struct{})}
}

func (u *stubUpdater) Current() selfupdate.Info {
	return selfupdate.Info{Version: "1.0.0", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Executable: "/opt/go-fs/go-fs", Keys: []string{"0123456789abcdef"}}
}

func (u *stubUpdater) Stage(_ context.Context, body io.Reader) (selfupdate.Staged, error) {
	content, err := io.ReadAll(body)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls++
	u.staged = content
	if err != nil {
		return selfupdate.Staged{}, err
	}
	if u.err != nil {
		return selfupdate.Staged{}, u.err
	}
	return selfupdate.Staged{Version: "2.0.0", Key: "0123456789abcdef"}, nil
}

func (u *stubUpdater) Request() {
	u.once.Do(func() { close(u.requested) })
}

func (u *stubUpdater) fail(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.err = err
}

func (u *stubUpdater) stageCalls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// wasRequested waits for the restart the endpoint asks for once it has
// answered.
func (u *stubUpdater) wasRequested(wait time.Duration) bool {
	select {
	case <-u.requested:
		return true
	case <-time.After(wait):
		return false
	}
}

// updateServer is an admin server with the update endpoint on, a token that
// may update and one that may not.
type updateServer struct {
	*testServer
	updater  *stubUpdater
	updating string
	plain    string
}

func newUpdateServer(t *testing.T, tune func(*httpConfig)) *updateServer {
	t.Helper()
	updating, updatingPlain := fullToken(t, "deploy")
	updating.AllowSelfUpdate = new(true)
	plain, plainPlain := fullToken(t, "backup")
	server := adminServer(t, func(cfg *httpConfig) {
		cfg.EnableSelfUpdate = true
		cfg.Tokens = []config.Token{updating, plain}
		if tune != nil {
			tune(cfg)
		}
	})
	updater := newStubUpdater()
	server.SetUpdater(updater)
	return &updateServer{testServer: server, updater: updater,
		updating: updatingPlain, plain: plainPlain}
}

const updatePath = "/?go-fs=update"

// The endpoint describes the running binary to whoever may update it.
func TestUpdateInfo(t *testing.T) {
	server := newUpdateServer(t, nil)
	res := bearer(t, server.testServer, http.MethodGet, updatePath, server.updating, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var info selfupdate.Info
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info.Version != "1.0.0" || info.OS != runtime.GOOS || info.Arch != runtime.GOARCH ||
		len(info.Keys) != 1 {
		t.Errorf("info %+v", info)
	}
}

// A token that may update uploads, is answered, and the restart follows.
func TestUpdateWithToken(t *testing.T) {
	server := newUpdateServer(t, nil)
	res := bearer(t, server.testServer, http.MethodPut, updatePath, server.updating,
		strings.NewReader("new binary"))
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d: %s", res.StatusCode, bodyOf(t, res))
	}
	var answer struct {
		Previous   string `json:"previous"`
		Version    string `json:"version"`
		Restarting bool   `json:"restarting"`
	}
	if err := json.NewDecoder(res.Body).Decode(&answer); err != nil {
		t.Fatal(err)
	}
	if answer.Previous != "1.0.0" || answer.Version != "2.0.0" || !answer.Restarting {
		t.Errorf("answer %+v", answer)
	}
	server.updater.mu.Lock()
	staged := string(server.updater.staged)
	server.updater.mu.Unlock()
	if staged != "new binary" {
		t.Errorf("the updater was handed %q", staged)
	}
	if !server.updater.wasRequested(5 * time.Second) {
		t.Error("no restart was requested")
	}
	if record := server.logs.find("http self update accepted, restarting"); record == nil ||
		record["user"] != "token:deploy" || record["version"] != "2.0.0" {
		t.Errorf("record %v", record)
	}
}

// An admin updates through the session the admin interface runs in.
func TestUpdateWithAdminSession(t *testing.T) {
	server := newUpdateServer(t, nil)
	session := login(t, server.testServer, "/", "root", "secret")
	req, err := http.NewRequest(http.MethodPut, server.url(updatePath), strings.NewReader("new binary"))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Origin", "http://"+req.URL.Host)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if res := do(t, req); res.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d: %s", res.StatusCode, bodyOf(t, res))
	}
	if !server.updater.wasRequested(5 * time.Second) {
		t.Error("no restart was requested")
	}
}

// Everything but a token that may update and an admin's session is turned
// away, and nothing reaches the updater.
func TestUpdateRefusesCredentials(t *testing.T) {
	server := newUpdateServer(t, nil)
	john := login(t, server.testServer, "/", "john", "doe")

	anonymous := func() *http.Response {
		req, err := http.NewRequest(http.MethodPut, server.url(updatePath), strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		return do(t, req)
	}
	session := func(cookie *http.Cookie) func() *http.Response {
		return func() *http.Response {
			req, err := http.NewRequest(http.MethodPut, server.url(updatePath), strings.NewReader("x"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(cookie)
			return do(t, req)
		}
	}
	tests := []struct {
		name   string
		send   func() *http.Response
		status int
	}{
		{"no credentials", anonymous, http.StatusUnauthorized},
		{"unknown token", func() *http.Response {
			return bearer(t, server.testServer, http.MethodPut, updatePath, "gofs_wrong", strings.NewReader("x"))
		}, http.StatusUnauthorized},
		{"token without allowSelfUpdate", func() *http.Response {
			return bearer(t, server.testServer, http.MethodPut, updatePath, server.plain, strings.NewReader("x"))
		}, http.StatusForbidden},
		{"basic for an admin", func() *http.Response {
			return basic(t, server.testServer, http.MethodPut, updatePath, "root", "secret", strings.NewReader("x"))
		}, http.StatusForbidden},
		{"session of an account that is not an admin", session(john), http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if res := test.send(); res.StatusCode != test.status {
				t.Errorf("status %d, want %d", res.StatusCode, test.status)
			}
		})
	}
	if calls := server.updater.stageCalls(); calls != 0 {
		t.Errorf("the updater was called %d times", calls)
	}
	if res := anonymous(); !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Bearer ") {
		t.Errorf("challenge %q", res.Header.Get("WWW-Authenticate"))
	}
}

// Switched off, or without an updater, the marker names nothing.
func TestUpdateDisabled(t *testing.T) {
	server := newUpdateServer(t, func(cfg *httpConfig) { cfg.EnableSelfUpdate = false })
	res := bearer(t, server.testServer, http.MethodPut, updatePath, server.updating, strings.NewReader("x"))
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("switched off: status %d", res.StatusCode)
	}

	server = newUpdateServer(t, nil)
	server.SetUpdater(nil)
	res = bearer(t, server.testServer, http.MethodGet, updatePath, server.updating, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("no updater: status %d", res.StatusCode)
	}
}

// A page on another site cannot use an admin's session to upload.
func TestUpdateRefusesCrossSite(t *testing.T) {
	server := newUpdateServer(t, nil)
	session := login(t, server.testServer, "/", "root", "secret")
	req, err := http.NewRequest(http.MethodPut, server.url(updatePath), strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	req.Header.Set("Origin", "https://evil.example")
	if res := do(t, req); res.StatusCode != http.StatusForbidden {
		t.Errorf("status %d", res.StatusCode)
	}
	if calls := server.updater.stageCalls(); calls != 0 {
		t.Errorf("the updater was called %d times", calls)
	}
}

// Each reason an update is refused has its own status, and no restart
// follows.
func TestUpdateRefusalStatus(t *testing.T) {
	tests := []struct {
		err    error
		status int
	}{
		{selfupdate.ErrUnsigned, http.StatusBadRequest},
		{fmt.Errorf("%w (key 00)", selfupdate.ErrUnknownKey), http.StatusUnprocessableEntity},
		{selfupdate.ErrBadSignature, http.StatusUnprocessableEntity},
		{fmt.Errorf("%w: linux/amd64", selfupdate.ErrPlatform), http.StatusUnprocessableEntity},
		{selfupdate.ErrNotGoFS, http.StatusUnprocessableEntity},
		{selfupdate.ErrTooLarge, http.StatusRequestEntityTooLarge},
		{selfupdate.ErrBusy, http.StatusConflict},
		{selfupdate.ErrNoKeys, http.StatusServiceUnavailable},
		{errors.New("disk full"), http.StatusInternalServerError},
	}
	server := newUpdateServer(t, nil)
	for _, test := range tests {
		t.Run(test.err.Error(), func(t *testing.T) {
			server.updater.fail(test.err)
			res := bearer(t, server.testServer, http.MethodPut, updatePath, server.updating,
				strings.NewReader("x"))
			if res.StatusCode != test.status {
				t.Errorf("status %d, want %d", res.StatusCode, test.status)
			}
		})
	}
	if server.updater.wasRequested(2 * restartDelay) {
		t.Error("a refused update requested a restart")
	}
}

// A declared length above the limit is refused before any of the body is
// read.
func TestUpdateRefusesDeclaredLength(t *testing.T) {
	server := newUpdateServer(t, nil)
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.url(""), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PUT %s HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer %s\r\n"+
		"Content-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n",
		updatePath, server.updating, selfupdate.MaxSize+1)
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d", res.StatusCode)
	}
	if calls := server.updater.stageCalls(); calls != 0 {
		t.Errorf("the updater was called %d times", calls)
	}
}

func TestUpdateMethodNotAllowed(t *testing.T) {
	server := newUpdateServer(t, nil)
	res := bearer(t, server.testServer, http.MethodDelete, updatePath, server.updating, nil)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status %d", res.StatusCode)
	}
}

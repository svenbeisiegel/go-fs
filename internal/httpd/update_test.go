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
	// release is what Latest answers, with latestErr; Download hands out
	// "release binary" or downloadErr
	release     selfupdate.Release
	latestErr   error
	downloadErr error
	refreshed   []bool

	mu        sync.Mutex
	staged    []byte
	calls     int
	requested chan struct{}
	once      sync.Once
}

func newStubUpdater() *stubUpdater {
	return &stubUpdater{
		requested: make(chan struct{}),
		release: selfupdate.Release{Current: "1.0.0", Version: "2.0.0", Newer: true,
			URL: "https://github.com/x/go-fs/releases/tag/v2.0.0", Asset: "go-fs_2.0.0_linux_amd64.update"},
	}
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

func (u *stubUpdater) Latest(_ context.Context, refresh bool) (selfupdate.Release, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshed = append(u.refreshed, refresh)
	return u.release, u.latestErr
}

func (u *stubUpdater) Download(context.Context, selfupdate.Release) (io.ReadCloser, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.downloadErr != nil {
		return nil, u.downloadErr
	}
	return io.NopCloser(strings.NewReader("release binary")), nil
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

const releasePath = "/?go-fs=update&release=latest"

// With release=latest the endpoint describes the latest release, from the
// updater's lookup unless refresh asks for a new one.
func TestUpdateLatestRelease(t *testing.T) {
	server := newUpdateServer(t, nil)
	res := bearer(t, server.testServer, http.MethodGet, releasePath, server.updating, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, bodyOf(t, res))
	}
	var release selfupdate.Release
	if err := json.NewDecoder(res.Body).Decode(&release); err != nil {
		t.Fatal(err)
	}
	if release.Version != "2.0.0" || release.Current != "1.0.0" || !release.Newer ||
		release.Asset == "" || release.URL == "" {
		t.Errorf("release %+v", release)
	}
	bearer(t, server.testServer, http.MethodGet, releasePath+"&refresh=1", server.updating, nil)
	server.updater.mu.Lock()
	refreshed := server.updater.refreshed
	server.updater.mu.Unlock()
	if len(refreshed) != 2 || refreshed[0] || !refreshed[1] {
		t.Errorf("refresh asked for %v", refreshed)
	}
	if calls := server.updater.stageCalls(); calls != 0 {
		t.Errorf("describing the release staged %d updates", calls)
	}
}

// The release is described only to whoever may update.
func TestUpdateLatestReleaseRefusesCredentials(t *testing.T) {
	server := newUpdateServer(t, nil)
	if res := bearer(t, server.testServer, http.MethodGet, releasePath, server.plain, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("token without allowSelfUpdate: status %d", res.StatusCode)
	}
	req, err := http.NewRequest(http.MethodGet, server.url(releasePath), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res := do(t, req); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credentials: status %d", res.StatusCode)
	}
}

// A lookup that fails is a bad gateway: go-fs itself is fine.
func TestUpdateLatestReleaseUnreachable(t *testing.T) {
	server := newUpdateServer(t, nil)
	server.updater.latestErr = fmt.Errorf("%w: no route to host", selfupdate.ErrUnreachable)
	res := bearer(t, server.testServer, http.MethodGet, releasePath, server.updating, nil)
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d", res.StatusCode)
	}
}

// An admin installs the latest release: go-fs downloads its update file and
// stages it as it would an upload, answers and restarts.
func TestUpdateInstallRelease(t *testing.T) {
	server := newUpdateServer(t, nil)
	session := login(t, server.testServer, "/", "root", "secret")
	req, err := http.NewRequest(http.MethodPost, server.url(releasePath), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	req.Header.Set("Origin", "http://"+req.URL.Host)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res := do(t, req)
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d: %s", res.StatusCode, bodyOf(t, res))
	}
	server.updater.mu.Lock()
	staged := string(server.updater.staged)
	server.updater.mu.Unlock()
	if staged != "release binary" {
		t.Errorf("the updater was handed %q", staged)
	}
	if !server.updater.wasRequested(5 * time.Second) {
		t.Error("no restart was requested")
	}
	if record := server.logs.find("http self update accepted, restarting"); record == nil ||
		record["source"] != "go-fs_2.0.0_linux_amd64.update" {
		t.Errorf("record %v", record)
	}
}

// A page on another site cannot have an admin's session install a release.
func TestUpdateInstallReleaseRefusesCrossSite(t *testing.T) {
	server := newUpdateServer(t, nil)
	session := login(t, server.testServer, "/", "root", "secret")
	req, err := http.NewRequest(http.MethodPost, server.url(releasePath), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	req.Header.Set("Origin", "https://evil.example")
	if res := do(t, req); res.StatusCode != http.StatusForbidden {
		t.Errorf("status %d", res.StatusCode)
	}
	server.updater.mu.Lock()
	looked := len(server.updater.refreshed)
	server.updater.mu.Unlock()
	if looked != 0 || server.updater.stageCalls() != 0 {
		t.Error("the updater was used")
	}
}

// A release that cannot be fetched, or has nothing for this platform, is
// refused with its own status, and no restart follows.
func TestUpdateInstallReleaseRefusal(t *testing.T) {
	tests := []struct {
		name     string
		latest   error
		download error
		status   int
	}{
		{"lookup fails", fmt.Errorf("%w: timeout", selfupdate.ErrUnreachable), nil, http.StatusBadGateway},
		{"download fails", nil, fmt.Errorf("%w: 404", selfupdate.ErrUnreachable), http.StatusBadGateway},
		{"no file for this platform", nil, selfupdate.ErrNoAsset, http.StatusNotFound},
	}
	server := newUpdateServer(t, nil)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server.updater.mu.Lock()
			server.updater.latestErr, server.updater.downloadErr = test.latest, test.download
			server.updater.mu.Unlock()
			res := bearer(t, server.testServer, http.MethodPost, releasePath, server.updating, nil)
			if res.StatusCode != test.status {
				t.Errorf("status %d, want %d", res.StatusCode, test.status)
			}
		})
	}
	if calls := server.updater.stageCalls(); calls != 0 {
		t.Errorf("the updater staged %d updates", calls)
	}
	if server.updater.wasRequested(2 * restartDelay) {
		t.Error("a refused update requested a restart")
	}
}

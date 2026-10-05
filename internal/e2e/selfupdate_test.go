package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/selfupdate"
)

// buildGoFS compiles go-fs at a version, trusting the update key given and
// looking up its releases at releases.
func buildGoFS(t *testing.T, gobin, out, version string, key ed25519.PublicKey, releases string) {
	t.Helper()
	ldflags := "-X main.version=" + version +
		" -X go-fs/internal/selfupdate.buildKeys=" + selfupdate.EncodePublicKey(key) +
		" -X go-fs/internal/selfupdate.releaseAPI=" + releases
	cmd := exec.Command(gobin, "build", "-trimpath", "-ldflags", ldflags, "-o", out, ".")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building go-fs %s: %v\n%s", version, err, output)
	}
}

// freePort finds a port nothing listens on, for a server this test does not
// start in process.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// updateInfo asks the running server what it is, or reports why it could not.
func updateInfo(url, token string) (selfupdate.Info, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return selfupdate.Info{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return selfupdate.Info{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return selfupdate.Info{}, fmt.Errorf("status %d", res.StatusCode)
	}
	var info selfupdate.Info
	err = json.NewDecoder(res.Body).Decode(&info)
	return info, err
}

func putUpdate(t *testing.T, url, token string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

// sign returns the update file of a binary.
func sign(t *testing.T, private ed25519.PrivateKey, binary []byte) []byte {
	t.Helper()
	var update bytes.Buffer
	if err := selfupdate.Sign(private, bytes.NewReader(binary), &update); err != nil {
		t.Fatal(err)
	}
	return update.Bytes()
}

// fakeRelease answers as the GitHub API does for the latest release, which
// is version, with update as its file for this platform. Until a version is
// set it answers that there is no release.
type fakeRelease struct {
	*httptest.Server
	mu      sync.Mutex
	version string
	update  []byte
}

func newFakeRelease(t *testing.T) *fakeRelease {
	t.Helper()
	fake := &fakeRelease{}
	name := func(version string) string {
		name := "go-fs_" + version + "_" + runtime.GOOS + "_" + runtime.GOARCH
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		return name + ".update"
	}
	fake.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		version, update := fake.version, fake.update
		fake.mu.Unlock()
		switch {
		case version == "":
			http.NotFound(w, r)
		case r.URL.Path == "/latest":
			fmt.Fprintf(w, `{"tag_name":"v%s","html_url":"%s/v%s","assets":[{"name":%q,"browser_download_url":"%s/download"}]}`,
				version, fake.URL, version, name(version), fake.URL)
		case r.URL.Path == "/download":
			_, _ = w.Write(update)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)
	return fake
}

func (f *fakeRelease) publish(version string, update []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version, f.update = version, update
}

// A running go-fs takes a signed build of a newer version over HTTP, replaces
// its own executable with it and comes back as that version: on unix as the
// same process, on Windows as a new one. It then fetches and installs the
// latest release the same way.
func TestSelfUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("builds go-fs twice")
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain to build go-fs with")
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "go-fs")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	releases := newFakeRelease(t)
	releasesAPI := releases.URL + "/latest"
	buildGoFS(t, gobin, exe, "1.0.0", public, releasesAPI)
	next := filepath.Join(t.TempDir(), "go-fs-next")
	buildGoFS(t, gobin, next, "2.0.0", public, releasesAPI)
	binary, err := os.ReadFile(next)
	if err != nil {
		t.Fatal(err)
	}
	update := sign(t, private, binary)
	released := filepath.Join(t.TempDir(), "go-fs-released")
	buildGoFS(t, gobin, released, "3.0.0", public, releasesAPI)
	releasedBinary, err := os.ReadFile(released)
	if err != nil {
		t.Fatal(err)
	}

	token, hash, err := config.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	served := filepath.Join(dir, "served")
	if err := os.Mkdir(served, 0o755); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	cfgPath := filepath.Join(dir, "go-fs.toml")
	cfg := fmt.Sprintf(`[general]
basefolder = %s
reloadConfig = false
[ftp]
enabled = false
[tftp]
enabled = false
[http]
enabled = true
address = "127.0.0.1"
port = %d
enableSelfUpdate = true
[[tokens]]
name = "deploy"
hash = %q
allowSelfUpdate = true
`, strconv.Quote(served), port, hash)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// a file rather than a pipe: on Windows the new process inherits it, and
	// a pipe would keep Wait from returning while that one runs
	logPath := filepath.Join(dir, "go-fs.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(exe, "-config", cfgPath)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	// whatever runs at the end is stopped, whether it is the process started
	// here or the one it became
	running := cmd.Process.Pid
	t.Cleanup(func() {
		if process, err := os.FindProcess(running); err == nil {
			_ = process.Kill()
		}
		if runtime.GOOS == "windows" {
			// the executable stays locked for a moment after its process ends
			time.Sleep(time.Second)
		}
	})
	logs := func() string {
		content, _ := os.ReadFile(logPath)
		return string(content)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/?go-fs=update", port)
	waitFor := func(version string) selfupdate.Info {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		var last error
		for time.Now().Before(deadline) {
			info, err := updateInfo(url, token)
			if err == nil && info.Version == version {
				return info
			}
			last = err
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("go-fs %s did not come up: %v\n%s", version, last, logs())
		return selfupdate.Info{}
	}

	first := waitFor("1.0.0")
	if first.PID != cmd.Process.Pid {
		t.Errorf("the server reports pid %d, it was started as %d", first.PID, cmd.Process.Pid)
	}

	// an unsigned build is refused, and the server keeps running
	if res := putUpdate(t, url, token, binary); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsigned update: status %d", res.StatusCode)
	}
	waitFor("1.0.0")

	if res := putUpdate(t, url, token, update); res.StatusCode != http.StatusAccepted {
		t.Fatalf("signed update: status %d\n%s", res.StatusCode, logs())
	}
	second := waitFor("2.0.0")
	running = second.PID

	if runtime.GOOS == "windows" {
		// the new process is a child of the old one, which has ended
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			t.Error("the previous process did not exit")
		}
	} else if second.PID != first.PID {
		t.Errorf("the new version runs as pid %d, the previous one ran as %d", second.PID, first.PID)
	}

	installed, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, binary) {
		t.Error("the installed executable is not the signed build")
	}
	// the previous version is kept beside it, as the way back
	if _, err := os.Stat(exe + ".old"); err != nil {
		t.Errorf("the previous executable was not kept: %v", err)
	}

	// with nothing released the lookup fails, and nothing changes
	if res := releaseRequest(t, http.MethodGet, url, token); res.StatusCode != http.StatusBadGateway {
		t.Fatalf("no release: status %d", res.StatusCode)
	}

	releases.publish("3.0.0", sign(t, private, releasedBinary))
	res := releaseRequest(t, http.MethodGet, url+"&refresh=1", token)
	var release selfupdate.Release
	if err := json.NewDecoder(res.Body).Decode(&release); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("release lookup: status %d, %v", res.StatusCode, err)
	}
	if release.Version != "3.0.0" || release.Current != "2.0.0" || !release.Newer || release.Asset == "" {
		t.Fatalf("release %+v", release)
	}
	if res := releaseRequest(t, http.MethodPost, url, token); res.StatusCode != http.StatusAccepted {
		t.Fatalf("release update: status %d\n%s", res.StatusCode, logs())
	}
	third := waitFor("3.0.0")
	running = third.PID
	installed, err = os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, releasedBinary) {
		t.Error("the installed executable is not the released build")
	}
}

// releaseRequest asks the update endpoint about the latest release, or with
// POST to install it.
func releaseRequest(t *testing.T, method, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url+"&release=latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

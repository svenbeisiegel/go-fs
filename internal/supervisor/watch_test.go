package supervisor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"go-fs/internal/config"
)

// freePort picks a port that is free right now. The configuration file cannot
// ask for port 0, because a port of zero is not a valid one to configure.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

// writeConfig puts a configuration file in place with the folders pointed at
// somewhere that exists.
func writeConfig(t *testing.T, path, folder string, port int, users string) {
	t.Helper()
	body := `
[general]
basefolder = "` + folder + `"
reloadInterval = 1

[ftp]
enabled = false

[tftp]
enabled = false

[http]
enabled = true
port = ` + strconv.Itoa(port) + `
loginFailureDelay = 0
pathsRequireAuth = ["^/private/.*"]
` + users
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startFromFile applies exactly what the file says, so that what is running
// and what the watcher will read start out in step.
func startFromFile(t *testing.T, sup *Supervisor, ctx context.Context, path string) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
}

const johnOnly = `
[[users]]
username = "john"
password = "doe"
http = true
paths = ["^/.*"]
allowUserFileRetrieve = true
`

const johnAndJane = johnOnly + `
[[users]]
username = "jane"
password = "secret"
http = true
paths = ["^/.*"]
allowUserFileRetrieve = true
`

// A change to the file is picked up and applied.
func TestWatchAppliesAChange(t *testing.T) {
	sup, logs, ctx := newSupervisor(t)
	folder := t.TempDir()
	if err := os.Mkdir(filepath.Join(folder, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "go-fs.toml")
	chosen := freePort(t)
	writeConfig(t, path, folder, chosen, johnOnly)
	startFromFile(t, sup, ctx, path)
	port := httpPort(t, sup)

	go sup.Watch(ctx, path, 50*time.Millisecond)

	// the file has to look different to the watcher
	time.Sleep(20 * time.Millisecond)
	writeConfig(t, path, folder, chosen, johnAndJane)
	logs.waitFor(t, "server reloaded server=http")

	if got := httpPort(t, sup); got != port {
		t.Errorf("the listener was rebound: %d -> %d", port, got)
	}
	if res := fetch(t, port, "/private/", "jane", "secret"); res.StatusCode == 401 {
		t.Error("the account added in the file should have been applied")
	}
}

// A file that does not parse is reported and the running configuration stays.
func TestWatchRejectsABrokenFile(t *testing.T) {
	sup, logs, ctx := newSupervisor(t)
	folder := t.TempDir()
	if err := os.Mkdir(filepath.Join(folder, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "go-fs.toml")
	writeConfig(t, path, folder, freePort(t), johnOnly)
	startFromFile(t, sup, ctx, path)
	port := httpPort(t, sup)

	go sup.Watch(ctx, path, 50*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("this is not [valid toml"), 0o600); err != nil {
		t.Fatal(err)
	}

	logs.waitFor(t, "the configuration was not applied, keeping the running one")
	if got := sup.Running(); len(got) != 1 || got[0] != "http" {
		t.Fatalf("running = %v, want the server still up", got)
	}
	if res := fetch(t, port, "/private/", "john", "doe"); res.StatusCode != 200 {
		t.Errorf("the running configuration should still serve john, got %d", res.StatusCode)
	}
}

// A configuration that validates but says the same thing changes nothing, so
// touching the file does not restart anything.
func TestWatchIgnoresAnUnchangedConfiguration(t *testing.T) {
	sup, logs, ctx := newSupervisor(t)
	folder := t.TempDir()
	path := filepath.Join(t.TempDir(), "go-fs.toml")
	writeConfig(t, path, folder, freePort(t), johnOnly)

	// start from exactly what the file says, so a reload is a no-op
	startFromFile(t, sup, ctx, path)
	go sup.Watch(ctx, path, 50*time.Millisecond)

	time.Sleep(20 * time.Millisecond)
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	if logs.has("server restarted") {
		t.Error("touching the file must not restart anything")
	}
}

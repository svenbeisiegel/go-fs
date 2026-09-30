package selfupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeSource is a program that stands in for go-fs: it prints line, and
// leaves a file named "ran" beside itself, so that a test can tell whether
// anything was run at all.
const fakeSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if exe, err := os.Executable(); err == nil {
		_ = os.WriteFile(filepath.Join(filepath.Dir(exe), "ran"), nil, 0o644)
	}
	fmt.Println(%q)
}
`

// buildFake compiles a fake that prints line, and returns its bytes.
func buildFake(t *testing.T, line string) []byte {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain to build a fake binary with")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, fmt.Appendf(nil, fakeSource, line), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "fake")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command(gobin, "build", "-o", out, source)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the fake: %v\n%s", err, output)
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// testUpdater is an updater whose "running executable" is a file in a folder
// of its own, holding "old", so that applying an update replaces nothing
// that matters.
func testUpdater(t *testing.T, keys ...ed25519.PublicKey) *Updater {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "go-fs")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	updater := New("1.0.0", keys)
	updater.exe, updater.exeErr = exe, nil
	return updater
}

func (u *Updater) dir() string { return filepath.Dir(u.exe) }

// assertNothingRan checks that no fake was started and that the folder holds
// nothing but the executable.
func assertNothingRan(t *testing.T, u *Updater) {
	t.Helper()
	entries, err := os.ReadDir(u.dir())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == "ran" {
			t.Error("the upload was run")
		} else if entry.Name() != filepath.Base(u.exe) {
			t.Errorf("%s was left beside the executable", entry.Name())
		}
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// A signed go-fs for this platform is staged without the trailer, and applying
// it puts it in place of the executable and keeps the previous one.
func TestStageAndApply(t *testing.T) {
	public, private := newKey(t)
	fake := buildFake(t, "go-fs 9.9.9")
	u := testUpdater(t, public)

	staged, err := u.Stage(context.Background(), bytes.NewReader(signed(t, private, fake)))
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if staged.Version != "9.9.9" || staged.Key != KeyID(public) {
		t.Errorf("staged %+v", staged)
	}
	if !bytes.Equal(readFile(t, u.staged), fake) {
		t.Error("the staged file is not the binary that was signed")
	}
	if got := string(readFile(t, u.exe)); got != "old" {
		t.Errorf("staging touched the executable, it holds %q", got)
	}

	select {
	case <-u.Done():
		t.Fatal("a restart was requested by staging alone")
	default:
	}
	u.Request()
	select {
	case <-u.Done():
	default:
		t.Fatal("Request did not ask for the restart")
	}

	if err := u.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(readFile(t, u.exe), fake) {
		t.Error("the executable is not the new binary")
	}
	if got := string(readFile(t, u.exe+oldSuffix)); got != "old" {
		t.Errorf("the previous executable holds %q", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(u.exe)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("the new executable has mode %v", info.Mode().Perm())
		}
	}
}

// Nothing that fails the signature check is ever run, and nothing of it is
// left behind.
func TestStageRefusesBeforeRunning(t *testing.T) {
	public, _ := newKey(t)
	_, stranger := newKey(t)
	fake := buildFake(t, "go-fs 9.9.9")

	tests := []struct {
		name string
		body []byte
		want error
	}{
		{"unsigned", fake, ErrUnsigned},
		{"unknown key", signed(t, stranger, fake), ErrUnknownKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u := testUpdater(t, public)
			if _, err := u.Stage(context.Background(), bytes.NewReader(test.body)); !errors.Is(err, test.want) {
				t.Fatalf("Stage: %v, want %v", err, test.want)
			}
			assertNothingRan(t, u)
		})
	}
}

// A signed binary that does not answer -version as go-fs does is refused.
func TestStageRefusesWhatIsNotGoFS(t *testing.T) {
	public, private := newKey(t)
	u := testUpdater(t, public)
	_, err := u.Stage(context.Background(), bytes.NewReader(signed(t, private, buildFake(t, "hello"))))
	if !errors.Is(err, ErrNotGoFS) {
		t.Fatalf("Stage: %v, want %v", err, ErrNotGoFS)
	}
	// it did run, that was the test; but it is gone again
	_ = os.Remove(filepath.Join(u.dir(), "ran"))
	assertNothingRan(t, u)
}

// A signed binary for another platform is refused from its header, without
// being run.
func TestStageRefusesOtherPlatform(t *testing.T) {
	public, private := newKey(t)
	other := peHeader(pe.IMAGE_FILE_MACHINE_AMD64)
	if runtime.GOOS == "windows" {
		other = machoHeader(macho.CpuArm64)
	}
	u := testUpdater(t, public)
	_, err := u.Stage(context.Background(), bytes.NewReader(signed(t, private, other)))
	if !errors.Is(err, ErrPlatform) {
		t.Fatalf("Stage: %v, want %v", err, ErrPlatform)
	}
	assertNothingRan(t, u)
}

func TestStageRefusesTooLarge(t *testing.T) {
	public, private := newKey(t)
	u := testUpdater(t, public)
	u.maxSize = 1000
	_, err := u.Stage(context.Background(), bytes.NewReader(signed(t, private, make([]byte, 1000))))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Stage: %v, want %v", err, ErrTooLarge)
	}
	assertNothingRan(t, u)
}

func TestStageWithoutKeys(t *testing.T) {
	u := testUpdater(t)
	if _, err := u.Stage(context.Background(), strings.NewReader("anything")); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("Stage: %v, want %v", err, ErrNoKeys)
	}
}

// A failed update frees the updater for the next one; a staged one keeps it,
// since the process is about to restart.
func TestStageBusy(t *testing.T) {
	public, private := newKey(t)
	fake := signed(t, private, buildFake(t, "go-fs 9.9.9"))
	u := testUpdater(t, public)

	if _, err := u.Stage(context.Background(), strings.NewReader("unsigned")); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("Stage: %v", err)
	}
	if _, err := u.Stage(context.Background(), bytes.NewReader(fake)); err != nil {
		t.Fatalf("Stage after a failed one: %v", err)
	}
	if _, err := u.Stage(context.Background(), bytes.NewReader(fake)); !errors.Is(err, ErrBusy) {
		t.Fatalf("Stage after a staged one: %v, want %v", err, ErrBusy)
	}
}

func TestRequestWithoutStagedUpdate(t *testing.T) {
	u := testUpdater(t)
	u.Request()
	select {
	case <-u.Done():
		t.Fatal("a restart was requested with nothing staged")
	default:
	}
	if err := u.Apply(); err == nil {
		t.Fatal("Apply succeeded with nothing staged")
	}
}

func TestCleanupOld(t *testing.T) {
	u := testUpdater(t)
	for _, name := range []string{filepath.Base(u.exe) + oldSuffix, stagePrefix + "123", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(u.dir(), name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	u.CleanupOld()
	entries, err := os.ReadDir(u.dir())
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	want := []string{filepath.Base(u.exe), filepath.Base(u.exe) + oldSuffix, "keep.txt"}
	if strings.Join(left, ",") != strings.Join(want, ",") {
		t.Errorf("left %v, want %v", left, want)
	}
}

func TestCurrent(t *testing.T) {
	public, _ := newKey(t)
	u := testUpdater(t, public)
	info := u.Current()
	if info.Version != "1.0.0" || info.OS != runtime.GOOS || info.Arch != runtime.GOARCH ||
		info.Executable != u.exe || len(info.Keys) != 1 || info.Keys[0] != KeyID(public) {
		t.Errorf("Current: %+v", info)
	}
}

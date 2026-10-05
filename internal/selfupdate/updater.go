// Package selfupdate replaces the running go-fs binary with an uploaded one
// and restarts into it.
//
// An update goes through three steps, split so that nothing irreversible
// happens while a request is still being answered:
//
//   - Stage writes the upload beside the executable, checks its signature
//     against the keys built into this binary, checks that it is built for
//     this OS and architecture, and runs it with -version. Only a signed file
//     is ever run.
//   - Request, once the client has its answer, tells main to shut down.
//   - Apply and Restart, after every listener is closed, move the new binary
//     into place and start it: on unix by exec, keeping the PID, on Windows by
//     starting it and exiting.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxSize is the largest update accepted, trailer included. It is its own
// limit rather than http.maxUploadSize, which may be kept small on purpose
// for the files the server holds.
const MaxSize = 256 << 20

// stagePrefix names the files an update is staged in, beside the executable,
// so that one left behind by a crash is recognised and removed at the next
// start.
const stagePrefix = ".go-fs-update-"

// oldSuffix names the previous binary, kept beside the new one as a way back
// until the next update replaces it. Moving the running file aside rather
// than deleting it is also what Windows allows.
const oldSuffix = ".old"

var (
	// ErrBusy is a second update while one is being staged or applied.
	ErrBusy = errors.New("an update is already in progress")
	// ErrNoKeys is an update to a build that trusts no key, which therefore
	// cannot accept any.
	ErrNoKeys = errors.New("this build has no update signing key")
	// ErrTooLarge is an upload above MaxSize.
	ErrTooLarge = fmt.Errorf("the update is larger than the maximum of %d bytes", MaxSize)
	// ErrPlatform is a correctly signed binary for another OS or architecture.
	ErrPlatform = errors.New("the binary is built for another platform")
	// ErrNotGoFS is a binary that did not answer -version as go-fs does.
	ErrNotGoFS = errors.New("the binary does not run as go-fs")
)

// Info describes the running binary. PID tells a script that the restart
// after an update has happened: on unix it stays the same, on Windows it
// changes, and in both cases the version does.
type Info struct {
	Version    string   `json:"version"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	Executable string   `json:"executable"`
	PID        int      `json:"pid"`
	Keys       []string `json:"keys"`
}

// Staged describes a binary that passed every check and waits to be applied.
type Staged struct {
	Version string
	Key     string
}

// Updater holds the one update a process can go through.
type Updater struct {
	version string
	keys    []ed25519.PublicKey

	// exe is the running executable with its symlinks resolved, so that the
	// file replaced is the file that runs; exeErr is why it is unknown.
	exe    string
	exeErr error

	// maxSize and smokeTimeout are MaxSize and how long -version may take,
	// variables so that a test can shrink them.
	maxSize      int64
	smokeTimeout time.Duration

	// busy is taken by Stage and kept once a binary is staged: the process
	// is about to restart, and a second upload has nothing left to replace.
	busy atomic.Bool

	mu     sync.Mutex
	staged string

	done      chan struct{}
	requested sync.Once

	// client and releaseAPI are what the latest release is fetched with and
	// from, fields so that a test can point them elsewhere; release is the
	// last lookup, which releaseMu also holds while one is made, so that page
	// loads at the same moment ask GitHub once.
	client     *http.Client
	releaseAPI string
	releaseMu  sync.Mutex
	release    releaseCache
}

// New prepares the updater for the running binary.
func New(version string, keys []ed25519.PublicKey) *Updater {
	exe, err := executable()
	return &Updater{
		version:      version,
		keys:         keys,
		exe:          exe,
		exeErr:       err,
		maxSize:      MaxSize,
		smokeTimeout: 10 * time.Second,
		done:         make(chan struct{}),
		client:       &http.Client{Transport: http.DefaultTransport},
		releaseAPI:   releaseAPI,
	}
}

func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// Current describes the running binary.
func (u *Updater) Current() Info {
	keys := make([]string, 0, len(u.keys))
	for _, key := range u.keys {
		keys = append(keys, KeyID(key))
	}
	return Info{
		Version:    u.version,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Executable: u.exe,
		PID:        os.Getpid(),
		Keys:       keys,
	}
}

// Stage reads an update from body and checks it. When it returns without an
// error the new binary is ready beside the executable, and the running one has
// not been touched; on an error nothing is left behind.
func (u *Updater) Stage(ctx context.Context, body io.Reader) (Staged, error) {
	if len(u.keys) == 0 {
		return Staged{}, ErrNoKeys
	}
	if u.exeErr != nil {
		return Staged{}, fmt.Errorf("the running executable cannot be located: %w", u.exeErr)
	}
	if !u.busy.CompareAndSwap(false, true) {
		return Staged{}, ErrBusy
	}
	ready := false
	defer func() {
		if !ready {
			u.busy.Store(false)
		}
	}()

	// beside the executable, so that moving it into place is a rename on one
	// filesystem; the extension is the executable's, which Windows needs to
	// run it
	dir := filepath.Dir(u.exe)
	file, err := os.CreateTemp(dir, stagePrefix+"*"+filepath.Ext(u.exe))
	if err != nil {
		return Staged{}, fmt.Errorf("cannot write beside the executable in %s: %w", dir, err)
	}
	name := file.Name()
	defer func() {
		if !ready {
			_ = file.Close()
			_ = os.Remove(name)
		}
	}()

	size, err := io.Copy(file, io.LimitReader(body, u.maxSize+1))
	if err != nil {
		return Staged{}, err
	}
	if size > u.maxSize {
		return Staged{}, ErrTooLarge
	}
	if err := file.Sync(); err != nil {
		return Staged{}, err
	}

	// nothing of the file is run, or even parsed beyond the trailer, before
	// its signature is known to be good
	payload, key, err := Verify(file, size, u.keys)
	if err != nil {
		return Staged{}, err
	}
	if err := file.Truncate(payload); err != nil {
		return Staged{}, err
	}
	goos, goarch, err := platformOf(io.NewSectionReader(file, 0, payload))
	if err != nil {
		return Staged{}, err
	}
	if goos != runtime.GOOS || goarch != runtime.GOARCH {
		return Staged{}, fmt.Errorf("%w: it is for %s/%s, this server runs %s/%s",
			ErrPlatform, goos, goarch, runtime.GOOS, runtime.GOARCH)
	}
	if err := file.Close(); err != nil {
		return Staged{}, err
	}

	mode := os.FileMode(0o755)
	if info, err := os.Stat(u.exe); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(name, mode); err != nil {
		return Staged{}, err
	}

	version, err := u.smoke(ctx, name)
	if err != nil {
		return Staged{}, err
	}

	u.mu.Lock()
	u.staged = name
	u.mu.Unlock()
	ready = true
	return Staged{Version: version, Key: key}, nil
}

// smoke runs the staged binary with -version, which proves that this machine
// can start it and that it is go-fs, and reports the version it prints.
func (u *Updater) smoke(ctx context.Context, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, u.smokeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, "-version").Output()
	if err != nil {
		return "", fmt.Errorf("%w: -version failed: %v", ErrNotGoFS, err)
	}
	line := strings.TrimSpace(string(out))
	version, ok := strings.CutPrefix(line, "go-fs ")
	if !ok || version == "" {
		return "", fmt.Errorf("%w: -version printed %q", ErrNotGoFS, line)
	}
	return version, nil
}

// Request asks main to shut down and restart into the staged binary. Without
// one it does nothing.
func (u *Updater) Request() {
	u.mu.Lock()
	staged := u.staged
	u.mu.Unlock()
	if staged == "" {
		return
	}
	u.requested.Do(func() { close(u.done) })
}

// Done is closed once a restart has been requested.
func (u *Updater) Done() <-chan struct{} {
	return u.done
}

// Apply moves the staged binary into place, keeping the running one as
// <exe>.old. It is called after the servers have shut down. Both steps are
// renames: a running file can be renamed on unix and on Windows alike, and
// writing into it instead would, on macOS, get a process killed whose signed
// pages no longer match.
func (u *Updater) Apply() error {
	u.mu.Lock()
	staged := u.staged
	u.mu.Unlock()
	if staged == "" {
		return errors.New("no update is staged")
	}
	old := u.exe + oldSuffix
	_ = os.Remove(old)
	if err := rename(u.exe, old); err != nil {
		return fmt.Errorf("cannot move the running executable aside: %w", err)
	}
	if err := rename(staged, u.exe); err != nil {
		if back := rename(old, u.exe); back != nil {
			return fmt.Errorf("cannot move the new executable into place: %w; "+
				"restoring the previous one failed as well: %v", err, back)
		}
		return fmt.Errorf("cannot move the new executable into place: %w", err)
	}
	return nil
}

// CleanupOld removes the staged files an earlier update left beside the
// executable, which only a crash between staging and applying leaves behind.
// The previous binary is kept: it is the way back should the new one
// misbehave, and the next update replaces it. Anything that cannot be removed
// is left for the next start.
func (u *Updater) CleanupOld() {
	if u.exeErr != nil {
		return
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(u.exe), stagePrefix+"*"))
	for _, name := range leftovers {
		_ = os.Remove(name)
	}
}

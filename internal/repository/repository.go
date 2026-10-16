// Package repository keeps the package repositories of [[repositories]] up to
// date: each one's folder is looked at every pollInterval seconds, and when a
// package was added, replaced or removed, the packages are checked, pruned to
// the newest keep versions, and the metadata clients read the repository by
// is written anew and signed. An rpm repository signs the rpms too, where they
// are not signed with its key; an F-Droid repository leaves the APKs as their
// developer signed them.
//
// The folder is polled rather than told about uploads: a package arrives by
// any of the servers, each with its own way of finishing a file, or is copied
// there on disk, and polling sees all of them alike. A package still being
// written fails the check of its digests and is tried again at the next look.
//
// Like internal/cleanup this deletes without a client having asked, so every
// removal is reported.
package repository

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"sync"
	"time"

	"go-fs/internal/config"
)

// Manager runs the repositories. It is run by the supervisor like a server,
// whichever servers are enabled.
type Manager struct {
	log *slog.Logger

	mu      sync.Mutex
	running map[string]*runner
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New builds a manager for the repositories of cfg, which is resolved: the
// folders are in cfg.HTTP.Basefolder.
func New(cfg config.Config, logger *slog.Logger) (*Manager, error) {
	m := &Manager{log: logger, running: map[string]*runner{}}
	wanted, err := build(cfg, logger)
	if err != nil {
		return nil, err
	}
	m.running = wanted
	return m, nil
}

// build makes a runner for every repository of cfg, by name.
func build(cfg config.Config, logger *slog.Logger) (map[string]*runner, error) {
	out := make(map[string]*runner, len(cfg.Repositories))
	for _, repo := range cfg.Repositories {
		r, err := newRunner(repo, cfg.HTTP.Basefolder, logger)
		if err != nil {
			return nil, fmt.Errorf("repository %q: %w", repo.Name, err)
		}
		out[repo.Name] = r
	}
	return out, nil
}

// Start looks at every folder once and then every pollInterval, until ctx
// ends or Shutdown is called.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx, m.cancel = context.WithCancel(ctx)
	for _, r := range m.running {
		m.launch(r)
	}
	return nil
}

func (m *Manager) launch(r *runner) {
	r.launched = true
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		r.run(m.ctx)
	}()
}

// Reload takes over the repositories of cfg. One whose entry did not change
// keeps running as it was; one that changed is stopped and started again,
// and looks at its folder at once; one taken out stops, and its status with
// it.
func (m *Manager) Reload(cfg config.Config) error {
	wanted, err := build(cfg, m.log)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := make(map[string]*runner, len(wanted))
	for name, r := range wanted {
		if old, ok := m.running[name]; ok && reflect.DeepEqual(old.repo, r.repo) && old.base == r.base {
			next[name] = old
			continue
		}
		next[name] = r
	}
	for name, old := range m.running {
		if next[name] != old {
			old.stop()
			forget(name)
		}
	}
	for name, r := range next {
		if m.running[name] != r && m.ctx != nil {
			m.launch(r)
		}
	}
	m.running = next
	return nil
}

// Shutdown stops every repository and waits for a look in progress to
// finish.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	for name, r := range m.running {
		r.stop()
		forget(name)
	}
	m.mu.Unlock()
	finished := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Status is what the admin interface shows of a repository.
type Status struct {
	// Packages is how many packages the metadata lists.
	Packages int `json:"packages"`
	// Built is when the metadata was last written, zero when it never was.
	Built time.Time `json:"built,omitzero"`
	// Checked is when the folder was last looked at.
	Checked time.Time `json:"checked,omitzero"`
	// Error is why the last look failed, "" when it did not.
	Error string `json:"error,omitempty"`
	// Skipped are the files that are not in the repository, by their path
	// in it, with the reason.
	Skipped map[string]string `json:"skipped,omitempty"`
	// KeyID is the id of the OpenPGP key an rpm repository signs with.
	KeyID string `json:"keyId,omitempty"`
	// Fingerprint is the fingerprint of the certificate an fdroid
	// repository signs with, which a client adds it by.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// statuses are the statuses of the running repositories, by name. They are
// kept here rather than on a Manager, because the admin interface that shows
// them is in the http server, which the supervisor builds apart from this.
var statuses = struct {
	sync.Mutex
	byName map[string]Status
}{byName: map[string]Status{}}

// Statuses reports the status of every running repository, by name.
func Statuses() map[string]Status {
	statuses.Lock()
	defer statuses.Unlock()
	out := make(map[string]Status, len(statuses.byName))
	for name, status := range statuses.byName {
		status.Skipped = maps.Clone(status.Skipped)
		out[name] = status
	}
	return out
}

func report(name string, status Status) {
	statuses.Lock()
	defer statuses.Unlock()
	statuses.byName[name] = status
}

func forget(name string) {
	statuses.Lock()
	defer statuses.Unlock()
	delete(statuses.byName, name)
}

// errStopped ends a look that Shutdown or a reload interrupted.
var errStopped = errors.New("the repository was stopped")

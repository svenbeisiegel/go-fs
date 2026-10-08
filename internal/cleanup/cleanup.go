// Package cleanup keeps the folders listed in [[general.cleanup]] from growing
// without bound: once an hour everything but the newest files in each is
// removed. It is the one thing in go-fs that deletes without a client having
// asked, so every removal is reported.
package cleanup

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/vfs"
)

// interval is how often the sweep runs, as in the Node implementation.
const interval = time.Hour

// Sweeper sweeps the configured folders. It is run by the supervisor like a
// server, whichever servers are enabled.
type Sweeper struct {
	log *slog.Logger

	mu      sync.Mutex
	entries []config.Cleanup
	base    string
	root    *vfs.Root

	done chan struct{}
	wg   sync.WaitGroup
}

// New builds a sweeper for the cleanup entries of cfg, whose paths are
// relative to cfg.Basefolder.
func New(cfg config.General, logger *slog.Logger) (*Sweeper, error) {
	root, err := vfs.New(cfg.Basefolder)
	if err != nil {
		return nil, err
	}
	return &Sweeper{
		log:     logger,
		entries: cfg.Cleanup,
		base:    cfg.Basefolder,
		root:    root,
		done:    make(chan struct{}),
	}, nil
}

// Reload takes over the entries of cfg. The configuration is read at every
// sweep, so a folder added by a reload is swept at the next one, and one taken
// out stops being swept at once.
func (s *Sweeper) Reload(cfg config.General) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Basefolder != s.base {
		root, err := vfs.New(cfg.Basefolder)
		if err != nil {
			return err
		}
		s.root, s.base = root, cfg.Basefolder
	}
	s.entries = cfg.Cleanup
	return nil
}

// Start sweeps once and then every interval until ctx ends or Shutdown is
// called.
func (s *Sweeper) Start(ctx context.Context) error {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sweepOnce()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.done:
				return
			case <-ticker.C:
				s.sweepOnce()
			}
		}
	}()
	return nil
}

// Shutdown stops the sweep and waits for one in progress to finish.
func (s *Sweeper) Shutdown(ctx context.Context) error {
	close(s.done)
	finished := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sweepOnce sweeps every configured folder once.
func (s *Sweeper) sweepOnce() {
	s.mu.Lock()
	entries, root := s.entries, s.root
	s.mu.Unlock()
	if len(entries) == 0 {
		return
	}
	s.log.Debug("cleanup sweep", "folders", len(entries))
	for _, entry := range entries {
		target := root.Resolve("/", entry.Path)
		if !target.Valid {
			s.log.Error("cleanup path is outside the base folder", "path", entry.Path)
			continue
		}
		files, err := newestFirst(target.Path)
		if err != nil {
			s.log.Debug("cleanup cannot read the folder", "path", entry.Path, "error", err)
			continue
		}
		if len(files) <= entry.Keep {
			continue
		}
		for _, name := range files[entry.Keep:] {
			path := filepath.Join(target.Path, name)
			if err := os.Remove(path); err != nil {
				s.log.Error("cleanup cannot remove the file",
					"path", entry.Path+"/"+name, "error", err)
				continue
			}
			s.log.Info("cleanup removed a file", "path", entry.Path+"/"+name, "keep", entry.Keep)
		}
	}
}

// newestFirst names the regular files in folder, the newest first.
func newestFirst(folder string) ([]string, error) {
	items, err := os.ReadDir(folder)
	if err != nil {
		return nil, err
	}
	type file struct {
		name    string
		modTime time.Time
	}
	var files []file
	for _, item := range items {
		info, err := item.Info()
		if err != nil || !info.Mode().IsRegular() {
			// a name that vanished between the read and the stat is skipped
			continue
		}
		files = append(files, file{info.Name(), info.ModTime()})
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].modTime.After(files[j].modTime) })
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.name
	}
	return names, nil
}

// Package supervisor owns the running servers and keeps them in step with the
// configuration file.
//
// Applying a change is per service: one whose section did not change is left
// alone, one whose accounts or limits changed is reloaded without dropping a
// connection, and one whose port, folder or certificate changed is torn down
// and built again, because those cannot move under a bound listener.
package supervisor

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/ftp"
	"go-fs/internal/httpd"
	"go-fs/internal/logging"
	"go-fs/internal/service"
	"go-fs/internal/sftp"
	"go-fs/internal/tftp"
)

// env is what building a service is given: the configuration, and the path of
// the file it came from, which the admin interface inside the http server
// edits.
type env struct {
	cfg  config.Config
	path string
}

// entry describes how one service is switched on, built and updated.
type entry struct {
	name    string
	enabled func(env) bool
	create  func(env, *slog.Logger) (service.Server, error)
	reload  func(service.Server, env) error
}

var services = []entry{
	{
		name:    "ftp",
		enabled: func(e env) bool { return e.cfg.FTP.Enabled || e.cfg.FTPS.Enabled },
		create: func(e env, log *slog.Logger) (service.Server, error) {
			return ftp.New(e.cfg.FTP, e.cfg.FTPS, e.cfg.FTPUsers(), log)
		},
		reload: func(s service.Server, e env) error {
			return s.(*ftp.Server).Reload(e.cfg.FTP, e.cfg.FTPS, e.cfg.FTPUsers())
		},
	},
	{
		name:    "sftp",
		enabled: func(e env) bool { return e.cfg.SFTP.Enabled },
		create: func(e env, log *slog.Logger) (service.Server, error) {
			return sftp.New(e.cfg.SFTP, e.cfg.SFTPUsers(), log)
		},
		reload: func(s service.Server, e env) error {
			return s.(*sftp.Server).Reload(e.cfg.SFTP, e.cfg.SFTPUsers())
		},
	},
	{
		name:    "http",
		enabled: func(e env) bool { return e.cfg.HTTP.Enabled || e.cfg.HTTPS.Enabled },
		create: func(e env, log *slog.Logger) (service.Server, error) {
			return httpd.New(e.cfg.HTTP, e.cfg.HTTPS, e.cfg.HTTPUsers(), e.path, log)
		},
		reload: func(s service.Server, e env) error {
			return s.(*httpd.Server).Reload(e.cfg.HTTP, e.cfg.HTTPS, e.cfg.HTTPUsers())
		},
	},
	{
		name:    "tftp",
		enabled: func(e env) bool { return e.cfg.TFTP.Enabled },
		create: func(e env, log *slog.Logger) (service.Server, error) {
			return tftp.New(e.cfg.TFTP, log)
		},
		reload: func(s service.Server, e env) error {
			return s.(*tftp.Server).Reload(e.cfg.TFTP)
		},
	},
}

// Supervisor holds what is running.
type Supervisor struct {
	log *slog.Logger
	// path is the configuration file everything came from. The http server is
	// handed it so that its admin interface can edit the file it is configured
	// by.
	path string

	// root is the logger whose level follows general.logLevel, when main
	// handed one over; tests leave it nil.
	root *logging.Logger

	mu      sync.Mutex
	running map[string]service.Server
	current config.Config
	// applied reports whether current holds a configuration at all, so that
	// the first Apply is not read as everything having changed.
	applied bool
}

func New(logger *slog.Logger, path string) *Supervisor {
	return &Supervisor{log: logger, path: path, running: make(map[string]service.Server)}
}

// TrackLog makes a reload of the log keys in [general] reach the logger: the
// level is switched in place, which is how debug output is turned on under a
// running server; the format cannot be, and a change to it is reported
// instead.
func (s *Supervisor) TrackLog(root *logging.Logger) {
	s.root = root
}

// Apply brings what is running in line with cfg. A service that cannot be
// built or reloaded is reported and left as it was, so a bad section never
// takes down a good one.
func (s *Supervisor) Apply(ctx context.Context, cfg config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := env{cfg: cfg, path: s.path}
	if s.applied {
		s.log.Info("applying the changed configuration",
			"sections", strings.Join(changedSections(s.current, cfg), ","))
	}
	s.applyLog(cfg.General)

	// a service that could not be brought up leaves the remembered
	// configuration alone, so that the next reload sees a change and tries it
	// again rather than deciding there is nothing to do
	incomplete := false
	for _, entry := range services {
		server, running := s.running[entry.name]
		wanted := entry.enabled(current)

		switch {
		case !running && !wanted:
			continue

		case !running && wanted:
			if err := s.start(ctx, entry, current); err != nil {
				incomplete = true
				s.log.Error("cannot start the server", "server", entry.name, "error", err)
			}

		case running && !wanted:
			s.stop(entry.name, server)
			s.log.Info("server stopped", "server", entry.name, "reason", "disabled in the configuration")

		default:
			err := entry.reload(server, current)
			switch {
			case err == nil:
				s.log.Info("server reloaded", "server", entry.name)
			case errors.Is(err, service.ErrNeedsRestart):
				s.stop(entry.name, server)
				if err := s.start(ctx, entry, current); err != nil {
					incomplete = true
					s.log.Error("cannot restart the server, it will be tried again "+
						"on the next reload", "server", entry.name, "error", err)
					continue
				}
				s.log.Info("server restarted", "server", entry.name,
					"reason", "a setting changed that needs the listener rebound")
			default:
				incomplete = true
				s.log.Error("cannot reload the server, keeping the running configuration",
					"server", entry.name, "error", err)
			}
		}
	}

	if !incomplete {
		s.current = cfg
		s.applied = true
	}
	if len(s.running) == 0 {
		return errors.New("no server is enabled, nothing to do")
	}
	s.log.Debug("configuration applied", "running", strings.Join(s.runningLocked(), ","),
		"complete", !incomplete)
	return nil
}

// applyLog carries the log keys of [general] over to the logger. The level
// takes effect at once; the format is baked into the handler, so a change to
// it is said out loud and waits for a restart.
func (s *Supervisor) applyLog(cfg config.General) {
	if s.root == nil {
		return
	}
	if s.root.SetLevel(cfg.LogLevel) {
		s.log.Info("log level changed", "level", cfg.LogLevel)
	}
	if s.applied && cfg.LogFormat != s.root.Format() {
		s.log.Warn("general.logFormat changed, which takes effect at the next restart",
			"configured", cfg.LogFormat, "running", s.root.Format())
	}
}

// changedSections names the top level sections that differ between two
// configurations, so a reload record says what it is about.
func changedSections(before, after config.Config) []string {
	var changed []string
	b, a := reflect.ValueOf(before), reflect.ValueOf(after)
	for i := range a.NumField() {
		if !reflect.DeepEqual(b.Field(i).Interface(), a.Field(i).Interface()) {
			changed = append(changed, strings.ToLower(a.Type().Field(i).Name))
		}
	}
	return changed
}

// start builds and starts one service.
func (s *Supervisor) start(ctx context.Context, e entry, current env) error {
	started := time.Now()
	server, err := e.create(current, s.log)
	if err != nil {
		return err
	}
	if err := server.Start(ctx); err != nil {
		return err
	}
	s.running[e.name] = server
	s.log.Info("server started", "server", e.name,
		"took", time.Since(started).Round(time.Millisecond))
	return nil
}

// stop takes one service down. How long it takes is reported, because a
// shutdown that waits on a client is the one thing that makes a reload slow.
func (s *Supervisor) stop(name string, server service.Server) {
	started := time.Now()
	if err := server.Shutdown(context.Background()); err != nil {
		s.log.Warn("the server did not shut down cleanly", "server", name, "error", err)
	}
	delete(s.running, name)
	s.log.Debug("server shut down", "server", name,
		"took", time.Since(started).Round(time.Millisecond))
}

// Shutdown stops everything.
func (s *Supervisor) Shutdown(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, server := range s.running {
		started := time.Now()
		if err := server.Shutdown(ctx); err != nil {
			s.log.Warn("the server did not shut down cleanly", "server", name, "error", err)
		}
		delete(s.running, name)
		s.log.Info("server stopped", "server", name,
			"took", time.Since(started).Round(time.Millisecond))
	}
}

// runningLocked is Running for a caller that holds the mutex.
func (s *Supervisor) runningLocked() []string {
	names := make([]string, 0, len(s.running))
	for _, entry := range services {
		if _, up := s.running[entry.name]; up {
			names = append(names, entry.name)
		}
	}
	return names
}

// Running reports the names of the servers that are up, for tests.
func (s *Supervisor) Running() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runningLocked()
}

// stamp is what the watcher compares to notice a change.
type stamp struct {
	size    int64
	modTime time.Time
}

// Watch re-reads path whenever it changes, and on a hangup signal where the
// operating system has one.
//
// The file is polled rather than watched by the kernel: it needs no dependency,
// behaves the same on every platform go-fs is built for, and an editor that
// writes a file in several steps is simply rejected once and picked up on the
// next tick.
func (s *Supervisor) Watch(ctx context.Context, path string, interval time.Duration) {
	last := stampOf(path)

	hangup := make(chan os.Signal, 1)
	if signals := hangupSignals(); len(signals) > 0 {
		signal.Notify(hangup, signals...)
		defer signal.Stop(hangup)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-hangup:
			s.log.Info("reloading the configuration", "reason", "hangup signal", "path", path)
			last = stampOf(path)
			s.reload(ctx, path)

		case <-ticker.C:
			current := stampOf(path)
			if current == last {
				continue
			}
			// the stamp is kept whatever the outcome, so a file that does not
			// parse is reported once rather than on every tick
			last = current
			if current == (stamp{}) {
				// an editor that writes by rename leaves a gap; the file is
				// read again when it is back, which the next tick sees
				s.log.Warn("the configuration file is missing, keeping the running configuration",
					"path", path)
				continue
			}
			s.log.Info("reloading the configuration", "reason", "the file changed",
				"path", path, "size", current.size, "modified", current.modTime.Format(time.RFC3339))
			s.reload(ctx, path)
		}
	}
}

// reload loads the file and applies it, unless it says the same thing as what
// is already running.
func (s *Supervisor) reload(ctx context.Context, path string) {
	cfg, err := config.Load(path)
	if err != nil {
		s.log.Error("the configuration was not applied, keeping the running one",
			"path", path, "error", err)
		return
	}

	s.mu.Lock()
	unchanged := reflect.DeepEqual(cfg, s.current)
	s.mu.Unlock()
	if unchanged {
		s.log.Info("the configuration file changed but says the same thing, nothing to do")
		return
	}

	if err := s.Apply(ctx, cfg); err != nil {
		s.log.Error("applying the configuration", "error", err)
	}
}

func stampOf(path string) stamp {
	info, err := os.Stat(path)
	if err != nil {
		return stamp{}
	}
	return stamp{size: info.Size(), modTime: info.ModTime()}
}

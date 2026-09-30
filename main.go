// Command go-fs serves FTP, FTPS, SFTP, HTTP, HTTPS and TFTP from a single
// configuration file.
package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/logging"
	"go-fs/internal/selfupdate"
	"go-fs/internal/supervisor"
)

// baseVersion is the released version of the tool and the one place it is
// recorded. The Makefile reads the same file.
//
//go:embed VERSION
var baseVersion string

// version is stamped at build time with -ldflags "-X main.version=...":
// make release stamps the plain version, make build stamps a dev version
// carrying a build timestamp. A plain go build stamps nothing and falls back
// to the embedded version below.
var version string

func currentVersion() string {
	if version != "" {
		return version
	}
	return strings.TrimSpace(baseVersion) + "-dev"
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "go-fs:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "go-fs.toml", "path of the configuration file")
		initPath    = flag.String("init", "", "write a documented starter configuration to this path and exit")
		checkOnly   = flag.Bool("check", false, "load the configuration, report problems and exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("go-fs", currentVersion())
		return nil
	}

	if *initPath != "" {
		if _, err := os.Stat(*initPath); err == nil {
			return fmt.Errorf("%s already exists", *initPath)
		}
		if err := os.WriteFile(*initPath, config.Template(), 0o600); err != nil {
			return err
		}
		fmt.Println("wrote", *initPath)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *checkOnly {
		fmt.Printf("%s is valid\n", *configPath)
		return nil
	}

	logger := logging.New(cfg.General.LogLevel, cfg.General.LogFormat)
	// the first record says what is running, so that a log handed over for
	// analysis carries the build it came from and the file it was configured by
	logger.Info("go-fs starting",
		"version", currentVersion(),
		"go", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"pid", os.Getpid(),
		"config", *configPath,
		"logLevel", cfg.General.LogLevel,
		"logFormat", cfg.General.LogFormat)
	warnAboutSecrets(logger.Logger, *configPath, cfg)

	keys, err := selfupdate.TrustedKeys()
	if err != nil {
		return err
	}
	updater := selfupdate.New(currentVersion(), keys)
	// a staged update a crash never applied is removed
	updater.CleanupOld()
	if cfg.HTTP.EnableSelfUpdate && len(keys) == 0 {
		logger.Warn("http.enableSelfUpdate is set, but this build trusts no update " +
			"signing key, so every update will be refused")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// the signal is taken by hand rather than through signal.NotifyContext, so
	// that the shutdown record can say which one it was
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	sup := supervisor.New(logger.Logger, *configPath)
	sup.TrackLog(logger)
	sup.Updates(updater)
	defer sup.Shutdown(context.Background())
	if err := sup.Apply(ctx, cfg); err != nil {
		return err
	}

	if cfg.General.ReloadConfig {
		interval := time.Duration(cfg.General.ReloadInterval) * time.Second
		logger.Info("watching the configuration file", "path", *configPath, "interval", interval)
		go sup.Watch(ctx, *configPath, interval)
	} else {
		logger.Info("the configuration file is not watched, a change needs a restart",
			"path", *configPath)
	}

	var received os.Signal
	select {
	case received = <-signals:
	case <-updater.Done():
	}
	// the signal is handed back to the runtime, so that a second one ends the
	// process at once should the shutdown below hang on a client
	signal.Stop(signals)
	if received != nil {
		logger.Info("shutting down", "signal", received.String())
	} else {
		logger.Info("shutting down to restart into the new version")
	}
	cancel()
	started := time.Now()
	sup.Shutdown(context.Background())
	logger.Info("shutdown complete", "took", time.Since(started).Round(time.Millisecond))
	if received != nil {
		return nil
	}
	return restart(logger.Logger, updater)
}

// restart moves the staged binary into place and starts it. On unix it only
// returns when that failed; on Windows the new process is running by then, and
// returning ends this one.
//
// An update that cannot be moved into place has left the previous binary
// where it was, and that one is started instead: the servers come back either
// way, rather than staying down until somebody notices.
func restart(logger *slog.Logger, updater *selfupdate.Updater) error {
	if err := updater.Apply(); err != nil {
		logger.Error("the update could not be applied, restarting the previous version",
			"error", err)
	} else {
		logger.Info("restarting into the new version", "executable", updater.Current().Executable)
	}
	if err := updater.Restart(); err != nil {
		return fmt.Errorf("the new version could not be started: %w", err)
	}
	return nil
}

// warnAboutSecrets says what is worth knowing about the file before the
// listeners come up: that an account still has a password out of the
// documentation, and that the file holding every password and private key can
// be read by more than its owner.
func warnAboutSecrets(logger *slog.Logger, path string, cfg config.Config) {
	// a key that no longer exists is ignored rather than refused, so that a
	// file written for an older version still starts; saying so here is the
	// only chance its author has to notice
	if data, err := os.ReadFile(path); err == nil {
		for _, retired := range config.RetiredKeys(data) {
			logger.Warn("the configuration file sets a key this version no longer reads",
				"key", retired)
		}
	}
	if accounts := cfg.ExampleAccounts(); len(accounts) > 0 {
		logger.Warn("an account still has the password this project's own documentation "+
			"prints, so it is a password anybody can look up; change it before this "+
			"server is reachable",
			"accounts", strings.Join(accounts, ", "))
	}
	if mode, loose := config.LooseFilePermissions(path); loose {
		logger.Warn("the configuration file can be read by more than its owner, and it "+
			"holds every password and every private key of this server",
			"path", path, "mode", fmt.Sprintf("%04o", mode), "suggested", "0600")
	}
}

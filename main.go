// Command go-fs serves FTP, FTPS, SFTP, HTTP, HTTPS and TFTP from a single
// configuration file. Built with the tag light it is go-fs-light, which serves
// HTTP and HTTPS only; see internal/features.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/features"
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

// packaging names the installer a build is made for, rpm or msi, stamped with
// -ldflags "-X main.packaging=...". The rpm owns the executable, so the self
// update leaves it alone; an msi install updates itself from the releases.
// Empty for the plain binaries.
var packaging string

// errRestartService is what run returns once an update is in place under the
// Windows service manager: the service ends with an error, and the recovery
// the service manager applies to that starts it again on the new binary.
var errRestartService = errors.New("restarting the service into the new version")

// errorOutput is where the error that ends the program is written: standard
// error, or the log file when -logfile names one, since a Windows service has
// no standard error that anybody reads.
var errorOutput io.Writer = os.Stderr

// featureList is the optional parts this build has, as -version and the first
// record of the log say them.
func featureList() string {
	if list := features.List(); len(list) > 0 {
		return strings.Join(list, ", ")
	}
	return "none"
}

func currentVersion() string {
	if version != "" {
		return version
	}
	return strings.TrimSpace(baseVersion) + "-dev"
}

func main() {
	// start runs run, under the service manager when Windows started go-fs
	// as a service
	if err := start(); err != nil {
		fmt.Fprintln(errorOutput, "go-fs:", err)
		os.Exit(1)
	}
}

// run serves until a signal, an update or stop ends it. stop is closed by the
// Windows service manager when it stops the service, and nil otherwise.
func run(stop <-chan struct{}) error {
	var (
		configPath  = flag.String("config", "go-fs.toml", "path of the configuration file")
		initPath    = flag.String("init", "", "write a documented starter configuration to this path and exit")
		checkOnly   = flag.Bool("check", false, "load the configuration, report problems and exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
		logFile     = flag.String("logfile", "", "write the log to this file, rotated by size, instead of standard output")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(selfupdate.Product, currentVersion())
		fmt.Println("features:", featureList())
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

	var output io.Writer = os.Stdout
	if *logFile != "" && !*checkOnly {
		file, err := logging.OpenFile(*logFile)
		if err != nil {
			return err
		}
		// left open: it takes every record up to the last one, and the
		// error that ends the program after that
		output, errorOutput = file, file
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *checkOnly {
		fmt.Printf("%s is valid\n", *configPath)
		return nil
	}

	logger := logging.NewTo(output, cfg.General.LogLevel, cfg.General.LogFormat)
	// the first record says what is running, so that a log handed over for
	// analysis carries the build it came from and the file it was configured by
	logger.Info("go-fs starting",
		"product", selfupdate.Product,
		"version", currentVersion(),
		"features", featureList(),
		"go", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"pid", os.Getpid(),
		"config", *configPath,
		"installer", packaging,
		"service", stop != nil,
		"logLevel", cfg.General.LogLevel,
		"logFormat", cfg.General.LogFormat)
	warnAboutSecrets(logger.Logger, *configPath, cfg)

	// the share links of files and the login tokens of browsers are signed
	// with keys the file keeps, so a link handed out and a browser logged in
	// survive a restart and an update; a file without them is given them
	if ensured, generated, err := config.EnsureSecrets(*configPath, cfg); err != nil {
		logger.Warn("cannot store generated secrets in the configuration file, so share "+
			"links stop working and browsers are logged out at every restart",
			"path", *configPath, "error", err)
	} else {
		cfg = ensured
		for _, key := range generated {
			logger.Info("generated a secret and stored it in the configuration file",
				"key", key, "path", *configPath)
		}
	}

	keys, err := selfupdate.TrustedKeys()
	if err != nil {
		return err
	}
	updater := selfupdate.New(currentVersion(), keys)
	if packaging == "rpm" {
		updater.SetManagedBy(packaging)
	}
	// a staged update a crash never applied is removed
	updater.CleanupOld()
	switch {
	case cfg.HTTP.EnableSelfUpdate && updater.Current().ManagedBy != "":
		logger.Warn("http.enableSelfUpdate is set, but this go-fs was installed by the "+
			packaging+" package, so every update over http is refused; update the "+
			"package instead", "installer", packaging)
	case cfg.HTTP.EnableSelfUpdate && len(keys) == 0:
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
	stopped := false
	select {
	case received = <-signals:
	case <-stop:
		stopped = true
	case <-updater.Done():
	}
	// the signal is handed back to the runtime, so that a second one ends the
	// process at once should the shutdown below hang on a client
	signal.Stop(signals)
	switch {
	case received != nil:
		logger.Info("shutting down", "signal", received.String())
	case stopped:
		logger.Info("shutting down, the service is stopped")
	default:
		logger.Info("shutting down to restart into the new version")
	}
	cancel()
	started := time.Now()
	sup.Shutdown(context.Background())
	logger.Info("shutdown complete", "took", time.Since(started).Round(time.Millisecond))
	if received != nil || stopped {
		return nil
	}
	if stop != nil {
		// Windows has no exec, and a process started from here would not be
		// the service; the service manager starts the new binary instead
		if err := updater.Apply(); err != nil {
			logger.Error("the update could not be applied, restarting the previous version",
				"error", err)
		} else {
			logger.Info("restarting into the new version through the service manager",
				"executable", updater.Current().Executable)
		}
		return errRestartService
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
	// a part this build was built without is ignored rather than refused, so
	// that go-fs-light starts on the file of go-fs
	for _, ignored := range cfg.Ignored() {
		logger.Warn("the configuration file switches on what this build does not have, "+
			"so it is ignored", "product", selfupdate.Product, "ignored", ignored)
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

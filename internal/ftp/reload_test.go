package ftp

import (
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/service"
)

// An account added while the server runs can log in, and a connection that was
// already open keeps the rules it was accepted under.
func TestReloadAppliesAccounts(t *testing.T) {
	server := newServer(t, nil)

	open := connect(t, server)
	open.login()

	next := server.settings().cfg
	users := append(append([]config.User{}, server.settings().users...),
		config.User{Username: "jane", Password: "secret", FTP: true})
	if err := server.Reload(next, server.settings().ftps, users); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	fresh := connect(t, server)
	fresh.send("USER jane")
	fresh.expect("331 Password required for jane")
	fresh.send("PASS secret")
	fresh.expect("230 Logged on")

	// the connection that was already up is undisturbed
	open.send("PWD")
	open.expect(`257 "/" is current directory`)
}

func TestReloadReportsWhatNeedsARestart(t *testing.T) {
	server := newServer(t, nil)

	cases := map[string]func(*config.FTP, *config.FTPS){
		"port":       func(c *config.FTP, _ *config.FTPS) { c.Port = 2121 },
		"basefolder": func(c *config.FTP, _ *config.FTPS) { c.Basefolder = t.TempDir() },
		"ftps on":    func(_ *config.FTP, f *config.FTPS) { f.Enabled = true },
		"ftps cert":  func(_ *config.FTP, f *config.FTPS) { f.Cert = "cert.pem" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, ftps := server.settings().cfg, server.settings().ftps
			change(&cfg, &ftps)
			if err := server.Reload(cfg, ftps, server.settings().users); err != service.ErrNeedsRestart {
				t.Errorf("err = %v, want ErrNeedsRestart", err)
			}
		})
	}
}

// A limit that is read per connection takes effect for the next one.
func TestReloadAppliesLimits(t *testing.T) {
	server := newServer(t, nil)

	next := server.settings().cfg
	next.MaxConnections = 1
	if err := server.Reload(next, server.settings().ftps, server.settings().users); err != nil {
		t.Fatal(err)
	}
	if got := server.settings().cfg.MaxConnections; got != 1 {
		t.Errorf("maxConnections = %d, want 1", got)
	}
}

// A per user folder that cannot be served leaves the running accounts alone.
func TestReloadKeepsTheRunningConfigurationOnError(t *testing.T) {
	server := newServer(t, nil)

	next := server.settings().cfg
	users := []config.User{{Username: "jane", FTP: true, Basefolder: t.TempDir() + "/nope"}}
	if err := server.Reload(next, server.settings().ftps, users); err == nil {
		t.Fatal("a missing user folder has to be refused")
	}

	c := connect(t, server)
	c.login()
	c.send("PWD")
	c.expect(`257 "/" is current directory`)
}

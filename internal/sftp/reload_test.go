package sftp

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/service"
)

func TestReloadAppliesAccounts(t *testing.T) {
	server := newServer(t, nil)

	if _, err := dial(t, server, "jane", ssh.Password("secret")); err == nil {
		t.Fatal("jane should not exist yet")
	}

	next := server.settings().cfg
	users := []config.User{fullUser("john", "doe"), fullUser("jane", "secret")}
	if err := server.Reload(next, users); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if _, err := dial(t, server, "jane", ssh.Password("secret")); err != nil {
		t.Errorf("jane should work now: %v", err)
	}
	if _, err := dial(t, server, "john", ssh.Password("doe")); err != nil {
		t.Errorf("john should still work: %v", err)
	}
}

func TestReloadReportsWhatNeedsARestart(t *testing.T) {
	server := newServer(t, nil)

	cases := map[string]func(*config.SFTP){
		"port":       func(c *config.SFTP) { c.Port = 2222 },
		"basefolder": func(c *config.SFTP) { c.Basefolder = t.TempDir() },
		"host key":   func(c *config.SFTP) { c.HostKey = "something" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := server.settings().cfg
			change(&cfg)
			if err := server.Reload(cfg, nil); err != service.ErrNeedsRestart {
				t.Errorf("err = %v, want ErrNeedsRestart", err)
			}
		})
	}
}

// A broken account leaves the running ones in place.
func TestReloadKeepsTheRunningConfigurationOnError(t *testing.T) {
	server := newServer(t, nil)

	next := server.settings().cfg
	users := []config.User{{Username: "jane", SFTP: true, AuthorizedKeys: []string{"ssh-ed25519 not-a-key"}}}
	if err := server.Reload(next, users); err == nil {
		t.Fatal("a malformed key has to be refused")
	}
	if _, err := dial(t, server, "john", ssh.Password("doe")); err != nil {
		t.Errorf("john should still work: %v", err)
	}
}

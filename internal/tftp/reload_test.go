package tftp

import (
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/service"
)

// A permission granted while the server runs applies to the next request.
func TestReloadAppliesPermissions(t *testing.T) {
	server := newServer(t, func(cfg *config.TFTP) { cfg.AllowWrite = false })

	c := dial(t, server.port)
	if failure := c.upload("new.txt", modeOctet, []byte("content")); failure == nil {
		t.Fatal("writing should be refused")
	}

	next := server.settings().cfg
	next.AllowWrite = true
	if err := server.Reload(next); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	c = dial(t, server.port)
	if failure := c.upload("new.txt", modeOctet, []byte("content")); failure != nil {
		code, message := errorOf(t, failure)
		t.Errorf("writing should work now, got ERROR(%d) %q", code, message)
	}
	if got := string(server.read(t, "new.txt")); got != "content" {
		t.Errorf("stored %q", got)
	}
}

func TestReloadReportsWhatNeedsARestart(t *testing.T) {
	server := newServer(t, nil)

	cases := map[string]func(*config.TFTP){
		"port":       func(c *config.TFTP) { c.Port = 6969 },
		"address":    func(c *config.TFTP) { c.Address = "127.0.0.1" },
		"type":       func(c *config.TFTP) { c.Type = "udp6" },
		"basefolder": func(c *config.TFTP) { c.Basefolder = t.TempDir() },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := server.settings().cfg
			change(&cfg)
			if err := server.Reload(cfg); err != service.ErrNeedsRestart {
				t.Errorf("err = %v, want ErrNeedsRestart", err)
			}
		})
	}
}

// The negotiated limits come from the snapshot, so a new block size ceiling
// applies to the next transfer.
func TestReloadAppliesLimits(t *testing.T) {
	server := newServer(t, nil)

	next := server.settings().cfg
	next.MaxBlockSize = 600
	if err := server.Reload(next); err != nil {
		t.Fatal(err)
	}
	if got := server.settings().limits.maxBlockSize; got != 600 {
		t.Errorf("maxBlockSize = %d, want 600", got)
	}
}

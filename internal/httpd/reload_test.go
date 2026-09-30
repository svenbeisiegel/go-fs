package httpd

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/service"
)

// An account added while the server runs works on the next request, and the
// one that was there keeps working.
func TestReloadAppliesAccounts(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/hello.txt", "hello")

	if res := basic(t, server, http.MethodGet, "/private/hello.txt", "jane", "secret", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("jane should not exist yet, got %d", res.StatusCode)
	}

	next := server.settings().cfg
	users := []config.User{fullUser("john", "doe"), fullUser("jane", "secret")}
	if err := server.Reload(next, server.settings().https, users); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if res := basic(t, server, http.MethodGet, "/private/hello.txt", "jane", "secret", nil); res.StatusCode != http.StatusOK {
		t.Errorf("jane should work now, got %d", res.StatusCode)
	}
	if res := basic(t, server, http.MethodGet, "/private/hello.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("john should still work, got %d", res.StatusCode)
	}
}

// A permission taken away applies to the next request.
func TestReloadRevokesAPermission(t *testing.T) {
	server := newServer(t, nil)

	next := server.settings().cfg
	user := fullUser("john", "doe")
	user.AllowUserFileCreate = new(false)
	if err := server.Reload(next, server.settings().https, []config.User{user}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/new.txt"), strings.NewReader("x"))
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	if res := do(t, req); res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.StatusCode)
	}
}

// A change that needs the listener rebound is reported rather than applied.
func TestReloadReportsWhatNeedsARestart(t *testing.T) {
	server := newServer(t, nil)

	cases := map[string]func(*config.HTTP, *config.HTTPS){
		"port":           func(c *config.HTTP, _ *config.HTTPS) { c.Port = c.Port + 1 },
		"basefolder":     func(c *config.HTTP, _ *config.HTTPS) { c.Basefolder = t.TempDir() },
		"maxConnections": func(c *config.HTTP, _ *config.HTTPS) { c.MaxConnections = 3 },
		"readTimeout":    func(c *config.HTTP, _ *config.HTTPS) { c.ReadTimeout = 7 },
		"https enabled":  func(_ *config.HTTP, h *config.HTTPS) { h.Enabled = true },
		"https cert":     func(_ *config.HTTP, h *config.HTTPS) { h.Cert = "cert.pem" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, https := server.settings().cfg, server.settings().https
			change(&cfg, &https)
			if err := server.Reload(cfg, https, nil); err != service.ErrNeedsRestart {
				t.Errorf("err = %v, want ErrNeedsRestart", err)
			}
		})
	}
}

// A configuration that cannot be built leaves the running one in place.
func TestReloadKeepsTheRunningConfigurationOnError(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/hello.txt", "hello")

	next := server.settings().cfg
	next.PathsRequireAuth = []string{"([unclosed"}
	if err := server.Reload(next, server.settings().https, []config.User{fullUser("john", "doe")}); err == nil {
		t.Fatal("a broken pattern has to be refused")
	}

	// the account that was there still works
	res := basic(t, server, http.MethodGet, "/private/hello.txt", "john", "doe", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Errorf("status %d body %q", res.StatusCode, body)
	}
}

// The lifetime is read when a token is minted, so a reload changes what is
// issued from here on with no restart and no live token disturbed.
func TestTheTokenLifetimeIsSwappedWithoutARestart(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})

	next := server.settings().cfg
	next.SessionTokenLifetime = 60
	if err := server.Reload(next, server.settings().https, []config.User{fullUser("john", "doe")}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if session := login(t, server, "/", "john", "doe"); session.MaxAge != 60 {
		t.Errorf("maxage = %d, want 60", session.MaxAge)
	}
}

// The key is derived once, at startup, and swapping it under a running server
// would invalidate every live token halfway through a request.
func TestChangingTheSigningKeyNeedsARestart(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	secret, err := config.GenerateSessionSecret()
	if err != nil {
		t.Fatalf("GenerateSessionSecret: %v", err)
	}

	next := server.settings().cfg
	next.SessionTokenSecret = secret
	if err := server.Reload(next, server.settings().https, nil); !errors.Is(err, service.ErrNeedsRestart) {
		t.Errorf("Reload = %v, want ErrNeedsRestart", err)
	}
}

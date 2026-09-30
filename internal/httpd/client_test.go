package httpd

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"go-fs/internal/config"
)

// proxiedServer is a server that trusts the test client's own address as a
// proxy, so the forwarding headers it sends are read.
func proxiedServer(t *testing.T, proxies []string, tune func(*httpConfig)) *testServer {
	t.Helper()
	server := newServer(t, func(cfg *httpConfig) {
		cfg.TrustedProxies = proxies
		cfg.Users = []config.User{fullUser("john", "doe")}
		if tune != nil {
			tune(cfg)
		}
	})
	server.write(t, "private/secret.txt", "secret")
	return server
}

// refusedFrom sends a wrong password with the given proxy headers and returns
// the address the refusal was recorded under.
func refusedFrom(t *testing.T, server *testServer, headers map[string]string) string {
	t.Helper()
	server.logs.mu.Lock()
	server.logs.records = nil
	server.logs.mu.Unlock()
	if res := forwarded(t, server, http.MethodGet, "/private/secret.txt", headers, "john", "wrong"); //
	res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	record := server.logs.find("http login refused")
	if record == nil {
		t.Fatal("the refusal was not recorded")
	}
	address, _ := record["address"].(string)
	return address
}

// Without a trusted proxy the forwarding headers are the client's word, and
// are not taken.
func TestForwardedForIsIgnoredFromAnUntrustedAddress(t *testing.T) {
	server := proxiedServer(t, nil, nil)
	if address := refusedFrom(t, server, map[string]string{"X-Forwarded-For": "203.0.113.9"}); address != "127.0.0.1" {
		t.Errorf("recorded under %q, want the connection's own address", address)
	}
}

// From a trusted proxy the client is the rightmost hop that is not itself a
// proxy; anything that is not an address falls back to the connection.
func TestForwardedForIsReadFromATrustedProxy(t *testing.T) {
	server := proxiedServer(t, []string{"127.0.0.1", "10.0.0.0/8"}, nil)
	for header, want := range map[string]string{
		"203.0.113.9":                            "203.0.113.9",
		"198.51.100.7, 10.0.0.1":                 "198.51.100.7",
		"1.1.1.1, 198.51.100.7, 10.1.2.3":        "198.51.100.7",
		"::ffff:198.51.100.7":                    "198.51.100.7",
		"2001:db8::1":                            "2001:db8::1",
		"garbage":                                "127.0.0.1",
		"10.0.0.1, 10.0.0.2":                     "127.0.0.1",
		"198.51.100.7, not-an-address, 10.0.0.1": "127.0.0.1",
	} {
		if address := refusedFrom(t, server, map[string]string{"X-Forwarded-For": header}); address != want {
			t.Errorf("X-Forwarded-For %q was recorded under %q, want %q", header, address, want)
		}
	}
}

// The lock follows the forwarded address, so two clients behind one proxy are
// locked one by one.
func TestTheLockFollowsTheForwardedAddress(t *testing.T) {
	server := proxiedServer(t, []string{"127.0.0.1"}, func(cfg *httpConfig) {
		cfg.LoginAttempts = 1
	})
	fixClock(server)
	first := map[string]string{"X-Forwarded-For": "203.0.113.1"}
	second := map[string]string{"X-Forwarded-For": "203.0.113.2"}

	if res := forwarded(t, server, http.MethodGet, "/private/secret.txt", first, "john", "wrong"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the first client's wrong password was answered %d", res.StatusCode)
	}
	if res := forwarded(t, server, http.MethodGet, "/private/secret.txt", first, "john", "doe"); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the first client is not locked: %d", res.StatusCode)
	}
	if res := forwarded(t, server, http.MethodGet, "/private/secret.txt", second, "john", "doe"); res.StatusCode != http.StatusOK {
		t.Errorf("the second client was locked along with the first: %d", res.StatusCode)
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("the proxy itself was locked: %d", res.StatusCode)
	}
}

// The session cookie is marked Secure when a trusted proxy says the client
// came over TLS, and not on anyone else's say-so.
func TestForwardedProtoMarksTheCookieSecure(t *testing.T) {
	for name, tc := range map[string]struct {
		proxies []string
		proto   string
		secure  bool
	}{
		"trusted https":      {[]string{"127.0.0.1"}, "https", true},
		"trusted mixed case": {[]string{"127.0.0.1"}, "HTTPS, http", true},
		"trusted http":       {[]string{"127.0.0.1"}, "http", false},
		"untrusted https":    {nil, "https", false},
	} {
		server := proxiedServer(t, tc.proxies, nil)
		req, err := http.NewRequest(http.MethodPost, server.url("/?go-fs=login"),
			strings.NewReader("username=john&password=doe"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-Proto", tc.proto)
		res := do(t, req)
		session := cookieNamed(res, sessionCookie)
		if session == nil {
			t.Fatalf("%s: no session was handed out (%d)", name, res.StatusCode)
		}
		if session.Secure != tc.secure {
			t.Errorf("%s: Secure = %v, want %v", name, session.Secure, tc.secure)
		}
	}
}

// A proxy that is not an address is refused at start, and a reload with one
// keeps the running configuration.
func TestBadTrustedProxiesAreRefused(t *testing.T) {
	cfg := config.Default().HTTP
	cfg.Enabled = true
	cfg.Basefolder = t.TempDir()
	cfg.TrustedProxies = []string{"not-an-address"}
	if _, err := New(cfg, config.Default().HTTPS, nil, "", discardLogger()); err == nil {
		t.Error("New accepted a proxy that is not an address")
	} else if !strings.Contains(err.Error(), "http.trustedProxies[0]") {
		t.Errorf("the error does not name the entry: %v", err)
	}

	server := proxiedServer(t, nil, nil)
	next := server.settings().cfg
	next.TrustedProxies = []string{"10.0.0.0/33"}
	if err := server.Reload(next, server.settings().https, []config.User{fullUser("john", "doe")}); err == nil {
		t.Fatal("Reload accepted a range that does not parse")
	}
	res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "secret" {
		t.Errorf("after the refused reload: status %d body %q", res.StatusCode, body)
	}
}

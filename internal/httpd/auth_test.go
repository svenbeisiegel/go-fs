package httpd

import (
	"net/http"
	"strings"
	"testing"
)

// A path that is not protected and a method that is not protected are served
// to anyone, which is what the Node implementation does.
func TestPublicRequestNeedsNoCredentials(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = []string{"PUT", "DELETE"}
	})
	server.write(t, "public/hello.txt", "hello")

	res, body := get(t, server, "/public/hello.txt")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if body != "hello" {
		t.Errorf("body = %q", body)
	}
}

func TestProtectedPathIsChallenged(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")

	res, _ := get(t, server, "/private/secret.txt")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	challenge := res.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Digest ") {
		t.Fatalf("challenge = %q", challenge)
	}
	for _, want := range []string{`realm="go-fs"`, `qop="auth"`, "nonce=", "opaque=", "algorithm="} {
		if !strings.Contains(challenge, want) {
			t.Errorf("challenge %q is missing %s", challenge, want)
		}
	}
}

// A protected method is challenged whatever the path.
func TestProtectedMethodIsChallenged(t *testing.T) {
	server := newServer(t, nil)

	req, _ := http.NewRequest(http.MethodDelete, server.url("/public/x.txt"), nil)
	if res := do(t, req); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", res.StatusCode)
	}
}

func TestBasicAuthentication(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")

	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("the right password got %d", res.StatusCode)
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong password got %d, want 401", res.StatusCode)
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "stranger", "doe", nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unknown user got %d, want 401", res.StatusCode)
	}
}

// Digest for both algorithms browsers use, and for the qop-less RFC 2069 form.
func TestDigestAuthentication(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")

	for _, agent := range []struct {
		name          string
		userAgent     string
		wantAlgorithm string
	}{
		{"chrome asks for sha-256", "Mozilla/5.0 Chrome/120.0", "SHA-256"},
		{"firefox asks for sha-256", "Mozilla/5.0 Firefox/121.0", "SHA-256"},
		{"anything else gets md5", "curl/8.4.0", "MD5"},
	} {
		t.Run(agent.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
			req.Header.Set("User-Agent", agent.userAgent)
			challenge := do(t, req)
			params := parseDigest(challenge.Header.Get("WWW-Authenticate"))
			if params["algorithm"] != agent.wantAlgorithm {
				t.Fatalf("algorithm = %q, want %q", params["algorithm"], agent.wantAlgorithm)
			}

			res := digestRequest(t, server, http.MethodGet, "/private/secret.txt",
				"john", "doe", agent.userAgent, nil)
			if res.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want 200", res.StatusCode)
			}
		})
	}

	t.Run("without qop, as RFC 2069 has it", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
		challenge := do(t, req)
		params := parseDigest(challenge.Header.Get("WWW-Authenticate"))

		req, _ = http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
		req.Header.Set("Authorization",
			digestHeader(t, params, http.MethodGet, "/private/secret.txt", "john", "doe", false))
		if res := do(t, req); res.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", res.StatusCode)
		}
	})

	t.Run("a wrong password is refused", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
		challenge := do(t, req)
		params := parseDigest(challenge.Header.Get("WWW-Authenticate"))

		req, _ = http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
		req.Header.Set("Authorization",
			digestHeader(t, params, http.MethodGet, "/private/secret.txt", "john", "wrong", true))
		if res := do(t, req); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", res.StatusCode)
		}
	})
}

// The header parser has to survive values that hold a comma or an equals sign,
// which the Node implementation mangled.
func TestParseDigestHeader(t *testing.T) {
	header := `Digest username="john", realm="go-fs", ` +
		`uri="/a/b.php?dir=x,y&z=1", qop=auth, nc=00000001, ` +
		`cnonce="abc\"def", response="deadbeef", algorithm=SHA-256`
	params := parseDigest(header)

	for key, want := range map[string]string{
		"username":  "john",
		"realm":     "go-fs",
		"uri":       "/a/b.php?dir=x,y&z=1",
		"qop":       "auth",
		"nc":        "00000001",
		"cnonce":    `abc"def`,
		"response":  "deadbeef",
		"algorithm": "SHA-256",
	} {
		if params[key] != want {
			t.Errorf("%s = %q, want %q", key, params[key], want)
		}
	}
}

func TestHasherMatchesTheNamedAlgorithm(t *testing.T) {
	md5Hash, ok := hasher("MD5")
	if !ok || md5Hash("go-fs") != md5Hex("go-fs") {
		t.Error("MD5 is wrong")
	}
	shaHash, ok := hasher("SHA-256")
	if !ok || shaHash("go-fs") != sha256Hex("go-fs") {
		t.Error("SHA-256 is wrong")
	}
	if _, ok := hasher("SHA-512"); ok {
		t.Error("an algorithm that is not offered has to be refused")
	}
}

// A pattern that covers what is in a folder covers the folder itself: the
// listing of a protected folder names every file in it, so it cannot be the one
// public thing about it.
func TestProtectedFolderListingNeedsAuth(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")

	for _, path := range []string{"/private", "/private/"} {
		res, body := get(t, server, path)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401; body %q", path, res.StatusCode, body)
		}
	}

	// the account whose pattern it is can still read it
	res := basic(t, server, http.MethodGet, "/private/", "john", "doe", nil)
	if res.StatusCode != http.StatusOK {
		t.Errorf("the account that owns the path got %d", res.StatusCode)
	}
}

// The digest response is computed over the uri in the header, so that uri has
// to be the one being asked for. Without the check a header captured on one
// path would authorize any other path with the same method.
func TestDigestIsBoundToThePath(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")
	server.write(t, "private/other.txt", "other")

	first, err := http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	challenge := do(t, first)
	params := parseDigest(challenge.Header.Get("WWW-Authenticate"))
	header := digestHeader(t, params, http.MethodGet, "/private/secret.txt", "john", "doe", true)

	// the header it was made for
	req, _ := http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
	req.Header.Set("Authorization", header)
	if res := do(t, req); res.StatusCode != http.StatusOK {
		t.Fatalf("the header has to work on its own path, got %d", res.StatusCode)
	}

	// the same header on another path
	req, _ = http.NewRequest(http.MethodGet, server.url("/private/other.txt"), nil)
	req.Header.Set("Authorization", header)
	if res := do(t, req); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a captured header worked on another path, got %d", res.StatusCode)
	}
}

// A nonce this server did not issue is not accepted, whatever the response
// computed over it says.
func TestDigestRefusesAForeignNonce(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")

	params := map[string]string{
		"realm":     server.settings().cfg.Realm,
		"nonce":     "1700000000:" + strings.Repeat("a", 64),
		"algorithm": "MD5",
	}
	req, _ := http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
	req.Header.Set("Authorization",
		digestHeader(t, params, http.MethodGet, "/private/secret.txt", "john", "doe", true))
	if res := do(t, req); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", res.StatusCode)
	}
}

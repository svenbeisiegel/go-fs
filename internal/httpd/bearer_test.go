package httpd

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

// fullToken is a token that may reach everything and do everything, with the
// plain token it is presented as.
func fullToken(t *testing.T, name string) (config.Token, string) {
	t.Helper()
	plain, hash, err := config.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	return config.Token{
		Name:                   name,
		Hash:                   hash,
		Paths:                  []string{"^/.*"},
		AllowUserFileCreate:    new(true),
		AllowUserFileRetrieve:  new(true),
		AllowUserFileOverwrite: new(true),
		AllowUserFileDelete:    new(true),
		AllowUserFolderDelete:  new(true),
		AllowUserFolderCreate:  new(true),
	}, plain
}

// bearer sends a request authenticated with a bearer token.
func bearer(t *testing.T, server *testServer, method, path, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, server.url(path), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return do(t, req)
}

// tokenServer is a server with one token, tuned by tune before it starts.
func tokenServer(t *testing.T, tune func(*config.Token)) (*testServer, string) {
	t.Helper()
	token, plain := fullToken(t, "ci")
	if tune != nil {
		tune(&token)
	}
	server := newServer(t, func(cfg *httpConfig) { cfg.Tokens = []config.Token{token} })
	return server, plain
}

// A token reads and writes what its rights allow, and is recorded under its
// own name.
func TestBearerTokenAuthenticates(t *testing.T) {
	server, plain := tokenServer(t, nil)
	server.write(t, "private/hello.txt", "hello")

	res := bearer(t, server, http.MethodGet, "/private/hello.txt", plain, nil)
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || body != "hello" {
		t.Errorf("GET status %d body %q", res.StatusCode, body)
	}
	if res := bearer(t, server, http.MethodPut, "/private/new.txt", plain, strings.NewReader("new")); res.StatusCode != http.StatusOK {
		t.Errorf("PUT status %d", res.StatusCode)
	}
	if got := server.read(t, "private/new.txt"); got != "new" {
		t.Errorf("the file holds %q", got)
	}
	record := server.logs.find("http authenticated")
	if record == nil || record["user"] != "token:ci" || record["method"] != "bearer" {
		t.Errorf("the record is %v", record)
	}
}

// What a token may do is only what it is granted.
func TestBearerTokenRights(t *testing.T) {
	server, plain := tokenServer(t, func(token *config.Token) {
		token.AllowUserFileCreate = nil
	})
	server.write(t, "private/hello.txt", "hello")

	if res := bearer(t, server, http.MethodPut, "/private/new.txt", plain, strings.NewReader("new")); res.StatusCode != http.StatusForbidden {
		t.Errorf("PUT without create was answered %d, want 403", res.StatusCode)
	}
	if res := bearer(t, server, http.MethodGet, "/private/hello.txt", plain, nil); res.StatusCode != http.StatusOK {
		t.Errorf("GET was answered %d, want 200", res.StatusCode)
	}
}

// A token reaches only the paths it lists.
func TestBearerTokenPaths(t *testing.T) {
	server, plain := tokenServer(t, func(token *config.Token) {
		token.Paths = []string{"^/private/allowed/.*"}
	})
	server.write(t, "private/allowed/a.txt", "a")
	server.write(t, "private/other/b.txt", "b")

	if res := bearer(t, server, http.MethodGet, "/private/allowed/a.txt", plain, nil); res.StatusCode != http.StatusOK {
		t.Errorf("a listed path was answered %d, want 200", res.StatusCode)
	}
	if res := bearer(t, server, http.MethodGet, "/private/other/b.txt", plain, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("an unlisted path was answered %d, want 403", res.StatusCode)
	}
}

// A token with a base folder is served from it: / is that folder, the
// server's own folder is out of reach, and what is public in the server's
// folder is not public in the token's.
func TestBearerTokenBasefolder(t *testing.T) {
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "mine.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	server, plain := tokenServer(t, func(token *config.Token) {
		token.Basefolder = folder
	})
	server.write(t, "theirs.txt", "theirs")

	res := bearer(t, server, http.MethodGet, "/mine.txt", plain, nil)
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || body != "mine" {
		t.Errorf("the token's file: status %d body %q", res.StatusCode, body)
	}
	if res := bearer(t, server, http.MethodGet, "/theirs.txt", plain, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("the server's file was answered %d, want 404", res.StatusCode)
	}
	if res := bearer(t, server, http.MethodPut, "/up.txt", plain, strings.NewReader("up")); res.StatusCode != http.StatusOK {
		t.Errorf("PUT status %d", res.StatusCode)
	}
	if content, err := os.ReadFile(filepath.Join(folder, "up.txt")); err != nil || string(content) != "up" {
		t.Errorf("the upload landed as %q, %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(server.base, "up.txt")); !os.IsNotExist(err) {
		t.Error("the upload landed in the server's folder")
	}
	// a move stays in the token's folder too
	if res := bearerMove(t, server, "/up.txt", "/moved.txt", plain); res.StatusCode != http.StatusNoContent {
		t.Errorf("MOVE status %d", res.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(folder, "moved.txt")); err != nil {
		t.Errorf("the moved file is not in the token's folder: %v", err)
	}

	// GET of / is public on this server, but not in the token's own tree
	server2, plain2 := tokenServer(t, func(token *config.Token) {
		token.Basefolder = folder
		token.AllowUserFileRetrieve = nil
	})
	if res := bearer(t, server2, http.MethodGet, "/mine.txt", plain2, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("a token without retrieve read its own folder: %d, want 403", res.StatusCode)
	}
}

func bearerMove(t *testing.T, server *testServer, from, to, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(methodMove, server.url(from), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Destination", server.url(to))
	return do(t, req)
}

// An expired token and an unknown one are refused with a bearer challenge,
// even on a path anyone may read: a program that sends a token has to learn
// that it is not accepted.
func TestBearerTokenRefused(t *testing.T) {
	server, plain := tokenServer(t, func(token *config.Token) {
		token.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	})
	server.write(t, "public.txt", "public")

	for name, token := range map[string]string{"expired": plain, "unknown": "gofs_nope"} {
		res := bearer(t, server, http.MethodGet, "/public.txt", token, nil)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, res.StatusCode)
		}
		if challenge := res.Header.Get("WWW-Authenticate"); !strings.HasPrefix(challenge, "Bearer ") ||
			!strings.Contains(challenge, `error="invalid_token"`) {
			t.Errorf("%s: challenge %q", name, challenge)
		}
	}
	if server.logs.find("http bearer token expired") == nil {
		t.Error("the expired token was not recorded as such")
	}
}

// A token that has not expired yet is accepted.
func TestBearerTokenNotYetExpired(t *testing.T) {
	server, plain := tokenServer(t, func(token *config.Token) {
		token.Expires = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	})
	server.write(t, "private/hello.txt", "hello")
	if res := bearer(t, server, http.MethodGet, "/private/hello.txt", plain, nil); res.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", res.StatusCode)
	}
}

// Wrong tokens count towards the login lock, as wrong passwords do.
func TestWrongTokensLockTheAddress(t *testing.T) {
	token, plain := fullToken(t, "ci")
	server := newServer(t, func(cfg *httpConfig) {
		cfg.LoginAttempts = 2
		cfg.LoginLockout = 60
		cfg.Tokens = []config.Token{token}
	})
	fixClock(server)
	server.write(t, "private/hello.txt", "hello")

	for range 2 {
		bearer(t, server, http.MethodGet, "/private/hello.txt", "gofs_wrong", nil)
	}
	if res := bearer(t, server, http.MethodGet, "/private/hello.txt", plain, nil); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the locked address was answered %d, want 429", res.StatusCode)
	}
}

// A token is never a session, so it cannot open the admin interface.
func TestBearerTokenCannotOpenTheAdminInterface(t *testing.T) {
	token, plain := fullToken(t, "ci")
	server := adminServer(t, func(cfg *httpConfig) { cfg.Tokens = []config.Token{token} })

	res := bearer(t, server, http.MethodGet, "/?go-fs=admin", plain, nil)
	if res.StatusCode == http.StatusOK {
		t.Error("a bearer token opened the admin interface")
	}
	res = bearer(t, server, http.MethodGet, "/?go-fs=admin-config", plain, nil)
	if res.StatusCode == http.StatusOK {
		t.Error("a bearer token read the configuration")
	}
}

// A reload adds and revokes tokens without a restart.
func TestReloadAddsAndRevokesTokens(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/hello.txt", "hello")
	token, plain := fullToken(t, "ci")

	if res := bearer(t, server, http.MethodGet, "/private/hello.txt", plain, nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("before: status %d, want 401", res.StatusCode)
	}
	set := server.settings()
	users := []config.User{fullUser("john", "doe")}
	if err := server.Reload(set.cfg, set.https, users, []config.Token{token}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res := bearer(t, server, http.MethodGet, "/private/hello.txt", plain, nil); res.StatusCode != http.StatusOK {
		t.Errorf("added: status %d, want 200", res.StatusCode)
	}
	if err := server.Reload(set.cfg, set.https, users, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res := bearer(t, server, http.MethodGet, "/private/hello.txt", plain, nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked: status %d, want 401", res.StatusCode)
	}
}

// A token works on the TLS listener as it does on the plain one.
func TestBearerTokenOverHTTPS(t *testing.T) {
	token, plain := fullToken(t, "ci")
	server := newServerWith(t, func(cfg *httpConfig) { cfg.Tokens = []config.Token{token} },
		func(https *config.HTTPS) { https.Enabled = true })
	server.write(t, "private/hello.txt", "over tls")

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	port := server.SecureAddr().(*net.TCPAddr).Port
	req, _ := http.NewRequest(http.MethodGet,
		"https://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/private/hello.txt", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "over tls" {
		t.Errorf("status %d body %q", res.StatusCode, body)
	}
}

// The header is explicit and wins over a session cookie the client carries.
func TestBearerTokenWinsOverTheCookie(t *testing.T) {
	token, plain := fullToken(t, "ci")
	token.Paths = []string{"^/private/ci/.*"}
	server := newServer(t, func(cfg *httpConfig) { cfg.Tokens = []config.Token{token} })
	server.write(t, "private/other.txt", "other")
	session := login(t, server, "/", "john", "doe")

	req, _ := http.NewRequest(http.MethodGet, server.url("/private/other.txt"), nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	req.AddCookie(session)
	if res := do(t, req); res.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403: the cookie's account answered instead of the token", res.StatusCode)
	}
}

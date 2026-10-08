package httpd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

// TestRegistryAccess walks the whole table of who may do what: a pull and a
// push, with the registry public for pulling and without, from nobody, from
// a wrong password, from an http account that does not set registry and from
// one that does.
func TestRegistryAccess(t *testing.T) {
	type credentials struct {
		name    string
		options []reqOption
	}
	callers := []credentials{
		{"nobody", nil},
		{"wrong password", []reqOption{as(pusher, "wrong")}},
		{"http account", []reqOption{as("john", "doe")}},
		{"registry account", []reqOption{asPusher}},
	}
	cases := []struct {
		anonymousRead bool
		write         bool
		want          [4]int
	}{
		{true, false, [4]int{http.StatusOK, http.StatusUnauthorized, http.StatusOK, http.StatusOK}},
		{true, true, [4]int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusForbidden, http.StatusAccepted}},
		{false, false, [4]int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusForbidden, http.StatusOK}},
		{false, true, [4]int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusForbidden, http.StatusAccepted}},
	}
	for _, c := range cases {
		server := newRegistryServer(t, func(cfg *httpConfig) { cfg.RegistryAnonymousRead = c.anonymousRead })
		for i, caller := range callers {
			name := fmt.Sprintf("anonymousRead=%v write=%v %s", c.anonymousRead, c.write, caller.name)
			t.Run(name, func(t *testing.T) {
				method, path := http.MethodGet, "/v2/_catalog"
				if c.write {
					method, path = http.MethodPost, "/v2/app/blobs/uploads/"
				}
				res, body := server.reg(t, method, path, nil, caller.options...)
				expectStatus(t, res, body, c.want[i])
				switch res.StatusCode {
				case http.StatusUnauthorized:
					if got := res.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got,
						`Bearer realm="`+server.url(registryTokenPath)+`",service="go-fs",scope=`) {
						t.Errorf("WWW-Authenticate = %q", got)
					}
					if code := errorCodeOf(t, body); code != "UNAUTHORIZED" {
						t.Errorf("code = %s", code)
					}
				case http.StatusForbidden:
					if code := errorCodeOf(t, body); code != "DENIED" {
						t.Errorf("code = %s", code)
					}
				}
			})
		}
	}
}

func TestRegistryAnonymousReadCoversEveryPull(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.RegistryAnonymousRead = false })
	img := server.pushImage(t, "app", "latest", "linux/amd64", "1")
	for _, path := range []string{"/v2/", "/v2/app/tags/list", "/v2/app/manifests/latest",
		"/v2/app/blobs/" + img.layer.String(), "/v2/app/referrers/" + img.digest.String()} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			res, body := server.reg(t, method, path, nil)
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s without credentials: %d %s", method, path, res.StatusCode, body)
			}
			res, body = server.reg(t, method, path, nil, asPusher)
			if res.StatusCode != http.StatusOK {
				t.Errorf("%s %s as the pusher: %d %s", method, path, res.StatusCode, body)
			}
		}
	}
}

func TestRegistryWritesAlwaysNeedTheRegistrySwitch(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.pushImage(t, "app", "latest", "linux/amd64", "1")
	cases := []struct{ method, path string }{
		{http.MethodPost, "/v2/app/blobs/uploads/"},
		{http.MethodPut, "/v2/app/manifests/other"},
		{http.MethodDelete, "/v2/app/manifests/latest"},
		{http.MethodDelete, "/v2/app/blobs/" + img.layer.String()},
		{http.MethodPatch, "/v2/app/blobs/uploads/0123456789abcdef0123456789abcdef"},
	}
	for _, c := range cases {
		res, body := server.reg(t, c.method, c.path, img.manifest)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s anonymously: %d %s", c.method, c.path, res.StatusCode, body)
		}
		res, body = server.reg(t, c.method, c.path, img.manifest, as("john", "doe"))
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s as john: %d %s", c.method, c.path, res.StatusCode, body)
		}
	}
	server.pullManifest(t, "app", "latest")
}

// TestRegistryUploadStatusIsPartOfThePush checks that asking how far an
// upload has got takes the account that pushes, not only a pull's rights:
// a client that asks without credentials is sent for a token that can push.
func TestRegistryUploadStatusIsPartOfThePush(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	location := res.Header.Get("Location")
	res, body = server.reg(t, http.MethodGet, location, nil)
	expectStatus(t, res, body, http.StatusUnauthorized)
	if got := res.Header.Get("WWW-Authenticate"); !strings.HasSuffix(got, `scope="repository:app:pull,push"`) {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	res, body = server.reg(t, http.MethodGet, location, nil, asPusher)
	expectStatus(t, res, body, http.StatusNoContent)
}

func TestRegistryLocksOutAnAddressThatGuesses(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) {
		cfg.LoginAttempts = 2
		cfg.LoginLockout = 60
	})
	for range 2 {
		res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, as(pusher, "wrong"))
		expectStatus(t, res, body, http.StatusUnauthorized)
	}
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusTooManyRequests)
	if res.Header.Get("Retry-After") == "" || errorCodeOf(t, body) != "TOOMANYREQUESTS" {
		t.Errorf("Retry-After %q, body %s", res.Header.Get("Retry-After"), body)
	}
}

func TestRegistryDoesNotCountTheRightPasswordOfAnotherAccount(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) {
		cfg.LoginAttempts = 1
		cfg.LoginLockout = 60
	})
	for range 3 {
		res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, as("john", "doe"))
		expectStatus(t, res, body, http.StatusForbidden)
	}
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
}

func TestARegistryAccountCannotReachTheFiles(t *testing.T) {
	server := newRegistryServer(t, nil)
	server.write(t, "private/secret.txt", "files")
	res := basic(t, server, http.MethodGet, "/private/secret.txt", pusher, pusherPassword, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a registry-only account read a file: %d", res.StatusCode)
	}
	res = basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil)
	if res.StatusCode != http.StatusOK {
		t.Errorf("john cannot read the file: %d", res.StatusCode)
	}
}

func TestRegistryRefusesAPushFromAnotherSite(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, _ := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher,
		withHeader("Origin", "https://evil.example"))
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-site push was answered %d", res.StatusCode)
	}
}

// fetchToken asks the token endpoint for a token, the way a client does after
// the challenge.
func (s *testServer) fetchToken(t *testing.T, scope string, options ...reqOption) (*http.Response, string) {
	t.Helper()
	res, body := s.reg(t, http.MethodGet, registryTokenPath+"?service=go-fs&scope="+scope, nil, options...)
	if res.StatusCode != http.StatusOK {
		return res, ""
	}
	var answer struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || answer.Token == "" ||
		answer.Token != answer.AccessToken || answer.ExpiresIn <= 0 {
		t.Fatalf("token answer: %s", body)
	}
	return res, answer.Token
}

func bearerToken(token string) reqOption {
	return withHeader("Authorization", "Bearer "+token)
}

// TestRegistryTokenFlow is what docker and podman do: ask /v2/, follow the
// challenge to the token endpoint, and send the token from then on.
func TestRegistryTokenFlow(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodGet, "/v2/", nil)
	expectStatus(t, res, body, http.StatusUnauthorized)
	if got := res.Header.Get("WWW-Authenticate"); got !=
		`Bearer realm="`+server.url(registryTokenPath)+`",service="go-fs"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}

	// anonymously, which pulls
	_, anonymous := server.fetchToken(t, "repository:app:pull")
	res, body = server.reg(t, http.MethodGet, "/v2/", nil, bearerToken(anonymous))
	expectStatus(t, res, body, http.StatusOK)
	res, body = server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, bearerToken(anonymous))
	expectStatus(t, res, body, http.StatusUnauthorized)
	if got := res.Header.Get("WWW-Authenticate"); !strings.HasSuffix(got, `scope="repository:app:pull,push"`) {
		t.Errorf("push challenge = %q", got)
	}

	// with the pusher's credentials, which does everything
	_, token := server.fetchToken(t, "repository:app:pull,push", asPusher)
	res, body = server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, bearerToken(token))
	expectStatus(t, res, body, http.StatusAccepted)
	location := res.Header.Get("Location")
	res, body = server.reg(t, http.MethodPut, location+"?digest="+sha256Digest("x"), []byte("x"), bearerToken(token))
	expectStatus(t, res, body, http.StatusCreated)
	res, body = server.reg(t, http.MethodGet, "/v2/app/blobs/"+sha256Digest("x"), nil, bearerToken(anonymous))
	expectStatus(t, res, body, http.StatusOK)
}

func sha256Digest(content string) string {
	return "sha256:" + sha256Hex(content)
}

func TestRegistryTokenEndpointChecksThePassword(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, _ := server.fetchToken(t, "repository:app:pull,push", as(pusher, "wrong"))
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get("WWW-Authenticate") != `Basic realm="go-fs"` {
		t.Errorf("a wrong password got %d, %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	if server.logs.find("http login refused") == nil {
		t.Error("the refused password was not recorded")
	}
}

func TestRegistryTokenEndpointWithoutAnonymousRead(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.RegistryAnonymousRead = false })
	res, _ := server.fetchToken(t, "repository:app:pull")
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get("WWW-Authenticate") != `Basic realm="go-fs"` {
		t.Errorf("an anonymous token request got %d, %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	res, _ = server.fetchToken(t, "repository:app:pull", as("john", "doe"))
	expectStatus(t, res, nil, http.StatusForbidden)
	_, token := server.fetchToken(t, "repository:app:pull", asPusher)
	res, body := server.reg(t, http.MethodGet, "/v2/_catalog", nil, bearerToken(token))
	expectStatus(t, res, body, http.StatusOK)
}

func TestRegistryAnonymousTokenStopsPullingWhenAnonymousReadIsSwitchedOff(t *testing.T) {
	server := newRegistryServer(t, nil)
	_, anonymous := server.fetchToken(t, "repository:app:pull")
	set := server.settings()
	cfg := set.cfg
	cfg.RegistryAnonymousRead = false
	if err := server.Reload(cfg, set.https, set.ssh, []config.User{fullUser("john", "doe"),
		registryUser(pusher, pusherPassword)}, nil); err != nil {
		t.Fatal(err)
	}
	res, body := server.reg(t, http.MethodGet, "/v2/_catalog", nil, bearerToken(anonymous))
	expectStatus(t, res, body, http.StatusUnauthorized)
}

func TestRegistryRefusesTokensItShouldNot(t *testing.T) {
	server := newRegistryServer(t, nil)
	pusherAccount := accountNamed(server.settings().registryAccounts, pusher)
	expired, _, err := server.tokens.mintRegistry(pusherAccount, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := server.tokens.mint(pusherAccount, time.Now(), sessionWindow{idle: time.Hour, max: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	stale := *pusherAccount
	stale.password = "the old one"
	oldPassword, _, err := server.tokens.mintRegistry(&stale, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"expired": expired, "a session token": session,
		"for an old password": oldPassword, "garbage": "not.a.token"} {
		res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, bearerToken(token))
		expectStatus(t, res, body, http.StatusUnauthorized)
		if got := res.Header.Get("WWW-Authenticate"); !strings.HasSuffix(got, `error="invalid_token"`) {
			t.Errorf("%s: WWW-Authenticate = %q", name, got)
		}
	}
	// and a registry token is no session: the file server does not take it
	_, token := server.fetchToken(t, "", asPusher)
	req, _ := http.NewRequest(http.MethodGet, server.url("/private/"), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	if res := do(t, req); res.StatusCode == http.StatusOK {
		t.Error("a registry token was taken for a session")
	}
}

package httpd

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"go-fs/internal/config"
)

// The form hands out a token, and the token stands in for the credentials on
// every request after it.
func TestTheLoginFormMintsASessionToken(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")

	session := login(t, server, "/private/secret.txt", "john", "doe")
	// the cookie is scoped to the root whatever folder the login happened in,
	// so one session covers everything the account may reach
	if session.Path != "/" {
		t.Errorf("path = %q, want /", session.Path)
	}
	if !session.HttpOnly {
		t.Error("the cookie has to be HttpOnly: nothing on the page reads it")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Errorf("samesite = %v, want Lax", session.SameSite)
	}
	if session.MaxAge != config.Default().HTTP.SessionTokenLifetime {
		t.Errorf("maxage = %d, want %d", session.MaxAge,
			config.Default().HTTP.SessionTokenLifetime)
	}

	if res := withSession(t, server, http.MethodGet, "/private/secret.txt", session); //
	res.StatusCode != http.StatusOK {
		t.Errorf("the token was not accepted: %d", res.StatusCode)
	}
}

// A browser is never shown its own password box: it is sent to a page of this
// server's own, and no answer in the exchange carries WWW-Authenticate.
func TestTheLoginPageReplacesTheBrowserPasswordBox(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")

	res := browserGet(t, server, "/private/")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", res.StatusCode)
	}
	if header := res.Header.Get("WWW-Authenticate"); header != "" {
		t.Errorf("the redirect carries a challenge: %q", header)
	}
	location := res.Header.Get("Location")
	if !strings.Contains(location, "go-fs=login") {
		t.Fatalf("location = %q, want the login marker", location)
	}

	page := browserGet(t, server, location)
	if page.StatusCode != http.StatusOK {
		t.Errorf("the login page = %d, want 200", page.StatusCode)
	}
	if header := page.Header.Get("WWW-Authenticate"); header != "" {
		t.Errorf("the login page carries a challenge: %q", header)
	}
	body := bodyOf(t, page)
	if !strings.Contains(body, `name="password"`) || !strings.Contains(body, `name="username"`) {
		t.Error("the login page has no form to fill in")
	}
	// it is reached before anything has authenticated, so it may show nothing
	if strings.Contains(body, "secret.txt") {
		t.Error("the login page names a file in the folder it guards")
	}
}

// A program is challenged exactly as it always was.
func TestANonBrowserStillGetsTheDigestChallenge(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")

	res, _ := get(t, server, "/private/secret.txt")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Digest ") {
		t.Errorf("challenge = %q, want a digest challenge",
			res.Header.Get("WWW-Authenticate"))
	}
}

// Downloading with Basic keeps working, and is not handed a session it never
// asked for.
func TestDownloadsStillWorkWithBasicAuthentication(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")

	res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if body := bodyOf(t, res); body != "secret" {
		t.Errorf("body = %q", body)
	}
	if cookie := cookieNamed(res, sessionCookie); cookie != nil {
		t.Errorf("a header request was handed a token it never asked for: %v", cookie)
	}
}

func TestBasicAuthenticationNeverMintsAToken(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")

	for _, name := range []string{"basic", "browser"} {
		req, _ := http.NewRequest(http.MethodGet,
			server.url("/private/secret.txt"), nil)
		req.SetBasicAuth("john", "doe")
		if name == "browser" {
			req.Header.Set("Sec-Fetch-Mode", "navigate")
		}
		if res := do(t, req); cookieNamed(res, sessionCookie) != nil {
			t.Errorf("%s: a token was minted for a header request", name)
		}
	}
}

func TestLogoutClearsTheSessionToken(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")
	session := login(t, server, "/private/", "john", "doe")

	req, _ := http.NewRequest(http.MethodPost, server.url("/private/?go-fs=logout"), nil)
	req.AddCookie(session)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res := do(t, req)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", res.StatusCode)
	}
	var cleared bool
	for _, cookie := range res.Cookies() {
		if cookie.Name == sessionCookie && cookie.Value == "" && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("the token was not cleared: %v", res.Cookies())
	}
	if server.logs.find("http logout") == nil {
		t.Error("the logout was not recorded")
	}
}

// Logging out cannot be a GET: browsers prefetch links, and a prefetched
// logout signs people out for reading a page.
func TestLogoutIsNotAGet(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	res := browserGet(t, server, "/?go-fs=logout")
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", res.StatusCode)
	}
}

// The token names the account and nothing else: the rights are looked up from
// the live configuration, so there is nothing in it that could go stale.
func TestTheTokenCarriesTheNameAndNotTheRights(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	session := login(t, server, "/private/", "john", "doe")

	parts := strings.Split(session.Value, ".")
	if len(parts) != 3 {
		t.Fatalf("the token has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("the payload is not base64url: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("the payload is not JSON: %v", err)
	}

	for _, want := range []string{"iss", "sub", "aud", "iat", "nbf", "exp", "jti", "cred"} {
		if _, ok := claims[want]; !ok {
			t.Errorf("the token has no %q claim", want)
		}
	}
	if len(claims) != 8 {
		t.Errorf("the token carries %v, want those eight claims and nothing else", claims)
	}
	if claims["sub"] != "john" {
		t.Errorf("sub = %v, want john", claims["sub"])
	}
	if strings.Contains(string(raw), "doe") {
		t.Error("the token carries the password, which anyone holding it can read")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("the header is not base64url: %v", err)
	}
	if !strings.Contains(string(header), `"HS256"`) {
		t.Errorf("header = %s, want HS256", header)
	}
}

// A token carries the rights of its account as they are right now, so a right
// taken away by a reload reaches a browser that already holds one.
func TestASessionTokenKeepsTheAccountsLimits(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = []string{"^/private/.*", "^/other/.*"}
		user := fullUser("john", "doe")
		user.Paths = []string{"^/private/.*"}
		cfg.Users = []config.User{user}
	})
	server.write(t, "private/secret.txt", "secret")
	server.write(t, "other/secret.txt", "other")

	session := login(t, server, "/private/secret.txt", "john", "doe")
	if res := withSession(t, server, http.MethodGet, "/other/secret.txt", session); //
	res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.StatusCode)
	}
}

func TestASessionTokenFollowsTheAccount(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")
	session := login(t, server, "/private/secret.txt", "john", "doe")

	reload := func(users ...config.User) {
		t.Helper()
		next := server.settings().cfg
		if err := server.Reload(next, server.settings().https, users); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	}
	status := func() int {
		return withSession(t, server, http.MethodGet, "/private/secret.txt", session).StatusCode
	}
	if got := status(); got != http.StatusOK {
		t.Fatalf("the token should work, got %d", got)
	}

	// the account keeps its name but loses the path it could reach
	narrowed := fullUser("john", "doe")
	narrowed.Paths = []string{"^/public/.*"}
	reload(narrowed)
	if got := status(); got != http.StatusForbidden {
		t.Errorf("the narrowed account should be refused, got %d", got)
	}

	// and an account that is gone leaves nothing behind for its token to name
	reload(fullUser("someone else", "doe"))
	if got := status(); got != http.StatusUnauthorized {
		t.Errorf("the removed account's token should be refused, got %d", got)
	}
	if server.logs.find("http session token names an account that is no longer configured") == nil {
		t.Error("the refusal was not recorded")
	}
}

// Changing a password signs out the browsers that were logged in under the old
// one, which is the only handle there is on a token already handed out.
func TestASessionTokenDoesNotSurviveAPasswordChange(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")
	session := login(t, server, "/private/secret.txt", "john", "doe")

	next := server.settings().cfg
	if err := server.Reload(next, server.settings().https, []config.User{fullUser("john", "something else")}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	res := withSession(t, server, http.MethodGet, "/private/secret.txt", session)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", res.StatusCode)
	}
	if server.logs.find("http session token was issued for other credentials") == nil {
		t.Error("the refusal was not recorded")
	}
}

func TestALoginWithTheWrongPasswordIsRefused(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	res := postLogin(t, server, "/private/", "john", "not it")
	// the form comes back rather than a 401, which would have to carry the
	// challenge this whole page exists to avoid
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if header := res.Header.Get("WWW-Authenticate"); header != "" {
		t.Errorf("the refusal carries a challenge: %q", header)
	}
	if cookieNamed(res, sessionCookie) != nil {
		t.Error("a wrong password was handed a token")
	}
	if !strings.Contains(bodyOf(t, res), "do not match") {
		t.Error("the form came back with no message on it")
	}
	if server.logs.find("http login refused") == nil {
		t.Error("the refused login was not recorded")
	}
}

// Where there is no account at all, there is nobody to log in as: there is no
// login page, and a browser is challenged as a program is.
func TestNothingIsOfferedWhenThereIsNoAccount(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = nil
	})
	server.write(t, "private/secret.txt", "secret")

	if res := browserGet(t, server, "/?go-fs=login"); res.StatusCode != http.StatusNotFound {
		t.Errorf("the login page = %d, want 404", res.StatusCode)
	}
	res := browserGet(t, server, "/private/")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Digest ") {
		t.Error("a browser should still be challenged where it cannot log in")
	}
}

// A signed token is the only thing accepted. These are the ways of writing one
// that has to fail.
func TestForgedSessionTokensAreRefused(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")
	user := server.settings().accounts[0]

	claims := func() sessionClaims {
		now := time.Now()
		return sessionClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    tokenIssuer,
				Subject:   "john",
				Audience:  jwt.ClaimStrings{tokenAudience},
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				ID:        "forged",
			},
			Credentials: server.tokens.fingerprint(user),
		}
	}
	sign := func(t *testing.T, method jwt.SigningMethod, body sessionClaims, key any) string {
		t.Helper()
		token, err := jwt.NewWithClaims(method, body).SignedString(key)
		if err != nil {
			t.Fatalf("SignedString: %v", err)
		}
		return token
	}

	expired := claims()
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	expired.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
	otherAudience := claims()
	otherAudience.Audience = jwt.ClaimStrings{"somebody-else"}
	otherIssuer := claims()
	otherIssuer.Issuer = "not go-fs"
	noExpiry := claims()
	noExpiry.ExpiresAt = nil
	otherCredentials := claims()
	otherCredentials.Credentials = "not the fingerprint"

	tampered := sign(t, jwt.SigningMethodHS256, claims(), server.tokens.key)
	parts := strings.Split(tampered, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	parts[1] = base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Replace(string(payload), `"john"`, `"max0"`, 1)))
	tampered = strings.Join(parts, ".")

	for _, item := range []struct {
		name  string
		token string
	}{
		{"alg none", sign(t, jwt.SigningMethodNone, claims(), jwt.UnsafeAllowNoneSignatureType)},
		{"another key", sign(t, jwt.SigningMethodHS256, claims(), []byte(strings.Repeat("k", 32)))},
		{"a tampered claim", tampered},
		{"expired", sign(t, jwt.SigningMethodHS256, expired, server.tokens.key)},
		{"another audience", sign(t, jwt.SigningMethodHS256, otherAudience, server.tokens.key)},
		{"another issuer", sign(t, jwt.SigningMethodHS256, otherIssuer, server.tokens.key)},
		{"no expiry at all", sign(t, jwt.SigningMethodHS256, noExpiry, server.tokens.key)},
		{"other credentials", sign(t, jwt.SigningMethodHS256, otherCredentials, server.tokens.key)},
		{"not a token", "not.a.token"},
	} {
		t.Run(item.name, func(t *testing.T) {
			res := withSession(t, server, http.MethodGet, "/private/secret.txt",
				&http.Cookie{Name: sessionCookie, Value: item.token})
			if res.StatusCode == http.StatusOK {
				t.Errorf("%s was accepted", item.name)
			}
		})
	}
}

// A browser whose token has stopped working is signed out rather than
// challenged: it lands on the login page, with the dead cookie cleared.
func TestABrowserWithADeadTokenIsSentToTheLoginPage(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")

	req, _ := http.NewRequest(http.MethodGet, server.url("/private/"), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "not.a.token"})
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res := do(t, req)

	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "go-fs=login") {
		t.Errorf("location = %q, want the login page", res.Header.Get("Location"))
	}
	var cleared bool
	for _, cookie := range res.Cookies() {
		if cookie.Name == sessionCookie && cookie.Value == "" {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the dead token was left in the browser")
	}
}

func TestAnExpiredTokenIsRefusedByRead(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	user := server.settings().accounts[0]
	token, _, err := server.tokens.mint(user, -time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := server.tokens.read(token); err == nil {
		t.Error("an expired token was read as valid")
	}
}

// A configured secret is what lets a login survive a restart and be shared by
// two hosts serving the same folder.
func TestTwoServersWithTheSameSecretShareALogin(t *testing.T) {
	secret, err := config.GenerateSessionSecret()
	if err != nil {
		t.Fatalf("GenerateSessionSecret: %v", err)
	}
	tune := func(cfg *httpConfig) {
		cfg.SessionTokenSecret = secret
		cfg.Users = []config.User{fullUser("john", "doe")}
	}
	first := newServer(t, tune)
	second := newServer(t, tune)
	second.write(t, "private/secret.txt", "secret")

	session := login(t, first, "/private/", "john", "doe")
	if res := withSession(t, second, http.MethodGet, "/private/secret.txt", session); //
	res.StatusCode != http.StatusOK {
		t.Errorf("the other server refused the token: %d", res.StatusCode)
	}
}

func TestAGeneratedSigningKeyIsWarnedAbout(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	if server.logs.findLike("no http.httpSessionTokenSecret configured") == nil {
		t.Error("a generated signing key was not warned about")
	}

	configured := newServer(t, func(cfg *httpConfig) {
		secret, err := config.GenerateSessionSecret()
		if err != nil {
			t.Fatalf("GenerateSessionSecret: %v", err)
		}
		cfg.SessionTokenSecret = secret
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	if configured.logs.findLike("no http.httpSessionTokenSecret configured") != nil {
		t.Error("a configured signing key was warned about")
	}
}

// The login and logout forms are the only ones a cross site page could post
// to, so they are guarded like every other thing that changes something.
func TestLoginFromAnotherSiteIsRefused(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})

	for _, item := range []struct {
		name   string
		header string
		value  string
	}{
		{"a named origin", "Origin", "https://elsewhere.example"},
		{"a cross site fetch", "Sec-Fetch-Site", "cross-site"},
	} {
		t.Run(item.name, func(t *testing.T) {
			form := url.Values{"username": {"john"}, "password": {"doe"}}
			req, _ := http.NewRequest(http.MethodPost,
				server.url("/?go-fs=login"), strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set(item.header, item.value)
			res := do(t, req)
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", res.StatusCode)
			}
			if cookieNamed(res, sessionCookie) != nil {
				t.Error("a cross site login was handed a token")
			}
		})
	}
}

// A browser says Sec-Fetch-Site on every request and a program says none, so
// this refuses a mutation from another site even where there is no Origin.
func TestAMutationFromAnotherSiteIsRefusedWithoutAnOrigin(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	session := login(t, server, "/", "john", "doe")

	req, _ := http.NewRequest(http.MethodPut, server.url("/dropped.txt"),
		strings.NewReader("x"))
	req.AddCookie(session)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if res := do(t, req); res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.StatusCode)
	}
}

// The marker is only a marker where it names an endpoint: a file whose name
// carries a go-fs query is still that file.
func TestAnUnknownMarkerIsNotAnEndpoint(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = nil
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "notes.txt", "hello")

	res, body := get(t, server, "/notes.txt?go-fs=something")
	if res.StatusCode != http.StatusOK || body != "hello" {
		t.Errorf("status = %d, body = %q", res.StatusCode, body)
	}
}

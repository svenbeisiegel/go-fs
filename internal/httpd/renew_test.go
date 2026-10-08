package httpd

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"go-fs/internal/config"
)

// sessionServer is a server whose sessions last idle without use and max
// from the login, with one account john/doe and a private file.
func sessionServer(t *testing.T, idle, max time.Duration) *testServer {
	t.Helper()
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
		cfg.SessionTokenLifetime = int(idle.Seconds())
		cfg.SessionMaxLifetime = int(max.Seconds())
	})
	server.write(t, "private/secret.txt", "secret")
	return server
}

// sessionFrom is the cookie of a login that happened at loggedIn, holding a
// token that runs out after expiresIn, as one minted by an earlier request
// would.
func sessionFrom(t *testing.T, server *testServer, loggedIn time.Time, expiresIn time.Duration) *http.Cookie {
	t.Helper()
	user := server.settings().accounts[0]
	token, _, err := server.tokens.mint(user, loggedIn,
		sessionWindow{idle: expiresIn, max: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return &http.Cookie{Name: sessionCookie, Value: token}
}

// renewed sends the session to the private file, which has to be served, and
// returns the claims of the token the answer hands back, or nothing.
func renewed(t *testing.T, server *testServer, session *http.Cookie) (*sessionClaims, *http.Cookie) {
	t.Helper()
	res := withSession(t, server, http.MethodGet, "/private/secret.txt", session)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the session was refused: %d", res.StatusCode)
	}
	fresh := cookieNamed(res, sessionCookie)
	if fresh == nil {
		return nil, nil
	}
	claims, err := server.tokens.read(fresh.Value)
	if err != nil {
		t.Fatalf("the renewed token does not read: %v", err)
	}
	return claims, fresh
}

// A token in the first half of its idle window is good for long enough, so a
// busy browser is not sent a cookie with every request.
func TestAFreshSessionIsNotRenewed(t *testing.T) {
	server := sessionServer(t, time.Hour, 24*time.Hour)
	session := login(t, server, "/private/", "john", "doe")
	if claims, _ := renewed(t, server, session); claims != nil {
		t.Errorf("a fresh token was renewed: %+v", claims)
	}
}

// Once less than half the idle window is left, a request renews the token for
// the whole window again, for the same login.
func TestASessionInUseIsRenewed(t *testing.T) {
	server := sessionServer(t, time.Hour, 24*time.Hour)
	loggedIn := time.Now().Add(-3 * time.Hour)
	claims, cookie := renewed(t, server, sessionFrom(t, server, loggedIn, 20*time.Minute))
	if claims == nil {
		t.Fatal("a token with 20 of 60 minutes left was not renewed")
	}
	if claims.AuthTime == nil || claims.AuthTime.Unix() != loggedIn.Unix() {
		t.Errorf("auth_time = %v, want the login at %v", claims.AuthTime, loggedIn)
	}
	if left := time.Until(claims.ExpiresAt.Time); left < 59*time.Minute || left > time.Hour {
		t.Errorf("the renewed token is good for %v, want the idle window of an hour", left)
	}
	if cookie.MaxAge < 3590 || cookie.MaxAge > 3600 || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Errorf("the renewed cookie is %+v, want what a login sets", cookie)
	}
	// and the renewed token is a session like the first one
	if res := withSession(t, server, http.MethodGet, "/private/secret.txt", cookie); //
	res.StatusCode != http.StatusOK {
		t.Errorf("the renewed token was refused: %d", res.StatusCode)
	}
}

// No renewal reaches beyond httpSessionMaxLifetime after the login.
func TestARenewalStopsAtTheCap(t *testing.T) {
	server := sessionServer(t, time.Hour, 2*time.Hour)
	loggedIn := time.Now().Add(-110 * time.Minute)
	claims, _ := renewed(t, server, sessionFrom(t, server, loggedIn, 5*time.Minute))
	if claims == nil {
		t.Fatal("a token short of the cap was not renewed")
	}
	if limit := loggedIn.Add(2 * time.Hour); claims.ExpiresAt.After(limit.Add(time.Second)) {
		t.Errorf("the renewed token runs to %v, past the cap at %v", claims.ExpiresAt, limit)
	}

	// a token that already runs to the cap is not renewed again
	atCap := sessionFrom(t, server, loggedIn, 10*time.Minute)
	if claims, _ := renewed(t, server, atCap); claims != nil {
		t.Errorf("a token at the cap was renewed to %v", claims.ExpiresAt)
	}
}

// A login older than the cap is over, whatever its token says: one minted
// while the cap was longer is held to the one configured now.
func TestASessionOlderThanTheCapIsRefused(t *testing.T) {
	server := sessionServer(t, time.Hour, 2*time.Hour)
	session := sessionFrom(t, server, time.Now().Add(-3*time.Hour), time.Hour)
	res := withSession(t, server, http.MethodGet, "/private/secret.txt", session)
	if res.StatusCode == http.StatusOK {
		t.Fatal("a session older than the cap was served")
	}
	if cleared := res.Cookies(); len(cleared) == 0 || cleared[0].Value != "" {
		t.Errorf("the outlived token was left in the browser: %v", cleared)
	}
}

// A token minted before auth_time existed carries none; its iat stands in,
// so it is renewed rather than logging the browser out at the update.
func TestATokenWithoutAuthTimeIsRenewedFromItsIssue(t *testing.T) {
	server := sessionServer(t, time.Hour, 24*time.Hour)
	user := server.settings().accounts[0]
	issued := time.Now().Add(-50 * time.Minute)
	old := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			Subject:   user.name,
			Audience:  jwt.ClaimStrings{tokenAudience},
			IssuedAt:  jwt.NewNumericDate(issued),
			NotBefore: jwt.NewNumericDate(issued),
			ExpiresAt: jwt.NewNumericDate(issued.Add(time.Hour)),
			ID:        "old",
		},
		Credentials: server.tokens.fingerprint(user),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, old).SignedString(server.tokens.key)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := renewed(t, server, &http.Cookie{Name: sessionCookie, Value: token})
	if claims == nil {
		t.Fatal("a token without auth_time was not renewed")
	}
	if claims.AuthTime == nil || claims.AuthTime.Unix() != issued.Unix() {
		t.Errorf("auth_time = %v, want the old token's iat %v", claims.AuthTime, issued)
	}
}

// A file from before the cap existed may set a lifetime longer than the
// default cap; the cap is raised to it rather than cutting the login short.
func TestACapShorterThanTheIdleWindowIsRaisedToIt(t *testing.T) {
	cfg := config.Default().HTTP
	cfg.SessionTokenLifetime = 30 * 24 * 60 * 60
	window := sessionWindowOf(cfg)
	if window.max != window.idle {
		t.Errorf("max = %v, want the idle window %v", window.max, window.idle)
	}
}

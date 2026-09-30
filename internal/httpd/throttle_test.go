package httpd

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

// lockingServer is a server whose lock trips after two wrong passwords, with
// a clock the test moves.
func lockingServer(t *testing.T, attempts int) (*testServer, func(time.Duration)) {
	t.Helper()
	server := newServer(t, func(cfg *httpConfig) {
		cfg.LoginAttempts = attempts
		cfg.LoginLockout = 60
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "private/secret.txt", "secret")
	return server, fixClock(server)
}

// Too many wrong passwords lock the address: the next request is refused
// without a look at its credentials, told when to come back, and not
// challenged. Once the lock has passed the right password works again.
func TestTooManyWrongPasswordsLockTheAddress(t *testing.T) {
	server, advance := lockingServer(t, 2)

	for i := 0; i < 2; i++ {
		if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil); //
		res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong password %d was answered %d, want 401", i+1, res.StatusCode)
		}
	}
	if record := server.logs.find("http address locked out after too many failed logins"); record == nil {
		t.Error("the lock was not recorded")
	} else if record["address"] != "127.0.0.1" || record["attempts"] != int64(2) {
		t.Errorf("the lock record says %v", record)
	}

	// the right password is not even looked at
	res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a locked address was answered %d, want 429", res.StatusCode)
	}
	if res.Header.Get("WWW-Authenticate") != "" {
		t.Error("a locked address must not be challenged")
	}
	if after, err := strconv.Atoi(res.Header.Get("Retry-After")); err != nil || after < 1 || after > 60 {
		t.Errorf("Retry-After = %q, want the seconds left on the lock", res.Header.Get("Retry-After"))
	}
	if record := server.logs.find("http login refused, the address is locked out"); record == nil {
		t.Error("the refusal was not recorded")
	} else if record["method"] != "basic" {
		t.Errorf("the refusal says method %v", record["method"])
	}

	advance(61 * time.Second)
	res = basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "secret" {
		t.Errorf("after the lock: status %d body %q", res.StatusCode, body)
	}
}

// The form, Basic and Digest share one count per address. A locked browser is
// told on the login page rather than challenged, and a browser asking for a
// protected folder is sent there.
func TestTheLoginFormSharesTheLock(t *testing.T) {
	server, _ := lockingServer(t, 2)

	if res := postLogin(t, server, "/", "john", "wrong"); res.StatusCode != http.StatusOK {
		t.Fatalf("the wrong password was answered %d, want the form back", res.StatusCode)
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil); //
	res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the second wrong password was answered %d, want 401", res.StatusCode)
	}

	res := postLogin(t, server, "/", "john", "doe")
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(page), "Too many failed logins") {
		t.Errorf("a locked form post was answered %d: %.200s", res.StatusCode, page)
	}
	if cookieNamed(res, sessionCookie) != nil {
		t.Error("a locked address was handed a session")
	}
	if res.Header.Get("WWW-Authenticate") != "" {
		t.Error("the login page must never challenge")
	}
	if record := server.logs.find("http login refused, the address is locked out"); record == nil {
		t.Error("the refusal was not recorded")
	} else if record["method"] != "form" {
		t.Errorf("the refusal says method %v", record["method"])
	}

	// a browser at a protected folder lands on the page, which explains
	res = browserGet(t, server, "/private/")
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "go-fs=login") {
		t.Fatalf("a locked browser was answered %d to %q, want 303 to the login page",
			res.StatusCode, res.Header.Get("Location"))
	}
	res = browserGet(t, server, "/private/?go-fs=login")
	page, _ = io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(page), "Too many failed logins") {
		t.Errorf("the login page for a locked browser was %d: %.200s", res.StatusCode, page)
	}
}

// A right password forgets what was counted before it.
func TestASuccessfulLoginClearsTheCounter(t *testing.T) {
	server, _ := lockingServer(t, 2)

	basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil)
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("the right password was answered %d", res.StatusCode)
	}
	// one more failure would have locked had the first still counted
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong password after a right one was answered %d, want 401", res.StatusCode)
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("the address was locked after one failure, answered %d", res.StatusCode)
	}
}

// A stale nonce with the right password is not a wrong password: the browser
// is asked again and nothing is counted, however often it happens.
func TestAStaleNonceIsNotAFailedLogin(t *testing.T) {
	server, _ := lockingServer(t, 2)

	issued := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	params := map[string]string{
		"realm":     server.settings().cfg.Realm,
		"nonce":     issued + ":" + server.signNonce(issued),
		"algorithm": "MD5",
	}
	for i := 0; i < 4; i++ {
		req, _ := http.NewRequest(http.MethodGet, server.url("/private/secret.txt"), nil)
		req.Header.Set("Authorization",
			digestHeader(t, params, http.MethodGet, "/private/secret.txt", "john", "doe", true))
		res := do(t, req)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d was answered %d, want 401", i+1, res.StatusCode)
		}
		if !strings.Contains(res.Header.Get("WWW-Authenticate"), "stale=true") {
			t.Fatalf("attempt %d was not asked again: %q", i+1, res.Header.Get("WWW-Authenticate"))
		}
	}
	if server.logs.find("http address locked out after too many failed logins") != nil {
		t.Error("stale nonces were counted as wrong passwords")
	}
}

// A session is not a guess: it is accepted from a locked address, so someone
// who logged in before a guesser behind the same address keeps their login.
func TestAValidSessionSurvivesALockout(t *testing.T) {
	server, _ := lockingServer(t, 2)
	session := login(t, server, "/", "john", "doe")

	for i := 0; i < 2; i++ {
		basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil)
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the address is not locked: %d", res.StatusCode)
	}
	if res := withSession(t, server, http.MethodGet, "/private/secret.txt", session); res.StatusCode != http.StatusOK {
		t.Errorf("a session from the locked address was answered %d, want 200", res.StatusCode)
	}
}

// Failures are counted inside a window: ones old enough are forgotten.
func TestFailuresExpireWithTheWindow(t *testing.T) {
	server, advance := lockingServer(t, 3)

	for i := 0; i < 2; i++ {
		basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil)
	}
	advance(61 * time.Second)
	for i := 0; i < 2; i++ {
		if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("failure %d after the window was answered %d, want 401", i+1, res.StatusCode)
		}
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("the address was locked across the window, answered %d", res.StatusCode)
	}
}

// 0 turns the lock off, whatever an address sends.
func TestTheLockIsOffAtZero(t *testing.T) {
	server, _ := lockingServer(t, 0)
	for i := 0; i < 20; i++ {
		if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d was answered %d, want 401", i+1, res.StatusCode)
		}
	}
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("the right password was answered %d", res.StatusCode)
	}
}

// The lock's settings are read at every failure, so a reload changes them
// without a restart.
func TestTheLockSettingsAreSwappedWithoutARestart(t *testing.T) {
	server, _ := lockingServer(t, 0)

	next := server.settings().cfg
	next.LoginAttempts = 1
	if err := server.Reload(next, server.settings().https, []config.User{fullUser("john", "doe")}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	basic(t, server, http.MethodGet, "/private/secret.txt", "john", "wrong", nil)
	if res := basic(t, server, http.MethodGet, "/private/secret.txt", "john", "doe", nil); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("after the reload one failure should lock, answered %d", res.StatusCode)
	}
}

// The tracker sweeps what has expired as it grows, and is bounded whatever
// the traffic.
func TestTheTrackerEvictsExpiredRecords(t *testing.T) {
	tracker := newLoginTracker()
	now := time.Now()
	tracker.now = func() time.Time { return now }

	for i := 0; i < evictAbove; i++ {
		tracker.failed("10.0."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256), 5, time.Minute)
	}
	if tracker.size() != evictAbove {
		t.Fatalf("tracked %d, want %d", tracker.size(), evictAbove)
	}
	now = now.Add(2 * time.Minute)
	tracker.failed("192.0.2.1", 5, time.Minute)
	if tracker.size() != 1 {
		t.Errorf("after the window closed %d are tracked, want the one new address", tracker.size())
	}
}

func TestTheTrackerIsBounded(t *testing.T) {
	tracker := newLoginTracker()
	now := time.Now()
	tracker.now = func() time.Time { return now }

	for i := 0; i < maxTracked+10; i++ {
		// each one a little later, so the eviction has an oldest to pick
		now = now.Add(time.Millisecond)
		tracker.failed("addr-"+strconv.Itoa(i), 5, time.Hour)
	}
	if tracker.size() > maxTracked {
		t.Errorf("tracked %d, want at most %d", tracker.size(), maxTracked)
	}
	if _, locked := tracker.locked("addr-0"); locked {
		t.Error("the oldest address should have been forgotten")
	}
}

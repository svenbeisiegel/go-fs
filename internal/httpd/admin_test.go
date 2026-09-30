package httpd

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go-fs/internal/config"
)

// adminUser is an account that may reach the admin interface: an http account
// that sets isAdmin.
func adminUser(name, password string) config.User {
	user := fullUser(name, password)
	user.IsAdmin = true
	return user
}

// withAdmin gives a server a configuration file to edit, which is what makes
// the admin interface exist at all. The file names the served folder and the
// accounts the server was built with, so that what the page shows is what the
// test set up.
func withAdmin(t *testing.T, cfg *httpConfig) {
	t.Helper()
	folder := t.TempDir()
	path := filepath.Join(folder, "go-fs.toml")
	body := "[general]\nbasefolder = " + strconv.Quote(cfg.Basefolder) + "\n" +
		"[ftp]\nenabled = false\n[tftp]\nenabled = false\n[http]\nenabled = true\n"
	for _, user := range cfg.Users {
		body += "[[users]]\nusername = " + strconv.Quote(user.Username) +
			"\npassword = " + strconv.Quote(user.Password) + "\nhttp = true\n"
		if user.IsAdmin {
			body += "isAdmin = true\n"
		}
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.ConfigPath = path
}

// adminServer is a server with the interface on and two accounts that may log
// in: root, who is an admin, and john, who is not.
func adminServer(t *testing.T, tune func(*httpConfig)) *testServer {
	t.Helper()
	return newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{adminUser("root", "secret"), fullUser("john", "doe")}
		if tune != nil {
			tune(cfg)
		}
		withAdmin(t, cfg)
	})
}

// A session of an admin account is what opens the interface, and nothing else
// does: not a session of another account, not the admin's own password sent
// as a header, and not the absence of any credentials.
func TestAdminInterfaceNeedsAnAdminSession(t *testing.T) {
	server := adminServer(t, nil)

	// nobody: a browser is sent to log in, a fetch is told
	res := browserGet(t, server, "/?go-fs=admin")
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("an anonymous browser was answered %d, want 303 to the login page", res.StatusCode)
	}
	if location := res.Header.Get("Location"); !strings.Contains(location, "go-fs=login") {
		t.Errorf("the browser was sent to %q, want the login page", location)
	}
	if res, _ := get(t, server, "/?go-fs=admin-config"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an anonymous fetch was answered %d, want 401", res.StatusCode)
	}
	if res.Header.Get("WWW-Authenticate") != "" {
		t.Error("the admin interface must never raise the browser's password box")
	}

	// the admin's password in a header: right account, wrong way in
	if res := basic(t, server, http.MethodGet, "/?go-fs=admin-config", "root", "secret", nil); //
	res.StatusCode != http.StatusUnauthorized {
		t.Errorf("basic authentication was answered %d, want 401", res.StatusCode)
	}

	// a session of an account that is not an admin
	john := login(t, server, "/", "john", "doe")
	if res := withSession(t, server, http.MethodGet, "/?go-fs=admin", john); res.StatusCode != http.StatusForbidden {
		t.Errorf("john was answered %d, want 403", res.StatusCode)
	}
	if res := withSession(t, server, http.MethodGet, "/?go-fs=admin-config", john); res.StatusCode != http.StatusForbidden {
		t.Errorf("john's fetch was answered %d, want 403", res.StatusCode)
	}
	if record := server.logs.find("http admin interface refused, the account is not an admin"); record == nil {
		t.Error("the refusal was not recorded")
	} else if record["user"] != "john" {
		t.Errorf("the refusal names %v", record["user"])
	}

	// and the admin
	root := login(t, server, "/", "root", "secret")
	res = withSession(t, server, http.MethodGet, "/?go-fs=admin", root)
	body := bodyOf(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("root was answered %d: %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "go-fs configuration") || !strings.Contains(body, "async function load()") {
		t.Error("the answer is not the admin page")
	}
	if policy := res.Header.Get("Content-Security-Policy"); !strings.Contains(policy, "script-src 'nonce-") {
		t.Errorf("the page carries no policy: %q", policy)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("the page must not be cached")
	}

	res = withSession(t, server, http.MethodGet, "/?go-fs=admin-config", root)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the state was answered %d", res.StatusCode)
	}
	var state struct {
		Path   string         `json:"path"`
		Values map[string]any `json:"values"`
	}
	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(state.Path, "go-fs.toml") {
		t.Errorf("the state names %q", state.Path)
	}
	httpSection, _ := state.Values["http"].(map[string]any)
	if enabled := httpSection["enableAdminInterface"]; enabled != true {
		t.Errorf("the state says enableAdminInterface = %v", enabled)
	}
	if record := server.logs.find("http admin interface request"); record == nil {
		t.Error("the request was not recorded")
	} else if record["user"] != "root" {
		t.Errorf("the record names %v", record["user"])
	}
}

// The switch is read per request, so a reload turns the interface off and on
// again without a restart. Off, the marker names nothing at all.
func TestAdminInterfaceCanBeSwitchedOff(t *testing.T) {
	server := adminServer(t, func(cfg *httpConfig) { cfg.EnableAdminInterface = false })
	root := login(t, server, "/", "root", "secret")

	if res := withSession(t, server, http.MethodGet, "/?go-fs=admin", root); res.StatusCode != http.StatusNotFound {
		t.Errorf("the disabled interface was answered %d, want 404", res.StatusCode)
	}
	res := withSession(t, server, http.MethodGet, "/", root)
	if body := bodyOf(t, res); strings.Contains(body, adminLink) {
		t.Error("the listing offers the Admin button while the interface is off")
	}

	set := server.settings()
	cfg := set.cfg
	cfg.EnableAdminInterface = true
	if err := server.Reload(cfg, set.https, []config.User{adminUser("root", "secret"), fullUser("john", "doe")}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res := withSession(t, server, http.MethodGet, "/?go-fs=admin", root); res.StatusCode != http.StatusOK {
		t.Errorf("the reenabled interface was answered %d, want 200", res.StatusCode)
	}
}

// A server built without a configuration file has no interface, whatever the
// switch says.
func TestAdminInterfaceNeedsTheFile(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{adminUser("root", "secret")}
	})
	root := login(t, server, "/", "root", "secret")
	if res := withSession(t, server, http.MethodGet, "/?go-fs=admin", root); res.StatusCode != http.StatusNotFound {
		t.Errorf("answered %d, want 404", res.StatusCode)
	}
}

// adminLink is what the Admin button looks like in the page. The marker on
// its own is not enough to look for: the listing's script names it too, for
// the #/admin alias.
const adminLink = `?go-fs=admin"><svg`

// The listing offers the Admin button to an admin session and to nobody else,
// and the link is the folder being looked at with the marker on it.
func TestTheListingOffersAdminToAdminsOnly(t *testing.T) {
	server := adminServer(t, func(cfg *httpConfig) { publicServer(cfg) })
	server.mkdir(t, "docs")

	if _, body := get(t, server, "/docs/"); strings.Contains(body, adminLink) {
		t.Error("an anonymous listing offers the Admin button")
	}
	john := login(t, server, "/", "john", "doe")
	if body := bodyOf(t, withSession(t, server, http.MethodGet, "/docs/", john)); strings.Contains(body, adminLink) {
		t.Error("john's listing offers the Admin button")
	}
	if res := basic(t, server, http.MethodGet, "/docs/", "root", "secret", nil); strings.Contains(bodyOf(t, res), adminLink) {
		t.Error("a header-authenticated listing offers the Admin button, but a header cannot reach the interface")
	}
	root := login(t, server, "/", "root", "secret")
	body := bodyOf(t, withSession(t, server, http.MethodGet, "/docs/", root))
	if !strings.Contains(body, `href="/docs/?go-fs=admin"`) {
		t.Errorf("root's listing does not link the interface from the folder:\n%s", body)
	}
	if !strings.Contains(body, `#/admin`) {
		t.Error("the listing's script does not know the #/admin alias")
	}
}

// The interface changes the file, so a request for it from another site is
// refused before it is looked at, the way every other mutation is.
func TestAdminInterfaceRefusesAnotherSite(t *testing.T) {
	server := adminServer(t, nil)
	root := login(t, server, "/", "root", "secret")

	for name, headers := range map[string]map[string]string{
		"origin": {"Origin": "https://elsewhere.example"},
		"site":   {"Sec-Fetch-Site": "cross-site"},
	} {
		req, err := http.NewRequest(http.MethodPost, server.url("/?go-fs=admin-generate"),
			strings.NewReader(`{"kind":"certificate"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		req.AddCookie(root)
		if res := do(t, req); res.StatusCode != http.StatusForbidden {
			t.Errorf("a request from another %s was answered %d, want 403", name, res.StatusCode)
		}
	}

	// and from its own page it goes through: the answer is key material
	req, err := http.NewRequest(http.MethodPost, server.url("/?go-fs=admin-generate"),
		strings.NewReader(`{"kind":"certificate"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(root)
	res := do(t, req)
	answer, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(answer), "pairValue") {
		t.Errorf("the page's own request was answered %d: %s", res.StatusCode, answer)
	}
}

// The interface is on by default, and a server that comes up with it on but
// no admin account, or on a plain listener beyond the loopback, says so.
func TestAdminInterfaceWarnsAtStartup(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Address = ""
		withAdmin(t, cfg)
	})
	if server.logs.findLike("http.enableAdminInterface is on but no account sets isAdmin") == nil {
		t.Error("a server with no admin account did not say so")
	}
	if server.logs.findLike("the admin interface is reachable over plain http") == nil {
		t.Error("a server on every interface did not warn about plain http")
	}

	quiet := adminServer(t, func(cfg *httpConfig) { cfg.Address = "127.0.0.1" })
	if quiet.logs.findLike("http.enableAdminInterface is on but") != nil ||
		quiet.logs.findLike("the admin interface is reachable over plain http") != nil {
		t.Error("a loopback server with an admin account was warned about")
	}
}

// The interface's own records name the client the file server resolved, which
// behind a trusted proxy is the forwarded address rather than the proxy.
func TestTheAdminInterfaceRecordsTheForwardedAddress(t *testing.T) {
	server := adminServer(t, func(cfg *httpConfig) {
		cfg.TrustedProxies = []string{"127.0.0.1"}
	})
	root := login(t, server, "/", "root", "secret")

	req, err := http.NewRequest(http.MethodPost, server.url("/?go-fs=admin-generate"),
		strings.NewReader(`{"kind":"certificate"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.AddCookie(root)
	if res := do(t, req); res.StatusCode != http.StatusOK {
		t.Fatalf("the request was answered %d", res.StatusCode)
	}
	if record := server.logs.find("http admin interface request"); record == nil {
		t.Error("the file server did not record the request")
	} else if record["address"] != "203.0.113.9" {
		t.Errorf("the file server recorded %v, want the forwarded address", record["address"])
	}
	if record := server.logs.find("key material was generated by the admin interface"); record == nil {
		t.Error("the interface did not record what it generated")
	} else if record["address"] != "203.0.113.9" {
		t.Errorf("the interface recorded %v, want the forwarded address", record["address"])
	}
}

// A browser that still remembers Basic credentials sends them with everything.
// Beside a session for the same account they are that session: the listing
// offers a logout and the admin page opens. A session for another account
// changes nothing.
func TestASessionIsRecognisedBesideABasicHeader(t *testing.T) {
	server := adminServer(t, nil)
	root := login(t, server, "/", "root", "secret")
	john := login(t, server, "/", "john", "doe")

	both := func(path, name, password string, session *http.Cookie, browser bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.url(path), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(name+":"+password)))
		if browser {
			req.Header.Set("Accept", "text/html")
		}
		req.AddCookie(session)
		return do(t, req)
	}

	res := both("/", "john", "doe", john, true)
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(page), "Log out") {
		t.Errorf("john with header and session was answered %d without a logout", res.StatusCode)
	}
	if res := both("/?go-fs=admin", "root", "secret", root, true); res.StatusCode != http.StatusOK {
		t.Errorf("root with header and session was answered %d, want the admin page", res.StatusCode)
	}

	// the header names root, the session john: no session for root, so a
	// fetch is told as it always was
	res = both("/?go-fs=admin-config", "root", "secret", john, false)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("root's header beside john's session was answered %d, want 401", res.StatusCode)
	}
	for _, cookie := range res.Cookies() {
		if cookie.Name == sessionCookie {
			t.Error("a session for another account must be left alone, not cleared")
		}
	}
}

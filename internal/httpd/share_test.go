package httpd

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

// shareLink asks for the share link of a file as john, and returns its path
// and query.
func shareLink(t *testing.T, server *testServer, path string) string {
	t.Helper()
	res := basic(t, server, http.MethodGet, path+"?go-fs=share", "john", "doe", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("share status = %d, want 200: %s", res.StatusCode, bodyOf(t, res))
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	var view struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(view.Path, path+"?key=") {
		t.Fatalf("share path = %q", view.Path)
	}
	return view.Path
}

func TestShareLinkDownloadsAProtectedFile(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/report.txt", "secret content")

	if res, _ := get(t, server, "/private/report.txt"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a key the status = %d, want 401", res.StatusCode)
	}

	link := shareLink(t, server, "/private/report.txt")
	key := strings.TrimPrefix(link, "/private/report.txt?key=")
	if len(key) != 128 {
		t.Errorf("the key is %d characters, want 128 (SHA-512 hex)", len(key))
	}
	res, body := get(t, server, link)
	if res.StatusCode != http.StatusOK || body != "secret content" {
		t.Fatalf("with the key: status = %d, body = %q", res.StatusCode, body)
	}
	if server.logs.find("http share link used") == nil {
		t.Error("the use of the link was not recorded")
	}

	req, err := http.NewRequest(http.MethodHead, server.url(link), nil)
	if err != nil {
		t.Fatal(err)
	}
	if head := do(t, req); head.StatusCode != http.StatusOK {
		t.Errorf("HEAD with the key: status = %d, want 200", head.StatusCode)
	}

	// a signed in client holding the link is served as well
	if res := basic(t, server, http.MethodGet, link, "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("with the key and credentials: status = %d, want 200", res.StatusCode)
	}
}

func TestShareLinkWithAWrongKeyIsAuthenticatedAsAnyOther(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/report.txt", "secret content")
	link := shareLink(t, server, "/private/report.txt")

	for _, wrong := range []string{
		"/private/report.txt?key=nothex",
		"/private/report.txt?key=" + strings.Repeat("0", 128),
		link[:len(link)-1] + "x",
	} {
		if res, _ := get(t, server, wrong); res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", wrong, res.StatusCode)
		}
	}
	// the right credentials still get the file, whatever the key says
	res := basic(t, server, http.MethodGet, "/private/report.txt?key=wrong", "john", "doe", nil)
	if res.StatusCode != http.StatusOK {
		t.Errorf("a wrong key with credentials: status = %d, want 200", res.StatusCode)
	}
}

func TestShareLinkStopsWorkingWhenTheFileChanges(t *testing.T) {
	cases := map[string]func(t *testing.T, server *testServer) string{
		"content": func(t *testing.T, server *testServer) string {
			server.write(t, "private/report.txt", "longer content now")
			return "/private/report.txt"
		},
		"modified time": func(t *testing.T, server *testServer) string {
			touch(t, server, "private/report.txt", time.Now().Add(-time.Hour))
			return "/private/report.txt"
		},
		"name": func(t *testing.T, server *testServer) string {
			from := filepath.Join(server.base, "private", "report.txt")
			if err := os.Rename(from, filepath.Join(server.base, "private", "renamed.txt")); err != nil {
				t.Fatal(err)
			}
			// the same file, the same time and size: only the path differs
			server.write(t, "private/report.txt", "")
			return "/private/renamed.txt"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			server := newServer(t, nil)
			server.write(t, "private/report.txt", "secret content")
			link := shareLink(t, server, "/private/report.txt")
			_, query, _ := strings.Cut(link, "?")

			path := change(t, server)
			if res, _ := get(t, server, path+"?"+query); res.StatusCode != http.StatusUnauthorized {
				t.Errorf("after changing the %s: status = %d, want 401", name, res.StatusCode)
			}
		})
	}
}

func TestShareLinkOnlyReads(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = []string{"PUT", "DELETE"}
	})
	server.write(t, "private/report.txt", "secret content")
	link := shareLink(t, server, "/private/report.txt")

	for _, method := range []string{http.MethodPut, http.MethodDelete, methodMove, http.MethodPost} {
		req, err := http.NewRequest(method, server.url(link), strings.NewReader("replaced"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Destination", "/private/moved.txt")
		res := do(t, req)
		if res.StatusCode < 400 {
			t.Errorf("%s with the key: status = %d, want a refusal", method, res.StatusCode)
		}
	}
	if got := server.read(t, "private/report.txt"); got != "secret content" {
		t.Errorf("the file now holds %q", got)
	}
}

func TestShareLinkDoesNotListAFolder(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/report.txt", "secret content")
	info, err := os.Stat(filepath.Join(server.base, "private"))
	if err != nil {
		t.Fatal(err)
	}
	key := shareKey(server.shareSecret(server.settings()), "/private", info)
	for _, path := range []string{"/private?key=" + key, "/private/?key=" + key} {
		res, body := get(t, server, path)
		if res.StatusCode != http.StatusUnauthorized || strings.Contains(body, "report.txt") {
			t.Errorf("%s: status = %d, want 401 and no listing", path, res.StatusCode)
		}
	}
}

func TestShareNeedsAnAccountThatMayReadTheFile(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		outsider := readOnlyUser("jane", "roe")
		outsider.Paths = []string{"^/public/.*"}
		cfg.Users = append(cfg.Users, outsider)
	})
	server.write(t, "public.txt", "anyone")
	server.write(t, "private/report.txt", "secret content")
	server.mkdir(t, "private/sub")

	if res, _ := get(t, server, "/public.txt?go-fs=share"); res.StatusCode != http.StatusForbidden {
		t.Errorf("anonymous share of a public file: status = %d, want 403", res.StatusCode)
	}
	res := basic(t, server, http.MethodGet, "/private/report.txt?go-fs=share", "jane", "roe", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("share by an account that may not read the file: status = %d, want 403", res.StatusCode)
	}
	res = basic(t, server, http.MethodGet, "/private/sub/?go-fs=share", "john", "doe", nil)
	if res.StatusCode == http.StatusOK && strings.Contains(res.Header.Get("Content-Type"), "json") {
		t.Errorf("a folder was shared")
	}
	// the share link of one file does not open another
	link := shareLink(t, server, "/public.txt")
	_, query, _ := strings.Cut(link, "?")
	if res, _ := get(t, server, "/private/report.txt?"+query); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("another file with the key: status = %d, want 401", res.StatusCode)
	}
}

func TestShareLinkSurvivesARestartWithTheConfiguredSecret(t *testing.T) {
	secret, err := config.GenerateShareSecret()
	if err != nil {
		t.Fatal(err)
	}
	folder := t.TempDir()
	tune := func(cfg *httpConfig) {
		cfg.Basefolder = folder
		cfg.ShareLinkSecret = secret
	}
	first := newServer(t, tune)
	first.write(t, "private/report.txt", "secret content")
	link := shareLink(t, first, "/private/report.txt")

	second := newServer(t, tune)
	if res, body := get(t, second, link); res.StatusCode != http.StatusOK || body != "secret content" {
		t.Errorf("after a restart: status = %d, body = %q", res.StatusCode, body)
	}

	// another secret revokes the link
	other := newServer(t, func(cfg *httpConfig) {
		cfg.Basefolder = folder
		cfg.ShareLinkSecret = secret + "changed"
	})
	if res, _ := get(t, other, link); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("with another secret: status = %d, want 401", res.StatusCode)
	}
}

func TestListingOffersShareToAnAccountOnly(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "file.txt", "content")

	_, anonymous := get(t, server, "/")
	if strings.Contains(anonymous, `data-do="share"`) || strings.Contains(anonymous, `id="share-dialog"`) {
		t.Error("an anonymous visitor is offered Share")
	}
	session := login(t, server, "/", "john", "doe")
	page := bodyOf(t, withSession(t, server, http.MethodGet, "/", session))
	if !strings.Contains(page, `data-do="share"`) || !strings.Contains(page, `id="share-dialog"`) {
		t.Error("a signed in account is not offered Share")
	}

	// the link the session is handed works for anyone
	res := withSession(t, server, http.MethodGet, "/file.txt?go-fs=share", session)
	var view struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(view.Path)
	if err != nil || parsed.Query().Get("key") == "" {
		t.Fatalf("share path = %q", view.Path)
	}
}

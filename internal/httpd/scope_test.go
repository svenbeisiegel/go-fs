package httpd

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go-fs/internal/config"
)

// readerPost asks the legacy directory reader at script for the folder dir,
// with Basic credentials when name is not empty.
func readerPost(t *testing.T, server *testServer, script, dir, name, password string) *http.Response {
	t.Helper()
	form := url.Values{"dir": {dir}}
	req, err := http.NewRequest(http.MethodPost, server.url(script), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		req.SetBasicAuth(name, password)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(t, req)
}

// scopedUser may do everything, but only below /public.
func scopedUser(name, password string) config.User {
	user := fullUser(name, password)
	user.Paths = []string{"^/public/.*"}
	return user
}

// The reader is permitted for its own path, and the folder it lists is a path
// of its own: an account scoped to /public must not see /private through it.
func TestDirectoryReaderStaysInTheAccountsScope(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{scopedUser("jane", "roe")}
	})
	server.write(t, "public/sub/open.txt", "open")
	server.write(t, "private/secret.txt", "secret")

	for _, dir := range []string{"../private", "/private", "sub/../../private"} {
		res := readerPost(t, server, "/public/dls_directory_reader.php", dir, "jane", "roe")
		body := bodyOf(t, res)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("dir=%q got %d, want 404", dir, res.StatusCode)
		}
		if strings.Contains(body, "secret.txt") {
			t.Errorf("dir=%q listed a file outside the account's paths", dir)
		}
	}

	res := readerPost(t, server, "/public/dls_directory_reader.php", "sub", "jane", "roe")
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, "open.txt") {
		t.Errorf("an in-scope listing got %d:\n%s", res.StatusCode, body)
	}
}

// With POST public, the reader is open to anyone, and still must not list a
// folder that pathsRequireAuth protects.
func TestAPublicDirectoryReaderKeepsProtectedFoldersClosed(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = nil
		cfg.PathsRequireAuth = []string{"^/private/.*"}
	})
	server.write(t, "private/secret.txt", "secret")
	server.write(t, "open/file.txt", "open")

	res := readerPost(t, server, "/dls_directory_reader.php", "private", "", "")
	if body := bodyOf(t, res); res.StatusCode != http.StatusNotFound || strings.Contains(body, "secret.txt") {
		t.Errorf("an anonymous reader listed a protected folder: %d\n%s", res.StatusCode, body)
	}

	res = readerPost(t, server, "/dls_directory_reader.php", "open", "", "")
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, "file.txt") {
		t.Errorf("a public folder got %d:\n%s", res.StatusCode, body)
	}
}

// HEAD answers what GET does without the body: the size, the date and whether
// the file is there at all. A server that protects GET protects HEAD with it.
func TestHeadIsProtectedAlongWithGet(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = []string{http.MethodGet}
		cfg.PathsRequireAuth = nil
	})
	server.write(t, "file.txt", "content")

	req, err := http.NewRequest(http.MethodHead, server.url("/file.txt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	res := do(t, req)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous HEAD got %d, want 401", res.StatusCode)
	}
	if res.Header.Get("Last-Modified") != "" || res.Header.Get("Content-Length") == "7" {
		t.Error("the refusal leaked the file's metadata")
	}

	if res := basic(t, server, http.MethodHead, "/file.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("HEAD with an account got %d, want 200", res.StatusCode)
	}
}

// caseInsensitive reports whether the filesystem under dir folds case.
func caseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "caseprobe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	_, err := os.Stat(filepath.Join(dir, "CASEPROBE"))
	return err == nil
}

// On a filesystem that folds case, /PRIVATE is /private, so the pattern that
// protects one has to protect the other.
func TestProtectedPathsCoverOtherCases(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = nil
		cfg.PathsRequireAuth = []string{"^/private/.*"}
	})
	if !caseInsensitive(t, server.base) {
		t.Skip("the filesystem is case sensitive, so /PRIVATE is another folder")
	}
	server.write(t, "private/secret.txt", "secret")

	for _, path := range []string{"/PRIVATE/secret.txt", "/Private/secret.txt", "/private/SECRET.TXT"} {
		res, body := get(t, server, path)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s got %d, want 401", path, res.StatusCode)
		}
		if strings.Contains(body, "secret") && res.StatusCode == http.StatusOK {
			t.Errorf("%s served the protected file", path)
		}
	}
}

// An account's paths fold the same way, so an account reaches its own folder
// under whatever case the client spells it in, as the filesystem does.
func TestAccountPathsCoverOtherCases(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = []string{http.MethodGet}
		cfg.Users = []config.User{scopedUser("jane", "roe")}
	})
	if !caseInsensitive(t, server.base) {
		t.Skip("the filesystem is case sensitive")
	}
	server.write(t, "public/open.txt", "open")

	if res := basic(t, server, http.MethodGet, "/PUBLIC/open.txt", "jane", "roe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("the account's own folder in another case got %d, want 200", res.StatusCode)
	}
}

// On Windows a backslash separates folders, so /private\secret.txt is a file
// in /private, reached by a path the pattern ^/private/ does not match.
func TestWindowsPathVariantsAreRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("backslashes, colons and trailing dots are ordinary name characters here")
	}
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = nil
		cfg.PathsRequireAuth = []string{"^/private/.*"}
	})
	server.write(t, "private/secret.txt", "secret")

	for _, path := range []string{
		"/private%5Csecret.txt",
		"/private./secret.txt",
		"/private%20/secret.txt",
		"/private/secret.txt::$DATA",
	} {
		res, _ := get(t, server, path)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s got %d, want 404", path, res.StatusCode)
		}
	}
}

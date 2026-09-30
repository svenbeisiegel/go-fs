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

// dlsPost asks the directory reader at script for the folder dir the way the
// DLS scanner does: with its fixed credentials in the form, and with Basic
// credentials as well when name is not empty.
func dlsPost(t *testing.T, server *testServer, script, dir, user, password, name, secret string) *http.Response {
	t.Helper()
	form := url.Values{"PHP_DLS_USER": {user}, "PHP_DLS_PW": {password}, "dir": {dir}}
	req, err := http.NewRequest(http.MethodPost, server.url(script), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		req.SetBasicAuth(name, secret)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	return do(t, req)
}

// The scanner sends no Authorization header, only the pair the PHP and ASP
// scripts checked, and POST is protected by default: the pair has to get it
// through to a folder anyone may browse.
func TestDirectoryReaderAcceptsTheDLSCredentials(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "phonesoftware/firmware.bin", "firmware")
	server.write(t, "phonesoftware/sub/other.bin", "other")

	for _, script := range []string{"/phonesoftware/dls_directory_reader.php", "/phonesoftware/dls_directory_reader.asp"} {
		res := dlsPost(t, server, script, "./", dlsUser, dlsPassword, "", "")
		body := bodyOf(t, res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s got %d:\n%s", script, res.StatusCode, body)
		}
		for _, want := range []string{
			`<a href="sub/">sub/</a> - filetype: dir`,
			`<a href="firmware.bin">firmware.bin</a> - filetype: file filesize: 8<br/>`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing %q\ngot: %s", script, want, body)
			}
		}
	}

	res := dlsPost(t, server, "/phonesoftware/dls_directory_reader.php", "./sub/", dlsUser, dlsPassword, "", "")
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, "other.bin") {
		t.Errorf("a subfolder got %d:\n%s", res.StatusCode, body)
	}
}

// Anything but the exact pair is a POST without credentials.
func TestDirectoryReaderRefusesWrongDLSCredentials(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "phonesoftware/firmware.bin", "firmware")

	for _, pair := range [][2]string{
		{dlsUser, "wrong"},
		{dlsUser, ""},
		{"other", dlsPassword},
		{"", ""},
	} {
		res := dlsPost(t, server, "/phonesoftware/dls_directory_reader.php", "./", pair[0], pair[1], "", "")
		if body := bodyOf(t, res); res.StatusCode != http.StatusUnauthorized || strings.Contains(body, "firmware.bin") {
			t.Errorf("user=%q password=%q got %d, want 401", pair[0], pair[1], res.StatusCode)
		}
	}
}

// The pair is public, so it opens no protected folder: that still takes an
// account, which the scanner sends as Basic credentials alongside it.
func TestDLSCredentialsKeepProtectedFoldersClosed(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")

	res := dlsPost(t, server, "/private/dls_directory_reader.php", "./", dlsUser, dlsPassword, "", "")
	if body := bodyOf(t, res); res.StatusCode != http.StatusUnauthorized || strings.Contains(body, "secret.txt") {
		t.Errorf("a reader in a protected folder got %d, want 401:\n%s", res.StatusCode, body)
	}

	res = dlsPost(t, server, "/dls_directory_reader.php", "private", dlsUser, dlsPassword, "", "")
	if body := bodyOf(t, res); res.StatusCode != http.StatusNotFound || strings.Contains(body, "secret.txt") {
		t.Errorf("a protected folder through a public reader got %d, want 404:\n%s", res.StatusCode, body)
	}

	res = dlsPost(t, server, "/private/dls_directory_reader.php", "./", dlsUser, dlsPassword, "john", "doe")
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, "secret.txt") {
		t.Errorf("the pair with an account got %d, want 200:\n%s", res.StatusCode, body)
	}
}

// A server that protects GET protects every listing, the reader's included.
func TestDLSCredentialsDoNotOpenAProtectedGet(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = []string{http.MethodGet, http.MethodPost}
	})
	server.write(t, "phonesoftware/firmware.bin", "firmware")

	res := dlsPost(t, server, "/phonesoftware/dls_directory_reader.php", "./", dlsUser, dlsPassword, "", "")
	if body := bodyOf(t, res); res.StatusCode != http.StatusUnauthorized || strings.Contains(body, "firmware.bin") {
		t.Errorf("got %d, want 401:\n%s", res.StatusCode, body)
	}

	res = dlsPost(t, server, "/phonesoftware/dls_directory_reader.php", "./", dlsUser, dlsPassword, "john", "doe")
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, "firmware.bin") {
		t.Errorf("with an account got %d, want 200:\n%s", res.StatusCode, body)
	}
}

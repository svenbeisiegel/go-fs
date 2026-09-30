package httpd

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

func TestDirectoryListing(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = nil
		cfg.PathsRequireAuth = nil
	})
	server.write(t, "sub/old.txt", "old")
	server.write(t, "sub/new.iso", "newer")
	server.write(t, "sub/alpha.txt", "first by name, last by date")
	server.write(t, "sub/deeper/kept.txt", "x")
	older := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(server.base, "sub", "old.txt"), older, older); err != nil {
		t.Fatal(err)
	}
	oldest := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(server.base, "sub", "alpha.txt"), oldest, oldest); err != nil {
		t.Fatal(err)
	}

	res, body := get(t, server, "/sub/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); got != "text/html; charset=UTF-8" {
		t.Errorf("Content-Type = %q", got)
	}

	for _, want := range []string{
		`<a href="/">..</a>`,            // the way back up
		`<a href="deeper/">deeper/</a>`, // folders carry a trailing slash
		`<a href="new.iso">new.iso</a>`, //
		`<a href="old.txt">old.txt</a>`, //
		"Folder",                        // the folder's Type cell
		"ISO",                           // from the extension table
		"Document",                      //
		`<table id="listing"`,           // the listing this server renders
		`data-folder="/sub/"`,           // what the script builds its requests from
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
}

// Without a sort the listing opens the way a file browser does: the folders
// above the files, both by name — not the newest first, which is the order the
// legacy reader endpoint still answers with.
func TestDefaultOrderIsFoldersThenNames(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "sub/old.txt", "old")
	server.write(t, "sub/new.iso", "newer")
	server.write(t, "sub/alpha.txt", "oldest")
	server.write(t, "sub/deeper/kept.txt", "x")
	touch(t, server, "sub/alpha.txt", time.Now().Add(-2*time.Hour))
	touch(t, server, "sub/old.txt", time.Now().Add(-time.Hour))

	_, body := get(t, server, "/sub/")
	assertOrder(t, body, "deeper/", "alpha.txt", "new.iso", "old.txt")
}

// Asking for a column drops the grouping: one flat list of everything.
func TestSortingMixesFoldersWithFiles(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "sub/big.bin", strings.Repeat("x", 4000))
	server.write(t, "sub/small.bin", "x")
	server.write(t, "sub/mid.bin", strings.Repeat("x", 500))
	server.write(t, "sub/zzz/kept.txt", "x")
	touch(t, server, "sub/big.bin", time.Now().Add(-3*time.Hour))
	touch(t, server, "sub/mid.bin", time.Now().Add(-2*time.Hour))
	touch(t, server, "sub/small.bin", time.Now().Add(-time.Hour))

	cases := []struct {
		query string
		order []string
	}{
		// zzz/ is a folder and still sorts among the files
		{"?sort=name&dir=asc", []string{"big.bin", "mid.bin", "small.bin", "zzz/"}},
		{"?sort=name&dir=desc", []string{"zzz/", "small.bin", "mid.bin", "big.bin"}},
		// a folder has no size worth showing, so it sorts as nothing
		{"?sort=size&dir=asc", []string{"zzz/", "small.bin", "mid.bin", "big.bin"}},
		{"?sort=size&dir=desc", []string{"big.bin", "mid.bin", "small.bin", "zzz/"}},
		{"?sort=date&dir=asc", []string{"big.bin", "mid.bin", "small.bin"}},
		{"?sort=date&dir=desc", []string{"small.bin", "mid.bin", "big.bin"}},
	}
	for _, item := range cases {
		_, body := get(t, server, "/sub/"+item.query)
		t.Run(item.query, func(t *testing.T) {
			assertOrder(t, body, item.order...)
		})
	}
}

// The query string is part of a link a user can edit, so a column this server
// does not have falls back to the grouped default rather than being an error.
func TestUnknownSortFallsBackToTheDefault(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "sub/b.txt", "b")
	server.write(t, "sub/a.txt", "a")
	server.write(t, "sub/folder/kept.txt", "x")

	for _, query := range []string{"?sort=nonsense", "?sort=", "?dir=desc"} {
		_, body := get(t, server, "/sub/"+query)
		t.Run(query, func(t *testing.T) {
			assertOrder(t, body, "folder/", "a.txt", "b.txt")
		})
	}
}

// A direction that is not descending is ascending. The column still stands:
// only the direction was unreadable, and the column is what was asked for.
func TestUnknownDirectionIsAscending(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "sub/b.txt", "b")
	server.write(t, "sub/a.txt", "a")
	server.write(t, "sub/folder/kept.txt", "x")

	_, body := get(t, server, "/sub/?sort=name&dir=sideways")
	assertOrder(t, body, "a.txt", "b.txt", "folder/")
}

// The active column says so, so that a reader is told what it is looking at
// and the script has somewhere to carry on from.
func TestSortedListingMarksTheColumn(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "sub/a.txt", "a")

	_, body := get(t, server, "/sub/?sort=size&dir=desc")
	for _, want := range []string{`aria-sort="descending"`, `data-sort="size"`, `data-dir="desc"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
	if strings.Contains(body, `aria-sort="ascending"`) {
		t.Error("only the sorted column should be marked")
	}
}

// Every column turns itself off on the third click rather than only being
// swappable for another one, and the header links say so without the script.
func TestEveryColumnCyclesBackToTheDefault(t *testing.T) {
	for _, key := range []string{sortName, sortDate, sortSize, sortType} {
		t.Run(key, func(t *testing.T) {
			want := []sortOrder{{key: key}, {key: key, desc: true}, {}}
			current := sortOrder{}
			for step, expected := range want {
				current = nextOrder(current, key)
				if current != expected {
					t.Fatalf("click %d = %+v, want %+v", step+1, current, expected)
				}
			}
			// and round again, so the cycle repeats rather than sticking
			if got := nextOrder(current, key); got != (sortOrder{key: key}) {
				t.Errorf("click 4 = %+v, want ascending again", got)
			}
		})
	}
}

// The link a header carries is the next step of that cycle, so a browser with
// no script walks the same three states.
func TestHeaderLinksCarryTheCycle(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "sub/a.txt", "a")

	cases := map[string]string{
		"/sub/":                    `href="?sort=size&amp;dir=asc"`,
		"/sub/?sort=size&dir=asc":  `href="?sort=size&amp;dir=desc"`,
		"/sub/?sort=size&dir=desc": `href="?"`,
	}
	for path, want := range cases {
		_, body := get(t, server, path)
		t.Run(path, func(t *testing.T) {
			if !strings.Contains(body, want) {
				t.Errorf("the size header does not link to %q", want)
			}
		})
	}
}

// The script remembers the order for the whole server, which is what carries it
// between folders: the links from one folder to another are relative and have
// no query string to carry.
func TestScriptRemembersTheOrder(t *testing.T) {
	for _, want := range []string{"localStorage", "go-fs.listing.order"} {
		if !strings.Contains(string(listingScript), want) {
			t.Errorf("listing.js does not use %q", want)
		}
	}
}

// The style and the script are carried by the page, so that no URL this server
// answers is anything but a path in the served folder.
func TestListingCarriesItsOwnAssets(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "sub/a.txt", "a")

	res, body := get(t, server, "/sub/")
	for _, want := range []string{"<style nonce=", "<script nonce=", "--ground:", "XMLHttpRequest"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
	policy := res.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "'nonce-"} {
		if !strings.Contains(policy, want) {
			t.Errorf("Content-Security-Policy = %q, missing %q", policy, want)
		}
	}
	// the nonce in the header has to be the one the page carries
	nonce := strings.SplitN(strings.SplitN(policy, "'nonce-", 2)[1], "'", 2)[0]
	if !strings.Contains(body, `<style nonce="`+nonce+`"`) {
		t.Error("the page and the policy name different nonces")
	}
}

// The script is inlined, so a closing tag anywhere in it would end the block
// early and spill the rest of it into the page.
func TestScriptCanBeInlined(t *testing.T) {
	if strings.Contains(string(listingScript), "</script") {
		t.Error("listing.js cannot contain a closing script tag")
	}
}

// The root has no way back up.
func TestListingRootHasNoParentLink(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "hello.txt", "hello")

	_, body := get(t, server, "/")
	if strings.Contains(body, `>..</a>`) {
		t.Error("the root should not link to a parent")
	}
}

// A name with characters that mean something in HTML or in a URL is escaped,
// in the link, in the text and in the attributes the script reads it back from.
func TestListingEscapesNames(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "a b&c<d>.txt", "x")

	_, body := get(t, server, "/")
	if strings.Contains(body, "<d>.txt") {
		t.Error("the name was not escaped into the page")
	}
	for _, want := range []string{
		`href="a%20b&amp;c%3Cd%3E.txt"`,      // escaped for a URL, then for the attribute
		`data-name="a b&amp;c&lt;d&gt;.txt"`, // what the script renames and deletes by
		`a b&amp;c&lt;d&gt;.txt</a>`,         // the text of the link
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q\ngot: %s", want, body)
		}
	}
}

// The legacy reader is what a client that is not a browser parses, so its
// bytes are the one answer this server must keep exactly as it was: the whole
// page is pinned rather than looked through for substrings.
func TestReaderPageBytesAreUnchanged(t *testing.T) {
	folder := t.TempDir()
	for _, name := range []string{"older.txt", "newer.iso"} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte("xyz"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	older := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(folder, "older.txt"), older, older); err != nil {
		t.Fatal(err)
	}

	entries, err := readDirectory(folder)
	if err != nil {
		t.Fatal(err)
	}
	want := "listing directory: listed\n" +
		`<a href="newer.iso">newer.iso</a> - filetype: file filesize: 3<br/>` + "\n" +
		`<a href="older.txt">older.txt</a> - filetype: file filesize: 3<br/>` + "\n"
	if got := string(readerPage("listed", entries)); got != want {
		t.Errorf("the reader answer changed\n got: %q\nwant: %q", got, want)
	}
}

// readDirectory still reports what the reader endpoint expects — the folders
// first and then the files newest first — however the page chooses to sort it.
func TestReadDirectoryKeepsTheLegacyOrder(t *testing.T) {
	folder := t.TempDir()
	if err := os.Mkdir(filepath.Join(folder, "zzz"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aaa.txt", "bbb.txt"} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	older := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(folder, "aaa.txt"), older, older); err != nil {
		t.Fatal(err)
	}

	entries, err := readDirectory(folder)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, item := range entries {
		names = append(names, item.Name)
	}
	want := []string{"zzz/", "bbb.txt", "aaa.txt"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", names, want)
	}
}

func TestDirectoryReaderEndpoint(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "area/listed/one.txt", "one")
	server.write(t, "area/listed/two.iso", "two")

	form := url.Values{"dir": {"listed"}}
	req, _ := http.NewRequest(http.MethodPost,
		server.url("/area/dls_directory_reader.php"), strings.NewReader(form.Encode()))
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res := do(t, req)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	page := string(body)
	for _, want := range []string{
		"listing directory: listed",
		`<a href="one.txt">one.txt</a> - filetype: file filesize: 3<br/>`,
		`<a href="two.iso">two.iso</a> - filetype: file filesize: 3<br/>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the answer is missing %q\ngot: %s", want, page)
		}
	}
}

func TestDirectoryReaderRefusesEscapes(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "area/listed/one.txt", "one")

	for _, dir := range []string{"../../../etc", "/etc", "missing"} {
		form := url.Values{"dir": {dir}}
		req, _ := http.NewRequest(http.MethodPost,
			server.url("/area/dls_directory_reader.php"), strings.NewReader(form.Encode()))
		req.SetBasicAuth("john", "doe")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if res := do(t, req); res.StatusCode != http.StatusNotFound {
			t.Errorf("dir=%q got %d, want 404", dir, res.StatusCode)
		}
	}
}

// A POST anywhere else is not a thing this server does.
func TestOtherPostsAreNotFound(t *testing.T) {
	server := newServer(t, nil)

	req, _ := http.NewRequest(http.MethodPost, server.url("/private/anything"), nil)
	req.SetBasicAuth("john", "doe")
	if res := do(t, req); res.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.StatusCode)
	}
}

func TestUnsupportedMethod(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.MethodsRequireAuth = nil })

	req, _ := http.NewRequest(http.MethodPatch, server.url("/"), nil)
	res := do(t, req)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", res.StatusCode)
	}
	for _, want := range []string{"GET", "MKCOL", "MOVE"} {
		if got := res.Header.Get("Allow"); !strings.Contains(got, want) {
			t.Errorf("Allow = %q, missing %q", got, want)
		}
	}
}

func TestReadableSize(t *testing.T) {
	cases := map[int64]string{
		512:            "0.5 KB",
		2048:           "2 KB",
		5 * 1000000:    "4.8 MB",
		3 * 1000000000: "2.8 GB",
	}
	for size, want := range cases {
		if got := readableSize(size); got != want {
			t.Errorf("readableSize(%d) = %q, want %q", size, got, want)
		}
	}
}

func TestTypeOf(t *testing.T) {
	cases := map[string]contentType{
		"a.iso":     {"application/x-iso9660-image", "ISO"},
		"a.RPM":     {"application/x-rpm", "RPM"},
		"a.tar.gz":  {"application/gzip", "Archive"},
		"a.unknown": {"application/octet-stream", "Generic"},
		"noext":     {"application/octet-stream", "Generic"},
	}
	for name, want := range cases {
		if got := typeOf(name); got != want {
			t.Errorf("typeOf(%q) = %+v, want %+v", name, got, want)
		}
	}
}

// The header says who is looking at the page, and offers the way in or out.
func TestTheListingShowsWhoIsSignedIn(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = nil
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	server.write(t, "notes.txt", "hello")

	// nobody is signed in: the way in is offered
	_, body := get(t, server, "/")
	if !strings.Contains(body, "go-fs=login") {
		t.Error("the page offers no way to log in")
	}
	if strings.Contains(body, "go-fs=logout") {
		t.Error("the page offers a logout to somebody who is not signed in")
	}

	session := login(t, server, "/", "john", "doe")
	signedIn := bodyOf(t, withSession(t, server, http.MethodGet, "/", session))
	if !strings.Contains(signedIn, "Log out john<") {
		t.Error("the page does not say who is signed in")
	}
	if !strings.Contains(signedIn, "go-fs=logout") {
		t.Error("the page offers no way to log out")
	}

	// somebody who authenticated with a header has no session to log out of
	withHeader := bodyOf(t, basic(t, server, http.MethodGet, "/", "john", "doe", nil))
	if strings.Contains(withHeader, "go-fs=logout") {
		t.Error("a header request was offered a logout that would clear nothing")
	}
}

// The listing depends on the cookie now, so a shared cache must not hand one
// browser's copy to another.
func TestTheListingVariesOnTheCookie(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = nil
		cfg.Users = []config.User{fullUser("john", "doe")}
	})
	res, _ := get(t, server, "/")
	if !strings.Contains(res.Header.Get("Vary"), "Cookie") {
		t.Errorf("vary = %q, want it to name Cookie", res.Header.Get("Vary"))
	}
}

// Logging in is the most core control on the page, so neither it nor the
// logout may be one of the things that only work once the script has run.
func TestTheLoginControlsWorkWithoutJavaScript(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = nil
		cfg.Users = []config.User{fullUser("john", "doe")}
	})

	for _, item := range []struct {
		name string
		body string
	}{
		{"the login link", bodyOf(t, browserGet(t, server, "/"))},
		{"the logout form", bodyOf(t, withSession(t, server, http.MethodGet, "/",
			login(t, server, "/", "john", "doe")))},
	} {
		marker := "go-fs=login"
		if strings.Contains(item.name, "logout") {
			marker = "go-fs=logout"
		}
		index := strings.Index(item.body, marker)
		if index < 0 {
			t.Errorf("%s is not on the page", item.name)
			continue
		}
		// the class would sit on the element the marker is in, which starts at
		// the last tag opened before it
		tag := item.body[strings.LastIndex(item.body[:index], "<"):index]
		if strings.Contains(tag, "needs-js") {
			t.Errorf("%s is hidden until the script runs: %s", item.name, tag)
		}
	}
}

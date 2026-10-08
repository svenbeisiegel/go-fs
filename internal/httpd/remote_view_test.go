package httpd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/remote/remotetest"
)

// remoteServer serves a stored server named Backup for the host, with a
// staging folder for chunked uploads, and returns a session of john.
func remoteServer(t *testing.T, host *remotetest.SFTPHost, tune func(*httpConfig)) (*testServer, *http.Cookie) {
	t.Helper()
	staging := t.TempDir()
	server := newServer(t, func(cfg *httpConfig) {
		cfg.UploadStagingFolder = staging
		cfg.Servers = []config.Server{storedServer(host, "Backup")}
		if tune != nil {
			tune(cfg)
		}
	})
	return server, login(t, server, "/", "john", "doe")
}

// remoteAt is the link of a path of the host, under Backup.
func remoteAt(host *remotetest.SFTPHost, rel string) string {
	return remoteURL("Backup", remotetest.Path(filepath.Join(host.Dir, filepath.FromSlash(rel))))
}

// remoteDo sends a request for a stored server with a session, and the
// headers given.
func remoteDo(t *testing.T, server *testServer, method, link string, session *http.Cookie, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, server.url(link), body)
	if err != nil {
		t.Fatal(err)
	}
	if session != nil {
		req.AddCookie(session)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return do(t, req)
}

// remoteFile reads a file of the host, "" for one that is not there.
func remoteFile(host *remotetest.SFTPHost, rel string) string {
	content, err := os.ReadFile(filepath.Join(host.Dir, filepath.FromSlash(rel)))
	if err != nil {
		return ""
	}
	return string(content)
}

var octetStream = map[string]string{"Content-Type": "application/octet-stream"}

func TestRemoteServersAreInTheMenuOfASession(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		publicServer(cfg)
		cfg.Servers = append(cfg.Servers, storedServer(host, "Archive"))
	})

	body := listingOf(t, server, session)
	backup := strings.Index(body, `>Backup</a>`)
	archive := strings.Index(body, `>Archive</a>`)
	logout := strings.Index(body, `Log out john`)
	if backup < 0 || archive < backup || logout < archive {
		t.Errorf("the menu does not list Backup, Archive and Log out in that order: %d %d %d", backup, archive, logout)
	}
	if !strings.Contains(body, `href="/?go-fs=remote&amp;server=Backup&amp;path="`) {
		t.Error("the menu does not link the stored server")
	}

	// nobody signed in, and someone who sent a header, have no session
	if _, public := get(t, server, "/"); strings.Contains(public, "go-fs=remote") {
		t.Error("the public listing offers the stored servers")
	}
	if header := bodyOf(t, basic(t, server, http.MethodGet, "/", "john", "doe", nil)); strings.Contains(header, "go-fs=remote") {
		t.Error("a listing for a header offers the stored servers")
	}
}

func TestRemotePageListsAFolderOfTheServer(t *testing.T) {
	const password = "hunter2-of-the-backup"
	host := remotetest.NewSFTPHost(t, "alice", password)
	host.Write(t, "zeta.txt", "z")
	host.Write(t, "Beta/inside.txt", "in")
	server, session := remoteServer(t, host, func(cfg *httpConfig) { cfg.Servers[0].Password = password })

	res := remoteDo(t, server, http.MethodGet, remoteURL("backup", ""), session, nil, nil)
	body := bodyOf(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the page answered %d: %s", res.StatusCode, body)
	}
	assertOrder(t, body, "Beta/", "zeta.txt")
	home := remotetest.Path(host.Dir) + "/"
	escaped := url.QueryEscape(home)
	for _, want := range []string{
		// the folder, as the script appends a name to it
		`data-remote="/?go-fs=remote&amp;server=Backup&amp;path=` + escaped + `"`,
		// a sort header keeps the server and the folder
		`href="?go-fs=remote&amp;server=Backup&amp;path=` + escaped + `&amp;sort=name&amp;dir=asc"`,
		// a folder is a page of the server, and a file a download from it
		`href="/?go-fs=remote&amp;server=Backup&amp;path=` + url.QueryEscape(home+"Beta") + `"`,
		// the menu is named after the server and leads back to the files
		`<a href="/"><svg class="ic"><use href="#i-folder"/></svg>Files</a>`,
		`#i-server"/></svg>Backup<svg`,
		`data-do="rename"`, `data-do="delete"`, `id="upload"`, `id="new-folder"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
	for _, unwanted := range []string{`data-do="share"`, `data-do="send"`, `id="fetch"`, `data-do="import"`,
		`>Backup</a>`, password, host.Fingerprint} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the page has %s", unwanted)
		}
	}

	// a folder below, and its way back up
	res = remoteDo(t, server, http.MethodGet, remoteAt(host, "Beta"), session, nil, nil)
	body = bodyOf(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `data-name="inside.txt"`) {
		t.Fatalf("the folder below answered %d: %s", res.StatusCode, body)
	}
	if !strings.Contains(body, `<a href="/?go-fs=remote&amp;server=Backup&amp;path=`+url.QueryEscape(strings.TrimSuffix(home, "/"))+`">..</a>`) {
		t.Error("the folder below does not lead back up")
	}
}

func TestRemoteIsOnlyForASessionThatMayRead(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		publicServer(cfg)
		cfg.Users = append(cfg.Users, config.User{Username: "blind", Password: "pw", HTTP: true, Paths: []string{"^/.*"}})
	})

	if res := remoteDo(t, server, http.MethodGet, remoteURL("Backup", ""), nil, nil, nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("without a session the server answered %d", res.StatusCode)
	}
	res := browserGet(t, server, remoteURL("Backup", ""))
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "go-fs=login") ||
		!strings.Contains(res.Header.Get("Location"), "go-fs-then=remote") {
		t.Errorf("a browser without a session was answered %d, to %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res := basic(t, server, http.MethodGet, remoteURL("Backup", ""), "john", "doe", nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("a header answered %d", res.StatusCode)
	}
	blind := login(t, server, "/", "blind", "pw")
	if res := remoteDo(t, server, http.MethodGet, remoteURL("Backup", ""), blind, nil, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("an account that may not read answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodGet, remoteURL("Nowhere", ""), session, nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("a server that is not stored answered %d", res.StatusCode)
	}
	if n := host.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered for requests that were refused", n)
	}
}

func TestRemoteLoginReturnsToTheServer(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	server, _ := remoteServer(t, host, nil)

	form := url.Values{"username": {"john"}, "password": {"doe"}}
	req, err := http.NewRequest(http.MethodPost, server.url("/?go-fs=login&go-fs-then=remote&server=Backup&path=%2F"),
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := do(t, req)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("the login answered %d", res.StatusCode)
	}
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if query.Get(sessionParam) != actionRemote || query.Get(remoteServerParam) != "Backup" {
		t.Errorf("the login returns to %s", location)
	}
}

func TestRemoteDownloadsAFileAndAFolder(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "docs/report.txt", "0123456789")
	host.Write(t, "docs/deeper/notes.md", "notes")
	if err := os.MkdirAll(filepath.Join(host.Dir, "docs", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	server, session := remoteServer(t, host, nil)

	res := remoteDo(t, server, http.MethodGet, remoteAt(host, "docs/report.txt"), session, nil, nil)
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || body != "0123456789" {
		t.Fatalf("the download answered %d: %q", res.StatusCode, body)
	}
	if !strings.Contains(res.Header.Get("Content-Disposition"), "report.txt") {
		t.Errorf("the download is called %q", res.Header.Get("Content-Disposition"))
	}
	res = remoteDo(t, server, http.MethodGet, remoteAt(host, "docs/report.txt"), session, nil,
		map[string]string{"Range": "bytes=2-4"})
	if body := bodyOf(t, res); res.StatusCode != http.StatusPartialContent || body != "234" {
		t.Errorf("a range answered %d: %q", res.StatusCode, body)
	}
	if res := remoteDo(t, server, http.MethodGet, remoteAt(host, "docs/gone.txt"), session, nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("a file that is not there answered %d", res.StatusCode)
	}

	res = remoteDo(t, server, http.MethodGet, remoteAt(host, "docs")+"&archive=1", session, nil, nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Content-Disposition"), "docs.tar.xz") {
		t.Fatalf("the archive answered %d, as %q", res.StatusCode, res.Header.Get("Content-Disposition"))
	}
	entries := unpack(t, readAll(t, res))
	want := map[string]string{
		"docs/": folderMark, "docs/report.txt": "0123456789",
		"docs/deeper/": folderMark, "docs/deeper/notes.md": "notes", "docs/empty/": folderMark,
	}
	if len(entries) != len(want) {
		t.Errorf("the archive holds %v", entries)
	}
	for name, content := range want {
		if entries[name] != content {
			t.Errorf("%s in the archive is %q, want %q", name, entries[name], content)
		}
	}
}

func TestRemoteUploadsAFile(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "in/folder/keep", "")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.MaxChunkSize = 4
		cfg.Users = append(cfg.Users, config.User{Username: "adder", Password: "pw", HTTP: true,
			Paths: []string{"^/.*"}, AllowUserFileRetrieve: new(true), AllowUserFileCreate: new(true)})
	})

	res := remoteDo(t, server, http.MethodPut, remoteAt(host, "in/new.txt"), session, strings.NewReader("hello"), octetStream)
	if res.StatusCode != http.StatusOK || remoteFile(host, "in/new.txt") != "hello" {
		t.Fatalf("the upload answered %d: %s, and wrote %q", res.StatusCode, bodyOf(t, res), remoteFile(host, "in/new.txt"))
	}
	res = remoteDo(t, server, http.MethodPut, remoteAt(host, "in/new.txt"), session, strings.NewReader("again"), octetStream)
	if res.StatusCode != http.StatusOK || remoteFile(host, "in/new.txt") != "again" {
		t.Errorf("a replacing upload answered %d, and left %q", res.StatusCode, remoteFile(host, "in/new.txt"))
	}
	if res := remoteDo(t, server, http.MethodPut, remoteAt(host, "in/folder"), session, strings.NewReader("x"), octetStream); res.StatusCode != http.StatusNotFound {
		t.Errorf("an upload over a folder answered %d", res.StatusCode)
	}
	if left := host.Leftovers(t, "in"); len(left) != 0 {
		t.Errorf("the uploads left %v", left)
	}

	// in chunks, staged here until the last one
	link := remoteAt(host, "in/chunked.bin")
	for _, chunk := range []struct {
		start, end int64
		body       string
		status     int
	}{{0, 3, "abcd", http.StatusOK}, {4, 7, "efgh", http.StatusOK}, {8, 9, "ij", http.StatusCreated}} {
		res := remoteDo(t, server, http.MethodPut, link, session, strings.NewReader(chunk.body), map[string]string{
			"Content-Type":  "application/octet-stream",
			"Content-Range": fmt.Sprintf("bytes %d-%d/10", chunk.start, chunk.end),
		})
		if res.StatusCode != chunk.status {
			t.Fatalf("the chunk at %d answered %d: %s", chunk.start, res.StatusCode, bodyOf(t, res))
		}
	}
	if got := remoteFile(host, "in/chunked.bin"); got != "abcdefghij" {
		t.Errorf("the chunked upload wrote %q", got)
	}

	// an account that may create files and not replace them
	adder := login(t, server, "/", "adder", "pw")
	if res := remoteDo(t, server, http.MethodPut, remoteAt(host, "in/new.txt"), adder, strings.NewReader("x"), octetStream); res.StatusCode != http.StatusForbidden {
		t.Errorf("replacing without the right answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodPut, remoteAt(host, "in/other.txt"), adder, strings.NewReader("x"), octetStream); res.StatusCode != http.StatusOK {
		t.Errorf("creating with the right answered %d", res.StatusCode)
	}
}

func TestRemoteCreatesRenamesAndDeletes(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	host.Write(t, "b.txt", "b")
	host.Write(t, "full/inside.txt", "x")
	server, session := remoteServer(t, host, nil)

	if res := remoteDo(t, server, methodMkcol, remoteAt(host, "made")+"/", session, nil, nil); res.StatusCode != http.StatusCreated {
		t.Fatalf("MKCOL answered %d: %s", res.StatusCode, bodyOf(t, res))
	}
	if info, err := os.Stat(filepath.Join(host.Dir, "made")); err != nil || !info.IsDir() {
		t.Fatal("the folder was not created")
	}
	if res := remoteDo(t, server, methodMkcol, remoteAt(host, "made"), session, nil, nil); res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("MKCOL of a name that is taken answered %d", res.StatusCode)
	}

	move := func(from, to string) int {
		return remoteDo(t, server, methodMove, remoteAt(host, from), session, nil,
			map[string]string{"Destination": server.url(remoteAt(host, to))}).StatusCode
	}
	if status := move("a.txt", "b.txt"); status != http.StatusPreconditionFailed {
		t.Errorf("a rename onto a name that is taken answered %d", status)
	}
	if status := move("a.txt", "c.txt"); status != http.StatusCreated || remoteFile(host, "c.txt") != "a" || remoteFile(host, "a.txt") != "" {
		t.Errorf("the rename answered %d", status)
	}
	res := remoteDo(t, server, methodMove, remoteAt(host, "b.txt"), session, nil,
		map[string]string{"Destination": remoteURL("Elsewhere", "/x")})
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("a rename onto another server answered %d", res.StatusCode)
	}

	if res := remoteDo(t, server, http.MethodDelete, remoteAt(host, "c.txt"), session, nil, nil); res.StatusCode != http.StatusNoContent || remoteFile(host, "c.txt") != "" {
		t.Errorf("deleting a file answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodDelete, remoteAt(host, "full"), session, nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("deleting a folder with something in it answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodDelete, remoteAt(host, "made"), session, nil, nil); res.StatusCode != http.StatusNoContent {
		t.Errorf("deleting an empty folder answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodDelete, remoteAt(host, "gone.txt"), session, nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("deleting what is not there answered %d", res.StatusCode)
	}
}

func TestRemoteWritesFollowThePermissionsOfTheAccount(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	server, _ := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, readOnlyUser("reader", "pw"))
	})
	reader := login(t, server, "/", "reader", "pw")

	body := bodyOf(t, remoteDo(t, server, http.MethodGet, remoteURL("Backup", ""), reader, nil, nil))
	for _, unwanted := range []string{`data-do="rename"`, `data-do="delete"`, `id="upload"`, `id="new-folder"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the page of a reader has %s", unwanted)
		}
	}
	for _, req := range []struct {
		method, rel string
		headers     map[string]string
	}{
		{http.MethodPut, "new.txt", octetStream},
		{methodMkcol, "made", nil},
		{http.MethodDelete, "a.txt", nil},
		{methodMove, "a.txt", map[string]string{"Destination": remoteAt(host, "b.txt")}},
	} {
		if res := remoteDo(t, server, req.method, remoteAt(host, req.rel), reader, strings.NewReader("x"), req.headers); res.StatusCode != http.StatusForbidden {
			t.Errorf("%s by a reader answered %d", req.method, res.StatusCode)
		}
	}
	if remoteFile(host, "a.txt") != "a" || remoteFile(host, "new.txt") != "" {
		t.Error("a reader changed the server")
	}
}

func TestRemoteRefusesAnotherSite(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	server, session := remoteServer(t, host, nil)

	res := remoteDo(t, server, http.MethodDelete, remoteAt(host, "a.txt"), session, nil,
		map[string]string{"Sec-Fetch-Site": "cross-site"})
	if res.StatusCode != http.StatusForbidden || remoteFile(host, "a.txt") != "a" {
		t.Errorf("a delete from another site answered %d", res.StatusCode)
	}
}

func TestRemotePageSaysWhyTheServerCannotBeReached(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Servers[0].HostKeyFingerprint = "SHA256:somebodyElse"
	})

	req, err := http.NewRequest(http.MethodGet, server.url(remoteURL("Backup", "")), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res := do(t, req)
	body := bodyOf(t, res)
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("a server with another key answered %d", res.StatusCode)
	}
	if !strings.Contains(body, `<div id="banner" class="banner"><span class="text">the key of`) ||
		!strings.Contains(body, "not the one saved for the server Backup") {
		t.Errorf("the page does not say why: %s", body)
	}
	if strings.Contains(body, `<p class="empty">`) {
		t.Error("the page says the folder is empty")
	}
	if n := host.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered to a host with another key", n)
	}
}

package httpd

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/remote/remotetest"
)

// remoteFetchOf is the link that fetches what a link of the page of a server
// downloads.
func remoteFetchOf(link string) string {
	return strings.Replace(link, "="+actionRemote+"&", "="+actionRemoteFetch+"&", 1)
}

// localBrowse lists a folder of the served tree as the dialog does.
func localBrowse(t *testing.T, server *testServer, folder string, session *http.Cookie) (int, localFolderJSON) {
	t.Helper()
	res, data := transferRequest(t, server, http.MethodGet, "/?go-fs=local-browse&path="+url.QueryEscape(folder), session, nil)
	var view localFolderJSON
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(data, &view); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, view
}

// remoteFetched starts a fetch of a link of a server into a folder and waits
// for it to end.
func remoteFetched(t *testing.T, server *testServer, link, folder string, session *http.Cookie) registryJobJSON {
	t.Helper()
	res, data := transferRequest(t, server, http.MethodPost, remoteFetchOf(link), session, remoteFetchBody{Folder: folder})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("the fetch answered %d: %s", res.StatusCode, data)
	}
	var job registryJobJSON
	if err := json.Unmarshal(data, &job); err != nil {
		t.Fatal(err)
	}
	if job.Kind != jobFetch {
		t.Fatalf("the job is a %q", job.Kind)
	}
	return waitForFetch(t, server, "/", job.ID, session)
}

func TestLocalBrowseListsTheFoldersOfTheServedTree(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	server, session := remoteServer(t, host, nil)
	server.write(t, "zeta.txt", "z")
	server.mkdir(t, "beta")
	server.write(t, "beta/inside.txt", "in")
	server.mkdir(t, "Alpha")

	status, view := localBrowse(t, server, "/", session)
	if status != http.StatusOK {
		t.Fatalf("the root answered %d", status)
	}
	if view.Path != "/" || view.Parent != "" || !view.Writable {
		t.Errorf("the root is %+v", view)
	}
	var names []string
	for _, entry := range view.Entries {
		names = append(names, entry.Name)
	}
	if got := strings.Join(names, ","); got != "Alpha,beta,zeta.txt" {
		t.Errorf("the root lists %s", got)
	}
	if !view.Entries[0].Dir || view.Entries[2].Dir || view.Entries[2].Size != 1 {
		t.Errorf("the entries are %+v", view.Entries)
	}

	status, view = localBrowse(t, server, "/beta/", session)
	if status != http.StatusOK || view.Path != "/beta" || view.Parent != "/" ||
		len(view.Entries) != 1 || view.Entries[0].Name != "inside.txt" {
		t.Errorf("a folder below answered %d: %+v", status, view)
	}
	if status, _ := localBrowse(t, server, "/../..", session); status != http.StatusNotFound {
		t.Errorf("a path above the root answered %d", status)
	}
	if status, _ := localBrowse(t, server, "/zeta.txt", session); status != http.StatusNotFound {
		t.Errorf("a file answered %d", status)
	}
	if status, _ := localBrowse(t, server, "/nowhere", session); status != http.StatusNotFound {
		t.Errorf("a folder that is not there answered %d", status)
	}
}

func TestLocalBrowseIsForASessionAndSaysWhereItMayStore(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	server, _ := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, readOnlyUser("reader", "pw"),
			config.User{Username: "blind", Password: "pw", HTTP: true, Paths: []string{"^/.*"}})
	})

	if status, _ := localBrowse(t, server, "/", nil); status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Errorf("without a session the root answered %d", status)
	}
	if res := basic(t, server, http.MethodGet, "/?go-fs=local-browse&path=/", "john", "doe", nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("a header answered %d", res.StatusCode)
	}
	reader := login(t, server, "/", "reader", "pw")
	if status, view := localBrowse(t, server, "/", reader); status != http.StatusOK || view.Writable {
		t.Errorf("a reader was answered %d: %+v", status, view)
	}
	// a folder that needs an account is listed as its page is: to one that
	// may read
	server.mkdir(t, "private")
	blind := login(t, server, "/", "blind", "pw")
	if status, _ := localBrowse(t, server, "/private", blind); status != http.StatusForbidden {
		t.Errorf("an account that may not read answered %d", status)
	}
	if status, _ := localBrowse(t, server, "/private", reader); status != http.StatusOK {
		t.Errorf("an account that may read answered %d", status)
	}
}

func TestRemoteFetchStoresAFileOfTheServer(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "deep/report.txt", "0123456789")
	server, session := remoteServer(t, host, nil)
	server.mkdir(t, "inbox")

	job := remoteFetched(t, server, remoteAt(host, "deep/report.txt"), "/inbox", session)
	expectDone(t, job)
	if got := server.read(t, "inbox/report.txt"); got != "0123456789" {
		t.Errorf("the file stored is %q", got)
	}
	if !strings.Contains(job.Message, "Fetched report.txt") || !strings.Contains(job.Message, "Backup") ||
		!strings.Contains(job.Message, "/inbox/") {
		t.Errorf("the job says %q", job.Message)
	}
	if job.Folder != "/inbox/" || job.Name != "report.txt" {
		t.Errorf("the job is of %q in %q", job.Name, job.Folder)
	}
	if remoteFile(host, "deep/report.txt") != "0123456789" {
		t.Error("the file of the server was changed")
	}
}

func TestRemoteFetchStoresAFileOfAnArtifactory(t *testing.T) {
	host := remotetest.NewArtifactoryHost(t, "the-token", "libs")
	host.Write(t, "libs/org/lib.jar", "jar-content")
	server, session := artifactoryServer(t, host)

	expectDone(t, remoteFetched(t, server, remoteURL("Artifacts", "/libs/org/lib.jar"), "/", session))
	if got := server.read(t, "lib.jar"); got != "jar-content" {
		t.Errorf("the file stored is %q", got)
	}
}

func TestRemoteFetchReplacesOnlyWithTheOverwriteRight(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "data.bin", "new")
	host.Write(t, "folder/inside.txt", "in")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		kim := fullUser("kim", "pw")
		kim.AllowUserFileOverwrite = new(false)
		cfg.Users = append(cfg.Users, kim)
	})
	server.write(t, "data.bin", "old")

	kim := login(t, server, "/", "kim", "pw")
	expectFailed(t, remoteFetched(t, server, remoteAt(host, "data.bin"), "/", kim), "already a file")
	if got := server.read(t, "data.bin"); got != "old" {
		t.Errorf("the file was replaced: %q", got)
	}
	expectDone(t, remoteFetched(t, server, remoteAt(host, "data.bin"), "/", session))
	if got := server.read(t, "data.bin"); got != "new" {
		t.Errorf("the file was not replaced: %q", got)
	}
	expectFailed(t, remoteFetched(t, server, remoteAt(host, "folder"), "/", session), "not a file")
	expectFailed(t, remoteFetched(t, server, remoteAt(host, "missing.txt"), "/", session), "there is no")
}

func TestRemoteFetchKeepsToTheUploadLimit(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "big.bin", "01234567890123456789")
	server, session := remoteServer(t, host, func(cfg *httpConfig) { cfg.MaxUploadSize = 10 })

	expectFailed(t, remoteFetched(t, server, remoteAt(host, "big.bin"), "/", session), "larger than the maximum")
	if _, err := os.Stat(filepath.Join(server.base, "big.bin")); err == nil {
		t.Error("the file was stored")
	}
}

func TestRemoteFetchRefusesWhatIsNotAFetch(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, readOnlyUser("reader", "pw"))
	})
	server.write(t, "file.txt", "f")
	link := remoteFetchOf(remoteAt(host, "a.txt"))
	reader := login(t, server, "/", "reader", "pw")

	for _, c := range []struct {
		name    string
		method  string
		link    string
		session *http.Cookie
		folder  string
		headers []string
		want    int
	}{
		{"no session", http.MethodPost, link, nil, "/", nil, http.StatusUnauthorized},
		{"a reader", http.MethodPost, link, reader, "/", nil, http.StatusForbidden},
		{"another site", http.MethodPost, link, session, "/", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"a GET", http.MethodGet, link, session, "/", nil, http.StatusMethodNotAllowed},
		{"a server that is not stored", http.MethodPost, remoteFetchOf(remoteURL("Nowhere", "/a.txt")), session, "/", nil, http.StatusNotFound},
		{"no file", http.MethodPost, remoteFetchOf(remoteURL("Backup", "")), session, "/", nil, http.StatusBadRequest},
		{"no folder", http.MethodPost, link, session, "", nil, http.StatusBadRequest},
		{"a folder above the root", http.MethodPost, link, session, "/../..", nil, http.StatusBadRequest},
		{"a file for a folder", http.MethodPost, link, session, "/file.txt", nil, http.StatusBadRequest},
		{"a folder that is not there", http.MethodPost, link, session, "/nowhere", nil, http.StatusBadRequest},
	} {
		res, data := transferRequest(t, server, c.method, c.link, c.session, remoteFetchBody{Folder: c.folder}, c.headers...)
		if res.StatusCode != c.want && !(c.want == http.StatusUnauthorized && res.StatusCode == http.StatusForbidden) {
			t.Errorf("%s answered %d, want %d: %s", c.name, res.StatusCode, c.want, data)
		}
	}
	if n := host.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered for fetches that were refused", n)
	}
	if _, err := os.Stat(filepath.Join(server.base, "a.txt")); err == nil {
		t.Error("a refused fetch stored the file")
	}
}

func TestRemotePageOffersFetchWhereTheAccountMayCreate(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, readOnlyUser("reader", "pw"))
	})

	body := bodyOf(t, remoteDo(t, server, http.MethodGet, remoteURL("Backup", ""), session, nil, nil))
	for _, want := range []string{`data-do="remote-fetch"`, `id="remote-fetch-dialog"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
	reader := login(t, server, "/", "reader", "pw")
	body = bodyOf(t, remoteDo(t, server, http.MethodGet, remoteURL("Backup", ""), reader, nil, nil))
	if strings.Contains(body, `data-do="remote-fetch"`) || strings.Contains(body, `id="remote-fetch-dialog"`) {
		t.Error("the page of a reader offers Fetch")
	}
	// and the listing of the served tree offers it nowhere
	if strings.Contains(listingOf(t, server, session), `data-do="remote-fetch"`) {
		t.Error("the listing of the served tree offers Fetch from a server")
	}
}

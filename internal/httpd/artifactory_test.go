package httpd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/remote/remotetest"
)

// storedArtifactory is an Artifactory the admin interface stored for the
// host.
func storedArtifactory(h *remotetest.ArtifactoryHost, name string) config.Server {
	return config.Server{Name: name, Type: config.ServerTypeArtifactory, URL: h.URL, Token: h.Token}
}

// artifactoryServer serves a stored Artifactory named Artifacts, with a
// staging folder for chunked uploads, and returns a session of john.
func artifactoryServer(t *testing.T, host *remotetest.ArtifactoryHost) (*testServer, *http.Cookie) {
	t.Helper()
	staging := t.TempDir()
	server := newServer(t, func(cfg *httpConfig) {
		cfg.UploadStagingFolder = staging
		cfg.MaxChunkSize = 4
		cfg.Servers = []config.Server{storedArtifactory(host, "Artifacts")}
	})
	return server, login(t, server, "/", "john", "doe")
}

func TestArtifactoryIsBrowsed(t *testing.T) {
	const token = "the-token-of-the-artifactory"
	host := remotetest.NewArtifactoryHost(t, token, "libs", "docs")
	host.Write(t, "libs/org/report.txt", "0123456789")
	host.Write(t, "libs/org/deeper/notes.md", "notes")
	server, session := artifactoryServer(t, host)
	at := func(p string) string { return remoteURL("Artifacts", p) }

	// the top lists the repositories
	res := remoteDo(t, server, http.MethodGet, at(""), session, nil, nil)
	body := bodyOf(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the page answered %d: %s", res.StatusCode, body)
	}
	assertOrder(t, body, "docs/", "libs/")
	if strings.Contains(body, token) {
		t.Error("the page shows the token")
	}
	res = remoteDo(t, server, http.MethodGet, at("/libs/org"), session, nil, nil)
	body = bodyOf(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `data-name="report.txt"`) ||
		!strings.Contains(body, `data-name="deeper"`) {
		t.Fatalf("a folder answered %d: %s", res.StatusCode, body)
	}

	// a download, a range of it, and a folder packed
	res = remoteDo(t, server, http.MethodGet, at("/libs/org/report.txt"), session, nil, nil)
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || body != "0123456789" {
		t.Fatalf("the download answered %d: %q", res.StatusCode, body)
	}
	res = remoteDo(t, server, http.MethodGet, at("/libs/org/report.txt"), session, nil,
		map[string]string{"Range": "bytes=2-4"})
	if body := bodyOf(t, res); res.StatusCode != http.StatusPartialContent || body != "234" {
		t.Errorf("a range answered %d: %q", res.StatusCode, body)
	}
	if res := remoteDo(t, server, http.MethodGet, at("/libs/gone.txt"), session, nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("a file that is not there answered %d", res.StatusCode)
	}
	res = remoteDo(t, server, http.MethodGet, at("/libs/org")+"&archive=1", session, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the archive answered %d", res.StatusCode)
	}
	entries := unpack(t, readAll(t, res))
	want := map[string]string{"org/": folderMark, "org/report.txt": "0123456789",
		"org/deeper/": folderMark, "org/deeper/notes.md": "notes"}
	if len(entries) != len(want) {
		t.Errorf("the archive holds %v", entries)
	}
	for name, content := range want {
		if entries[name] != content {
			t.Errorf("%s in the archive is %q, want %q", name, entries[name], content)
		}
	}

	// uploads, whole and in chunks; none beside the repositories
	res = remoteDo(t, server, http.MethodPut, at("/docs/new.txt"), session, strings.NewReader("hello"), octetStream)
	if res.StatusCode != http.StatusOK || host.Read(t, "docs/new.txt") != "hello" {
		t.Fatalf("the upload answered %d: %s", res.StatusCode, bodyOf(t, res))
	}
	for _, chunk := range []struct {
		start, end int64
		body       string
		status     int
	}{{0, 3, "abcd", http.StatusOK}, {4, 7, "efgh", http.StatusOK}, {8, 9, "ij", http.StatusCreated}} {
		res := remoteDo(t, server, http.MethodPut, at("/docs/chunked.bin"), session, strings.NewReader(chunk.body),
			map[string]string{"Content-Type": "application/octet-stream",
				"Content-Range": fmt.Sprintf("bytes %d-%d/10", chunk.start, chunk.end)})
		if res.StatusCode != chunk.status {
			t.Fatalf("the chunk at %d answered %d: %s", chunk.start, res.StatusCode, bodyOf(t, res))
		}
	}
	if got := host.Read(t, "docs/chunked.bin"); got != "abcdefghij" {
		t.Errorf("the chunked upload wrote %q", got)
	}
	res = remoteDo(t, server, http.MethodPut, at("/top.txt"), session, strings.NewReader("x"), octetStream)
	if body := bodyOf(t, res); res.StatusCode != http.StatusForbidden || !strings.Contains(body, "the token may not write") {
		t.Errorf("an upload beside the repositories answered %d: %s", res.StatusCode, body)
	}

	// a folder, a rename, and deletes
	if res := remoteDo(t, server, methodMkcol, at("/docs/made")+"/", session, nil, nil); res.StatusCode != http.StatusCreated {
		t.Fatalf("MKCOL answered %d: %s", res.StatusCode, bodyOf(t, res))
	}
	if info, err := os.Stat(filepath.Join(host.Dir, "docs", "made")); err != nil || !info.IsDir() {
		t.Fatal("the folder was not created")
	}
	move := remoteDo(t, server, methodMove, at("/docs/new.txt"), session, nil,
		map[string]string{"Destination": server.url(at("/docs/made/moved.txt"))})
	if move.StatusCode != http.StatusCreated || host.Read(t, "docs/made/moved.txt") != "hello" {
		t.Errorf("the rename answered %d: %s", move.StatusCode, bodyOf(t, move))
	}
	if res := remoteDo(t, server, http.MethodDelete, at("/docs/made"), session, nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("deleting a folder with something in it answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodDelete, at("/docs/made/moved.txt"), session, nil, nil); res.StatusCode != http.StatusNoContent {
		t.Errorf("deleting a file answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodDelete, at("/docs/made"), session, nil, nil); res.StatusCode != http.StatusNoContent {
		t.Errorf("deleting an empty folder answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodDelete, at("/docs"), session, nil, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("deleting a repository answered %d", res.StatusCode)
	}

	// without Pro, the listing has no sizes and a rename says why it failed
	host.OSS.Store(true)
	res = remoteDo(t, server, http.MethodGet, at("/libs/org"), session, nil, nil)
	if body := bodyOf(t, res); res.StatusCode != http.StatusOK || !strings.Contains(body, `data-name="report.txt"`) {
		t.Errorf("a folder without Pro answered %d: %s", res.StatusCode, body)
	}
	move = remoteDo(t, server, methodMove, at("/libs/org/report.txt"), session, nil,
		map[string]string{"Destination": server.url(at("/libs/org/renamed.txt"))})
	if body := bodyOf(t, move); move.StatusCode != http.StatusBadGateway || !strings.Contains(body, "Artifactory Pro") {
		t.Errorf("a rename without Pro answered %d: %s", move.StatusCode, body)
	}
}

func TestArtifactoryPageSaysTheTokenWasRefused(t *testing.T) {
	host := remotetest.NewArtifactoryHost(t, "secret", "libs")
	server := newServer(t, func(cfg *httpConfig) {
		wrong := storedArtifactory(host, "Artifacts")
		wrong.Token = "wrong"
		cfg.Servers = []config.Server{wrong}
	})
	session := login(t, server, "/", "john", "doe")
	res := remoteDo(t, server, http.MethodGet, remoteURL("Artifacts", ""), session, nil,
		map[string]string{"Accept": "text/html"})
	if body := bodyOf(t, res); res.StatusCode != http.StatusBadGateway || !strings.Contains(body, "refused the token") {
		t.Errorf("a wrong token answered %d: %s", res.StatusCode, body)
	}
}

func TestSendToAnArtifactory(t *testing.T) {
	host := remotetest.NewArtifactoryHost(t, "secret", "libs")
	host.Write(t, "libs/inbox/other.txt", "")
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Servers = []config.Server{storedArtifactory(host, "Artifacts")}
	})
	server.write(t, "report.txt", "the report")
	session := login(t, server, "/", "john", "doe")

	if listing := listingOf(t, server, session); !strings.Contains(listing, `data-token="true">Artifactory</option>`) {
		t.Error("the dialog does not offer Artifactory for a login typed in")
	}

	browse := func(body sendBody) sendFolderJSON {
		t.Helper()
		res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("browsing %+v answered %d: %s", body, res.StatusCode, data)
		}
		var view sendFolderJSON
		if err := json.Unmarshal(data, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	home := browse(sendBody{Server: "Artifacts"})
	if home.Path != "/" || home.Base != host.URL || home.Parent != "" ||
		len(home.Entries) != 1 || home.Entries[0].Name != "libs" || !home.Entries[0].Dir {
		t.Errorf("the stored Artifactory starts at %+v", home)
	}
	manual := sendBody{Protocol: config.ServerTypeArtifactory, URL: host.URL, Token: "secret", Path: "/libs"}
	if inner := browse(manual); inner.Path != "/libs" || inner.Parent != "/" {
		t.Errorf("the login typed in lists %+v", inner)
	}

	job := startSend(t, server, "/report.txt", session, sendBody{Server: "Artifacts", Path: "/libs/inbox"})
	ended := waitForFetch(t, server, "/", job.ID, session)
	expectDone(t, ended)
	if got := host.Read(t, "libs/inbox/report.txt"); got != "the report" {
		t.Errorf("the Artifactory holds %q", got)
	}
	if !strings.Contains(ended.Message, host.URL+"/libs/inbox/report.txt") || strings.Contains(ended.Message, "secret") {
		t.Errorf("message %q", ended.Message)
	}
	if record := server.logs.find("http send"); record == nil {
		t.Error("the send was not logged")
	} else if logged, _ := json.Marshal(record); strings.Contains(string(logged), "secret") {
		t.Errorf("the log holds the token: %s", logged)
	}

	manual.Path = "/libs"
	expectDone(t, waitForFetch(t, server, "/", startSend(t, server, "/report.txt", session, manual).ID, session))
	if got := host.Read(t, "libs/report.txt"); got != "the report" {
		t.Errorf("the send of the login typed in stored %q", got)
	}

	// a file goes into a repository, and an Artifactory shows no key
	job = startSend(t, server, "/report.txt", session, sendBody{Server: "Artifacts", Path: "/"})
	expectFailed(t, waitForFetch(t, server, "/", job.ID, session), "may not write")
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", session, manual)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("the key of an Artifactory answered %d: %s", res.StatusCode, data)
	}
	manual.Token = "wrong"
	res, data = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, manual)
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "refused the token") {
		t.Errorf("a wrong token answered %d: %s", res.StatusCode, data)
	}
}

func TestSendToAnArtifactoryCanBeStopped(t *testing.T) {
	host := remotetest.NewArtifactoryHost(t, "secret", "libs")
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Servers = []config.Server{storedArtifactory(host, "Artifacts")}
	})
	server.write(t, "big.bin", strings.Repeat("x", 16<<20))
	session := login(t, server, "/", "john", "doe")

	host.Slow.Store(int64(20 * time.Millisecond))
	job := startSend(t, server, "/big.bin", session, sendBody{Server: "Artifacts", Path: "/libs"})
	waitForDownload(t, server, "/", job.ID, session)
	res, data := transferRequest(t, server, http.MethodDelete, "/?go-fs=fetch-job&id="+job.ID, session, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the stop answered %d: %s", res.StatusCode, data)
	}
	host.Slow.Store(0)
	if ended := waitForFetch(t, server, "/", job.ID, session); ended.State != jobCancelled {
		t.Errorf("the send ended %s: %s", ended.State, ended.Message)
	}
	if got := host.Read(t, "libs/big.bin"); got != "" {
		t.Errorf("a stopped send stored %d bytes", len(got))
	}
}

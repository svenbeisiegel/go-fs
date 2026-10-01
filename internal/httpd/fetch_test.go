package httpd

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startFetch starts a fetch into a folder and returns the job it started.
func startFetch(t *testing.T, server *testServer, folder string, session *http.Cookie, body fetchBody) registryJobJSON {
	t.Helper()
	res, data := transferRequest(t, server, http.MethodPost, folder+"?go-fs=fetch", session, body)
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("POST %s answered %d: %s", folder, res.StatusCode, data)
	}
	var job registryJobJSON
	if err := json.Unmarshal(data, &job); err != nil {
		t.Fatal(err)
	}
	if job.Kind != jobFetch {
		t.Fatalf("the job is a %q", job.Kind)
	}
	return job
}

// waitForFetch asks after a fetch until it has ended.
func waitForFetch(t *testing.T, server *testServer, folder, id string, session *http.Cookie) registryJobJSON {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		res, data := transferRequest(t, server, http.MethodGet, folder+"?go-fs=fetch-job&id="+id, session, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("the fetch answered %d: %s", res.StatusCode, data)
		}
		var job registryJobJSON
		if err := json.Unmarshal(data, &job); err != nil {
			t.Fatal(err)
		}
		if job.State != jobRunning {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fetch is still running: %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fetched starts a fetch and waits for it to end.
func fetched(t *testing.T, server *testServer, folder string, session *http.Cookie, body fetchBody) registryJobJSON {
	t.Helper()
	job := startFetch(t, server, folder, session, body)
	return waitForFetch(t, server, folder, job.ID, session)
}

func expectDone(t *testing.T, job registryJobJSON) {
	t.Helper()
	if job.State != jobDone {
		t.Fatalf("the fetch ended %s: %s", job.State, job.Message)
	}
}

func expectFailed(t *testing.T, job registryJobJSON, says string) {
	t.Helper()
	if job.State != jobFailed || !strings.Contains(job.Message, says) {
		t.Fatalf("the fetch ended %s with %q, want failed with %q", job.State, job.Message, says)
	}
}

func origin(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	remote := httptest.NewServer(handler)
	t.Cleanup(remote.Close)
	return remote
}

// untrusted is an HTTPS server with a certificate nobody vouches for. The
// handshakes it fails are not logged.
func untrusted(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	remote := httptest.NewUnstartedServer(handler)
	remote.Config.ErrorLog = log.New(io.Discard, "", 0)
	remote.StartTLS()
	t.Cleanup(remote.Close)
	return remote
}

func TestFetchFollowsARedirectAndKeepsTheLoginHome(t *testing.T) {
	var mu sync.Mutex
	var seenAuth, seenCustom, seenAccept string
	files := origin(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenAuth, seenCustom, seenAccept = r.Header.Get("Authorization"), r.Header.Get("X-Custom"), r.Header.Get("Accept")
		mu.Unlock()
		if r.URL.Path != "/files/release-1.0.tar.gz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("the release"))
	})
	front := origin(t, func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); !ok || user != "u" || password != "p" {
			http.Error(w, "who are you", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Custom") != "yes" {
			http.Error(w, "no header", http.StatusBadRequest)
			return
		}
		// another port is another origin, on the same host name
		http.Redirect(w, r, files.URL+"/files/release-1.0.tar.gz", http.StatusFound)
	})

	server := newServer(t, nil)
	server.mkdir(t, "sub")
	session := login(t, server, "/", "john", "doe")
	job := fetched(t, server, "/sub/", session, fetchBody{URL: front.URL + "/download?token=secret",
		Username: "u", Password: "p", Headers: "X-Custom: yes\n\n  Accept: application/octet-stream  \r\n"})
	expectDone(t, job)
	if got := server.read(t, "sub/release-1.0.tar.gz"); got != "the release" {
		t.Errorf("stored %q", got)
	}
	if !strings.Contains(job.Message, "release-1.0.tar.gz") || !strings.Contains(job.Message, "/sub/") {
		t.Errorf("message %q", job.Message)
	}
	if strings.Contains(job.What, "secret") {
		t.Errorf("the job shows the query: %q", job.What)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenAuth != "" {
		t.Errorf("the login followed the redirect to another origin: %q", seenAuth)
	}
	if seenCustom != "yes" || seenAccept != "application/octet-stream" {
		t.Errorf("the headers did not follow the redirect: %q %q", seenCustom, seenAccept)
	}
	if record := server.logs.find("http fetch"); record == nil || strings.Contains(fmt.Sprint(record["url"]), "secret") {
		t.Errorf("the fetch was recorded as %v", record)
	}
}

// A remote with a certificate nobody vouches for is refused while the fetch
// validates the connection, and fetched once it does not.
func TestFetchValidatesTheConnectionUnlessToldNotTo(t *testing.T) {
	remote := untrusted(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("self-signed"))
	})

	server := newServer(t, nil)
	server.mkdir(t, "in")
	session := login(t, server, "/", "john", "doe")
	expectFailed(t, fetched(t, server, "/in/", session, fetchBody{URL: remote.URL + "/cert.txt"}),
		"untick Validate Connection")
	if _, err := os.Stat(filepath.Join(server.base, "in", "cert.txt")); err == nil {
		t.Error("the file was stored from a connection that failed validation")
	}
	expectDone(t, fetched(t, server, "/in/", session, fetchBody{URL: remote.URL + "/cert.txt", SkipVerify: true}))
	if got := server.read(t, "in/cert.txt"); got != "self-signed" {
		t.Errorf("stored %q", got)
	}
	if record := server.logs.find("http fetch started"); record == nil || record["verify"] != true {
		t.Errorf("the first fetch was recorded as %v", record)
	}
}

func TestFetchNamesTheFileByItsContentDisposition(t *testing.T) {
	cases := []struct{ disposition, want string }{
		{`attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`, "résumé.pdf"},
		{`attachment; filename="report.csv"`, "report.csv"},
		{`attachment; filename="../../evil.txt"`, "evil.txt"},
		{`attachment; filename="a\\b.txt"`, "b.txt"},
		// nothing usable there: the URL names it
		{`attachment; filename=".."`, "dl"},
		{`not a disposition;;`, "dl"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			remote := origin(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Disposition", c.disposition)
				_, _ = w.Write([]byte(c.want))
			})
			server := newServer(t, nil)
			server.mkdir(t, "in")
			session := login(t, server, "/", "john", "doe")
			expectDone(t, fetched(t, server, "/in/", session, fetchBody{URL: remote.URL + "/dl?id=3"}))
			if got := server.read(t, "in/"+c.want); got != c.want {
				t.Errorf("stored %q", got)
			}
			if _, err := os.Stat(filepath.Join(server.base, "evil.txt")); err == nil {
				t.Error("the file landed outside the folder")
			}
		})
	}
}

func TestFetchNeedsAName(t *testing.T) {
	remote := origin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	})
	server := newServer(t, nil)
	session := login(t, server, "/", "john", "doe")
	expectFailed(t, fetched(t, server, "/", session, fetchBody{URL: remote.URL + "/"}), "names no file")
}

func TestFetchReplacesOnlyWithTheOverwriteRight(t *testing.T) {
	remote := origin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("new"))
	})
	server := newServer(t, func(cfg *httpConfig) {
		kim := fullUser("kim", "pw")
		kim.AllowUserFileOverwrite = new(false)
		cfg.Users = append(cfg.Users, kim)
	})
	server.write(t, "data.bin", "old")
	server.mkdir(t, "data.dir")

	kim := login(t, server, "/", "kim", "pw")
	expectFailed(t, fetched(t, server, "/", kim, fetchBody{URL: remote.URL + "/data.bin"}), "already a file")
	if got := server.read(t, "data.bin"); got != "old" {
		t.Errorf("the file was replaced: %q", got)
	}

	john := login(t, server, "/", "john", "doe")
	expectFailed(t, fetched(t, server, "/", john, fetchBody{URL: remote.URL + "/data.dir"}), "not a file")
	expectDone(t, fetched(t, server, "/", john, fetchBody{URL: remote.URL + "/data.bin"}))
	if got := server.read(t, "data.bin"); got != "new" {
		t.Errorf("the file was not replaced: %q", got)
	}
}

func TestFetchKeepsToTheUploadLimit(t *testing.T) {
	staging := t.TempDir()
	remote := origin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chunked.bin" {
			// flushed before it ends, so it goes without a length
			_, _ = w.Write([]byte("0123456789"))
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("0123456789"))
			return
		}
		_, _ = w.Write([]byte("01234567890123456789"))
	})
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MaxUploadSize = 10
		cfg.UploadStagingFolder = staging
	})
	session := login(t, server, "/", "john", "doe")
	for _, name := range []string{"sized.bin", "chunked.bin"} {
		expectFailed(t, fetched(t, server, "/", session, fetchBody{URL: remote.URL + "/" + name}), "larger than the maximum")
		if _, err := os.Stat(filepath.Join(server.base, name)); err == nil {
			t.Errorf("%s was stored", name)
		}
	}
	if left, _ := os.ReadDir(staging); len(left) != 0 {
		t.Errorf("the staging folder kept %v", left)
	}
}

func TestFetchSaysWhatTheRemoteAnswered(t *testing.T) {
	remote := origin(t, http.NotFound)
	server := newServer(t, nil)
	session := login(t, server, "/", "john", "doe")
	expectFailed(t, fetched(t, server, "/", session, fetchBody{URL: remote.URL + "/gone.zip"}), "404 Not Found")
}

func TestFetchStoresWhatItIsSentAsItIsSent(t *testing.T) {
	var packed bytes.Buffer
	zipper := gzip.NewWriter(&packed)
	_, _ = zipper.Write([]byte(strings.Repeat("a tarball ", 100)))
	_ = zipper.Close()
	remote := origin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(packed.Bytes())
	})
	server := newServer(t, nil)
	session := login(t, server, "/", "john", "doe")
	expectDone(t, fetched(t, server, "/", session, fetchBody{URL: remote.URL + "/app.tar.gz"}))
	if got := server.read(t, "app.tar.gz"); got != packed.String() {
		t.Error("the file was not stored as it was sent")
	}
}

func TestFetchRefusesWhatIsNotAFetch(t *testing.T) {
	server := newServer(t, nil)
	session := login(t, server, "/", "john", "doe")
	for _, body := range []fetchBody{
		{URL: ""},
		{URL: "ftp://example.com/file"},
		{URL: "file:///etc/passwd"},
		{URL: "https:///nohost"},
		{URL: "https://user:pw@example.com/file"},
		{URL: "https://example.com/file", Headers: "no colon here"},
		{URL: "https://example.com/file", Headers: "Bad Name: x"},
		{URL: "https://example.com/file", Headers: "Host: elsewhere"},
		{URL: "https://example.com/file", Headers: "Proxy-Authorization: Basic x"},
		{URL: "https://example.com/file", Headers: "X-A: a\rb"},
		{URL: "https://example.com/file", Headers: "Authorization: Bearer x", Username: "u"},
		{URL: "https://example.com/file", Headers: strings.Repeat("X-A: a\n", maxFetchHeaders+1)},
	} {
		res, data := transferRequest(t, server, http.MethodPost, "/?go-fs=fetch", session, body)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%+v answered %d: %s", body, res.StatusCode, data)
		}
	}
	res, _ := transferRequest(t, server, http.MethodGet, "/?go-fs=fetch", session, nil)
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "POST" {
		t.Errorf("GET of the fetch answered %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
	server.write(t, "file.txt", "x")
	res, _ = transferRequest(t, server, http.MethodPost, "/file.txt?go-fs=fetch", session, fetchBody{URL: "https://example.com/f"})
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("a fetch into a file answered %d", res.StatusCode)
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/?go-fs=fetch", session, fetchBody{URL: "https://example.com/f"},
		"Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a fetch from another site answered %d", res.StatusCode)
	}
}

func TestFetchIsOfferedToASessionThatMayCreate(t *testing.T) {
	listing := func(t *testing.T, server *testServer, session *http.Cookie, name, password string) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.url("/"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if session != nil {
			req.AddCookie(session)
		}
		if name != "" {
			req.SetBasicAuth(name, password)
		}
		return bodyOf(t, do(t, req))
	}
	const button = `id="fetch"`

	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, readOnlyUser("reader", "pw"))
	})
	if page := listing(t, server, login(t, server, "/", "john", "doe"), "", ""); !strings.Contains(page, button) {
		t.Error("a session that may create is not offered Fetch")
	}
	if page := listing(t, server, login(t, server, "/", "reader", "pw"), "", ""); strings.Contains(page, button) {
		t.Error("a session that may not create is offered Fetch")
	}
	if page := listing(t, server, nil, "john", "doe"); strings.Contains(page, button) {
		t.Error("a Basic header is offered Fetch")
	}
	body := fetchBody{URL: "https://example.com/f"}
	res, _ := transferRequest(t, server, http.MethodPost, "/?go-fs=fetch", login(t, server, "/", "reader", "pw"), body)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a session that may not create answered %d", res.StatusCode)
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/?go-fs=fetch", nil, body)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a fetch without an account answered %d", res.StatusCode)
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/?go-fs=fetch", nil, body, "Authorization", "Basic "+
		basicToken("john", "doe"))
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a fetch with a Basic header answered %d", res.StatusCode)
	}

	open := newServer(t, publicServer)
	if page := listing(t, open, nil, "", ""); strings.Contains(page, button) {
		t.Error("an anonymous visitor of a public folder is offered Fetch")
	}
	res, _ = transferRequest(t, open, http.MethodPost, "/?go-fs=fetch", nil, body)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("an anonymous fetch into a public folder answered %d", res.StatusCode)
	}
}

func basicToken(name, password string) string {
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.SetBasicAuth(name, password)
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
}

func TestFetchCanBeStopped(t *testing.T) {
	release := make(chan struct{})
	remote := origin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("begun"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	server := newServer(t, nil)
	session := login(t, server, "/", "john", "doe")
	job := startFetch(t, server, "/", session, fetchBody{URL: remote.URL + "/slow.bin"})

	deadline := time.Now().Add(10 * time.Second)
	for {
		_, data := transferRequest(t, server, http.MethodGet, "/?go-fs=fetch-job&id="+job.ID, session, nil)
		var view registryJobJSON
		_ = json.Unmarshal(data, &view)
		if view.BytesDone > 0 {
			if view.BytesTotal != 1000 {
				t.Errorf("the size is %d", view.BytesTotal)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing arrived: %+v", view)
		}
		time.Sleep(20 * time.Millisecond)
	}
	res, data := transferRequest(t, server, http.MethodDelete, "/?go-fs=fetch-job&id="+job.ID, session, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the stop answered %d: %s", res.StatusCode, data)
	}
	if ended := waitForFetch(t, server, "/", job.ID, session); ended.State != jobCancelled {
		t.Errorf("the fetch ended %s: %s", ended.State, ended.Message)
	}
	if _, err := os.Stat(filepath.Join(server.base, "slow.bin")); err == nil {
		t.Error("a stopped fetch stored its file")
	}
}

func TestFetchJobsAreTheirOwn(t *testing.T) {
	remote := origin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	})
	server := newRegistryServer(t, func(cfg *httpConfig) {
		both := fullUser("both", "pw")
		both.Registry = true
		cfg.Users = append(cfg.Users, both)
	})
	session := login(t, server, "/", "both", "pw")
	job := startFetch(t, server, "/", session, fetchBody{URL: remote.URL + "/x.txt"})
	expectDone(t, waitForFetch(t, server, "/", job.ID, session))

	res, _ := transferRequest(t, server, http.MethodGet, "/?go-fs=fetch-job&id="+job.ID, login(t, server, "/", "john", "doe"), nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("someone else's fetch answered %d", res.StatusCode)
	}
	res, _ = transferRequest(t, server, http.MethodGet, "/?go-fs=registry-job&id="+job.ID, session, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("the registry answered %d for a fetch", res.StatusCode)
	}
}

func TestParseFetchHeaders(t *testing.T) {
	header, err := parseFetchHeaders("Accept: a\n\nX-Many: 1\nx-many: 2\r\nX-Empty:\n")
	if err != nil {
		t.Fatal(err)
	}
	if header.Get("Accept") != "a" || len(header.Values("X-Many")) != 2 || header.Get("X-Empty") != "" {
		t.Errorf("%v", header)
	}
}

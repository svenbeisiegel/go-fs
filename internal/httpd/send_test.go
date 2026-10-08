package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/remote/remotetest"
)

// sendTo is a send to the host, as the dialog asks for one once the key was
// accepted.
func sendTo(h *remotetest.SFTPHost, path string) sendBody {
	return sendBody{Host: h.Host, Port: h.Port, Username: "alice", Password: "secret",
		HostKey: h.Fingerprint, Path: path}
}

// startSend starts sending a file and returns the job it started.
func startSend(t *testing.T, server *testServer, file string, session *http.Cookie, body sendBody) registryJobJSON {
	t.Helper()
	res, data := transferRequest(t, server, http.MethodPost, file+"?go-fs=send", session, body)
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("POST %s answered %d: %s", file, res.StatusCode, data)
	}
	var job registryJobJSON
	if err := json.Unmarshal(data, &job); err != nil {
		t.Fatal(err)
	}
	if job.Kind != jobSend {
		t.Fatalf("the job is a %q", job.Kind)
	}
	return job
}

func TestSendShowsTheHostKeyWithoutLoggingIn(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", session,
		sendBody{Host: remote.Host, Port: remote.Port})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the host key answered %d: %s", res.StatusCode, data)
	}
	var view sendHostKeyJSON
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	if view.Fingerprint != remote.Fingerprint || view.KeyType != ssh.KeyAlgoED25519 {
		t.Errorf("the key is %+v, want %s", view, remote.Fingerprint)
	}
	if view.Host != net.JoinHostPort(remote.Host, strconv.Itoa(remote.Port)) {
		t.Errorf("the host is shown as %q", view.Host)
	}
	if n := remote.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered for the key alone", n)
	}

	// a port where nothing listens
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	res, _ = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", session,
		sendBody{Host: "127.0.0.1", Port: port})
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("a host that is not there answered %d", res.StatusCode)
	}
}

func TestSendLogsInOnlyWithTheAcceptedKey(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	body := sendTo(remote, "")
	body.HostKey = "SHA256:somebodyElse"
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, body)
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "not the one that was accepted") {
		t.Errorf("another key answered %d: %s", res.StatusCode, data)
	}
	if n := remote.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered to a host with another key", n)
	}

	body = sendTo(remote, "")
	body.Password = "wrong"
	res, data = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, body)
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "refused the login") {
		t.Errorf("a wrong password answered %d: %s", res.StatusCode, data)
	}
}

func TestSendListsTheFoldersOfTheHost(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	remote.Write(t, "zeta.txt", "z")
	remote.Write(t, "Beta/inside.txt", "in")
	remote.Write(t, "alpha/deeper/x.txt", "x")
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	browse := func(path string) sendFolderJSON {
		t.Helper()
		res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, sendTo(remote, path))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("the folder %q answered %d: %s", path, res.StatusCode, data)
		}
		var view sendFolderJSON
		if err := json.Unmarshal(data, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	home := browse("")
	if home.Path != remotetest.Path(remote.Dir) {
		t.Errorf("the login starts in %q, want %q", home.Path, remote.Dir)
	}
	var names []string
	for _, entry := range home.Entries {
		names = append(names, entry.Name)
	}
	if got := strings.Join(names, ","); got != "alpha,Beta,zeta.txt" {
		t.Errorf("the folder lists %s", got)
	}
	if !home.Entries[0].Dir || home.Entries[2].Dir || home.Entries[2].Size != 1 {
		t.Errorf("the entries are %+v", home.Entries)
	}
	if home.Parent != remotetest.Path(filepath.Dir(remote.Dir)) {
		t.Errorf("the parent is %q", home.Parent)
	}

	inner := browse(home.Path + "/alpha")
	if len(inner.Entries) != 1 || inner.Entries[0].Name != "deeper" || inner.Parent != home.Path {
		t.Errorf("the subfolder is %+v", inner)
	}
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session,
		sendTo(remote, home.Path+"/missing"))
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "there is no folder") {
		t.Errorf("a missing folder answered %d: %s", res.StatusCode, data)
	}
}

func TestSendUploadsTheFile(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	remote.Write(t, "inbox/.keep", "")
	server := newServer(t, nil)
	content := strings.Repeat("the report\n", 50000)
	server.mkdir(t, "docs")
	server.write(t, "docs/report.txt", content)
	session := login(t, server, "/", "john", "doe")

	folder := remotetest.Path(filepath.Join(remote.Dir, "inbox"))
	job := startSend(t, server, "/docs/report.txt", session, sendTo(remote, folder))
	ended := waitForFetch(t, server, "/", job.ID, session)
	expectDone(t, ended)
	stored, err := os.ReadFile(filepath.Join(remote.Dir, "inbox", "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != content {
		t.Errorf("the host stored %d bytes, want %d", len(stored), len(content))
	}
	if ended.BytesDone != int64(len(content)) || ended.BytesTotal != int64(len(content)) {
		t.Errorf("the job counted %d of %d bytes", ended.BytesDone, ended.BytesTotal)
	}
	if !strings.Contains(ended.Message, "report.txt") || !strings.Contains(ended.Message, folder) {
		t.Errorf("message %q", ended.Message)
	}
	if strings.Contains(ended.What, "secret") || strings.Contains(ended.Message, "secret") {
		t.Errorf("the job shows the password: %q, %q", ended.What, ended.Message)
	}
	if left := remote.Leftovers(t, "inbox"); len(left) != 0 {
		t.Errorf("the send left %v behind", left)
	}

	listed, ok := listedFetch(fetchList(t, server, "/docs/", session), job.ID)
	if !ok {
		t.Fatal("the send is not among the transfers")
	}
	if listed.Name != "report.txt" || !strings.HasPrefix(listed.Folder, "sftp://") || !strings.HasSuffix(listed.Folder, folder) {
		t.Errorf("the send is listed as %q to %q", listed.Name, listed.Folder)
	}
	record := server.logs.find("http send")
	if record == nil {
		t.Fatal("the send was not logged")
	}
	if logged, _ := json.Marshal(record); strings.Contains(string(logged), "secret") {
		t.Errorf("the log holds the password: %s", logged)
	}
}

func TestSendReplacesAFileThatIsThere(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	remote.Write(t, "report.txt", "the old one, which was longer")
	server := newServer(t, nil)
	server.write(t, "report.txt", "the new one")
	session := login(t, server, "/", "john", "doe")

	job := startSend(t, server, "/report.txt", session, sendTo(remote, remotetest.Path(remote.Dir)))
	expectDone(t, waitForFetch(t, server, "/", job.ID, session))
	stored, err := os.ReadFile(filepath.Join(remote.Dir, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != "the new one" {
		t.Errorf("the host holds %q", stored)
	}

	// a folder of that name is not replaced
	remote.Write(t, "taken/report.txt/inside", "x")
	job = startSend(t, server, "/report.txt", session, sendTo(remote, remotetest.Path(filepath.Join(remote.Dir, "taken"))))
	expectFailed(t, waitForFetch(t, server, "/", job.ID, session), "is a folder")
}

func TestSendCanBeStopped(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	server := newServer(t, nil)
	server.write(t, "big.bin", strings.Repeat("x", 16<<20))
	session := login(t, server, "/", "john", "doe")

	remote.Slow.Store(int64(20 * time.Millisecond))
	job := startSend(t, server, "/big.bin", session, sendTo(remote, remotetest.Path(remote.Dir)))
	waitForDownload(t, server, "/", job.ID, session)
	res, data := transferRequest(t, server, http.MethodDelete, "/?go-fs=fetch-job&id="+job.ID, session, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the stop answered %d: %s", res.StatusCode, data)
	}
	remote.Slow.Store(0)
	if ended := waitForFetch(t, server, "/", job.ID, session); ended.State != jobCancelled {
		t.Errorf("the send ended %s: %s", ended.State, ended.Message)
	}
	if _, err := os.Stat(filepath.Join(remote.Dir, "big.bin")); err == nil {
		t.Error("a stopped send stored its file")
	}
	if left := remote.Leftovers(t, "."); len(left) != 0 {
		t.Errorf("a stopped send left %v behind", left)
	}
}

func TestSendRefusesWhatIsNotASend(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	server.mkdir(t, "sub")
	session := login(t, server, "/", "john", "doe")
	good := sendBody{Host: "example.com", Username: "u", HostKey: "SHA256:x", Path: "/in"}
	for _, tc := range []struct {
		action string
		body   sendBody
	}{
		{actionSendHostKey, sendBody{}},
		{actionSendHostKey, sendBody{Host: "sftp://example.com"}},
		{actionSendHostKey, sendBody{Host: "u@example.com"}},
		{actionSendHostKey, sendBody{Host: "example.com/in"}},
		{actionSendHostKey, sendBody{Host: "example.com", Port: 70000}},
		{actionSendBrowse, sendBody{Host: "example.com", HostKey: "SHA256:x"}},
		{actionSendBrowse, sendBody{Host: "example.com", Username: "u"}},
		{actionSend, sendBody{Host: "example.com", Username: "u", HostKey: "SHA256:x"}},
	} {
		res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs="+tc.action, session, tc.body)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s %+v answered %d: %s", tc.action, tc.body, res.StatusCode, data)
		}
	}
	res, _ := transferRequest(t, server, http.MethodGet, "/report.txt?go-fs=send", session, nil)
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "POST" {
		t.Errorf("GET of the send answered %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/sub/?go-fs=send", session, good)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("a send of a folder answered %d", res.StatusCode)
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send", session, good,
		"Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a send from another site answered %d", res.StatusCode)
	}
}

func TestSendIsOfferedToASessionThatMayRead(t *testing.T) {
	const item = `data-do="send"`
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, readOnlyUser("reader", "pw"), config.User{
			Username: "blind", Password: "pw", HTTP: true, Paths: []string{"^/.*"},
			AllowUserFileCreate: new(true),
		})
	})
	server.write(t, "report.txt", "x")
	listing := func(session *http.Cookie, name, password string) string {
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
	if !strings.Contains(listing(login(t, server, "/", "reader", "pw"), "", ""), item) {
		t.Error("a session that may read is not offered Send")
	}
	if strings.Contains(listing(nil, "john", "doe"), item) {
		t.Error("a Basic header is offered Send")
	}
	body := sendBody{Host: "example.com"}
	res, _ := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", login(t, server, "/", "blind", "pw"), body)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a session that may not read answered %d", res.StatusCode)
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", nil, body)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a send without an account answered %d", res.StatusCode)
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", nil, body,
		"Authorization", "Basic "+basicToken("john", "doe"))
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a send with a Basic header answered %d", res.StatusCode)
	}
}

func TestSendsAreTransfersOfTheListing(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) {
		both := fullUser("both", "pw")
		both.Registry = true
		cfg.Users = append(cfg.Users, both)
	})
	release := make(chan struct{})
	defer close(release)
	block := func(ctx context.Context, job *registryJob) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-release:
			return "", nil
		}
	}
	job, err := server.startJob(jobSend, "both", "a send", block)
	if err != nil {
		t.Fatal(err)
	}
	session := login(t, server, "/", "both", "pw")
	res, _ := transferRequest(t, server, http.MethodGet, "/?go-fs=registry-job&id="+job.id, session, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("the registry answered %d for a send", res.StatusCode)
	}
	if _, ok := listedFetch(fetchList(t, server, "/", session), job.id); !ok {
		t.Error("the send is not among the transfers")
	}
	// sends and fetches share their limit
	for i := 1; i < maxRunningFetches; i++ {
		if _, err := server.startJob(jobFetch, "both", "a fetch", block); err != nil {
			t.Fatalf("fetch %d did not start: %v", i, err)
		}
	}
	if _, err := server.startJob(jobSend, "both", "a send", block); !errors.Is(err, errTooManyJobs) {
		t.Errorf("a send past the limit started: %v", err)
	}
}

func TestSendOffersOnlyTheAlgorithmsOfGeneralSSH(t *testing.T) {
	old := func(c *ssh.ServerConfig) { c.KeyExchanges = []string{ssh.InsecureKeyExchangeDH14SHA1} }
	remote := remotetest.NewSFTPHostWith(t, "alice", "secret", old)
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	keyOf := sendBody{Host: remote.Host, Port: remote.Port}
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", session, keyOf)
	if res.StatusCode != http.StatusBadGateway ||
		!strings.Contains(string(data), "offers no key exchange that general.ssh allows") ||
		!strings.Contains(string(data), ssh.InsecureKeyExchangeDH14SHA1) {
		t.Errorf("a host with only SHA-1 key exchange answered %d: %s", res.StatusCode, data)
	}

	server = newServer(t, func(c *httpConfig) {
		c.SSH.KeyExchanges = []string{ssh.KeyExchangeCurve25519, ssh.InsecureKeyExchangeDH14SHA1}
	})
	server.write(t, "report.txt", "x")
	session = login(t, server, "/", "john", "doe")
	res, data = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", session, keyOf)
	if res.StatusCode != http.StatusOK {
		t.Errorf("listed in general.ssh, the host has to be reached: %d %s", res.StatusCode, data)
	}
	res, data = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, sendTo(remote, ""))
	if res.StatusCode != http.StatusOK {
		t.Errorf("and logged in to: %d %s", res.StatusCode, data)
	}
}

// listingOf is the listing of the top folder, as a session sees it.
func listingOf(t *testing.T, server *testServer, session *http.Cookie) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.url("/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	return bodyOf(t, do(t, req))
}

// storedServer is a server the admin interface stored for the host, which
// allows everything.
func storedServer(h *remotetest.SFTPHost, name string) config.Server {
	return allowingAll(config.Server{Name: name, Type: config.ServerTypeSFTP, Host: h.Host, Port: h.Port,
		Username: "alice", Password: "secret", HostKeyFingerprint: h.Fingerprint})
}

// allowingAll is the server with every right switched on.
func allowingAll(server config.Server) config.Server {
	server.AllowDownload, server.AllowUpload, server.AllowCreate = ptr(true), ptr(true), ptr(true)
	server.AllowDelete, server.AllowRename = ptr(true), ptr(true)
	return server
}

func TestSendToAStoredServer(t *testing.T) {
	const password = "hunter2-of-the-backup"
	remote := remotetest.NewSFTPHost(t, "alice", password)
	remote.Write(t, "inbox/.keep", "")
	server := newServer(t, func(cfg *httpConfig) {
		backup := storedServer(remote, "Backup")
		backup.Password = password
		cfg.Servers = []config.Server{backup}
	})
	server.write(t, "report.txt", "the report")
	session := login(t, server, "/", "john", "doe")

	// the listing names the server, and nothing of its login
	listing := listingOf(t, server, session)
	if !strings.Contains(listing, `<option value="Backup">Backup</option>`) {
		t.Error("the listing does not offer the stored server")
	}
	if strings.Contains(listing, password) || strings.Contains(listing, remote.Fingerprint) {
		t.Error("the listing shows the login of the stored server")
	}

	// the name alone, in whatever case, is enough to browse the server
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session,
		sendBody{Server: "backup"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("browsing the stored server answered %d: %s", res.StatusCode, data)
	}
	var home sendFolderJSON
	if err := json.Unmarshal(data, &home); err != nil {
		t.Fatal(err)
	}
	if home.Path != remotetest.Path(remote.Dir) || !strings.HasPrefix(home.Base, "sftp://") {
		t.Errorf("the stored server starts in %q at %q", home.Path, home.Base)
	}

	// what the body says beside the name is not used: the login is the
	// server's
	folder := remotetest.Path(filepath.Join(remote.Dir, "inbox"))
	job := startSend(t, server, "/report.txt", session,
		sendBody{Server: "Backup", Host: "elsewhere.example", Username: "mallory", Password: "x", Path: folder})
	ended := waitForFetch(t, server, "/", job.ID, session)
	expectDone(t, ended)
	stored, err := os.ReadFile(filepath.Join(remote.Dir, "inbox", "report.txt"))
	if err != nil || string(stored) != "the report" {
		t.Errorf("the host stored %q, %v", stored, err)
	}
	if strings.Contains(ended.What, password) || strings.Contains(ended.Message, password) {
		t.Errorf("the job shows the password: %q, %q", ended.What, ended.Message)
	}
	record := server.logs.find("http send")
	if record == nil {
		t.Fatal("the send was not logged")
	}
	if logged, _ := json.Marshal(record); strings.Contains(string(logged), password) ||
		!strings.Contains(string(logged), "Backup") {
		t.Errorf("the log of the send is %s", logged)
	}
}

func TestSendRefusesWhatAStoredServerIsNot(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	moved := storedServer(remote, "Moved")
	moved.HostKeyFingerprint = "SHA256:theOneBefore"
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Servers = []config.Server{storedServer(remote, "Backup"), moved}
	})
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	for _, tc := range []struct {
		action string
		body   sendBody
	}{
		{actionSendBrowse, sendBody{Server: "nobody"}},
		// a stored server's key was accepted when it was stored
		{actionSendHostKey, sendBody{Server: "Backup"}},
		{actionSend, sendBody{Server: "Backup"}},
		// a login typed in by a protocol go-fs does not know
		{actionSendHostKey, sendBody{Protocol: "gopher", Host: remote.Host, Port: remote.Port}},
	} {
		res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs="+tc.action, session, tc.body)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s %+v answered %d: %s", tc.action, tc.body, res.StatusCode, data)
		}
	}

	// a server that shows another key than the one stored is not logged in
	// to, and the user is told who can change that
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session,
		sendBody{Server: "Moved"})
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "an administrator has to edit the server") {
		t.Errorf("a changed key answered %d: %s", res.StatusCode, data)
	}
	if n := remote.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered to a host with another key", n)
	}

	// the login typed in names its protocol, or none
	res, data = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", session,
		sendBody{Protocol: config.ServerTypeSFTP, Host: remote.Host, Port: remote.Port})
	if res.StatusCode != http.StatusOK {
		t.Errorf("a login typed in for sftp answered %d: %s", res.StatusCode, data)
	}
}

func TestSendDialogFollowsTheStoredServers(t *testing.T) {
	remote := remotetest.NewSFTPHost(t, "alice", "secret")
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")
	listing := listingOf(t, server, session)
	if !strings.Contains(listing, `<option value="" selected>Manual</option>`) || strings.Contains(listing, `<option value="Backup"`) {
		t.Error("without stored servers, the dialog offers Manual alone")
	}

	set := server.settings()
	if err := server.Reload(set.cfg, set.https, set.ssh, []config.User{fullUser("john", "doe")}, nil,
		[]config.Server{storedServer(remote, "Backup")}); err != nil {
		t.Fatal(err)
	}
	listing = listingOf(t, server, session)
	if !strings.Contains(listing, `<option value="Backup">Backup</option>`) {
		t.Error("a reload does not offer the server it adds")
	}
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session,
		sendBody{Server: "Backup"})
	if res.StatusCode != http.StatusOK {
		t.Errorf("the server a reload added answered %d: %s", res.StatusCode, data)
	}
}

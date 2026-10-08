package httpd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
)

// sftpHost is an SFTP server a test sends to. It serves dir, which is also
// where a login starts, and takes one login.
type sftpHost struct {
	host        string
	port        int
	dir         string
	fingerprint string
	// logins counts the logins offered to it, right or wrong.
	logins atomic.Int32
	// slow is how long every read of what a client sent waits, which holds a
	// send up for a test that stops it.
	slow atomic.Int64
}

func newSFTPHost(t *testing.T, username, password string) *sftpHost {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	remote := &sftpHost{dir: t.TempDir(), fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, given []byte) (*ssh.Permissions, error) {
			remote.logins.Add(1)
			if meta.User() == username && string(given) == password {
				return nil, nil
			}
			return nil, errors.New("wrong login")
		},
	}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	remote.host, remote.port = addr.IP.String(), addr.Port

	var mu sync.Mutex
	var conns []net.Conn
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				remote.serve(conn, serverConfig)
			}()
		}
	}()
	return remote
}

func (h *sftpHost) serve(conn net.Conn, serverConfig *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	_, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for incoming := range chans {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range requests {
				ok := req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
				_ = req.Reply(ok, nil)
				if !ok {
					continue
				}
				go func() {
					defer func() { _ = channel.Close() }()
					server, err := sftp.NewServer(slowChannel{channel, h}, sftp.WithServerWorkingDirectory(h.dir))
					if err != nil {
						return
					}
					_ = server.Serve()
				}()
			}
		}()
	}
}

// slowChannel is the channel of an SFTP session, which reads as slowly as the
// host is told to.
type slowChannel struct {
	ssh.Channel
	host *sftpHost
}

func (c slowChannel) Read(b []byte) (int, error) {
	if wait := time.Duration(c.host.slow.Load()); wait > 0 {
		time.Sleep(wait)
	}
	return c.Channel.Read(b)
}

// sftpPath is a local path as an SFTP server names it: with slashes, and on
// Windows with a slash before the drive letter.
func sftpPath(p string) string {
	p = filepath.ToSlash(p)
	if len(p) > 1 && p[1] == ':' {
		p = "/" + p
	}
	return p
}

// body is a send to the host, as the dialog asks for one once the key was
// accepted.
func (h *sftpHost) body(path string) sendBody {
	return sendBody{Host: h.host, Port: h.port, Username: "alice", Password: "secret",
		HostKey: h.fingerprint, Path: path}
}

func (h *sftpHost) write(t *testing.T, name, content string) {
	t.Helper()
	full := filepath.Join(h.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// leftovers are the files of a folder of the host a send writes under a
// name of its own.
func (h *sftpHost) leftovers(t *testing.T, name string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(h.dir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".part") {
			found = append(found, entry.Name())
		}
	}
	return found
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
	remote := newSFTPHost(t, "alice", "secret")
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-hostkey", session,
		sendBody{Host: remote.host, Port: remote.port})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the host key answered %d: %s", res.StatusCode, data)
	}
	var view sendHostKeyJSON
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	if view.Fingerprint != remote.fingerprint || view.KeyType != ssh.KeyAlgoED25519 {
		t.Errorf("the key is %+v, want %s", view, remote.fingerprint)
	}
	if view.Host != net.JoinHostPort(remote.host, strconv.Itoa(remote.port)) {
		t.Errorf("the host is shown as %q", view.Host)
	}
	if n := remote.logins.Load(); n != 0 {
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
	remote := newSFTPHost(t, "alice", "secret")
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	body := remote.body("")
	body.HostKey = "SHA256:somebodyElse"
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, body)
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "not the one that was accepted") {
		t.Errorf("another key answered %d: %s", res.StatusCode, data)
	}
	if n := remote.logins.Load(); n != 0 {
		t.Errorf("%d logins were offered to a host with another key", n)
	}

	body = remote.body("")
	body.Password = "wrong"
	res, data = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, body)
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "refused the login") {
		t.Errorf("a wrong password answered %d: %s", res.StatusCode, data)
	}
}

func TestSendListsTheFoldersOfTheHost(t *testing.T) {
	remote := newSFTPHost(t, "alice", "secret")
	remote.write(t, "zeta.txt", "z")
	remote.write(t, "Beta/inside.txt", "in")
	remote.write(t, "alpha/deeper/x.txt", "x")
	server := newServer(t, nil)
	server.write(t, "report.txt", "x")
	session := login(t, server, "/", "john", "doe")

	browse := func(path string) sendFolderJSON {
		t.Helper()
		res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session, remote.body(path))
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
	if home.Path != sftpPath(remote.dir) {
		t.Errorf("the login starts in %q, want %q", home.Path, remote.dir)
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
	if home.Parent != sftpPath(filepath.Dir(remote.dir)) {
		t.Errorf("the parent is %q", home.Parent)
	}

	inner := browse(home.Path + "/alpha")
	if len(inner.Entries) != 1 || inner.Entries[0].Name != "deeper" || inner.Parent != home.Path {
		t.Errorf("the subfolder is %+v", inner)
	}
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session,
		remote.body(home.Path+"/missing"))
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "there is no folder") {
		t.Errorf("a missing folder answered %d: %s", res.StatusCode, data)
	}
}

func TestSendUploadsTheFile(t *testing.T) {
	remote := newSFTPHost(t, "alice", "secret")
	remote.write(t, "inbox/.keep", "")
	server := newServer(t, nil)
	content := strings.Repeat("the report\n", 50000)
	server.mkdir(t, "docs")
	server.write(t, "docs/report.txt", content)
	session := login(t, server, "/", "john", "doe")

	folder := sftpPath(filepath.Join(remote.dir, "inbox"))
	job := startSend(t, server, "/docs/report.txt", session, remote.body(folder))
	ended := waitForFetch(t, server, "/", job.ID, session)
	expectDone(t, ended)
	stored, err := os.ReadFile(filepath.Join(remote.dir, "inbox", "report.txt"))
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
	if left := remote.leftovers(t, "inbox"); len(left) != 0 {
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
	remote := newSFTPHost(t, "alice", "secret")
	remote.write(t, "report.txt", "the old one, which was longer")
	server := newServer(t, nil)
	server.write(t, "report.txt", "the new one")
	session := login(t, server, "/", "john", "doe")

	job := startSend(t, server, "/report.txt", session, remote.body(sftpPath(remote.dir)))
	expectDone(t, waitForFetch(t, server, "/", job.ID, session))
	stored, err := os.ReadFile(filepath.Join(remote.dir, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != "the new one" {
		t.Errorf("the host holds %q", stored)
	}

	// a folder of that name is not replaced
	remote.write(t, "taken/report.txt/inside", "x")
	job = startSend(t, server, "/report.txt", session, remote.body(sftpPath(filepath.Join(remote.dir, "taken"))))
	expectFailed(t, waitForFetch(t, server, "/", job.ID, session), "is a folder")
}

func TestSendCanBeStopped(t *testing.T) {
	remote := newSFTPHost(t, "alice", "secret")
	server := newServer(t, nil)
	server.write(t, "big.bin", strings.Repeat("x", 16<<20))
	session := login(t, server, "/", "john", "doe")

	remote.slow.Store(int64(20 * time.Millisecond))
	job := startSend(t, server, "/big.bin", session, remote.body(sftpPath(remote.dir)))
	waitForDownload(t, server, "/", job.ID, session)
	res, data := transferRequest(t, server, http.MethodDelete, "/?go-fs=fetch-job&id="+job.ID, session, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the stop answered %d: %s", res.StatusCode, data)
	}
	remote.slow.Store(0)
	if ended := waitForFetch(t, server, "/", job.ID, session); ended.State != jobCancelled {
		t.Errorf("the send ended %s: %s", ended.State, ended.Message)
	}
	if _, err := os.Stat(filepath.Join(remote.dir, "big.bin")); err == nil {
		t.Error("a stopped send stored its file")
	}
	if left := remote.leftovers(t, "."); len(left) != 0 {
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

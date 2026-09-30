package httpd

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

func TestDownload(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/hello.iso", "iso payload")

	res := basic(t, server, http.MethodGet, "/private/hello.iso", "john", "doe", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "iso payload" {
		t.Fatalf("status %d body %q", res.StatusCode, body)
	}
	if got := res.Header.Get("Content-Type"); got != "application/x-iso9660-image" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := res.Header.Get("Content-Disposition"); got != `attachment; filename="hello.iso"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := res.Header.Get("Content-Length"); got != "11" {
		t.Errorf("Content-Length = %q", got)
	}
	if record := server.logs.find("http download"); record == nil {
		t.Error("a download has to be reported")
	} else if record["file"] != "/private/hello.iso" {
		t.Errorf("download record = %v", record)
	}
}

// ServeContent answers a range request, which the Node implementation could
// not, so a large download can be resumed.
func TestRangeRequest(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/big.bin", "0123456789")

	req, _ := http.NewRequest(http.MethodGet, server.url("/private/big.bin"), nil)
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Range", "bytes=2-5")
	res := do(t, req)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusPartialContent || string(body) != "2345" {
		t.Errorf("status %d body %q", res.StatusCode, body)
	}
}

func TestUploadBinary(t *testing.T) {
	server := newServer(t, nil)

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/sub/new.txt"),
		strings.NewReader("uploaded"))
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	if res := do(t, req); res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	// the folders above the file are created
	if got := server.read(t, "private/sub/new.txt"); got != "uploaded" {
		t.Errorf("stored %q", got)
	}
	if record := server.logs.find("http upload"); record == nil {
		t.Error("an upload has to be reported")
	} else if record["bytes"] != int64(8) {
		t.Errorf("upload record = %v", record)
	}
}

// A slow upload whose total duration is longer than readTimeout must still
// succeed as long as no single gap between chunks is: readTimeout bounds how
// long an upload may stall, not how long it may take overall. This is what
// used to abort large uploads partway through at an arbitrary point, because
// readTimeout was wired into http.Server's own ReadTimeout, which caps the
// entire request.
func TestUploadSurvivesBeingSlowerThanReadTimeout(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.ReadTimeout = 1 })

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/slow.txt"),
		&trickleReader{chunks: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")},
			delay: 400 * time.Millisecond})
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	if res := do(t, req); res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := server.read(t, "private/slow.txt"); got != "abcd" {
		t.Errorf("stored %q", got)
	}
}

// A stall longer than readTimeout still has to fail: the idle timeout is a
// safety net, not a timeout that only applied by accident.
func TestUploadFailsOnARealStall(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.ReadTimeout = 1 })

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/stalled.txt"),
		&trickleReader{chunks: [][]byte{[]byte("a"), []byte("b")}, delay: 2 * time.Second})
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := (&http.Client{}).Do(req)
	// the server may answer with an error before the client even finishes
	// writing the stalled body, rather than the connection failing outright,
	// so either counts as the stall being caught
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Fatalf("a stalled upload has to fail rather than succeed, got %d", res.StatusCode)
		}
	}
}

// trickleReader hands out its chunks one at a time, pausing before each.
type trickleReader struct {
	chunks [][]byte
	delay  time.Duration
}

func (r *trickleReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	time.Sleep(r.delay)
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

func TestUploadMultipart(t *testing.T) {
	server := newServer(t, nil)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "whatever.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("from a form")); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/form.txt"), &body)
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if res := do(t, req); res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if got := server.read(t, "private/form.txt"); got != "from a form" {
		t.Errorf("stored %q", got)
	}
}

// A PUT replaces what is already there only for an account granted
// allowUserFileOverwrite; without the right the name is taken, as in the
// original.
func TestUploadReplacesOnlyWithTheRight(t *testing.T) {
	put := func(t *testing.T, server *testServer, user, password string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, server.url("/private/exists.txt"),
			strings.NewReader("replacement"))
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		return do(t, req).StatusCode
	}

	t.Run("without the right", func(t *testing.T) {
		server := newServer(t, func(cfg *httpConfig) {
			user := fullUser("john", "doe")
			user.AllowUserFileOverwrite = new(false)
			cfg.Users = []config.User{user}
		})
		server.write(t, "private/exists.txt", "original")
		if status := put(t, server, "john", "doe"); status != http.StatusForbidden {
			t.Errorf("status = %d, want 403", status)
		}
		if got := server.read(t, "private/exists.txt"); got != "original" {
			t.Errorf("the file was changed to %q", got)
		}
	})

	t.Run("with the right", func(t *testing.T) {
		server := newServer(t, nil)
		server.write(t, "private/exists.txt", "original")
		if status := put(t, server, "john", "doe"); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
		if got := server.read(t, "private/exists.txt"); got != "replacement" {
			t.Errorf("the file holds %q, want it replaced", got)
		}
	})

	// a public PUT never replaced a file, and being public is not a right
	t.Run("public", func(t *testing.T) {
		server := newServer(t, publicServer)
		server.write(t, "private/exists.txt", "original")
		if status := put(t, server, "", ""); status != http.StatusForbidden {
			t.Errorf("status = %d, want 403", status)
		}
		if got := server.read(t, "private/exists.txt"); got != "original" {
			t.Errorf("the file was changed to %q", got)
		}
	})
}

func TestUploadSizeLimit(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.MaxUploadSize = 8 })

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/big.txt"),
		strings.NewReader("far more than eight bytes"))
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	if res := do(t, req); res.StatusCode == http.StatusOK {
		t.Error("an upload past maxUploadSize has to fail")
	}
	if _, err := os.Stat(filepath.Join(server.base, "private", "big.txt")); !os.IsNotExist(err) {
		t.Error("the partial file has to be removed")
	}
}

func TestDelete(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/gone.txt", "x")
	server.write(t, "private/full/keep.txt", "x")
	if err := os.Mkdir(filepath.Join(server.base, "private", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	if res := basic(t, server, http.MethodDelete, "/private/gone.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("deleting a file got %d", res.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(server.base, "private", "gone.txt")); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}

	if res := basic(t, server, http.MethodDelete, "/private/empty", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("deleting an empty folder got %d", res.StatusCode)
	}
	// a folder with something in it is left alone
	if res := basic(t, server, http.MethodDelete, "/private/full", "john", "doe", nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("deleting a full folder got %d, want 404", res.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(server.base, "private", "full")); err != nil {
		t.Error("the folder that is not empty was removed")
	}
}

// Each right is granted explicitly, so an account without one is refused.
func TestPermissionsAreEnforced(t *testing.T) {
	// without names the one right each case takes away
	without := func(take func(*config.User)) config.User {
		user := fullUser("john", "doe")
		take(&user)
		return user
	}
	cases := []struct {
		name   string
		user   config.User
		method string
		path   string
		want   int
	}{
		{"read denied", without(func(u *config.User) { u.AllowUserFileRetrieve = new(false) }),
			http.MethodGet, "/private/hello.txt", http.StatusForbidden},
		{"listing denied", without(func(u *config.User) { u.AllowUserFileRetrieve = new(false) }),
			http.MethodGet, "/private/", http.StatusForbidden},
		{"create denied", without(func(u *config.User) { u.AllowUserFileCreate = new(false) }),
			http.MethodPut, "/private/new.txt", http.StatusForbidden},
		{"overwrite denied", without(func(u *config.User) { u.AllowUserFileOverwrite = new(false) }),
			http.MethodPut, "/private/hello.txt", http.StatusForbidden},
		// the rights are read separately, so the one does not stand in for the other
		{"create is not overwrite", without(func(u *config.User) { u.AllowUserFileCreate = new(false) }),
			http.MethodPut, "/private/hello.txt", http.StatusOK},
		{"overwrite is not create", without(func(u *config.User) { u.AllowUserFileOverwrite = new(false) }),
			http.MethodPut, "/private/new.txt", http.StatusOK},
		{"file delete denied", without(func(u *config.User) { u.AllowUserFileDelete = new(false) }),
			http.MethodDelete, "/private/hello.txt", http.StatusForbidden},
		{"folder delete denied", without(func(u *config.User) { u.AllowUserFolderDelete = new(false) }),
			http.MethodDelete, "/private/empty/", http.StatusForbidden},
		{"file delete is not folder delete", without(func(u *config.User) { u.AllowUserFileDelete = new(false) }),
			http.MethodDelete, "/private/empty/", http.StatusOK},
		{"folder delete is not file delete", without(func(u *config.User) { u.AllowUserFolderDelete = new(false) }),
			http.MethodDelete, "/private/hello.txt", http.StatusOK},
		{"mkcol denied", without(func(u *config.User) { u.AllowUserFolderCreate = new(false) }),
			methodMkcol, "/private/made/", http.StatusForbidden},
		{"path denied", without(func(u *config.User) { u.Paths = []string{"^/elsewhere/.*"} }),
			http.MethodGet, "/private/hello.txt", http.StatusForbidden},
		{"no path at all", without(func(u *config.User) { u.Paths = nil }),
			http.MethodGet, "/private/hello.txt", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newServer(t, func(cfg *httpConfig) {
				cfg.Users = []config.User{tc.user}
			})
			server.write(t, "private/hello.txt", "hello")
			server.mkdir(t, "private/empty")

			var body io.Reader
			if tc.method == http.MethodPut {
				body = strings.NewReader("x")
			}
			req, _ := http.NewRequest(tc.method, server.url(tc.path), body)
			req.SetBasicAuth("john", "doe")
			req.Header.Set("Content-Type", "application/octet-stream")
			if res := do(t, req); res.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", res.StatusCode, tc.want)
			}
		})
	}
}

// The served folder is the whole of the filesystem a client can reach, whether
// it climbs out with .. or follows a symbolic link out.
func TestConfinement(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = nil
		cfg.PathsRequireAuth = nil
	})
	server.write(t, "hello.txt", "hello")
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(server.base, "escape.txt")); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/../../etc/hosts", "/sub/../../../etc/hosts", "/escape.txt"} {
		res, body := get(t, server, path)
		if res.StatusCode == http.StatusOK && strings.Contains(body, "secret") {
			t.Errorf("%s leaked content", path)
		}
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, res.StatusCode)
		}
	}
	if res, body := get(t, server, "/hello.txt"); res.StatusCode != http.StatusOK || body != "hello" {
		t.Errorf("a file inside the folder got %d %q", res.StatusCode, body)
	}
}

// A path regex is matched after normalization, so ".." cannot be used to get
// inside a pattern and then climb out of it again.
func TestPathPatternsCannotBeWalkedAround(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = []string{"^/.*"}
		cfg.Users = []config.User{{
			Username: "john", Password: "doe", HTTP: true, Paths: []string{"^/public/.*"},
			AllowUserFileRetrieve: new(true),
		}}
	})
	server.write(t, "public/fine.txt", "fine")
	server.write(t, "secret.txt", "secret")

	if res := basic(t, server, http.MethodGet, "/public/fine.txt", "john", "doe", nil); res.StatusCode != http.StatusOK {
		t.Errorf("the allowed path got %d", res.StatusCode)
	}
	// this normalizes to /secret.txt, which the pattern does not cover
	res := basic(t, server, http.MethodGet, "/public/../secret.txt", "john", "doe", nil)
	body, _ := io.ReadAll(res.Body)
	if strings.Contains(string(body), "secret") {
		t.Fatal("the pattern was walked around")
	}
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.StatusCode)
	}
}

func TestCleanupKeepsTheNewest(t *testing.T) {
	base := t.TempDir()
	for i, name := range []string{"old3.iso", "old2.iso", "old1.iso", "new2.iso", "new1.iso"} {
		path := filepath.Join(base, "iso", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(time.Duration(i-10) * time.Hour)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}

	server := newServer(t, func(cfg *httpConfig) {
		cfg.Basefolder = base
		cfg.Cleanup = []config.Cleanup{{Path: "/iso", Keep: 2}}
	})
	// the sweep runs at startup; wait for it to report
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && server.logs.find("http cleanup removed a file") == nil {
		time.Sleep(20 * time.Millisecond)
	}

	left, err := os.ReadDir(filepath.Join(base, "iso"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 2 {
		t.Fatalf("%d files left, want 2", len(left))
	}
	kept := map[string]bool{left[0].Name(): true, left[1].Name(): true}
	if !kept["new1.iso"] || !kept["new2.iso"] {
		t.Errorf("the wrong files were kept: %v", kept)
	}
}

// The limit belongs on the request body itself: the multipart parser reads the
// body directly, so a limit put on a reader derived from it would leave a
// multipart upload unbounded.
func TestUploadSizeLimitCoversMultipart(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.MaxUploadSize = 64 })

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "big.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(strings.Repeat("x", 4096))); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	payload := append([]byte(nil), body.Bytes()...)

	// with a declared length, which is what every ordinary client sends
	req, _ := http.NewRequest(http.MethodPut, server.url("/private/big.txt"),
		bytes.NewReader(payload))
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if res := do(t, req); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", res.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(server.base, "private", "big.txt")); !os.IsNotExist(err) {
		t.Error("nothing has to be left behind")
	}

	// and without one: the body is cut short mid-part, which the multipart
	// parser calls malformed. What the client did is send too much, and that is
	// what it has to be told.
	chunked, _ := http.NewRequest(http.MethodPut, server.url("/private/chunked.txt"),
		io.NopCloser(bytes.NewReader(payload)))
	chunked.ContentLength = -1
	chunked.SetBasicAuth("john", "doe")
	chunked.Header.Set("Content-Type", writer.FormDataContentType())
	if res := do(t, chunked); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked status = %d, want 413", res.StatusCode)
	}
}

// An upload above the limit is what the client did, not a server error.
func TestUploadTooLargeIsReportedAsSuch(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.MaxUploadSize = 8 })

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/big.txt"),
		strings.NewReader("far more than eight bytes"))
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	if res := do(t, req); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", res.StatusCode)
	}
}

// The links in a listing are relative, so a folder reached without its trailing
// slash is redirected to the form they are relative to.
func TestFolderRedirectsToTheSlashedForm(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	server.write(t, "photos/sub/inside.txt", "inside")

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Get(server.url("/photos"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "/photos/" {
		t.Errorf("Location = %q, want %q", got, "/photos/")
	}

	// and the slashed form is served, with links that point inside it
	answer, body := get(t, server, "/photos/")
	if answer.StatusCode != http.StatusOK || !strings.Contains(body, `<a href="sub/">`) {
		t.Errorf("status %d, body %q", answer.StatusCode, body)
	}
}

// A name that a header cannot carry as it is keeps a readable ASCII form and
// carries the real one beside it.
func TestDispositionOfANonASCIIName(t *testing.T) {
	got := disposition("Grüße.txt")
	want := `attachment; filename="Gr__e.txt"; filename*=UTF-8''Gr%C3%BC%C3%9Fe.txt`
	if got != want {
		t.Errorf("disposition = %q, want %q", got, want)
	}
	if got := disposition(`odd"name.txt`); got != `attachment; filename="odd\"name.txt"` {
		t.Errorf("a quote in the name is not escaped: %q", got)
	}
}

// maxUploadSize is a limit on the file, not on the request that carries it: the
// same file has to be accepted whether it is sent as octet-stream or wrapped in
// a multipart form, whose boundaries and headers are not part of it.
func TestUploadSizeLimitCountsTheFileNotTheEnvelope(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) { cfg.MaxUploadSize = 64 })
	content := strings.Repeat("z", 60)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "small.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if body.Len() <= 64 {
		t.Fatalf("the envelope should make the body larger than the limit, it is %d", body.Len())
	}

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/small.txt"), &body)
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if res := do(t, req); res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := server.read(t, "private/small.txt"); got != content {
		t.Errorf("stored %d bytes, want %d", len(got), len(content))
	}
}

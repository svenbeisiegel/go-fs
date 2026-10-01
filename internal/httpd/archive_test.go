package httpd

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"

	"go-fs/internal/config"
)

// folderMark is what unpack records for a folder in place of content.
const folderMark = "<folder>"

// unpack reads a tar.xz into its entries: the name, and what the file holds
// or folderMark.
func unpack(t *testing.T, body []byte) map[string]string {
	t.Helper()
	decompressed, err := xz.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("not an xz stream: %v", err)
	}
	archive := tar.NewReader(decompressed)
	entries := map[string]string{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatalf("not a tar archive: %v", err)
		}
		if header.Typeflag == tar.TypeDir {
			entries[header.Name] = folderMark
			continue
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = string(content)
	}
}

func readAll(t *testing.T, res *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestArchivePacksTheFolder(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "sub/top.txt", "top")
	server.write(t, "sub/deeper/inside.txt", "inside")
	server.mkdir(t, "sub/empty")
	server.write(t, "beside.txt", "not in it")

	res := basic(t, server, http.MethodGet, "/sub/?go-fs=archive", "john", "doe", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); got != "application/x-xz" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := res.Header.Get("Content-Disposition"); got != `attachment; filename="sub.tar.xz"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	entries := unpack(t, readAll(t, res))
	want := map[string]string{
		"sub/":                  folderMark,
		"sub/top.txt":           "top",
		"sub/deeper/":           folderMark,
		"sub/deeper/inside.txt": "inside",
		"sub/empty/":            folderMark,
	}
	if len(entries) != len(want) {
		t.Errorf("entries = %v, want %v", entries, want)
	}
	for name, content := range want {
		if entries[name] != content {
			t.Errorf("%s = %q, want %q", name, entries[name], content)
		}
	}

	record := server.logs.find("http archive download")
	if record == nil {
		t.Fatal("an archive download has to be reported")
	}
	if record["folder"] != "/sub" || record["user"] != "john" || record["files"] != int64(2) {
		t.Errorf("archive record = %v", record)
	}
}

// The marker names the folder itself, so it is answered without the redirect
// a listing needs for its relative links.
func TestArchiveNeedsNoTrailingSlash(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "sub/top.txt", "top")

	res, body := get(t, server, "/sub?go-fs=archive")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if entries := unpack(t, []byte(body)); entries["sub/top.txt"] != "top" {
		t.Errorf("entries = %v", entries)
	}
}

// A file is a file, whatever the query says.
func TestArchiveMarkerOnAFileServesTheFile(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "one.txt", "plain")

	res, body := get(t, server, "/one.txt?go-fs=archive")
	if res.StatusCode != http.StatusOK || body != "plain" {
		t.Errorf("status = %d, body = %q", res.StatusCode, body)
	}
}

func TestArchiveOfTheServedFolderIsNamedAfterIt(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "one.txt", "x")

	res, body := get(t, server, "/?go-fs=archive")
	name := filepath.Base(server.base)
	if got := res.Header.Get("Content-Disposition"); !strings.Contains(got, `filename="`+name+`.tar.xz"`) {
		t.Errorf("Content-Disposition = %q, want the name %q", got, name)
	}
	if entries := unpack(t, []byte(body)); entries[name+"/one.txt"] != "x" {
		t.Errorf("entries = %v", entries)
	}
}

func TestArchiveCarriesANameThatIsNotASCII(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "Bücher/one.txt", "x")

	res, body := get(t, server, "/B%C3%BCcher/?go-fs=archive")
	got := res.Header.Get("Content-Disposition")
	if !strings.Contains(got, "filename*=UTF-8''B%C3%BCcher.tar.xz") {
		t.Errorf("Content-Disposition = %q", got)
	}
	if entries := unpack(t, []byte(body)); entries["Bücher/one.txt"] != "x" {
		t.Errorf("entries = %v", entries)
	}
}

// What a GET of an entry would refuse is left out of the archive of the
// folder above it, rather than handed over because that folder was open.
func TestArchiveLeavesOutProtectedPaths(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "open.txt", "open")
	server.write(t, "private/secret.txt", "secret")

	name := filepath.Base(server.base)
	_, body := get(t, server, "/?go-fs=archive")
	entries := unpack(t, []byte(body))
	if entries[name+"/open.txt"] != "open" {
		t.Errorf("the open file is missing: %v", entries)
	}
	for entry := range entries {
		if strings.Contains(entry, "private") {
			t.Errorf("a public archive carries %q", entry)
		}
	}

	// the account that may read it gets it
	res := basic(t, server, http.MethodGet, "/?go-fs=archive", "john", "doe", nil)
	if entries := unpack(t, readAll(t, res)); entries[name+"/private/secret.txt"] != "secret" {
		t.Errorf("the account's archive is missing the protected file: %v", entries)
	}
}

func TestArchiveFollowsTheAccountsPaths(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		scoped := fullUser("scoped", "pw")
		scoped.Paths = []string{"^/sub/(open/.*)?$"}
		cfg.Users = []config.User{scoped}
		cfg.PathsRequireAuth = []string{"^/.*"}
	})
	server.write(t, "sub/open/a.txt", "a")
	server.write(t, "sub/closed/b.txt", "b")
	server.write(t, "sub/top.txt", "top")

	res := basic(t, server, http.MethodGet, "/sub/?go-fs=archive", "scoped", "pw", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	entries := unpack(t, readAll(t, res))
	if entries["sub/open/a.txt"] != "a" {
		t.Errorf("the reachable file is missing: %v", entries)
	}
	for _, gone := range []string{"sub/closed/", "sub/closed/b.txt", "sub/top.txt"} {
		if _, ok := entries[gone]; ok {
			t.Errorf("the archive carries %q, which the account may not read", gone)
		}
	}
}

// The archive needs what listing the folder needs.
func TestArchiveOfAProtectedFolderNeedsAnAccount(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/secret.txt", "secret")

	if res, _ := get(t, server, "/private/?go-fs=archive"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", res.StatusCode)
	}
	res := basic(t, server, http.MethodGet, "/private/?go-fs=archive", "john", "doe", nil)
	if entries := unpack(t, readAll(t, res)); entries["private/secret.txt"] != "secret" {
		t.Errorf("entries = %v", entries)
	}
}

// A link goes in as the file it points to while that is inside the served
// folder, and not at all where it leads out of it.
func TestArchiveFollowsOnlyLinksThatStayInside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	server := newServer(t, nil)
	server.write(t, "sub/real.txt", "real")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(server.base, "sub", "out.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(server.base, "sub", "real.txt"), filepath.Join(server.base, "sub", "in.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(server.base, filepath.Join(server.base, "sub", "loop")); err != nil {
		t.Fatal(err)
	}

	_, body := get(t, server, "/sub/?go-fs=archive")
	entries := unpack(t, []byte(body))
	if entries["sub/in.txt"] != "real" {
		t.Errorf("a link inside is not carried as its file: %v", entries)
	}
	for _, gone := range []string{"sub/out.txt", "sub/loop", "sub/loop/"} {
		if _, ok := entries[gone]; ok {
			t.Errorf("the archive carries %q", gone)
		}
	}
}

func TestArchiveHeadHasNoBody(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "sub/top.txt", "top")

	req, err := http.NewRequest(http.MethodHead, server.url("/sub/?go-fs=archive"), nil)
	if err != nil {
		t.Fatal(err)
	}
	res := do(t, req)
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/x-xz" {
		t.Errorf("status = %d, Content-Type = %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if body := readAll(t, res); len(body) != 0 {
		t.Errorf("a HEAD carries %d bytes", len(body))
	}
}

package httpd

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
)

// chunkedServer is newServer with a staging folder of its own, isolated from
// the OS temp directory every other test would otherwise share.
func chunkedServer(t *testing.T, tune func(*httpConfig)) *testServer {
	t.Helper()
	staging := t.TempDir()
	return newServer(t, func(cfg *httpConfig) {
		cfg.UploadStagingFolder = staging
		if tune != nil {
			tune(cfg)
		}
	})
}

// putChunk sends one Content-Range chunk as john/doe.
func putChunk(t *testing.T, server *testServer, path string, start, end, total int64, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, server.url(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
	return do(t, req)
}

// putChunkRaw is putChunk without any *testing.T calls, safe to use from a
// goroutine that is not the one running the test.
func putChunkRaw(server *testServer, path string, start, end, total int64, body string) (int, error) {
	req, err := http.NewRequest(http.MethodPut, server.url(path), strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode, nil
}

func TestChunkedUploadHappyPath(t *testing.T) {
	server := chunkedServer(t, nil)

	if res := putChunk(t, server, "/private/big.iso", 0, 3, 10, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("chunk 1 status = %d, want 200", res.StatusCode)
	}
	if res := putChunk(t, server, "/private/big.iso", 4, 7, 10, "efgh"); res.StatusCode != http.StatusOK {
		t.Fatalf("chunk 2 status = %d, want 200", res.StatusCode)
	}
	if res := putChunk(t, server, "/private/big.iso", 8, 9, 10, "ij"); res.StatusCode != http.StatusCreated {
		t.Fatalf("final chunk status = %d, want 201", res.StatusCode)
	}

	if got := server.read(t, "private/big.iso"); got != "abcdefghij" {
		t.Errorf("stored %q", got)
	}
	record := server.logs.find("http upload")
	if record == nil {
		t.Fatal("a chunked upload has to be reported")
	}
	if record["bytes"] != int64(10) || record["chunked"] != true {
		t.Errorf("upload record = %v", record)
	}
}

// A chunk whose start does not match what the server has staged is refused
// with 416 naming the offset that would have fit, and the upload can still be
// finished by sending the right one afterwards.
func TestChunkedUploadOutOfOrderChunkIsRejected(t *testing.T) {
	server := chunkedServer(t, nil)

	if res := putChunk(t, server, "/private/big.iso", 0, 3, 10, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("chunk 1 status = %d, want 200", res.StatusCode)
	}

	res := putChunk(t, server, "/private/big.iso", 8, 9, 10, "ij")
	if res.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416", res.StatusCode)
	}
	if got := res.Header.Get("Content-Range"); got != "bytes */4" {
		t.Errorf("Content-Range = %q, want the real offset", got)
	}

	if res := putChunk(t, server, "/private/big.iso", 4, 9, 10, "efghij"); res.StatusCode != http.StatusCreated {
		t.Fatalf("recovering chunk status = %d, want 201", res.StatusCode)
	}
	if got := server.read(t, "private/big.iso"); got != "abcdefghij" {
		t.Errorf("stored %q", got)
	}
}

// A chunk that fails partway through is undone back to its own start, not the
// whole upload, so retrying the exact same Content-Range always works.
func TestChunkedUploadRetriesAFailedChunk(t *testing.T) {
	server := chunkedServer(t, func(cfg *httpConfig) { cfg.ReadTimeout = 1 })

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/big.iso"),
		&trickleReader{chunks: [][]byte{[]byte("ab"), []byte("cd")}, delay: 2 * time.Second})
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", "bytes 0-3/10")
	res, err := (&http.Client{}).Do(req)
	if err == nil {
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode == http.StatusOK {
			t.Fatalf("a stalled chunk has to fail, got %d", res.StatusCode)
		}
	}

	if res := putChunk(t, server, "/private/big.iso", 0, 3, 10, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", res.StatusCode)
	}
	if res := putChunk(t, server, "/private/big.iso", 4, 9, 10, "efghij"); res.StatusCode != http.StatusCreated {
		t.Fatalf("final chunk status = %d, want 201", res.StatusCode)
	}
	if got := server.read(t, "private/big.iso"); got != "abcdefghij" {
		t.Errorf("stored %q", got)
	}
}

// A slow-but-steady chunk survives being slower overall than readTimeout, the
// same guarantee the whole-file path already has, just per chunk here.
func TestChunkedUploadSurvivesBeingSlowerThanReadTimeout(t *testing.T) {
	server := chunkedServer(t, func(cfg *httpConfig) { cfg.ReadTimeout = 1 })

	req, _ := http.NewRequest(http.MethodPut, server.url("/private/slow.iso"),
		&trickleReader{chunks: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")},
			delay: 400 * time.Millisecond})
	req.SetBasicAuth("john", "doe")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", "bytes 0-3/10")
	if res := do(t, req); res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	if res := putChunk(t, server, "/private/slow.iso", 4, 9, 10, "efghij"); res.StatusCode != http.StatusCreated {
		t.Fatalf("final chunk status = %d, want 201", res.StatusCode)
	}
	if got := server.read(t, "private/slow.iso"); got != "abcdefghij" {
		t.Errorf("stored %q", got)
	}
}

// Two requests racing to finish the same upload cannot both win: uploadLock
// serializes them fully, so exactly one finalizes (the staging file is gone,
// renamed onto the real target, by the time the other one runs) and the
// other is told its chunk no longer matches anything in progress.
func TestChunkedUploadFinalizeRaceOnlyOneWins(t *testing.T) {
	server := chunkedServer(t, nil)

	if res := putChunk(t, server, "/private/race.iso", 0, 3, 8, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("first chunk status = %d, want 200", res.StatusCode)
	}

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	errs := make([]error, 2)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i], errs[i] = putChunkRaw(server, "/private/race.iso", 4, 7, 8, "efgh")
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	created, outOfSync := 0, 0
	for _, status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusRequestedRangeNotSatisfiable:
			outOfSync++
		}
	}
	if created != 1 || outOfSync != 1 {
		t.Fatalf("statuses = %v, want exactly one 201 and one 416", statuses)
	}
	if got := server.read(t, "private/race.iso"); got != "abcdefgh" {
		t.Errorf("stored %q", got)
	}
}

// maxChunkSize bounds a single chunk, independently of maxUploadSize.
func TestChunkedUploadMaxChunkSizeIsEnforced(t *testing.T) {
	server := chunkedServer(t, func(cfg *httpConfig) { cfg.MaxChunkSize = 4 })

	res := putChunk(t, server, "/private/limited.iso", 0, 9, 10, "0123456789")
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", res.StatusCode)
	}

	if res := putChunk(t, server, "/private/limited.iso", 0, 3, 10, "0123"); res.StatusCode != http.StatusOK {
		t.Fatalf("compliant chunk status = %d, want 200", res.StatusCode)
	}
}

// A declared total over maxUploadSize is refused on the first chunk, before
// anything is staged — a client cannot chunk its way past the file-size limit.
func TestChunkedUploadRefusesATotalOverMaxUploadSize(t *testing.T) {
	server := chunkedServer(t, func(cfg *httpConfig) {
		cfg.MaxUploadSize = 5
		cfg.MaxChunkSize = 100
	})

	res := putChunk(t, server, "/private/huge.iso", 0, 3, 10, "abcd")
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", res.StatusCode)
	}
	entries, err := os.ReadDir(server.settings().cfg.UploadStagingFolder)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a staging file was left behind: %v", entries)
	}
}

// A finalize that fails for a reason unrelated to the data it staged (a
// read-only destination folder stands in here for the cross-device rename
// failure a real deployment hit, which this test cannot portably force) does
// not lose the upload: the staging file is left exactly where finalize left
// it, and the client's retry of the same last chunk is recognized as already
// landed and only retries finishing, rather than dead-ending in a 416 forever.
func TestChunkedUploadRecoversAfterAFinalizeFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only folder anyway")
	}
	server := chunkedServer(t, nil)

	if res := putChunk(t, server, "/locked.iso", 0, 3, 8, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("first chunk status = %d, want 200", res.StatusCode)
	}

	if err := os.Chmod(server.base, 0o555); err != nil {
		t.Skipf("cannot drop the permissions: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(server.base, 0o755) })

	if res := putChunk(t, server, "/locked.iso", 4, 7, 8, "efgh"); res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("finalize into a read-only folder should fail, got %d", res.StatusCode)
	}

	if err := os.Chmod(server.base, 0o755); err != nil {
		t.Fatal(err)
	}
	if res := putChunk(t, server, "/locked.iso", 4, 7, 8, "efgh"); res.StatusCode != http.StatusCreated {
		t.Fatalf("retry once the folder is writable again, status = %d, want 201", res.StatusCode)
	}
	if got := server.read(t, "locked.iso"); got != "abcdefgh" {
		t.Errorf("stored %q", got)
	}
}

func TestCopyFileCopiesContent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("copied %q, want %q", got, "hello")
	}
}

func TestCopyFileRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, false); err == nil {
		t.Fatal("copying onto an existing file has to fail")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Errorf("dst was changed to %q", got)
	}
}

func TestCopyFileReplacesWhenAsked(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("the original is longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("dst holds %q, want it replaced whole", got)
	}
}

// A chunked upload onto a name that is taken follows the same rule as a whole
// one: the account needs allowUserFileOverwrite, and then the file is replaced
// when the last chunk lands.
func TestChunkedUploadReplacesOnlyWithTheRight(t *testing.T) {
	t.Run("with the right", func(t *testing.T) {
		server := chunkedServer(t, nil)
		server.write(t, "exists.txt", "the original is longer")
		if res := putChunk(t, server, "/exists.txt", 0, 3, 8, "abcd"); res.StatusCode != http.StatusOK {
			t.Fatalf("first chunk status = %d, want 200", res.StatusCode)
		}
		if got := server.read(t, "exists.txt"); got != "the original is longer" {
			t.Errorf("the file was changed before the upload was complete: %q", got)
		}
		if res := putChunk(t, server, "/exists.txt", 4, 7, 8, "efgh"); res.StatusCode != http.StatusCreated {
			t.Fatalf("last chunk status = %d, want 201", res.StatusCode)
		}
		if got := server.read(t, "exists.txt"); got != "abcdefgh" {
			t.Errorf("stored %q", got)
		}
	})

	t.Run("without the right", func(t *testing.T) {
		server := chunkedServer(t, func(cfg *httpConfig) {
			user := fullUser("john", "doe")
			user.AllowUserFileOverwrite = new(false)
			cfg.Users = []config.User{user}
		})
		server.write(t, "exists.txt", "original")
		if res := putChunk(t, server, "/exists.txt", 0, 3, 8, "abcd"); res.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", res.StatusCode)
		}
		if got := server.read(t, "exists.txt"); got != "original" {
			t.Errorf("the file was changed to %q", got)
		}
	})
}

// The staging sweep removes a chunked upload nobody has touched in a long
// time, and leaves an upload still in progress alone.
func TestChunkedUploadCleanupSweepsAnAbandonedStagingFile(t *testing.T) {
	staging := t.TempDir()
	server := newServer(t, func(cfg *httpConfig) { cfg.UploadStagingFolder = staging })

	old := filepath.Join(staging, "abandoned.part")
	if err := os.WriteFile(old, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(old, when, when); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(staging, "inprogress.part")
	if err := os.WriteFile(fresh, []byte("still going"), 0o600); err != nil {
		t.Fatal(err)
	}

	server.sweepStaging()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("the abandoned staging file should have been removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a fresh staging file should have been left alone")
	}
	if record := server.logs.find("http cleanup removed an orphaned upload"); record == nil {
		t.Error("the sweep has to be reported")
	}
}

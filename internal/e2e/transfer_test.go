package e2e

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"testing"

	"go-fs/internal/config"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	content := make([]byte, n)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	return content
}

// A file stored over one protocol is read back byte for byte over every
// other, including one with no bytes, one larger than any buffer on the way,
// line endings that a text mode would rewrite, and a name outside ASCII.
func TestFilesCrossProtocolsIntact(t *testing.T) {
	c := newCluster(t, []config.User{account("john", "doe", allRights...)}, nil)
	files := []struct {
		name    string
		content []byte
	}{
		{"/large.bin", randomBytes(t, 3<<20+17)},
		{"/empty.bin", []byte{}},
		{"/lines.txt", []byte("one\r\ntwo\nthree\rfour\r\n")},
		{"/grüße 日本.txt", []byte("unicode")},
		{"/sub folder/nested.txt", []byte("nested")},
	}

	clients := map[string]client{}
	for _, proto := range protocols {
		cl, err := proto.login(t, c, "john", "doe")
		if err != nil {
			t.Fatalf("%s login: %v", proto.name, err)
		}
		clients[proto.name] = cl
	}

	for _, file := range files {
		for _, from := range protocols {
			for _, to := range protocols {
				t.Run(fmt.Sprintf("%s %s to %s", file.name, from.name, to.name), func(t *testing.T) {
					c.reset(t)
					c.mkdir(t, "/sub folder")
					if err := clients[from.name].put(file.name, file.content); err != nil {
						t.Fatalf("upload: %v", err)
					}
					if stored := c.read(t, file.name); !bytes.Equal(stored, file.content) {
						t.Fatalf("stored %d bytes, want %d", len(stored), len(file.content))
					}
					got, err := clients[to.name].get(file.name)
					if err != nil {
						t.Fatalf("download: %v", err)
					}
					if !bytes.Equal(got, file.content) {
						t.Fatalf("downloaded %d bytes that differ from the %d uploaded", len(got), len(file.content))
					}
				})
			}
		}
	}
}

// An HTTP upload in Content-Range chunks ends as one file the other protocols
// read whole.
func TestAChunkedHTTPUploadIsWholeForTheOthers(t *testing.T) {
	c := newCluster(t, []config.User{account("john", "doe", allRights...)}, nil)
	content := randomBytes(t, 1<<20+333)
	cl, err := loginHTTP(t, c, "john", "doe")
	if err != nil {
		t.Fatal(err)
	}
	web := cl.(*httpClient)

	const chunk = 256 << 10
	total := len(content)
	for start := 0; start < total; start += chunk {
		end := min(start+chunk, total) - 1
		res, err := web.do(http.MethodPut, "/chunked.bin", content[start:end+1], http.Header{
			"Content-Type":  {"application/octet-stream"},
			"Content-Range": {fmt.Sprintf("bytes %d-%d/%d", start, end, total)},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode > 299 {
			t.Fatalf("chunk %d-%d: %s", start, end, res.Status)
		}
		// nothing is visible under the final name until the last chunk
		if last := end == total-1; !last && c.exists("/chunked.bin") {
			t.Fatalf("the file appeared after chunk %d-%d, before the upload was complete", start, end)
		}
	}

	for _, proto := range protocols {
		reader, err := proto.login(t, c, "john", "doe")
		if err != nil {
			t.Fatal(err)
		}
		got, err := reader.get("/chunked.bin")
		if err != nil {
			t.Fatalf("%s download: %v", proto.name, err)
		}
		if !bytes.Equal(got, content) {
			t.Errorf("%s read %d bytes that differ from the %d uploaded", proto.name, len(got), len(content))
		}
	}
}

// A download resumed at an offset answers the same bytes over every protocol:
// FTP by REST, HTTP by Range and SFTP by reading from the offset.
func TestResumedDownloadsAgree(t *testing.T) {
	c := newCluster(t, []config.User{account("john", "doe", allRights...)}, nil)
	content := randomBytes(t, 512<<10)
	c.write(t, "/resume.bin", content)
	const offset = 123457
	want := content[offset:]

	ftpCl, err := loginFTP(t, c, "john", "doe")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ftpCl.(*ftpClient).getFrom("/resume.bin", offset)
	if err != nil {
		t.Fatalf("ftp REST: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ftp REST %d answered %d bytes that differ from the tail", offset, len(got))
	}

	webCl, err := loginHTTP(t, c, "john", "doe")
	if err != nil {
		t.Fatal(err)
	}
	res, err := webCl.(*httpClient).do(http.MethodGet, "/resume.bin", nil,
		http.Header{"Range": {fmt.Sprintf("bytes=%d-", offset)}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusPartialContent || !bytes.Equal(got, want) {
		t.Errorf("http Range answered %s with %d bytes", res.Status, len(got))
	}

	sftpCl, err := loginSFTP(t, c, "john", "doe")
	if err != nil {
		t.Fatal(err)
	}
	file, err := sftpCl.(*sftpClient).Open("/resume.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(file)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("sftp from offset %d read %d bytes (err %v)", offset, len(got), err)
	}
}

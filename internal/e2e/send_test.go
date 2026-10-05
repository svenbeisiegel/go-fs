package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

// ask sends a request of the listing's script, as JSON from the same site,
// and decodes what it answers into into.
func (c *httpClient) ask(t *testing.T, method, path string, body, into any) int {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(c.token)
	res, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if into != nil && res.StatusCode < 300 {
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatalf("%s %s answered %s", method, path, data)
		}
	}
	if res.StatusCode >= 300 {
		t.Logf("%s %s answered %d: %s", method, path, res.StatusCode, data)
	}
	return res.StatusCode
}

// TestAFileIsSentToAnSFTPServer sends a file of the HTTP server to the SFTP
// server of the same cluster, replacing the one that is there: the way the
// listing's dialog does, step by step.
func TestAFileIsSentToAnSFTPServer(t *testing.T) {
	c := newCluster(t, []config.User{account("alice", "pw", allRights...)}, nil)
	c.write(t, share+"/report.txt", []byte("the new report"))
	c.mkdir(t, share+"/inbox")
	c.write(t, share+"/inbox/report.txt", []byte("the old report, which was longer"))
	web, err := loginHTTPSession(t, c, "alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(c.sftp.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	file := share + "/report.txt"

	var key struct {
		Fingerprint string `json:"fingerprint"`
	}
	if status := web.ask(t, http.MethodPost, file+"?go-fs=send-hostkey",
		map[string]any{"host": host, "port": portNumber}, &key); status != http.StatusOK {
		t.Fatalf("the host key answered %d", status)
	}
	login := map[string]any{"host": host, "port": portNumber, "username": "alice", "password": "pw",
		"hostKey": key.Fingerprint, "path": share + "/inbox"}
	var folder struct {
		Path    string `json:"path"`
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	if status := web.ask(t, http.MethodPost, file+"?go-fs=send-browse", login, &folder); status != http.StatusOK {
		t.Fatalf("the folder answered %d", status)
	}
	if folder.Path != share+"/inbox" || len(folder.Entries) != 1 || folder.Entries[0].Name != "report.txt" {
		t.Errorf("the folder is %+v", folder)
	}

	var job struct {
		ID      string `json:"id"`
		State   string `json:"state"`
		Message string `json:"message"`
	}
	if status := web.ask(t, http.MethodPost, file+"?go-fs=send", login, &job); status != http.StatusAccepted {
		t.Fatalf("the send answered %d", status)
	}
	deadline := time.Now().Add(20 * time.Second)
	for job.State == "" || job.State == "running" {
		if time.Now().After(deadline) {
			t.Fatalf("the send is still running: %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
		web.ask(t, http.MethodGet, "/?go-fs=fetch-job&id="+job.ID, nil, &job)
	}
	if job.State != "done" {
		t.Fatalf("the send ended %s: %s", job.State, job.Message)
	}
	if got := string(c.read(t, share+"/inbox/report.txt")); got != "the new report" {
		t.Errorf("the SFTP server holds %q", got)
	}
	// the file was written under a name of its own, which is gone again
	entries, err := os.ReadDir(c.path(share + "/inbox"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("the folder holds %s", strings.Join(names, ", "))
	}
}

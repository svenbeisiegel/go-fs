package admin

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go-fs/internal/config"
)

func TestStateDescribesTheFile(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)

	body := get(t, front)
	if body.Path != path {
		t.Errorf("the state names %q, want %q", body.Path, path)
	}
	if !body.Writable || body.WriteError != "" {
		t.Errorf("a writable file was reported as %v: %s", body.Writable, body.WriteError)
	}
	if !body.Reload {
		t.Error("reloadConfig is on by default, the state says it is off")
	}
	if len(body.Schema.Sections) == 0 {
		t.Fatal("the state carries no schema")
	}
	if port := section(t, body.Values, "ftp")["port"]; port != float64(2121) {
		t.Errorf("ftp.port is %v, want the 2121 the file says", port)
	}
	// an inherited folder stays inherited in what the page shows
	if folder := section(t, body.Values, "ftp")["basefolder"]; folder != "" {
		t.Errorf("ftp.basefolder is %q, the file leaves it to general.basefolder", folder)
	}
}

func TestApplyWritesTheFile(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)

	body := get(t, front)
	section(t, body.Values, "ftp")["port"] = 2122
	section(t, body.Values, "general")["logLevel"] = "debug"

	if status, answer := post(t, front, body.Values, nil); status != http.StatusOK {
		t.Fatalf("apply answered %d: %s", status, answer)
	}

	written, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if written.FTP.Port != 2122 || written.General.LogLevel != "debug" {
		t.Errorf("the file says port %d level %q", written.FTP.Port, written.General.LogLevel)
	}
	if len(written.Users) != 1 || written.Users[0].Username != "john" || !written.Users[0].FTP {
		t.Errorf("the accounts did not survive the write: %+v", written.Users)
	}
	if !written.Users[0].Permissions().FileRetrieve {
		t.Error("a granted permission did not survive the write")
	}

	// the previous file is kept, because the rewrite drops its comments
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(backup), "port = 2121") {
		t.Errorf("the backup does not hold the previous file:\n%s", backup)
	}
}

func TestApplyAddsAndRemovesRecords(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)

	body := get(t, front)
	users, ok := body.Values["users"].([]any)
	if !ok {
		t.Fatalf("users is %T, want the list of records", body.Values["users"])
	}
	body.Values["users"] = append(users, map[string]any{
		"username":              "max",
		"password":              "mustermann",
		"sftp":                  true,
		"allowUserFileRetrieve": true,
	})
	if status, answer := post(t, front, body.Values, nil); status != http.StatusOK {
		t.Fatalf("apply answered %d: %s", status, answer)
	}
	written, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(written.Users) != 2 || written.Users[1].Username != "max" || !written.Users[1].SFTP {
		t.Fatalf("the account was not added: %+v", written.Users)
	}

	body = get(t, front)
	body.Values["users"] = body.Values["users"].([]any)[:1]
	if status, answer := post(t, front, body.Values, nil); status != http.StatusOK {
		t.Fatalf("apply answered %d: %s", status, answer)
	}
	written, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(written.Users) != 1 {
		t.Errorf("the account was not removed: %+v", written.Users)
	}
}

// TestApplyRefusesWhatWouldNotStart checks that the page reports what -check
// reports, and that a file that cannot work is never written.
func TestApplyRefusesWhatWouldNotStart(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	body := get(t, front)
	section(t, body.Values, "ftp")["port"] = 70000

	status, answer := post(t, front, body.Values, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("a port of 70000 answered %d: %s", status, answer)
	}
	if !strings.Contains(answer, "ftp.port 70000 is out of range") {
		t.Errorf("the message was %q", answer)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the file was written although the configuration was refused")
	}
	if _, err := os.Stat(path + ".bak"); err == nil {
		t.Error("a backup was made although nothing was written")
	}
}

func TestApplyReportsAFileItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only file")
	}
	path := testConfig(t)
	_, front := testServer(t, path)
	body := get(t, front)

	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if state := get(t, front); state.Writable || !strings.Contains(state.WriteError, "permission denied") {
		t.Errorf("a read-only file reported writable=%v error=%q", state.Writable, state.WriteError)
	}
	status, answer := post(t, front, body.Values, nil)
	if status != http.StatusConflict {
		t.Fatalf("writing a read-only file answered %d: %s", status, answer)
	}
	if !strings.Contains(answer, "permission denied") {
		t.Errorf("the message was %q", answer)
	}
}

// TestApplyRefusesAnotherOrigin covers the two guards against a page on another
// site writing this configuration with the browser's saved credentials.
func TestApplyRefusesAnotherOrigin(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)
	body := get(t, front)

	if status, _ := post(t, front, body.Values, map[string]string{
		"Origin": "https://elsewhere.example",
	}); status != http.StatusForbidden {
		t.Errorf("a foreign origin answered %d", status)
	}
	if status, _ := post(t, front, body.Values, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}); status != http.StatusUnsupportedMediaType {
		t.Errorf("a form post answered %d", status)
	}
	if status, _ := post(t, front, body.Values, map[string]string{
		"Origin": front.URL,
	}); status != http.StatusOK {
		t.Errorf("the interface's own origin answered %d", status)
	}
	// the host is what is compared, so a proxy that terminates TLS in front of
	// the interface does not lock everyone out
	if status, _ := post(t, front, body.Values, map[string]string{
		"Origin": "https://" + strings.TrimPrefix(front.URL, "http://"),
	}); status != http.StatusOK {
		t.Errorf("the same host over another scheme answered %d", status)
	}
}

// TestPageIsServed checks the page and that everything it needs is in it: its
// style and script are inlined under a nonce, because a URL of their own
// would shadow a name in the served folder.
func TestPageIsServed(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)

	answer, err := front.Client().Get(front.URL + "/sub/?go-fs=admin")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(answer.Body)
	answer.Body.Close()
	if answer.StatusCode != http.StatusOK {
		t.Fatalf("the page answered %s", answer.Status)
	}
	if got := answer.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("the page is %q", got)
	}
	if got := answer.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	policy := answer.Header.Get("Content-Security-Policy")
	nonce := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(policy)
	if nonce == nil {
		t.Fatalf("the policy names no script nonce: %q", policy)
	}
	page := string(body)
	for _, want := range []string{
		`<style nonce="` + nonce[1] + `">`,
		`<script nonce="` + nonce[1] + `">`,
		// the script and the style are there, not linked
		"async function load()",
		"--accent:",
		// the way back and out, relative to the folder the page was opened in
		`href="/sub/"`,
		`action="/sub/?go-fs=logout"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q", want)
		}
	}
	if strings.Contains(page, "/admin.js") || strings.Contains(page, "/admin.css") {
		t.Error("the page still links its assets by URL")
	}
}

// TestEndpointsTakeOnlyTheirMethod checks the dispatch on the marker.
func TestEndpointsTakeOnlyTheirMethod(t *testing.T) {
	_, front := testServer(t, testConfig(t))
	for _, tc := range []struct {
		method, marker string
		want           int
	}{
		{http.MethodPost, ActionPage, http.StatusMethodNotAllowed},
		{http.MethodDelete, ActionConfig, http.StatusMethodNotAllowed},
		{http.MethodGet, ActionUpload, http.StatusMethodNotAllowed},
		{http.MethodGet, ActionGenerate, http.StatusMethodNotAllowed},
		{http.MethodHead, ActionPage, http.StatusOK},
	} {
		request, _ := http.NewRequest(tc.method, front.URL+"/?go-fs="+tc.marker, nil)
		answer, err := front.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		answer.Body.Close()
		if answer.StatusCode != tc.want {
			t.Errorf("%s ?go-fs=%s answered %d, want %d", tc.method, tc.marker, answer.StatusCode, tc.want)
		}
	}
	if !IsAction(ActionPage) || IsAction("login") || IsAction("") {
		t.Error("IsAction does not tell the interface's markers from the others")
	}
}

// TestNewNeedsThePath guards the one thing the interface cannot work without.
func TestNewNeedsThePath(t *testing.T) {
	if _, err := New("", slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("a server was built with no configuration file to edit")
	}
}

// TestWriteFollowsASymlink checks that a linked configuration file is replaced
// where it lives rather than turning the link into a regular file.
func TestWriteFollowsASymlink(t *testing.T) {
	path := testConfig(t)
	link := filepath.Join(filepath.Dir(path), "linked.toml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}

	_, front := testServer(t, link)
	body := get(t, front)
	section(t, body.Values, "ftp")["port"] = 2123
	if status, answer := post(t, front, body.Values, nil); status != http.StatusOK {
		t.Fatalf("apply answered %d: %s", status, answer)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	written, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if written.FTP.Port != 2123 {
		t.Errorf("the target says port %d", written.FTP.Port)
	}
}

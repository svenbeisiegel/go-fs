package httpd

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/remote"
	"go-fs/internal/remote/remotetest"
)

// A server with a vault is browsed, uploaded to, downloaded from and fetched
// from as any other, by the cleartext names, while the host keeps only
// ciphertext.
func TestRemoteServerWithAVault(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	login := remote.FromServer(storedServer(host, "Backup"))
	login.VaultPath, login.VaultPassword = "vault", "pw"
	login, err := login.Checked(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.CreateVault(context.Background(), login, config.Default().General.SSH); err != nil {
		t.Fatal(err)
	}
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Servers[0].VaultPath, cfg.Servers[0].VaultPassword = "vault", "pw"
	})
	server.mkdir(t, "inbox")

	const secret = "the quarterly numbers"
	res := remoteDo(t, server, http.MethodPut, remoteURL("Backup", "/report.txt"), session, strings.NewReader(secret), octetStream)
	if res.StatusCode/100 != 2 {
		t.Fatalf("the upload answered %d", res.StatusCode)
	}
	res = remoteDo(t, server, http.MethodGet, remoteURL("Backup", ""), session, nil, map[string]string{"Accept": "text/html"})
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(page), "report.txt") {
		t.Errorf("the page of the vault answered %d without the file", res.StatusCode)
	}
	res = remoteDo(t, server, http.MethodGet, remoteURL("Backup", "/report.txt"), session, nil, nil)
	if got, _ := io.ReadAll(res.Body); res.StatusCode != http.StatusOK || string(got) != secret {
		t.Errorf("the download answered %d: %q", res.StatusCode, got)
	}
	expectDone(t, remoteFetched(t, server, remoteURL("Backup", "/report.txt"), "/inbox", session))
	if got := server.read(t, "inbox/report.txt"); got != secret {
		t.Errorf("the file fetched is %q", got)
	}

	_ = filepath.WalkDir(host.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(d.Name(), "report") {
			t.Errorf("the host keeps %s", p)
		}
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), secret) {
			t.Errorf("the host keeps the cleartext in %s", p)
		}
		return nil
	})
}

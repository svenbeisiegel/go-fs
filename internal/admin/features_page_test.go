package admin

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/features"
)

// The page of a binary built without the FTP, SFTP and TFTP servers, sending
// by SFTP and SMB and the repositories, go-fs-light, shows none of them, and
// a save keeps the stored servers it does not show in the file as they were.
func TestPageLeavesOutWhatIsNotBuilt(t *testing.T) {
	for _, name := range features.All() {
		if features.Has(name) {
			t.Skipf("built with %s", name)
		}
	}
	folder := t.TempDir()
	path := filepath.Join(folder, "go-fs.toml")
	body := `
[general]
basefolder = ` + strconv.Quote(folder) + `

[[users]]
username = "john"
password = "doe"
http = true
sftp = true
paths = [".*"]
authorizedKeys = ["not a key"]

[[servers]]
name = "share"
type = "smb"
host = "fileserver"
username = "john"
password = "doe"

[http]
enabled = true

[tftp]
enabled = true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, front := testServer(t, path)
	got := get(t, front)

	for _, hidden := range []string{"ftp", "ftps", "sftp", "tftp", "repositories"} {
		for _, s := range got.Schema.Sections {
			if s.Key == hidden {
				t.Errorf("the page shows the section %s", hidden)
			}
		}
		if _, ok := got.Values[hidden]; ok {
			t.Errorf("the values hold the section %s", hidden)
		}
	}
	for _, s := range got.Schema.Sections {
		for _, sub := range s.Subsections {
			if s.Key == "general" && sub.Key == "ssh" {
				t.Error("the page shows general.ssh")
			}
		}
		for _, table := range s.Tables {
			for _, f := range table.Fields {
				switch table.Key + "." + f.Key {
				case "users.ftp", "users.sftp", "users.authorizedKeys", "users.basefolder",
					"users.allowLoginWithoutPassword", "servers.hostKeyFingerprint":
					t.Errorf("the page shows %s.%s", table.Key, f.Key)
				}
			}
		}
	}
	if servers, _ := got.Values["servers"].([]any); len(servers) != 0 {
		t.Errorf("the page shows a server of a protocol the binary has not: %v", servers)
	}
	for _, p := range got.Protocols {
		if p.ID != config.ServerTypeArtifactory {
			t.Errorf("the page offers the protocol %s", p.ID)
		}
	}

	if status, answer := post(t, front, roundTripJSON(t, got.Values), nil); status != http.StatusOK {
		t.Fatalf("saving the page answered %d: %s", status, answer)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Servers) != 1 || saved.Servers[0].Name != "share" || saved.Servers[0].Host != "fileserver" ||
		saved.Servers[0].Password != "doe" {
		t.Errorf("the stored servers became %+v", saved.Servers)
	}
}

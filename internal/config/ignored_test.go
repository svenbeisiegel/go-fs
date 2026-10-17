package config

import (
	"strings"
	"testing"

	"go-fs/internal/features"
)

// A binary built without the servers, the protocols and the repositories of
// a file reads it all the same: go-fs-light starts on the file of go-fs,
// ignores what it does not have and checks none of it.
func TestAbsentPartsAreIgnored(t *testing.T) {
	for _, name := range []string{features.FTP, features.SFTP, features.TFTP, features.SMB, features.RPM} {
		if features.Has(name) {
			t.Skipf("built with %s", name)
		}
	}
	folder := t.TempDir()
	cfg := Default()
	cfg.HTTP.Enabled = true
	cfg.HTTP.Basefolder = folder
	// all of it wrong, which a binary with the parts would refuse
	cfg.FTP.Enabled, cfg.FTP.Port = true, 70000
	cfg.SFTP.Enabled, cfg.SFTP.HostKey = true, "not a key"
	cfg.TFTP.Enabled, cfg.TFTP.Port = true, -1
	cfg.General.SSH.Ciphers = []string{"no-such-cipher"}
	cfg.Users = []User{{Username: "alice", Password: "secret", HTTP: true, SFTP: true,
		AuthorizedKeys: []string{"not a key"}}}
	cfg.Servers = []Server{{Name: "share", Type: ServerTypeSMB}}
	cfg.Repositories = []Repository{{Name: "rpms", Type: RepositoryTypeRPM, SigningKey: "not a key"}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("the parts this binary has not were checked: %v", err)
	}
	ignored := strings.Join(cfg.Ignored(), "; ")
	for _, want := range []string{"ftp", "sftp", "tftp", `"share" of type smb`, `"rpms" of type rpm`} {
		if !strings.Contains(ignored, want) {
			t.Errorf("ignored = %q, which does not name %s", ignored, want)
		}
	}
	if len(cfg.UsableServers()) != 0 || len(cfg.UsableRepositories()) != 0 {
		t.Error("a server or a repository of a part this binary has not is offered")
	}

	// a file with nothing but those switched on serves nothing here
	cfg.HTTP.Enabled = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "no server is enabled") {
		t.Errorf("a file whose servers are all absent was accepted: %v", err)
	}
}

// A binary built with every part ignores nothing.
func TestNothingIsIgnoredWithEveryPart(t *testing.T) {
	skipWithout(t, features.All()...)
	cfg := Default()
	cfg.FTP.Enabled, cfg.SFTP.Enabled, cfg.TFTP.Enabled = true, true, true
	cfg.Servers = []Server{{Name: "share", Type: ServerTypeSMB}}
	cfg.Repositories = []Repository{{Name: "rpms", Type: RepositoryTypeRPM}}
	if ignored := cfg.Ignored(); len(ignored) != 0 {
		t.Errorf("ignored = %q", ignored)
	}
}

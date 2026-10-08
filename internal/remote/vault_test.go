package remote_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/cryptomator"
	"go-fs/internal/remote"
	"go-fs/internal/remote/remotetest"
)

// vaultHost is a host a vault is tried on: its login, without the vault, and
// the folder of the disk it keeps what it is sent in.
type vaultHost struct {
	login remote.Login
	dir   string
}

func vaultHosts(t *testing.T) map[string]vaultHost {
	sftp := remotetest.NewSFTPHost(t, "alice", "secret")
	artifactory := remotetest.NewArtifactoryHost(t, "secret", "libs")
	return map[string]vaultHost{
		"sftp": {remote.Login{Type: config.ServerTypeSFTP, Host: sftp.Host, Port: sftp.Port,
			Username: "alice", Password: "secret", HostKey: sftp.Fingerprint, VaultPath: "vault", VaultPassword: "pw"}, sftp.Dir},
		"artifactory": {remote.Login{Type: config.ServerTypeArtifactory, URL: artifactory.URL,
			Token: artifactory.Token, VaultPath: "/libs/vault", VaultPassword: "pw"}, artifactory.Dir},
	}
}

func openTestVault(t *testing.T, login remote.Login) remote.FS {
	t.Helper()
	fsys, err := remote.Open(context.Background(), login, sshConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsys.Close() })
	return fsys
}

func vaultPut(t *testing.T, fsys remote.FS, p string, content []byte) {
	t.Helper()
	n, err := fsys.Put(p, bytes.NewReader(content), int64(len(content)))
	if err != nil || n != int64(len(content)) {
		t.Fatalf("putting %s wrote %d, %v", p, n, err)
	}
}

func vaultRead(t *testing.T, fsys remote.FS, p string) []byte {
	t.Helper()
	f, err := fsys.Open(p)
	if err != nil {
		t.Fatalf("opening %s: %v", p, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading %s: %v", p, err)
	}
	return b
}

func vaultNames(t *testing.T, fsys remote.FS, p string) []string {
	t.Helper()
	entries, err := fsys.ReadDir(p)
	if err != nil {
		t.Fatalf("listing %s: %v", p, err)
	}
	var found []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		found = append(found, name)
	}
	slices.Sort(found)
	return found
}

func TestVault(t *testing.T) {
	long := strings.Repeat("long name ", 25) + ".txt"
	big := make([]byte, 100*1024)
	_, _ = rand.Read(big)
	small := []byte("the cleartext of a small file")
	for name, host := range vaultHosts(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			login, err := host.login.Checked(false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := remote.Open(ctx, withVaultPassword(login, "pw"), sshConfig()); err == nil {
				t.Fatal("a vault that is not there was opened")
			}
			recovery, err := remote.CreateVault(ctx, withVaultPassword(login, "pw"), sshConfig())
			if err != nil || recovery == "" {
				t.Fatalf("the vault was made with %q, %v", recovery, err)
			}
			if _, err := remote.CreateVault(ctx, withVaultPassword(login, "pw"), sshConfig()); err == nil {
				t.Error("a vault was made over another")
			}
			if _, err := remote.Open(ctx, withVaultPassword(login, "wrong"), sshConfig()); !errors.Is(err, cryptomator.ErrWrongPassword) {
				t.Errorf("a wrong password opened the vault with %v", err)
			}
			login = withVaultPassword(login, "pw")
			fsys := openTestVault(t, login)

			if home, err := fsys.Resolve(""); err != nil || home != "/" {
				t.Fatalf("the vault starts at %q, %v", home, err)
			}
			if got := vaultNames(t, fsys, "/"); len(got) != 0 {
				t.Errorf("a new vault holds %v", got)
			}

			vaultPut(t, fsys, "/big.bin", big)
			vaultPut(t, fsys, "/a.txt", small)
			if err := fsys.Mkdir("/docs"); err != nil {
				t.Fatal(err)
			}
			if err := fsys.Mkdir("/docs"); !errors.Is(err, fs.ErrExist) {
				t.Errorf("a folder made twice answered %v", err)
			}
			vaultPut(t, fsys, "/docs/"+long, small)
			if err := fsys.Mkdir("/docs/" + long + " folder"); err != nil {
				t.Fatal(err)
			}
			if got, want := vaultNames(t, fsys, "/"), []string{"a.txt", "big.bin", "docs/"}; !slices.Equal(got, want) {
				t.Errorf("the vault holds %v, want %v", got, want)
			}
			if got, want := vaultNames(t, fsys, "/docs"), []string{long, long + " folder/"}; !slices.Equal(got, want) {
				t.Errorf("docs holds %v, want %v", got, want)
			}
			info, err := fsys.Stat("/big.bin")
			if err != nil || info.Size() != int64(len(big)) || info.IsDir() || info.Name() != "big.bin" {
				t.Fatalf("big.bin is %+v, %v", info, err)
			}
			if !bytes.Equal(vaultRead(t, fsys, "/big.bin"), big) || !bytes.Equal(vaultRead(t, fsys, "/docs/"+long), small) {
				t.Error("a file read back differently")
			}
			f, err := fsys.Open("/big.bin")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(40000, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if rest, err := io.ReadAll(f); err != nil || !bytes.Equal(rest, big[40000:]) {
				t.Errorf("big.bin read from 40000 differently, %v", err)
			}
			_ = f.Close()
			if _, err := fsys.Stat("/nothing"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a file that is not there is %v", err)
			}
			if _, err := fsys.Open("/docs"); err == nil {
				t.Error("a folder was opened as a file")
			}

			// renamed in its folder, into another, from a short name to a long
			// one and back, and a folder with what it holds
			for _, move := range [][2]string{
				{"/a.txt", "/b.txt"},
				{"/b.txt", "/docs/b.txt"},
				{"/docs/b.txt", "/docs/" + long + " too"},
				{"/docs/" + long + " too", "/c.txt"},
				{"/docs", "/papers"},
				{"/papers/" + long + " folder", "/papers/short folder"},
			} {
				if err := fsys.Rename(move[0], move[1]); err != nil {
					t.Fatalf("moving %s to %s: %v", move[0], move[1], err)
				}
			}
			if err := fsys.Rename("/c.txt", "/big.bin"); !errors.Is(err, fs.ErrExist) {
				t.Errorf("a move onto a file answered %v", err)
			}
			if !bytes.Equal(vaultRead(t, fsys, "/c.txt"), small) || !bytes.Equal(vaultRead(t, fsys, "/papers/"+long), small) {
				t.Error("a moved file read back differently")
			}
			if got, want := vaultNames(t, fsys, "/papers"), []string{long, "short folder/"}; !slices.Equal(got, want) {
				t.Errorf("papers holds %v, want %v", got, want)
			}
			vaultPut(t, fsys, "/papers/short folder/deep.txt", small)

			// a vault opened again finds what the first one left
			again := openTestVault(t, login)
			if !bytes.Equal(vaultRead(t, again, "/papers/short folder/deep.txt"), small) {
				t.Error("a file read back differently in the vault opened again")
			}

			if err := fsys.RemoveDir("/papers"); err == nil {
				t.Error("a folder with files in it was removed")
			}
			for _, p := range []string{"/papers/short folder/deep.txt", "/papers/" + long} {
				if err := fsys.Remove(p); err != nil {
					t.Fatalf("removing %s: %v", p, err)
				}
			}
			for _, p := range []string{"/papers/short folder", "/papers"} {
				if err := fsys.RemoveDir(p); err != nil {
					t.Fatalf("removing %s: %v", p, err)
				}
			}
			if got, want := vaultNames(t, again, "/"), []string{"big.bin", "c.txt"}; !slices.Equal(got, want) {
				t.Errorf("the vault holds %v, want %v", got, want)
			}

			// the host never saw a name or a byte of the cleartext
			_ = filepath.WalkDir(host.dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				for _, cleartext := range []string{"a.txt", "big.bin", "docs", "papers", "long name"} {
					if strings.Contains(d.Name(), cleartext) {
						t.Errorf("the host keeps %s", p)
					}
				}
				if !d.IsDir() {
					if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, small) {
						t.Errorf("the host keeps the cleartext in %s", p)
					}
				}
				return nil
			})
		})
	}
}

func withVaultPassword(l remote.Login, password string) remote.Login {
	l.VaultPassword = password
	return l
}

func TestVaultLoginIsChecked(t *testing.T) {
	base := remote.Login{Host: "example.com", Username: "alice", HostKey: "SHA256:x"}
	for name, l := range map[string]remote.Login{
		"a vault without a password": {VaultPath: "/vault"},
		"the top of the host":        {VaultPath: "/", VaultPassword: "pw"},
		"a vault above the login":    {VaultPath: "../vault", VaultPassword: "pw"},
	} {
		l.Host, l.Username, l.HostKey = base.Host, base.Username, base.HostKey
		if _, err := l.Checked(false); err == nil {
			t.Errorf("a login with %s was accepted", name)
		}
	}
	l := base
	l.VaultPath, l.VaultPassword = " /vaults//team/ ", "pw"
	checked, err := l.Checked(false)
	if err != nil || checked.VaultPath != "/vaults/team" {
		t.Errorf("the vault reads %q, %v", checked.VaultPath, err)
	}
	if got := checked.Where("/docs/a.txt"); got != "sftp://example.com/vaults/team/docs/a.txt" {
		t.Errorf("a file of the vault is shown as %q", got)
	}
	l.VaultPath = ""
	if checked, err := l.Checked(false); err != nil || checked.VaultPassword != "" {
		t.Errorf("a password without a vault was kept as %q, %v", checked.VaultPassword, err)
	}
}

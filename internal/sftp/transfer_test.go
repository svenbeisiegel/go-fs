package sftp

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"

	"go-fs/internal/config"
)

func TestDownload(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "hello sftp")
	client := login(t, server)

	file, err := client.Open("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if string(content) != "hello sftp" {
		t.Errorf("content = %q", content)
	}

	if record := server.logs.find("sftp download"); record == nil {
		t.Error("a download has to be reported")
	} else if record["file"] != "/hello.txt" || record["bytes"] != int64(10) {
		t.Errorf("download record = %v", record)
	}
}

func TestUpload(t *testing.T) {
	server := newServer(t, nil)
	client := login(t, server)

	file, err := client.Create("/up.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("uploaded")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if got := server.read(t, "up.txt"); got != "uploaded" {
		t.Errorf("stored %q", got)
	}
	if record := server.logs.find("sftp upload"); record == nil {
		t.Error("an upload has to be reported")
	} else if record["file"] != "/up.txt" || record["bytes"] != int64(8) {
		t.Errorf("upload record = %v", record)
	}
}

func TestLargeRoundTrip(t *testing.T) {
	server := newServer(t, nil)
	client := login(t, server)

	payload := strings.Repeat("go-fs sftp payload ", 60000) // about 1.1 MB
	file, err := client.Create("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	back, err := client.Open("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(back)
	if err != nil {
		t.Fatal(err)
	}
	_ = back.Close()
	if string(content) != payload {
		t.Errorf("the file came back changed: %d bytes instead of %d", len(content), len(payload))
	}
}

func TestListing(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "b.txt", "b")
	server.write(t, "a.txt", "aa")
	server.write(t, "sub/inside.txt", "in")
	client := login(t, server)

	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if got := names(entries); len(got) != 3 || got[0] != "a.txt" || got[1] != "b.txt" || got[2] != "sub" {
		t.Fatalf("listing = %v", got)
	}
	if entries[0].Size() != 2 {
		t.Errorf("a.txt is reported as %d bytes", entries[0].Size())
	}

	sub, err := client.ReadDir("/sub")
	if err != nil {
		t.Fatal(err)
	}
	if got := names(sub); len(got) != 1 || got[0] != "inside.txt" {
		t.Errorf("sub listing = %v", got)
	}

	info, err := client.Stat("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 2 || info.IsDir() {
		t.Errorf("stat = %+v", info)
	}
}

func TestFolderCommands(t *testing.T) {
	server := newServer(t, nil)
	client := login(t, server)

	if err := client.Mkdir("/made"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if info, err := os.Stat(filepath.Join(server.base, "made")); err != nil || !info.IsDir() {
		t.Fatal("the folder was not created")
	}
	// a second Mkdir on the same name fails, as MKD does over FTP
	if err := client.Mkdir("/made"); err == nil {
		t.Error("Mkdir over an existing folder has to fail")
	}

	if err := client.RemoveDirectory("/made"); err != nil {
		t.Fatalf("RemoveDirectory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(server.base, "made")); !os.IsNotExist(err) {
		t.Error("the folder was not removed")
	}
}

func TestRemoveAndRename(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "old.txt", "content")
	server.write(t, "taken.txt", "other")
	client := login(t, server)

	if err := client.Rename("/old.txt", "/new.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if got := server.read(t, "new.txt"); got != "content" {
		t.Errorf("renamed file holds %q", got)
	}
	// a rename must not silently replace an existing file
	if err := client.Rename("/new.txt", "/taken.txt"); err == nil {
		t.Error("renaming onto an existing name has to fail")
	}

	if err := client.Remove("/new.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(server.base, "new.txt")); !os.IsNotExist(err) {
		t.Error("the file was not removed")
	}
}

// Every right is denied unless the account grants it, so each of these takes
// exactly one right away from an otherwise complete account.
func TestPermissionsAreEnforced(t *testing.T) {
	no := false
	cases := []struct {
		name string
		deny func(*config.User)
		do   func(*testServer, *sftp.Client) error
	}{
		{"retrieve", func(u *config.User) { u.AllowUserFileRetrieve = &no },
			func(s *testServer, c *sftp.Client) error { _, err := c.Open("/hello.txt"); return err }},
		{"create", func(u *config.User) { u.AllowUserFileCreate = &no },
			func(s *testServer, c *sftp.Client) error { _, err := c.Create("/new.txt"); return err }},
		{"overwrite", func(u *config.User) { u.AllowUserFileOverwrite = &no },
			func(s *testServer, c *sftp.Client) error { _, err := c.Create("/hello.txt"); return err }},
		{"delete", func(u *config.User) { u.AllowUserFileDelete = &no },
			func(s *testServer, c *sftp.Client) error { return c.Remove("/hello.txt") }},
		{"folder create", func(u *config.User) { u.AllowUserFolderCreate = &no },
			func(s *testServer, c *sftp.Client) error { return c.Mkdir("/made") }},
		{"folder delete", func(u *config.User) { u.AllowUserFolderDelete = &no },
			func(s *testServer, c *sftp.Client) error { return c.RemoveDirectory("/sub") }},
		{"rename needs create and delete", func(u *config.User) { u.AllowUserFileDelete = &no },
			func(s *testServer, c *sftp.Client) error { return c.Rename("/hello.txt", "/moved.txt") }},
		{"setstat", func(u *config.User) { u.AllowUserFileOverwrite = &no },
			func(s *testServer, c *sftp.Client) error { return c.Chmod("/hello.txt", 0o600) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newServer(t, func(cfg *sftpConfig) {
				user := fullUser("john", "doe")
				tc.deny(&user)
				cfg.Users = []config.User{user}
			})
			server.write(t, "hello.txt", "hello")
			server.write(t, "sub/keep.txt", "keep")

			err := tc.do(server, login(t, server))
			if err == nil {
				t.Fatal("the operation has to be refused")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
				t.Errorf("error = %v, want a permission denial", err)
			}
		})
	}
}

// Listing needs no right, the same way LIST does not over FTP.
func TestListingNeedsNoPermission(t *testing.T) {
	server := newServer(t, func(cfg *sftpConfig) {
		cfg.Users = []config.User{{Username: "john", Password: "doe"}}
	})
	server.write(t, "hello.txt", "hello")

	client := login(t, server)
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("an account with no rights still has to be able to list: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("listing = %v", names(entries))
	}
	if _, err := client.Open("/hello.txt"); err == nil {
		t.Error("but it must not read the file")
	}
}

// The base folder is the whole of the filesystem the client can reach, whether
// it tries to climb out with .. or to follow a symbolic link out.
func TestConfinement(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "hello")
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := writeFile(outside, "secret"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(server.base, "escape.txt")); err != nil {
		t.Fatal(err)
	}

	client := login(t, server)
	for _, path := range []string{
		"/../../etc/hosts",
		"../../etc/hosts",
		"/sub/../../../etc/hosts",
		"/escape.txt",
	} {
		if _, err := client.Open(path); err == nil {
			t.Errorf("%s has to be refused", path)
		}
	}
	// and the file that is really inside still works
	if _, err := client.Open("/hello.txt"); err != nil {
		t.Errorf("a file inside the folder has to be readable: %v", err)
	}
}

// Symbolic links are never created, because a link is the one thing that could
// point out of the base folder.
func TestSymlinkIsRefused(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "hello")
	client := login(t, server)

	if err := client.Symlink("/hello.txt", "/link.txt"); err == nil {
		t.Error("creating a symbolic link has to be refused")
	}
}

func TestAppendAndTruncate(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "log.txt", "first\n")
	client := login(t, server)

	file, err := client.OpenFile("/log.txt", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := server.read(t, "log.txt"); got != "first\nsecond\n" {
		t.Errorf("after append the file holds %q", got)
	}

	if err := client.Truncate("/log.txt", 6); err != nil {
		t.Fatal(err)
	}
	if got := server.read(t, "log.txt"); got != "first\n" {
		t.Errorf("after truncate the file holds %q", got)
	}
}

// rmdir removes an empty folder, as it does everywhere else. A folder with
// files in it is not emptied by an account that may not delete files, and the
// base folder itself is never removed at all.
func TestRmdirIsNotRecursive(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "full/inside.txt", "inside")
	client := login(t, server)

	if err := client.RemoveDirectory("/full"); err == nil {
		t.Error("removing a folder with a file in it has to fail")
	}
	if got := server.read(t, "full/inside.txt"); got != "inside" {
		t.Errorf("the file inside holds %q", got)
	}

	if err := client.RemoveDirectory("/"); err == nil {
		t.Error("removing the base folder has to fail")
	}
	if _, err := os.Stat(server.base); err != nil {
		t.Fatalf("the base folder is gone: %v", err)
	}

	if err := client.Mkdir("/empty"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := client.RemoveDirectory("/empty"); err != nil {
		t.Errorf("removing an empty folder: %v", err)
	}
}

// An account is resolved per request, so a right taken away by a reload applies
// to the next request an open session makes, and an account that is gone can do
// nothing at all.
func TestReloadReachesALiveSession(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "hello")
	client := login(t, server)

	if _, err := client.Open("/hello.txt"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	no := false
	next := server.settings().cfg
	user := fullUser("john", "doe")
	user.AllowUserFileRetrieve = &no
	if err := server.Reload(next, []config.User{user}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := client.Open("/hello.txt"); err == nil {
		t.Error("the right was taken away, the open session has to feel it")
	}

	// and an account that is no longer configured can do nothing
	if err := server.Reload(next, []config.User{fullUser("someone else", "doe")}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := client.ReadDir("/"); err == nil {
		t.Error("the account is gone, its session has to be refused")
	}
}

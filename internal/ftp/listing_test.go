package ftp

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go-fs/internal/config"
)

// seed puts a small tree into the served folder.
func seed(t *testing.T, server *testServer) {
	t.Helper()
	server.write(t, "hello.txt", "hello world\n")
	server.write(t, "sub/inner.txt", "inner\n")
}

func TestNlstReturnsBareNames(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	listing, reply := c.download(server, "NLST")
	names := strings.Split(strings.TrimSpace(listing), "\r\n")
	sort.Strings(names)
	if len(names) != 2 || names[0] != "hello.txt" || names[1] != "sub" {
		t.Errorf("names = %q", names)
	}
	if !strings.HasPrefix(reply, "226 Successfully transferred") {
		t.Errorf("reply = %q", reply)
	}
}

func TestListingsHonourAPathArgument(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	for _, command := range []string{"NLST sub", "LIST sub", "MLSD sub"} {
		listing, _ := c.download(server, command)
		if !strings.Contains(listing, "inner.txt") {
			t.Errorf("%s = %q, want inner.txt", command, listing)
		}
		if strings.Contains(listing, "hello.txt") {
			t.Errorf("%s listed the root instead of sub: %q", command, listing)
		}
	}
}

func TestListSkipsUnixStyleFlags(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	listing, _ := c.download(server, "LIST -la")
	if !strings.Contains(listing, "hello.txt") {
		t.Errorf("LIST -la = %q", listing)
	}

	listing, _ = c.download(server, "LIST -la sub")
	if !strings.Contains(listing, "inner.txt") || strings.Contains(listing, "hello.txt") {
		t.Errorf("LIST -la sub = %q", listing)
	}
}

func TestListOfASingleFile(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	listing, _ := c.download(server, "LIST hello.txt")
	if !strings.Contains(listing, "hello.txt") {
		t.Errorf("listing = %q", listing)
	}
	if strings.Contains(listing, " sub") {
		t.Errorf("only the named file should be listed: %q", listing)
	}
}

func TestListFormats(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	listing, _ := c.download(server, "LIST")
	if !regexp.MustCompile(`-r--r--r-- 1 john john\s+12 \w{3} \d\d \d\d:\d\d hello\.txt`).MatchString(listing) {
		t.Errorf("LIST line does not look right: %q", listing)
	}
	if !strings.Contains(listing, "dr--r--r--") {
		t.Errorf("a folder should be marked as one: %q", listing)
	}

	listing, _ = c.download(server, "MLSD")
	if !regexp.MustCompile(`type=file;size=12;modify=\d{14}; hello\.txt`).MatchString(listing) {
		t.Errorf("MLSD line does not look right: %q", listing)
	}
	if !regexp.MustCompile(`type=dir;modify=\d{14}; sub`).MatchString(listing) {
		t.Errorf("a folder carries no size fact: %q", listing)
	}
}

func TestListingOfAMissingPathIsRefused(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	c.send("NLST nosuchdir")
	c.expect("550 Directory not found")

	c.send("LIST ../../..")
	c.expect("550 Directory not found")
}

func TestListSkipsEntriesThatCannotBeStatted(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	// a dangling symlink must not break the whole listing
	if err := os.Symlink(filepath.Join(server.base, "gone"), filepath.Join(server.base, "dangling")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	c := connect(t, server)
	c.login()
	listing, reply := c.download(server, "LIST")
	if !strings.HasPrefix(reply, "226") {
		t.Errorf("reply = %q", reply)
	}
	if !strings.Contains(listing, "hello.txt") {
		t.Errorf("listing = %q", listing)
	}
	if strings.Contains(listing, "dangling") {
		t.Errorf("the broken link should have been skipped: %q", listing)
	}
}

func TestMlstRepliesOnTheControlConnection(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	c.send("MLST hello.txt")
	reply := c.expectCode("250")
	lines := strings.Split(reply, "\r\n")
	if len(lines) != 3 {
		t.Fatalf("MLST = %q, want three lines", reply)
	}
	if lines[0] != "250-Listing /hello.txt" {
		t.Errorf("first line = %q", lines[0])
	}
	if !regexp.MustCompile(`^ type=file;size=12;modify=\d{14}; /hello\.txt$`).MatchString(lines[1]) {
		t.Errorf("entry line = %q", lines[1])
	}
	if lines[2] != "250 End" {
		t.Errorf("last line = %q", lines[2])
	}

	c.send("MLST nosuchfile")
	c.expect("550 File not found")
}

func TestFeatAdvertisesMlst(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("FEAT")
	feat := c.expectCode("211")
	// RFC 3659 names the feature MLST, with the facts it supports
	if !strings.Contains(feat, " MLST type*;size*;modify*;") {
		t.Errorf("FEAT = %q", feat)
	}
	for _, want := range []string{"AUTH TLS", "EPSV", "MDTM", "REST STREAM", "SIZE", "UTF8"} {
		if !strings.Contains(feat, want) {
			t.Errorf("FEAT is missing %q: %q", want, feat)
		}
	}
}

func TestOptsMlstSelectsFacts(t *testing.T) {
	server := newServer(t, nil)
	seed(t, server)
	c := connect(t, server)
	c.login()

	c.send("OPTS MLST type;size;")
	c.expect("200 MLST OPTS type;size;")

	listing, _ := c.download(server, "MLSD")
	if !strings.Contains(listing, "type=file;size=12; hello.txt") {
		t.Errorf("listing = %q", listing)
	}
	if strings.Contains(listing, "modify=") {
		t.Errorf("modify was not selected: %q", listing)
	}

	// unknown facts are dropped
	c.send("OPTS MLST type;bogus;")
	c.expect("200 MLST OPTS type;")

	// an empty list turns every fact off
	c.send("OPTS MLST")
	c.expect("200 MLST OPTS ")

	listing, _ = c.download(server, "MLSD")
	if !strings.Contains(listing, " hello.txt") || strings.Contains(listing, "type=") {
		t.Errorf("listing = %q", listing)
	}
}

func TestOptsUtf8(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("OPTS UTF8 ON")
	c.expect("200 UTF8 ON")
	c.send("OPTS UTF8 OFF")
	c.expect("200 UTF8 OFF")
	c.send("OPTS SOMETHING")
	c.expect("451 Not supported")
}

func TestLargeFileSizeDoesNotBreakThePadding(t *testing.T) {
	server := newServer(t, nil)
	// a sparse file with a 15 digit size
	path := filepath.Join(server.base, "hugefile")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(100000000000000); err != nil {
		_ = file.Close()
		t.Skipf("cannot create a sparse file: %v", err)
	}
	_ = file.Close()

	c := connect(t, server)
	c.login()
	c.send("STAT hugefile")
	reply := c.expectCode("213")
	if !strings.Contains(reply, "100000000000000 ") {
		t.Errorf("STAT = %q", reply)
	}
}

func TestFolderCommands(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("MKD testfolder")
	c.expect("250 Folder created successfully")
	c.send("MKD testfolder")
	c.expect("550 Folder exists")

	c.send("CWD testfolder")
	c.expect(`250 CWD successful. "/testfolder/" is current directory`)
	c.send("PWD")
	c.expect(`257 "/testfolder/" is current directory`)
	c.send("CDUP")
	c.expect(`250 CWD successful. "/" is current directory`)

	c.send("RMD testfolder")
	c.expect("250 Folder deleted successfully")
	c.send("RMD testfolder")
	c.expect("550 Folder not found")
}

func TestFolderCommandsWithoutPermission(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFolderCreate = &no
		user.AllowUserFolderDelete = &no
		cfg.Users = []config.User{user}
	})
	server.write(t, "existing/keep.txt", "keep")

	c := connect(t, server)
	c.login()
	c.send("MKD nope")
	c.expect("550 Permission denied")
	c.send("RMD existing")
	c.expect("550 Permission denied")
}

func TestCwdNormalizesDotSegments(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "sub/inner.txt", "inner")
	c := connect(t, server)
	c.login()

	c.send("CWD ./sub/.")
	c.expect(`250 CWD successful. "/sub/" is current directory`)
	c.send("PWD")
	c.expect(`257 "/sub/" is current directory`)

	c.send("CWD ../sub")
	c.expect(`250 CWD successful. "/sub/" is current directory`)

	c.send("CWD ../../..")
	c.expect("530 CWD not successful")

	c.send("CWD ..")
	c.expect(`250 CWD successful. "/" is current directory`)

	// going up from the root is a no-op, not an error
	c.send("CWD ..")
	c.expect(`250 CWD successful. "/" is current directory`)

	c.send("CWD nosuchfolder")
	c.expect("530 CWD not successful")
}

func TestTheXAliases(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("XPWD")
	c.expect(`257 "/" is current directory`)
	c.send("XMKD xdir")
	c.expect("250 Folder created successfully")
	c.send("XCWD xdir")
	c.expect(`250 CWD successful. "/xdir/" is current directory`)
	c.send("XCUP")
	c.expect(`250 CWD successful. "/" is current directory`)
	c.send("XRMD xdir")
	c.expect("250 Folder deleted successfully")
}

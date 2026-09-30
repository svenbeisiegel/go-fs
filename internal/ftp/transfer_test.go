package ftp

import (
	"context"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

func TestRetr(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "hello world")
	c := connect(t, server)
	c.login()

	content, reply := c.download(server, "RETR hello.txt")
	if content != "hello world" {
		t.Errorf("content = %q", content)
	}
	if reply != `226 Successfully transferred "hello.txt"` {
		t.Errorf("reply = %q", reply)
	}
}

func TestRetrOfAMissingFile(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	data := c.passive(server)
	defer func() { _ = data.Close() }()
	c.send("RETR nosuchfile")
	c.expect("550 File not found")
}

func TestRetrWithoutPermission(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFileRetrieve = &no
		cfg.Users = []config.User{user}
	})
	server.write(t, "hello.txt", "hello")

	c := connect(t, server)
	c.login()
	c.send("RETR hello.txt")
	c.expect(`550 Transfer failed "hello.txt"`)
}

func TestRetrOutsideTheBasefolderIsAnswered(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	// the reply matters as much as the refusal: the original hung here
	data := c.passive(server)
	defer func() { _ = data.Close() }()
	c.send("RETR ../../../../../../etc/hosts")
	c.expect(`550 Transfer failed "../../../../../../etc/hosts"`)
}

func TestRetrWithRestartOffset(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "0123456789")
	c := connect(t, server)
	c.login()

	c.send("REST 4")
	c.expect("350 Restarting at 4")
	content, reply := c.download(server, "RETR hello.txt")
	if content != "456789" {
		t.Errorf("content = %q, want the tail from offset 4", content)
	}
	if !strings.HasPrefix(reply, "226") {
		t.Errorf("reply = %q", reply)
	}

	// the offset is consumed by one transfer
	content, _ = c.download(server, "RETR hello.txt")
	if content != "0123456789" {
		t.Errorf("the restart offset leaked into the next transfer: %q", content)
	}
}

func TestRestRejectsANegativeOffset(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("REST -1")
	c.expect("550 Wrong restart offset")
	c.send("REST 0")
	c.expect("350 Restarting at 0")
}

func TestStor(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	reply := c.upload(server, "STOR mytestfile", "SOMETESTCONTENT")
	if reply != `226 Successfully transferred "mytestfile"` {
		t.Errorf("reply = %q", reply)
	}
	if got := server.read(t, "mytestfile"); got != "SOMETESTCONTENT" {
		t.Errorf("stored %q", got)
	}
}

func TestStorWithoutPermission(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFileCreate = &no
		cfg.Users = []config.User{user}
	})

	c := connect(t, server)
	c.login()
	c.send("STOR mytestfile")
	c.expect(`550 Transfer failed "mytestfile"`)
}

func TestStorOverwrite(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFileOverwrite = &no
		cfg.Users = []config.User{user}
	})
	server.write(t, "exists.txt", "old")

	c := connect(t, server)
	c.login()
	c.send("STOR exists.txt")
	c.expect("550 File already exists")

	// a traversing path is refused before the permission is even considered
	c.send("STOR ../../escape.txt")
	c.expect(`550 Transfer failed "../../escape.txt"`)
}

func TestStorWithRestartOffset(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "resume", "AAAABBBB")
	c := connect(t, server)
	c.login()

	c.send("REST 4")
	c.expect("350 Restarting at 4")
	reply := c.upload(server, "STOR resume", "CCCC")
	if !strings.HasPrefix(reply, "226") {
		t.Errorf("reply = %q", reply)
	}
	// the first four bytes are kept, the rest replaced from the offset
	if got := server.read(t, "resume"); got != "AAAACCCC" {
		t.Errorf("stored %q, want AAAACCCC", got)
	}
}

func TestAppe(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "appefile", "FIRST")
	c := connect(t, server)
	c.login()

	reply := c.upload(server, "APPE appefile", "SECOND")
	if !strings.HasPrefix(reply, "226") {
		t.Errorf("reply = %q", reply)
	}
	if got := server.read(t, "appefile"); got != "FIRSTSECOND" {
		t.Errorf("stored %q", got)
	}
}

func TestStou(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	data := c.passive(server)
	c.send("STOU upload")
	opening := c.expectCode("150")
	// RFC 1123 requires the generated name in the opening reply
	pattern := regexp.MustCompile(`^150 FILE: (upload\.[0-9a-f]{8})$`)
	match := pattern.FindStringSubmatch(opening)
	if match == nil {
		t.Fatalf("opening reply = %q", opening)
	}
	name := match[1]

	if _, err := io.WriteString(data, "UNIQUECONTENT"); err != nil {
		t.Fatal(err)
	}
	_ = data.Close()

	reply := c.reply()
	if reply != `226 Successfully transferred "`+name+`"` {
		t.Errorf("reply = %q", reply)
	}
	if got := server.read(t, name); got != "UNIQUECONTENT" {
		t.Errorf("stored %q", got)
	}
}

func TestStouWithoutPermission(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFileCreate = &no
		cfg.Users = []config.User{user}
	})

	c := connect(t, server)
	c.login()
	c.send("STOU upload")
	c.expectCode("550")
}

func TestTransfersAreLogged(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "hello")
	c := connect(t, server)
	c.login()

	if _, reply := c.download(server, "RETR hello.txt"); !strings.HasPrefix(reply, "226") {
		t.Fatalf("reply = %q", reply)
	}
	time.Sleep(100 * time.Millisecond)
	records := server.logs.all("ftp download")
	if len(records) != 1 {
		t.Fatalf("got %d download records, want 1", len(records))
	}
	if records[0].attrs["file"] != "/hello.txt" || records[0].attrs["user"] != "john" {
		t.Errorf("record = %v", records[0].attrs)
	}

	c.upload(server, "STOR up.txt", "written")
	time.Sleep(100 * time.Millisecond)
	uploads := server.logs.all("ftp upload")
	if len(uploads) != 1 || uploads[0].attrs["bytes"] != int64(7) {
		t.Errorf("upload records = %v", uploads)
	}
}

func TestAbortWithoutATransfer(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("ABOR")
	c.expect("226 Abort successful")
}

func TestAbortDuringATransfer(t *testing.T) {
	server := newServer(t, nil)
	// a file large enough that the transfer is still going when ABOR arrives
	server.write(t, "big.bin", strings.Repeat("x", 8<<20))

	c := connect(t, server)
	c.login()
	data := c.passive(server)
	c.send("RETR big.bin")
	c.expectCode("150")

	// read a little, then abort without draining the rest
	buf := make([]byte, 1024)
	_ = data.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(data, buf); err != nil {
		t.Fatalf("reading the first bytes: %v", err)
	}
	c.send("ABOR")

	c.expect("426 Connection closed; transfer aborted")
	c.expect("226 Abort successful")
	_ = data.Close()

	// the connection stays usable afterwards
	c.send("PWD")
	c.expect(`257 "/" is current directory`)
}

func TestRenameCommands(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "mytestfile", "content")
	c := connect(t, server)
	c.login()

	c.send("RNFR nosuchfile")
	c.expect("550 File does not exist")

	c.send("RNFR mytestfile")
	c.expect("350 File exists")
	c.send("RNTO renamed")
	c.expect("250 File renamed successfully")
	if got := server.read(t, "renamed"); got != "content" {
		t.Errorf("renamed file holds %q", got)
	}

	// renaming onto an existing name is refused
	server.write(t, "other", "other")
	c.send("RNFR renamed")
	c.expect("350 File exists")
	c.send("RNTO other")
	c.expect("550 File already exists")
}

func TestDele(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "mytestfile", "content")
	c := connect(t, server)
	c.login()

	c.send("DELE nosuchfile")
	c.expect("550 File not found")
	c.send("DELE mytestfile")
	c.expect("250 File deleted successfully")
	c.send("DELE mytestfile")
	c.expect("550 File not found")
}

func TestDeleWithoutPermission(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFileDelete = &no
		cfg.Users = []config.User{user}
	})
	server.write(t, "mytestfile", "content")

	c := connect(t, server)
	c.login()
	c.send("DELE mytestfile")
	c.expect("550 Permission denied")
}

func TestActiveModeTransfer(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "active data")
	c := connect(t, server)
	c.login()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := portOf(listener.Addr())

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	c.send("PORT 127,0,0,1,%d,%d", port/256, port%256)
	c.expect("200 Port command successful")
	c.send("RETR hello.txt")
	c.expectCode("150")

	select {
	case data := <-accepted:
		_ = data.SetReadDeadline(time.Now().Add(3 * time.Second))
		content, _ := io.ReadAll(data)
		_ = data.Close()
		if string(content) != "active data" {
			t.Errorf("content = %q", content)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the server never connected back")
	}
	c.expectCode("226")
}

func TestEprtTransfer(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "eprt data")
	c := connect(t, server)
	c.login()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	c.send("EPRT |1|127.0.0.1|%s|", strconv.Itoa(portOf(listener.Addr())))
	c.expect("200 Extended Port command successful")
	c.send("RETR hello.txt")
	c.expectCode("150")

	select {
	case data := <-accepted:
		content, _ := io.ReadAll(data)
		_ = data.Close()
		if string(content) != "eprt data" {
			t.Errorf("content = %q", content)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the server never connected back")
	}
	c.expectCode("226")
}

func TestTransferWithoutADataChannel(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "content")
	c := connect(t, server)
	c.login()

	c.send("RETR hello.txt")
	c.expect("501 Command failed")
}

// A transfer in flight is blocked moving bytes over the data connection, which
// closing the control connection does not reach. Shutdown has to abort it, or a
// client that stops reading holds up the shutdown of the whole process and
// every reload that has to rebind the listener.
func TestShutdownAbortsARunningTransfer(t *testing.T) {
	server := newServer(t, nil)
	// large enough that the copy blocks once the socket buffers are full
	server.write(t, "big.bin", strings.Repeat("x", 8<<20))

	c := connect(t, server)
	c.login()
	data := c.passive(server)
	defer func() { _ = data.Close() }()

	c.send("RETR big.bin")
	c.expectCode("150")

	// read a little and then stop, leaving the server blocked in the copy
	buf := make([]byte, 1024)
	_ = data.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(data, buf); err != nil {
		t.Fatalf("reading the start of the transfer: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_ = server.Shutdown(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not return while a transfer was stalled")
	}
}

// A transfer that runs longer than idleTimeout is not an idle session: the
// client is busy on the data connection and owes nothing on the control one.
// Before this, a download longer than the idle timeout finished and the session
// was then closed with a 421 for having been "idle" throughout it.
func TestATransferDoesNotTripTheIdleTimeout(t *testing.T) {
	server := newServer(t, func(cfg *ftpConfig) {
		cfg.IdleTimeout = 1
		cfg.TransferIdleTimeout = 30
	})
	// large enough that the server blocks writing it, so the transfer is still
	// running while the control connection stays silent
	server.write(t, "slow.bin", strings.Repeat("y", 8<<20))

	c := connect(t, server)
	c.login()
	data := c.passive(server)

	c.send("RETR slow.bin")
	c.expectCode("150")

	buf := make([]byte, 4096)
	_ = data.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(data, buf); err != nil {
		t.Fatalf("reading the start of the transfer: %v", err)
	}
	// stay silent on the control connection for longer than idleTimeout while
	// the transfer is still going
	time.Sleep(2500 * time.Millisecond)

	_ = data.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.Copy(io.Discard, data); err != nil {
		t.Fatalf("draining the transfer: %v", err)
	}
	_ = data.Close()

	// the transfer is answered, and the session it ran on is still there
	c.expectCode("226")
	c.send("NOOP")
	c.expect("200 NOOP ok")
}

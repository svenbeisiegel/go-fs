package ftp

import (
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-fs/internal/service"
)

// activeListener is the client half of an active transfer: it listens, and
// reports the connection the server opens back to it.
func activeListener(t *testing.T) (net.Listener, chan net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	return listener, accepted
}

// awaitData takes the connection the server opened, or fails.
func awaitData(t *testing.T, accepted chan net.Conn) net.Conn {
	t.Helper()
	select {
	case data := <-accepted:
		t.Cleanup(func() { _ = data.Close() })
		return data
	case <-time.After(3 * time.Second):
		t.Fatal("the server never connected back")
		return nil
	}
}

// sourcePortOf is the port the server's end of a data connection came from,
// which is what ftp.activeSourcePort sets.
func sourcePortOf(t *testing.T, data net.Conn) int {
	t.Helper()
	_, port, err := net.SplitHostPort(data.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return number
}

// An active transfer leaves from the configured port, which is the whole point
// of the setting: a firewall can then be told one port instead of the whole
// ephemeral range.
func TestActiveSourcePortIsUsed(t *testing.T) {
	source := reserveDataPorts(1)
	server := newServer(t, func(cfg *ftpConfig) { cfg.ActiveSourcePort = source })
	server.write(t, "hello.txt", "active data")

	for _, mode := range []string{"PORT", "EPRT"} {
		t.Run(mode, func(t *testing.T) {
			c := connect(t, server)
			c.login()

			listener, accepted := activeListener(t)
			port := portOf(listener.Addr())
			if mode == "PORT" {
				c.send("PORT 127,0,0,1,%d,%d", port/256, port%256)
				c.expect("200 Port command successful")
			} else {
				c.send("EPRT |1|127.0.0.1|%d|", port)
				c.expect("200 Extended Port command successful")
			}

			c.send("RETR hello.txt")
			c.expectCode("150")

			data := awaitData(t, accepted)
			if got := sourcePortOf(t, data); got != source {
				t.Errorf("the data connection came from port %d, want %d", got, source)
			}
			if content, _ := io.ReadAll(data); string(content) != "active data" {
				t.Errorf("content = %q", content)
			}
			c.expectCode("226")
		})
	}
}

// The reason the socket asks for SO_REUSEADDR: without it the second transfer
// cannot bind the port, which the first one leaves in TIME_WAIT.
func TestActiveSourcePortIsReusedBackToBack(t *testing.T) {
	source := reserveDataPorts(1)
	server := newServer(t, func(cfg *ftpConfig) { cfg.ActiveSourcePort = source })
	server.write(t, "hello.txt", "again and again")

	c := connect(t, server)
	c.login()

	for attempt := 1; attempt <= 3; attempt++ {
		listener, accepted := activeListener(t)
		c.send("EPRT |1|127.0.0.1|%d|", portOf(listener.Addr()))
		c.expect("200 Extended Port command successful")
		c.send("RETR hello.txt")
		c.expectCode("150")

		data := awaitData(t, accepted)
		if got := sourcePortOf(t, data); got != source {
			t.Fatalf("transfer %d came from port %d, want %d", attempt, got, source)
		}
		if content, _ := io.ReadAll(data); string(content) != "again and again" {
			t.Fatalf("transfer %d: content = %q", attempt, content)
		}
		c.expectCode("226")
	}
}

// And two at once, which is the other collision: both sockets want the same
// local port at the same time, and differ only in where they connect to.
func TestActiveSourcePortServesTwoAtOnce(t *testing.T) {
	source := reserveDataPorts(1)
	server := newServer(t, func(cfg *ftpConfig) { cfg.ActiveSourcePort = source })
	server.write(t, "hello.txt", "shared port")

	first, firstData := activeListener(t)
	second, secondData := activeListener(t)

	clients := make([]*client, 2)
	for i, listener := range []net.Listener{first, second} {
		c := connect(t, server)
		c.login()
		c.send("EPRT |1|127.0.0.1|%d|", portOf(listener.Addr()))
		c.expect("200 Extended Port command successful")
		c.send("RETR hello.txt")
		c.expectCode("150")
		clients[i] = c
	}

	for i, accepted := range []chan net.Conn{firstData, secondData} {
		data := awaitData(t, accepted)
		if got := sourcePortOf(t, data); got != source {
			t.Errorf("transfer %d came from port %d, want %d", i, got, source)
		}
		if content, _ := io.ReadAll(data); string(content) != "shared port" {
			t.Errorf("transfer %d: content = %q", i, content)
		}
		clients[i].expectCode("226")
	}
}

// 0 is the setting that leaves the choice to the system, which is the default.
func TestActiveSourcePortZeroTakesAnEphemeralPort(t *testing.T) {
	server := newServer(t, nil)
	if server.settings().cfg.ActiveSourcePort != 0 {
		t.Fatal("the test server should not pin a source port")
	}
	server.write(t, "hello.txt", "ephemeral")

	c := connect(t, server)
	c.login()
	listener, accepted := activeListener(t)
	c.send("EPRT |1|127.0.0.1|%d|", portOf(listener.Addr()))
	c.expect("200 Extended Port command successful")
	c.send("RETR hello.txt")
	c.expectCode("150")

	data := awaitData(t, accepted)
	if got := sourcePortOf(t, data); got == 0 {
		t.Error("the data connection has no source port")
	}
	if content, _ := io.ReadAll(data); string(content) != "ephemeral" {
		t.Errorf("content = %q", content)
	}
	c.expectCode("226")
}

// A passive transfer is accepted inside the configured range and nowhere else.
func TestPassiveRangeIsHonoured(t *testing.T) {
	first := reserveDataPorts(3)
	server := newServer(t, func(cfg *ftpConfig) {
		cfg.PassiveMinPort = first
		cfg.PassiveMaxPort = first + 2
	})
	server.write(t, "hello.txt", "passive data")

	c := connect(t, server)
	c.login()
	data := c.passive(server)
	defer func() { _ = data.Close() }()

	port := sourcePortOf(t, data) // the port the client dialled is the server's
	if port < first || port > first+2 {
		t.Errorf("the passive port %d is outside %d..%d", port, first, first+2)
	}

	// and the transfer over it works
	c.send("RETR hello.txt")
	c.expectCode("150")
	if content, _ := io.ReadAll(data); string(content) != "passive data" {
		t.Errorf("content = %q", content)
	}
	c.expectCode("226")
}

// passivePort asks for a passive channel and reads the port out of the reply
// without connecting to it, so the listener stays bound and the port stays
// taken.
func passivePort(c *client) int {
	c.t.Helper()
	c.send("EPSV")
	reply := c.expectCode("229")
	open := strings.Index(reply, "|||")
	closing := strings.LastIndex(reply, "|")
	if open < 0 || closing <= open+3 {
		c.t.Fatalf("cannot read the port out of %q", reply)
	}
	port, err := strconv.Atoi(reply[open+3 : closing])
	if err != nil {
		c.t.Fatalf("cannot read the port out of %q", reply)
	}
	return port
}

// A range of one port pins the passive port exactly, and once it is held a
// second channel has nowhere to go rather than straying outside the range.
func TestPassiveRangeOfOnePortIsExact(t *testing.T) {
	only := reserveDataPorts(1)
	server := newServer(t, func(cfg *ftpConfig) {
		cfg.PassiveMinPort = only
		cfg.PassiveMaxPort = only
		cfg.MaxConnections = 2
	})

	// the listener is released as soon as the data connection is accepted, so
	// this one is left waiting to keep the port
	first := connect(t, server)
	first.login()
	if got := passivePort(first); got != only {
		t.Errorf("the passive port is %d, want %d", got, only)
	}

	second := connect(t, server)
	second.login()
	second.send("EPSV")
	second.expectCode("501")

	if len(server.logs.matching("holds fewer ports than")) == 0 {
		t.Error("a range narrower than maxConnections should be warned about at startup")
	}
}

// Narrowing the range through the web interface is a reload, not a restart, so
// the warning has to be reported there too or it would only ever be seen by
// someone who edited the file and restarted.
func TestNarrowPassiveRangeIsWarnedAboutOnReload(t *testing.T) {
	server := newServer(t, nil)
	if len(server.logs.matching("holds fewer ports than")) != 0 {
		t.Fatal("the test server starts with a wide enough range")
	}

	next := server.settings().cfg
	next.PassiveMinPort = reserveDataPorts(1)
	next.PassiveMaxPort = next.PassiveMinPort
	if err := server.Reload(next, server.settings().ftps, server.settings().users); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(server.logs.matching("holds fewer ports than")) == 0 {
		t.Error("narrowing the range on a reload should warn")
	}
}

// All three are read per transfer, so none of them needs the listener rebound.
func TestDataPortsReloadWithoutARestart(t *testing.T) {
	server := newServer(t, nil)

	next := server.settings().cfg
	next.PassiveMinPort = reserveDataPorts(2)
	next.PassiveMaxPort = next.PassiveMinPort + 1
	next.ActiveSourcePort = reserveDataPorts(1)
	if err := server.Reload(next, server.settings().ftps, server.settings().users); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if err := server.Reload(next, server.settings().ftps, server.settings().users); err == service.ErrNeedsRestart {
		t.Fatal("the data ports should not need a restart")
	}

	// and the next transfer uses them
	c := connect(t, server)
	c.login()
	data := c.passive(server)
	defer func() { _ = data.Close() }()
	if got := sourcePortOf(t, data); got != next.PassiveMinPort {
		t.Errorf("the passive port is %d, want %d", got, next.PassiveMinPort)
	}
}

package tftp

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-fs/internal/config"
)

func TestServerStartsAndStops(t *testing.T) {
	server := newServer(t, nil)
	if server.port == 0 {
		t.Fatal("the server did not report a bound port")
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// stopping twice is not an error
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func TestNewRejectsMissingBasefolder(t *testing.T) {
	cfg := config.Default().TFTP
	cfg.Basefolder = filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := New(cfg, discardLogger()); err == nil {
		t.Error("a missing base folder has to be refused")
	}
}

func TestReadRequest(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", []byte("hello world"))

	payload, packets, failure := dial(t, server.port).download("hello.txt", modeOctet, 1)
	if failure != nil {
		code, message := errorOf(t, failure)
		t.Fatalf("unexpected error %d %q", code, message)
	}
	if string(payload) != "hello world" {
		t.Errorf("payload = %q", payload)
	}
	if packets != 1 {
		t.Errorf("got %d data packets, want 1", packets)
	}
}

func TestReadRequestInSubfolder(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "sub/inner.txt", []byte("inner"))

	payload, _, failure := dial(t, server.port).download("sub/inner.txt", modeOctet, 1)
	if failure != nil {
		t.Fatal("a path below the base folder has to work")
	}
	if string(payload) != "inner" {
		t.Errorf("payload = %q", payload)
	}
}

func TestReadRequestForMissingFile(t *testing.T) {
	server := newServer(t, nil)
	_, _, failure := dial(t, server.port).download("nope.txt", modeOctet, 1)
	if failure == nil {
		t.Fatal("expected an error")
	}
	if code, _ := errorOf(t, failure); code != errFileNotFound {
		t.Errorf("code = %d, want %d", code, errFileNotFound)
	}
}

func TestReadRequestOfEmptyFileSendsOneEmptyBlock(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "empty.txt", nil)

	payload, packets, failure := dial(t, server.port).download("empty.txt", modeOctet, 1)
	if failure != nil {
		t.Fatal("an empty file has to transfer")
	}
	if len(payload) != 0 {
		t.Errorf("payload = %q, want empty", payload)
	}
	if packets != 1 {
		t.Errorf("got %d data packets, want exactly one empty block", packets)
	}
}

func TestReadRequestOfExactMultipleEndsWithEmptyBlock(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "exact.txt", bytes.Repeat([]byte("x"), 512))

	payload, packets, failure := dial(t, server.port).download("exact.txt", modeOctet, 1)
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	if len(payload) != 512 {
		t.Errorf("payload is %d bytes, want 512", len(payload))
	}
	if packets != 2 {
		t.Errorf("got %d data packets, want a full block plus an empty one", packets)
	}
}

func TestReadRequestMultipleBlocks(t *testing.T) {
	server := newServer(t, nil)
	content := make([]byte, 4096+17)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	server.write(t, "big.bin", content)

	payload, _, failure := dial(t, server.port).download("big.bin", modeOctet, 1)
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	if !bytes.Equal(payload, content) {
		t.Errorf("payload differs: got %d bytes, want %d", len(payload), len(content))
	}
}

func TestWriteRequestRefusedWhenNotAllowed(t *testing.T) {
	server := newServer(t, nil) // allowWrite defaults to false
	failure := dial(t, server.port).upload("new.txt", modeOctet, []byte("data"))
	if failure == nil {
		t.Fatal("expected an error")
	}
	if code, _ := errorOf(t, failure); code != errAccessViolation {
		t.Errorf("code = %d, want %d", code, errAccessViolation)
	}
}

func TestWriteRequestCreatesFile(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })

	if failure := dial(t, server.port).upload("new.txt", modeOctet, []byte("written")); failure != nil {
		code, message := errorOf(t, failure)
		t.Fatalf("unexpected error %d %q", code, message)
	}
	if got := server.read(t, "new.txt"); string(got) != "written" {
		t.Errorf("stored %q", got)
	}
}

func TestWriteRequestMultipleBlocks(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })
	content := make([]byte, 3*512+11)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	if failure := dial(t, server.port).upload("big.bin", modeOctet, content); failure != nil {
		t.Fatal("the upload failed")
	}
	if got := server.read(t, "big.bin"); !bytes.Equal(got, content) {
		t.Errorf("stored %d bytes, want %d", len(got), len(content))
	}
}

func TestWriteRequestOverwrite(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })
	server.write(t, "exists.txt", []byte("old"))

	failure := dial(t, server.port).upload("exists.txt", modeOctet, []byte("new"))
	if failure == nil {
		t.Fatal("overwriting has to be refused by default")
	}
	if code, _ := errorOf(t, failure); code != errFileExists {
		t.Errorf("code = %d, want %d", code, errFileExists)
	}

	allowed := newServer(t, func(c *config.TFTP) {
		c.AllowWrite = true
		c.AllowOverwrite = true
	})
	allowed.write(t, "exists.txt", []byte("old"))
	if failure := dial(t, allowed.port).upload("exists.txt", modeOctet, []byte("new")); failure != nil {
		t.Fatal("overwriting should be allowed")
	}
	if got := allowed.read(t, "exists.txt"); string(got) != "new" {
		t.Errorf("stored %q, want new", got)
	}
}

func TestNetasciiRoundTrip(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) {
		c.AllowWrite = true
		c.AllowOverwrite = true
	})
	server.write(t, "text.txt", []byte("line1\nline2\n"))

	// reading translates the host line endings into netascii
	payload, _, failure := dial(t, server.port).download("text.txt", modeNetascii, 1)
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	if string(payload) != "line1\r\nline2\r\n" {
		t.Errorf("netascii payload = %q", payload)
	}

	// and octet mode leaves the file alone
	payload, _, failure = dial(t, server.port).download("text.txt", modeOctet, 1)
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	if string(payload) != "line1\nline2\n" {
		t.Errorf("octet payload = %q", payload)
	}

	// writing translates back
	if failure := dial(t, server.port).upload("written.txt", modeNetascii, []byte("a\r\nb\r\n")); failure != nil {
		t.Fatal("the upload failed")
	}
	if got := server.read(t, "written.txt"); string(got) != "a\nb\n" {
		t.Errorf("stored %q, want a\\nb\\n", got)
	}
}

func TestNetasciiLoneCarriageReturn(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })
	server.write(t, "cr.txt", []byte("a\rb"))

	payload, _, failure := dial(t, server.port).download("cr.txt", modeNetascii, 1)
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	// a lone carriage return travels as CR NUL
	if string(payload) != "a\r\x00b" {
		t.Errorf("payload = %q", payload)
	}

	if failure := dial(t, server.port).upload("back.txt", modeNetascii, []byte("a\r\x00b")); failure != nil {
		t.Fatal("the upload failed")
	}
	if got := server.read(t, "back.txt"); string(got) != "a\rb" {
		t.Errorf("stored %q", got)
	}
}

func TestUnsupportedModeIsRefused(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "f.txt", []byte("data"))

	_, _, failure := dial(t, server.port).download("f.txt", "mail", 1)
	if failure == nil {
		t.Fatal("expected an error")
	}
	code, message := errorOf(t, failure)
	if code != errIllegalOperation {
		t.Errorf("code = %d, want %d", code, errIllegalOperation)
	}
	if message != "Unsupported transfer mode mail" {
		t.Errorf("message = %q", message)
	}
}

func TestNonASCIIFilename(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "näme.txt", []byte("content"))

	payload, _, failure := dial(t, server.port).download("näme.txt", modeOctet, 1)
	if failure != nil {
		t.Fatal("a UTF-8 file name has to work")
	}
	if string(payload) != "content" {
		t.Errorf("payload = %q", payload)
	}
}

func TestMalformedRequestIsAnswered(t *testing.T) {
	server := newServer(t, nil)
	c := dial(t, server.port)
	// an RRQ opcode with no terminated file name
	c.sendTo(c.server, []byte{0x00, 0x01, 'a', 'b'})

	packet := c.receive(time.Second)
	if packet == nil {
		t.Fatal("a malformed request should still be answered")
	}
	if code, _ := errorOf(t, packet); code != errIllegalOperation {
		t.Errorf("code = %d, want %d", code, errIllegalOperation)
	}
}

func TestPacketThatIsNotARequestGetsNoReply(t *testing.T) {
	server := newServer(t, nil)
	c := dial(t, server.port)

	// An ERROR is never acknowledged (RFC 1350) and stray DATA/ACK packets get
	// no reply either, so the server cannot bounce a larger packet at a spoofed
	// source.
	for _, op := range []opcode{opDATA, opACK, opERROR, opOACK, 99} {
		c.sendTo(c.server, []byte{byte(op >> 8), byte(op), 0x00, 0x01})
		if packet := c.receive(250 * time.Millisecond); packet != nil {
			t.Errorf("opcode %d was answered with %v", op, packet)
		}
	}
}

func TestUnknownTransferID(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "big.bin", bytes.Repeat([]byte("x"), 2048))

	c := dial(t, server.port)
	c.request(opRRQ, "big.bin", modeOctet)
	first := c.receive(time.Second)
	if first == nil || opcodeOf(first) != opDATA {
		t.Fatal("expected the first data block")
	}

	// a second socket talking to the transfer port is not the transfer's peer
	stranger := dial(t, server.port)
	stranger.sendTo(c.peer, encodeACK(1))
	reply := stranger.receive(time.Second)
	if reply == nil {
		t.Fatal("the stranger should be told about the unknown transfer id")
	}
	if code, _ := errorOf(t, reply); code != errUnknownTID {
		t.Errorf("code = %d, want %d", code, errUnknownTID)
	}
}

func TestBlockNumberRollover(t *testing.T) {
	if testing.Short() {
		t.Skip("the rollover transfer is slow")
	}
	server := newServer(t, nil)
	// with the smallest block size the 16 bit counter wraps within 512 KB
	const blockSize = 8
	content := make([]byte, 600*1024)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	server.write(t, "big.bin", content)

	payload, packets, failure := dial(t, server.port).download("big.bin", modeOctet, 1,
		option{"blksize", "8"})
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	if !bytes.Equal(payload, content) {
		t.Fatalf("the payload differs: got %d bytes, want %d", len(payload), len(content))
	}
	if want := len(content)/blockSize + 1; packets != want {
		t.Errorf("got %d data packets, want %d", packets, want)
	}
}

func TestWriteBlockNumberRollover(t *testing.T) {
	if testing.Short() {
		t.Skip("the rollover transfer is slow")
	}
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })
	content := make([]byte, 600*1024)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	if failure := dial(t, server.port).upload("big.bin", modeOctet, content, option{"blksize", "8"}); failure != nil {
		t.Fatal("the upload failed")
	}
	if got := server.read(t, "big.bin"); !bytes.Equal(got, content) {
		t.Errorf("stored %d bytes, want %d", len(got), len(content))
	}
}

func TestTransferEventsAreLogged(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })
	server.write(t, "f.txt", []byte("hello"))

	if _, _, failure := dial(t, server.port).download("f.txt", modeOctet, 1); failure != nil {
		t.Fatal("the download failed")
	}
	record, ok := server.logs.find("tftp transfer complete")
	if !ok {
		t.Fatal("no completion record for the download")
	}
	if record.attrs["direction"] != "download" || record.attrs["bytes"] != int64(5) {
		t.Errorf("download record = %v", record.attrs)
	}
	if record.attrs["file"] != "f.txt" || record.attrs["client"] == nil {
		t.Errorf("the record has to name the file and the client: %v", record.attrs)
	}

	if failure := dial(t, server.port).upload("up.txt", modeOctet, []byte("written")); failure != nil {
		t.Fatal("the upload failed")
	}
	found := false
	for _, record := range server.logs.all("tftp transfer complete") {
		if record.attrs["direction"] == "upload" && record.attrs["bytes"] == int64(7) {
			found = true
		}
	}
	if !found {
		t.Error("no completion record for the upload")
	}
}

func TestShutdownAbortsRunningTransfers(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "big.bin", bytes.Repeat([]byte("x"), 8192))

	c := dial(t, server.port)
	c.request(opRRQ, "big.bin", modeOctet)
	if packet := c.receive(time.Second); packet == nil {
		t.Fatal("expected the first data block")
	}
	if server.ActiveTransfers() != 1 {
		t.Fatalf("got %d active transfers, want 1", server.ActiveTransfers())
	}

	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if server.ActiveTransfers() != 0 {
		t.Errorf("got %d active transfers after shutdown, want 0", server.ActiveTransfers())
	}
}

func TestReadErrorIsReported(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a mode 000 file anyway")
	}
	server := newServer(t, nil)
	path := server.write(t, "locked.txt", []byte("secret"))
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skipf("cannot drop the permissions: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, _, failure := dial(t, server.port).download("locked.txt", modeOctet, 1)
	if failure == nil {
		t.Fatal("a file that cannot be opened has to produce an error")
	}
	if code, _ := errorOf(t, failure); code != errAccessViolation {
		t.Errorf("code = %d, want %d", code, errAccessViolation)
	}
}

// An upload is written beside its destination and renamed over it only once it
// is complete. A transfer that is abandoned halfway leaves neither an empty
// file where there was none, nor a truncated one where the client was replacing
// something that was already there.
func TestAbandonedWriteLeavesTheDestinationAlone(t *testing.T) {
	t.Run("nothing was there", func(t *testing.T) {
		server := newServer(t, func(c *config.TFTP) {
			c.AllowWrite = true
			c.Timeout = 1
			c.Retries = 0
		})

		client := dial(t, server.port)
		client.request(opWRQ, "abandoned.bin", modeOctet)
		if op := opcodeOf(client.receive(2 * time.Second)); op != opACK {
			t.Fatalf("opcode = %d, want an ACK", op)
		}
		// one full block, then silence
		client.reply(encodeDATA(1, bytes.Repeat([]byte("x"), 512)))
		if op := opcodeOf(client.receive(2 * time.Second)); op != opACK {
			t.Fatalf("opcode = %d, want an ACK", op)
		}
		waitForNoTransfers(t, server)

		if _, err := os.Stat(filepath.Join(server.base, "abandoned.bin")); !os.IsNotExist(err) {
			t.Error("an abandoned upload left a file behind")
		}
		leftovers, err := os.ReadDir(server.base)
		if err != nil {
			t.Fatal(err)
		}
		if len(leftovers) != 0 {
			t.Errorf("the folder holds %d entries, want none", len(leftovers))
		}
	})

	t.Run("something was there", func(t *testing.T) {
		server := newServer(t, func(c *config.TFTP) {
			c.AllowWrite = true
			c.AllowOverwrite = true
			c.Timeout = 1
			c.Retries = 0
		})
		server.write(t, "exists.txt", []byte("the original"))

		client := dial(t, server.port)
		client.request(opWRQ, "exists.txt", modeOctet)
		if op := opcodeOf(client.receive(2 * time.Second)); op != opACK {
			t.Fatalf("opcode = %d, want an ACK", op)
		}
		client.reply(encodeDATA(1, bytes.Repeat([]byte("y"), 512)))
		if op := opcodeOf(client.receive(2 * time.Second)); op != opACK {
			t.Fatalf("opcode = %d, want an ACK", op)
		}
		waitForNoTransfers(t, server)

		if got := server.read(t, "exists.txt"); string(got) != "the original" {
			t.Errorf("the file that was there now holds %q", got)
		}
	})
}

func waitForNoTransfers(t *testing.T, server *testServer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if server.ActiveTransfers() == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the transfer did not end")
}

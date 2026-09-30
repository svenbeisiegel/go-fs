package tftp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-fs/internal/config"
)

func TestSymlinkOutOfBasefolderIsRefused(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := newServer(t, nil)
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(server.base, "link.txt")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	_, _, failure := dial(t, server.port).download("link.txt", modeOctet, 1)
	if failure == nil {
		t.Fatal("a symlink pointing out of the base folder must not be served")
	}
	if code, _ := errorOf(t, failure); code != errAccessViolation {
		t.Errorf("code = %d, want %d", code, errAccessViolation)
	}
}

func TestWritingThroughASymlinkedFolderIsRefused(t *testing.T) {
	outside := t.TempDir()
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })
	if err := os.Symlink(outside, filepath.Join(server.base, "escape")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	failure := dial(t, server.port).upload("escape/planted.txt", modeOctet, []byte("x"))
	if failure == nil {
		t.Fatal("writing through a symlinked folder must be refused")
	}
	if code, _ := errorOf(t, failure); code != errAccessViolation {
		t.Errorf("code = %d, want %d", code, errAccessViolation)
	}
	if _, err := os.Stat(filepath.Join(outside, "planted.txt")); err == nil {
		t.Error("the file was written outside the base folder")
	}
}

func TestPathTraversalIsRefused(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })

	for _, name := range []string{"../escape.txt", "../../etc/passwd", "sub/../../escape.txt"} {
		_, _, failure := dial(t, server.port).download(name, modeOctet, 1)
		if failure == nil {
			t.Errorf("%q should be refused", name)
			continue
		}
		if code, _ := errorOf(t, failure); code != errAccessViolation {
			t.Errorf("%q: code = %d, want %d", name, code, errAccessViolation)
		}
	}
	if failure := dial(t, server.port).upload("../escape.txt", modeOctet, []byte("x")); failure == nil {
		t.Error("a traversing write should be refused")
	}
}

func TestReadsCanBeTurnedOff(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) {
		c.AllowRead = false
		c.AllowWrite = true
	})
	server.write(t, "f.txt", []byte("hello"))

	_, _, failure := dial(t, server.port).download("f.txt", modeOctet, 1)
	if failure == nil {
		t.Fatal("reading should be refused")
	}
	if code, _ := errorOf(t, failure); code != errAccessViolation {
		t.Errorf("code = %d, want %d", code, errAccessViolation)
	}

	// writing still works on a read only server
	if failure := dial(t, server.port).upload("w.txt", modeOctet, []byte("x")); failure != nil {
		t.Error("writing should still be allowed")
	}
}

func TestDirectoryCreationCanBeTurnedOff(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) {
		c.AllowWrite = true
		c.AllowCreateDirectory = false
	})

	failure := dial(t, server.port).upload("newdir/x.txt", modeOctet, []byte("x"))
	if failure == nil {
		t.Fatal("creating a folder should be refused")
	}
	if code, _ := errorOf(t, failure); code != errAccessViolation {
		t.Errorf("code = %d, want %d", code, errAccessViolation)
	}
	if _, err := os.Stat(filepath.Join(server.base, "newdir")); err == nil {
		t.Error("the folder was created anyway")
	}

	// a file straight in the base folder is still accepted
	if failure := dial(t, server.port).upload("x.txt", modeOctet, []byte("x")); failure != nil {
		t.Error("a plain file should still be accepted")
	}
}

func TestUploadLargerThanMaxFileSizeIsRefused(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) {
		c.AllowWrite = true
		c.MaxFileSize = 100
	})

	// announced upfront through tsize, so no byte ever reaches the disk
	c := dial(t, server.port)
	c.request(opWRQ, "big.bin", modeOctet, option{"tsize", "999999"})
	packet := c.receive(time.Second)
	if packet == nil {
		t.Fatal("no answer")
	}
	code, message := errorOf(t, packet)
	if code != errDiskFull {
		t.Errorf("code = %d, want %d", code, errDiskFull)
	}
	if message != "File exceeds the maximum of 100 bytes" {
		t.Errorf("message = %q", message)
	}

	// and while the data arrives, without any announcement
	failure := dial(t, server.port).upload("big2.bin", modeOctet, bytes.Repeat([]byte("A"), 512), option{"blksize", "64"})
	if failure == nil {
		t.Fatal("the transfer should have been cut off")
	}
	if code, _ := errorOf(t, failure); code != errDiskFull {
		t.Errorf("code = %d, want %d", code, errDiskFull)
	}
}

func TestRetransmittedRequestDoesNotStartASecondTransfer(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "big.bin", bytes.Repeat([]byte("x"), 4096))

	c := dial(t, server.port)
	// the client believes its request was lost and sends it again
	c.request(opRRQ, "big.bin", modeOctet)
	c.request(opRRQ, "big.bin", modeOctet)

	firstBlocks := 0
	for {
		packet := c.receive(400 * time.Millisecond)
		if packet == nil {
			break
		}
		if opcodeOf(packet) == opDATA && blockOf(packet) == 1 {
			firstBlocks++
		}
	}
	if firstBlocks != 1 {
		t.Errorf("got %d copies of the first block, want 1", firstBlocks)
	}
	if active := server.ActiveTransfers(); active != 1 {
		t.Errorf("got %d transfers, want 1", active)
	}
}

func TestOneHostCannotTakeEverySlot(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) {
		c.MaxConnections = 10
		c.MaxConnectionsPerHost = 2
	})
	server.write(t, "f.txt", bytes.Repeat([]byte("x"), 4096))

	// five clients that never acknowledge anything
	for range 5 {
		c := dial(t, server.port)
		c.request(opRRQ, "f.txt", modeOctet)
	}
	time.Sleep(300 * time.Millisecond)

	if active := server.ActiveTransfers(); active != 2 {
		t.Errorf("got %d transfers, want the per host cap of 2", active)
	}
}

func TestServerBusyWhenMaxConnectionsReached(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) {
		c.MaxConnections = 2
		c.MaxConnectionsPerHost = 10
	})
	server.write(t, "f.txt", bytes.Repeat([]byte("x"), 4096))

	for range 2 {
		c := dial(t, server.port)
		c.request(opRRQ, "f.txt", modeOctet)
	}
	time.Sleep(200 * time.Millisecond)

	c := dial(t, server.port)
	c.request(opRRQ, "f.txt", modeOctet)
	packet := c.receive(time.Second)
	if packet == nil {
		t.Fatal("the third client got no answer")
	}
	code, message := errorOf(t, packet)
	if code != errNotDefined || message != "Server busy" {
		t.Errorf("got %d %q, want a server busy error", code, message)
	}
}

func TestTransferIsAbortedWhenItOutlivesTheDeadline(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) {
		c.TransferTimeout = 1
		c.Timeout = 30
		c.MaxTimeout = 30
	})
	server.write(t, "f.txt", []byte("hello"))

	c := dial(t, server.port)
	// negotiating a long retransmit interval would otherwise hold the slot
	c.request(opRRQ, "f.txt", modeOctet, option{"timeout", "30"})

	var failure []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		packet := c.receive(time.Second)
		if packet == nil {
			continue
		}
		if opcodeOf(packet) == opERROR {
			failure = packet
			break
		}
	}
	if failure == nil {
		t.Fatal("the transfer was not aborted")
	}
	if _, message := errorOf(t, failure); message != "Transfer took too long" {
		t.Errorf("message = %q", message)
	}
	time.Sleep(100 * time.Millisecond)
	if active := server.ActiveTransfers(); active != 0 {
		t.Errorf("got %d transfers after the deadline, want 0", active)
	}
}

func TestFinalAcknowledgementIsRepeatedWhileDallying(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })

	c := dial(t, server.port)
	c.request(opWRQ, "dally.txt", modeOctet)
	if packet := c.receive(time.Second); packet == nil || opcodeOf(packet) != opACK {
		t.Fatal("expected the initial acknowledgement")
	}
	c.reply(encodeDATA(1, []byte("short")))
	first := c.receive(time.Second)
	if first == nil || opcodeOf(first) != opACK || blockOf(first) != 1 {
		t.Fatal("expected the final acknowledgement")
	}

	// the client believes the acknowledgement was lost and retransmits
	c.reply(encodeDATA(1, []byte("short")))
	second := c.receive(time.Second)
	if second == nil || opcodeOf(second) != opACK || blockOf(second) != 1 {
		t.Fatal("the retransmitted final block was not acknowledged again")
	}
	if got := server.read(t, "dally.txt"); string(got) != "short" {
		t.Errorf("stored %q, want short", got)
	}
}

func TestAcknowledgingEveryBlockDoesNotMultiplyTheTraffic(t *testing.T) {
	server := newServer(t, nil)
	const blocks, blockSize = 400, 8
	server.write(t, "big.bin", bytes.Repeat([]byte("A"), blocks*blockSize))

	// a receiver that acknowledges every block instead of once per window is
	// not RFC 7440 conformant; the rewind budget has to keep it bounded
	c := dial(t, server.port)
	c.request(opRRQ, "big.bin", modeOctet, option{"blksize", "8"}, option{"windowsize", "16"})

	dataPackets := 0
	for {
		packet := c.receive(2 * time.Second)
		if packet == nil {
			break
		}
		switch opcodeOf(packet) {
		case opOACK:
			c.reply(encodeACK(0))
		case opDATA:
			dataPackets++
			c.reply(encodeACK(blockOf(packet)))
			if len(packet)-4 < blockSize {
				goto done
			}
		}
	}
done:
	ideal := blocks + 1
	if dataPackets < ideal {
		t.Errorf("got %d data packets, want at least %d", dataPackets, ideal)
	}
	if dataPackets > ideal*3 {
		t.Errorf("traffic amplified %.1fx, the rewind budget should keep it bounded",
			float64(dataPackets)/float64(ideal))
	}
}

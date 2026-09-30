package tftp

import (
	"bytes"
	"testing"
	"time"

	"go-fs/internal/config"
)

// oack sends a request and returns the options the server confirmed, or nil
// when it answered without an OACK.
func oack(t *testing.T, server *testServer, op opcode, filename string, mode string, options ...option) ([]option, []byte) {
	t.Helper()
	c := dial(t, server.port)
	c.request(op, filename, mode, options...)
	packet := c.receive(time.Second)
	if packet == nil {
		t.Fatal("the server did not answer")
	}
	if opcodeOf(packet) != opOACK {
		return nil, packet
	}
	return optionsOf(t, packet), packet
}

func TestTsizeIsAnsweredWithTheFileSize(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "f.txt", []byte("0123456789"))

	options, _ := oack(t, server, opRRQ, "f.txt", modeOctet, option{"tsize", "0"})
	want := []option{{"tsize", "10"}}
	if len(options) != 1 || options[0] != want[0] {
		t.Errorf("options = %v, want %v", options, want)
	}
}

func TestTsizeIsDeclinedForNetascii(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "f.txt", []byte("line\n"))

	// netascii changes the number of octets on the wire, so the size is not
	// known upfront and the option is declined; the transfer starts with DATA
	options, packet := oack(t, server, opRRQ, "f.txt", modeNetascii, option{"tsize", "0"})
	if options != nil {
		t.Errorf("tsize should not be answered for netascii, got %v", options)
	}
	if opcodeOf(packet) != opDATA {
		t.Errorf("expected the transfer to start with DATA, got opcode %d", opcodeOf(packet))
	}
}

func TestBlockSizeIsNegotiated(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "f.txt", bytes.Repeat([]byte("x"), 200))

	options, _ := oack(t, server, opRRQ, "f.txt", modeOctet, option{"blksize", "64"})
	if len(options) != 1 || options[0] != (option{"blksize", "64"}) {
		t.Fatalf("options = %v", options)
	}

	// and the negotiated size is actually used
	payload, packets, failure := dial(t, server.port).download("f.txt", modeOctet, 1, option{"blksize", "64"})
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	if len(payload) != 200 {
		t.Errorf("payload is %d bytes, want 200", len(payload))
	}
	if packets != 4 { // 64 + 64 + 64 + 8
		t.Errorf("got %d data packets, want 4", packets)
	}
}

func TestOversizedBlockSizeIsCapped(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.MaxBlockSize = 1468 })
	server.write(t, "f.txt", []byte("hello"))

	// a server may answer with a smaller value than requested (RFC 2348), which
	// is better than declining and falling back to 512
	options, _ := oack(t, server, opRRQ, "f.txt", modeOctet, option{"blksize", "65464"})
	if len(options) != 1 || options[0] != (option{"blksize", "1468"}) {
		t.Errorf("options = %v, want blksize 1468", options)
	}

	// a value the server can honour comes back unchanged
	options, _ = oack(t, server, opRRQ, "f.txt", modeOctet, option{"blksize", "1024"})
	if len(options) != 1 || options[0] != (option{"blksize", "1024"}) {
		t.Errorf("options = %v, want blksize 1024", options)
	}
}

func TestOversizedWindowSizeIsCapped(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.MaxWindowSize = 4 })
	server.write(t, "f.txt", []byte("hello"))

	options, _ := oack(t, server, opRRQ, "f.txt", modeOctet, option{"windowsize", "64"})
	if len(options) != 1 || options[0] != (option{"windowsize", "4"}) {
		t.Errorf("options = %v, want windowsize 4", options)
	}
}

func TestWndsizeSpellingIsAnswered(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "f.txt", []byte("hello"))

	// some clients spell the option wndsize, the answer has to use the same key
	options, _ := oack(t, server, opRRQ, "f.txt", modeOctet, option{"wndsize", "4"})
	if len(options) != 1 || options[0] != (option{"wndsize", "4"}) {
		t.Errorf("options = %v, want wndsize 4", options)
	}
}

func TestWindowSizeIsIgnoredForWriteRequests(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })

	// RFC 7440 windows are only implemented for reads, so the option is
	// declined and the transfer runs lock step
	options, packet := oack(t, server, opWRQ, "w.txt", modeOctet, option{"windowsize", "8"})
	if options != nil {
		t.Errorf("windowsize should be declined on a write request, got %v", options)
	}
	if opcodeOf(packet) != opACK || blockOf(packet) != 0 {
		t.Errorf("expected a plain ACK 0, got opcode %d", opcodeOf(packet))
	}
}

func TestNonNumericOptionValuesAreDeclined(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.AllowWrite = true })
	server.write(t, "f.txt", []byte("hello"))

	// tsize must not be echoed back verbatim
	options, packet := oack(t, server, opWRQ, "w.txt", modeOctet, option{"tsize", "notanumber"})
	if options != nil {
		t.Errorf("a non numeric tsize should be declined, got %v", options)
	}
	if opcodeOf(packet) != opACK {
		t.Errorf("expected a plain ACK, got opcode %d", opcodeOf(packet))
	}

	// a partly numeric blksize is not silently truncated to 512
	options, packet = oack(t, server, opRRQ, "f.txt", modeOctet, option{"blksize", "512abc"})
	if options != nil {
		t.Errorf("a partly numeric blksize should be declined, got %v", options)
	}
	if opcodeOf(packet) != opDATA {
		t.Errorf("expected the transfer to start with DATA, got opcode %d", opcodeOf(packet))
	}
}

func TestTimeoutIsCappedByMaxTimeout(t *testing.T) {
	server := newServer(t, func(c *config.TFTP) { c.MaxTimeout = 10 })
	server.write(t, "f.txt", []byte("hello"))

	// RFC 2349 requires the value to be echoed exactly, so one the server will
	// not use has to be declined rather than answered with something else
	options, packet := oack(t, server, opRRQ, "f.txt", modeOctet, option{"timeout", "255"})
	if options != nil {
		t.Errorf("an out of range timeout should be declined, got %v", options)
	}
	if opcodeOf(packet) != opDATA {
		t.Errorf("expected the transfer to start with DATA, got opcode %d", opcodeOf(packet))
	}

	options, _ = oack(t, server, opRRQ, "f.txt", modeOctet, option{"timeout", "10"})
	if len(options) != 1 || options[0] != (option{"timeout", "10"}) {
		t.Errorf("options = %v, want timeout 10", options)
	}
}

func TestOptionsAreAnsweredInAStableOrder(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "f.txt", []byte("hello"))

	options, _ := oack(t, server, opRRQ, "f.txt", modeOctet,
		option{"tsize", "0"}, option{"timeout", "3"},
		option{"windowsize", "2"}, option{"blksize", "256"})

	want := []option{{"blksize", "256"}, {"windowsize", "2"}, {"timeout", "3"}, {"tsize", "5"}}
	if len(options) != len(want) {
		t.Fatalf("options = %v, want %v", options, want)
	}
	for i := range want {
		if options[i] != want[i] {
			t.Fatalf("options = %v, want %v", options, want)
		}
	}
}

func TestWindowedTransferUsesTheIdealPacketCount(t *testing.T) {
	server := newServer(t, nil)
	const blocks, blockSize, windowSize = 400, 8, 16
	content := bytes.Repeat([]byte("B"), blocks*blockSize)
	server.write(t, "big.bin", content)

	payload, packets, failure := dial(t, server.port).download("big.bin", modeOctet, windowSize,
		option{"blksize", "8"}, option{"windowsize", "16"})
	if failure != nil {
		t.Fatal("the transfer failed")
	}
	if !bytes.Equal(payload, content) {
		t.Errorf("the payload differs: got %d bytes, want %d", len(payload), len(content))
	}
	// a receiver that acknowledges once per window costs no extra packets
	if packets != blocks+1 {
		t.Errorf("got %d data packets, want the ideal %d", packets, blocks+1)
	}
}

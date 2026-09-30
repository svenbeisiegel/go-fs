package tftp

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
)

// entry is one captured log record, flattened for easy assertions.
type entry struct {
	message string
	attrs   map[string]any
}

// logStore collects what the server logged during a test.
type logStore struct {
	mu      sync.Mutex
	entries []entry
}

// all returns every record with the given message.
func (s *logStore) all(message string) []entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []entry
	for _, e := range s.entries {
		if e.message == message {
			out = append(out, e)
		}
	}
	return out
}

// find returns the first record with the given message.
func (s *logStore) find(message string) (entry, bool) {
	if matches := s.all(message); len(matches) > 0 {
		return matches[0], true
	}
	return entry{}, false
}

// recorder is a slog handler that writes into a logStore. Unlike a throwaway
// handler it has to keep the attributes added with With, since that is where
// the client and file name live.
type recorder struct {
	store *logStore
	attrs []slog.Attr
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) WithGroup(string) slog.Handler            { return r }

func (r *recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, 0, len(r.attrs)+len(attrs))
	combined = append(combined, r.attrs...)
	combined = append(combined, attrs...)
	return &recorder{store: r.store, attrs: combined}
}

func (r *recorder) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]any, len(r.attrs)+record.NumAttrs())
	for _, a := range r.attrs {
		attrs[a.Key] = a.Value.Any()
	}
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	r.store.entries = append(r.store.entries, entry{message: record.Message, attrs: attrs})
	return nil
}

type testServer struct {
	*Server
	base string
	port int
	logs *logStore
}

// newServer starts a server on an ephemeral port with the given configuration
// tweaks applied to the defaults.
func newServer(t *testing.T, tune func(*config.TFTP)) *testServer {
	t.Helper()
	base := t.TempDir()
	cfg := config.Default().TFTP
	cfg.Basefolder = base
	cfg.Port = 0
	// bind IPv4 so the tests do not depend on how localhost resolves
	cfg.Type = "udp4"
	if tune != nil {
		tune(&cfg)
	}
	// the base folder may have been replaced by the tweak
	if cfg.Basefolder != base {
		base = cfg.Basefolder
	}

	logs := &logStore{}
	server, err := New(cfg, slog.New(&recorder{store: logs}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
	})
	return &testServer{Server: server, base: base, port: portOf(server.Addr()), logs: logs}
}

// write puts a file into the served folder.
func (s *testServer) write(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(s.base, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (s *testServer) read(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(s.base, name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// client is a raw UDP peer for driving the server.
type client struct {
	t      *testing.T
	conn   *net.UDPConn
	server *net.UDPAddr
	// peer is the transfer socket the server answered from
	peer *net.UDPAddr
}

func dial(t *testing.T, port int) *client {
	t.Helper()
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	server, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, conn: conn, server: server}
}

// request sends an RRQ or WRQ to the request socket.
func (c *client) request(op opcode, filename, mode string, options ...option) {
	c.t.Helper()
	packet := binary.BigEndian.AppendUint16(nil, uint16(op))
	packet = append(packet, filename...)
	packet = append(packet, 0)
	if mode == "" {
		mode = modeOctet
	}
	packet = append(packet, mode...)
	packet = append(packet, 0)
	for _, opt := range options {
		packet = append(packet, opt.key...)
		packet = append(packet, 0)
		packet = append(packet, opt.value...)
		packet = append(packet, 0)
	}
	c.sendTo(c.server, packet)
}

func (c *client) sendTo(to *net.UDPAddr, packet []byte) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDP(packet, to); err != nil {
		c.t.Fatal(err)
	}
}

// reply sends to whichever socket the server last answered from.
func (c *client) reply(packet []byte) {
	c.t.Helper()
	to := c.peer
	if to == nil {
		to = c.server
	}
	c.sendTo(to, packet)
}

// receive waits for one packet. It returns nil when nothing arrives in time.
func (c *client) receive(timeout time.Duration) []byte {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65536)
	n, from, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	c.peer = from
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

func opcodeOf(packet []byte) opcode {
	return opcode(binary.BigEndian.Uint16(packet))
}

func blockOf(packet []byte) uint16 {
	return binary.BigEndian.Uint16(packet[2:])
}

// errorOf splits an ERROR packet into its code and message.
func errorOf(t *testing.T, packet []byte) (errorCode, string) {
	t.Helper()
	if opcodeOf(packet) != opERROR {
		t.Fatalf("expected an ERROR packet, got opcode %d", opcodeOf(packet))
	}
	return errorCode(binary.BigEndian.Uint16(packet[2:])), string(packet[4 : len(packet)-1])
}

// optionsOf splits an OACK packet into its options.
func optionsOf(t *testing.T, packet []byte) []option {
	t.Helper()
	if opcodeOf(packet) != opOACK {
		t.Fatalf("expected an OACK packet, got opcode %d", opcodeOf(packet))
	}
	var out []option
	body := packet[2:]
	for {
		end := indexZero(body)
		if end < 0 {
			return out
		}
		key := string(body[:end])
		body = body[end+1:]
		end = indexZero(body)
		if end < 0 {
			return out
		}
		out = append(out, option{key: key, value: string(body[:end])})
		body = body[end+1:]
	}
}

// download runs a complete read request, acknowledging one window at a time as
// RFC 7440 requires. It returns the payload and how many DATA packets arrived.
func (c *client) download(filename, mode string, windowSize int, options ...option) (payload []byte, dataPackets int, failure []byte) {
	c.t.Helper()
	c.request(opRRQ, filename, mode, options...)

	blockSize := defaultBlockSize
	for _, opt := range options {
		if opt.key == "blksize" {
			blockSize, _ = strconv.Atoi(opt.value)
		}
	}
	if windowSize < 1 {
		windowSize = 1
	}

	inWindow := 0
	var lastBlock uint16
	for {
		packet := c.receive(2 * time.Second)
		if packet == nil {
			return payload, dataPackets, nil
		}
		switch opcodeOf(packet) {
		case opERROR:
			return payload, dataPackets, packet
		case opOACK:
			c.reply(encodeACK(0))
		case opDATA:
			dataPackets++
			data := packet[4:]
			lastBlock = blockOf(packet)
			payload = append(payload, data...)
			inWindow++
			last := len(data) < blockSize
			if inWindow == windowSize || last {
				inWindow = 0
				c.reply(encodeACK(lastBlock))
			}
			if last {
				// the server logs and closes after this acknowledgement
				time.Sleep(150 * time.Millisecond)
				return payload, dataPackets, nil
			}
		}
	}
}

// upload runs a complete write request.
func (c *client) upload(filename, mode string, content []byte, options ...option) (failure []byte) {
	c.t.Helper()
	c.request(opWRQ, filename, mode, options...)

	blockSize := defaultBlockSize
	for _, opt := range options {
		if opt.key == "blksize" {
			blockSize, _ = strconv.Atoi(opt.value)
		}
	}

	offset := 0
	block := uint16(0)
	for {
		packet := c.receive(2 * time.Second)
		if packet == nil {
			return nil
		}
		switch opcodeOf(packet) {
		case opERROR:
			return packet
		case opOACK, opACK:
			if opcodeOf(packet) == opACK && blockOf(packet) != block {
				continue
			}
			if offset > len(content) {
				return nil
			}
			end := min(offset+blockSize, len(content))
			chunk := content[offset:end]
			done := len(chunk) < blockSize
			block++
			c.reply(encodeDATA(block, chunk))
			offset = end
			if done {
				// give the server a moment to close the file
				time.Sleep(150 * time.Millisecond)
				return nil
			}
		}
	}
}

// discardLogger is for the rare test that does not care about output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

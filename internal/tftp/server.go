// Package tftp implements the TFTP server: RFC 1350 with the option extension
// of RFC 2347, the blksize, timeout and tsize options of RFC 2348 and RFC 2349,
// and windowed reads as described in RFC 7440.
package tftp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/service"
	"go-fs/internal/vfs"
)

const (
	modeOctet    = "octet"
	modeNetascii = "netascii"
)

// Server serves read and write requests over UDP.
type Server struct {
	// snapshot holds what a reload may swap. Every read goes through
	// settings(), so a running transfer keeps the values it started under
	// while the next one sees the new ones.
	snapshot atomic.Pointer[settings]
	root     *vfs.Root
	log      *slog.Logger

	conn net.PacketConn
	wg   sync.WaitGroup

	mu sync.Mutex
	// transfers are the running transfers, keyed by an increasing number.
	transfers map[uint64]context.CancelFunc
	// activeClients suppresses a retransmitted request, which would otherwise
	// start a second, competing transfer for the same client port.
	activeClients map[string]struct{}
	// hostTransfers counts the transfers one address holds.
	hostTransfers map[string]int
	// pending counts requests that have been admitted but not started yet.
	pending  int
	lastKey  uint64
	shutdown bool
}

// New prepares a server. The base folder has to exist.
// settings is the part of the server a reload can replace.
type settings struct {
	cfg    config.TFTP
	limits limits
}

// settings returns the current snapshot. Callers hold on to the pointer for
// the length of one transfer rather than reading it again mid-flight.
func (s *Server) settings() *settings {
	return s.snapshot.Load()
}

// newSettings derives what the server needs from a section.
func newSettings(cfg config.TFTP) *settings {
	return &settings{
		cfg: cfg,
		limits: limits{
			timeout:       time.Duration(cfg.Timeout) * time.Second,
			maxTimeout:    time.Duration(cfg.MaxTimeout) * time.Second,
			retries:       cfg.Retries,
			maxBlockSize:  cfg.MaxBlockSize,
			maxWindowSize: cfg.MaxWindowSize,
		},
	}
}

// Reload swaps what can change while the server runs. The address it is bound
// to and the folder it serves cannot, so those report ErrNeedsRestart.
func (s *Server) Reload(cfg config.TFTP) error {
	current := s.settings().cfg
	if cfg.Enabled != current.Enabled || cfg.Port != current.Port ||
		cfg.Address != current.Address || cfg.Type != current.Type ||
		cfg.Basefolder != current.Basefolder {
		return service.ErrNeedsRestart
	}
	s.snapshot.Store(newSettings(cfg))
	return nil
}

func New(cfg config.TFTP, logger *slog.Logger) (*Server, error) {
	root, err := vfs.New(cfg.Basefolder)
	if err != nil {
		return nil, fmt.Errorf("tftp.basefolder: %w", err)
	}
	server := &Server{
		root:          root,
		log:           logger,
		transfers:     make(map[uint64]context.CancelFunc),
		activeClients: make(map[string]struct{}),
		hostTransfers: make(map[string]int),
	}
	server.snapshot.Store(newSettings(cfg))
	return server, nil
}

// network returns the network to listen on.
//
// An empty type binds dual stack, so IPv4 clients are served as well; udp4 and
// udp6 restrict the server to that family.
func (s *Server) network() string {
	cfg := s.settings().cfg
	switch cfg.Type {
	case "udp4", "udp6":
		return cfg.Type
	}
	if cfg.Address != "" && net.ParseIP(cfg.Address).To4() != nil {
		return "udp4"
	}
	return "udp"
}

// Start binds the request socket and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	cfg := s.settings().cfg
	address := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))
	conn, err := net.ListenPacket(s.network(), address)
	if err != nil {
		return err
	}
	s.conn = conn

	local := conn.LocalAddr()
	s.log.Info("tftp listening", "protocol", "udp", "address", addressOf(local), "port", portOf(local))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serve(ctx)
	}()
	return nil
}

// Addr reports the bound address, which is useful when port 0 was requested.
func (s *Server) Addr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Shutdown stops accepting requests and aborts the running transfers.
func (s *Server) Shutdown(context.Context) error {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil
	}
	s.shutdown = true
	cancels := make([]context.CancelFunc, 0, len(s.transfers))
	for _, cancel := range s.transfers {
		cancels = append(cancels, cancel)
	}
	s.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.log.Error("tftp read failed", "error", err)
			continue
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		s.dispatch(ctx, msg, from)
	}
}

// dispatch answers a datagram that arrived on the request socket.
func (s *Server) dispatch(ctx context.Context, msg []byte, from net.Addr) {
	// one snapshot per request, so everything it is judged by is consistent
	set := s.settings()
	if len(msg) < 2 {
		return
	}
	op := opcode(uint16(msg[0])<<8 | uint16(msg[1]))
	client := clientKey(from)

	switch op {
	case opRRQ, opWRQ:
		req, ok := parseRequest(msg)
		if !ok {
			s.log.Info("tftp request refused", "client", client, "reason", "malformed request",
				"bytes", len(msg))
			s.sendTo(from, encodeError(errIllegalOperation, "Malformed request"))
			return
		}
		what := "RRQ"
		if op == opWRQ {
			what = "WRQ"
		}
		s.log.Debug("tftp request", "client", client, "type", what,
			"file", sanitize(req.filename), "mode", sanitize(req.mode))
		if op == opRRQ {
			s.handleRead(ctx, set, req, from)
		} else {
			s.handleWrite(ctx, set, req, from)
		}
	default:
		// An ERROR is never acknowledged (RFC 1350); answering one makes two
		// servers bounce errors forever. Stray DATA and ACK packets are dropped
		// as well, so that a spoofed datagram cannot make the server send a
		// larger reply to somebody else.
		s.log.Debug("tftp ignoring packet", "client", client, "opcode", uint16(op))
	}
}

// admission is a reserved transfer slot.
type admission struct {
	key    uint64
	client string
	host   string
}

// refused records a request that was answered with an error before a
// transfer started. TFTP has no login, so a refused request is the event an
// operator looks for when a client reports that it "cannot get the file".
func (s *Server) refused(from net.Addr, what string, req request, reason string) {
	s.log.Info("tftp request refused", "client", clientKey(from), "type", what,
		"file", sanitize(req.filename), "mode", sanitize(req.mode), "reason", reason)
}

// admit reserves a slot for a request, or answers why it cannot.
func (s *Server) admit(set *settings, req request, from net.Addr, what string) (admission, bool) {
	client := clientKey(from)
	host := hostKey(from)

	if len(req.filename) == 0 || len(req.filename) > maxFilenameLength {
		s.refused(from, what, req, "the file name is empty or too long")
		s.sendTo(from, encodeError(errIllegalOperation, "Filename too long"))
		return admission{}, false
	}
	if req.mode != modeOctet && req.mode != modeNetascii {
		s.refused(from, what, req, "unsupported transfer mode")
		s.sendTo(from, encodeError(errIllegalOperation, "Unsupported transfer mode "+sanitize(req.mode)))
		return admission{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.shutdown {
		return admission{}, false
	}
	// A client retransmits its request when the first server reply is lost.
	// Answering again would start a second, competing transfer.
	if _, busy := s.activeClients[client]; busy {
		s.log.Debug("tftp ignoring retransmitted request", "client", client, "type", what)
		return admission{}, false
	}
	if len(s.transfers)+s.pending >= set.cfg.MaxConnections {
		s.log.Info("tftp request refused, server busy", "client", client, "type", what,
			"file", sanitize(req.filename), "transfers", len(s.transfers)+s.pending,
			"maxConnections", set.cfg.MaxConnections)
		s.sendLocked(from, encodeError(errNotDefined, "Server busy"))
		return admission{}, false
	}
	// A single host must not be able to take every slot, otherwise one client
	// that never answers starves everybody else.
	if s.hostTransfers[host] >= set.cfg.MaxConnectionsPerHost {
		s.log.Info("tftp request refused, host busy", "client", client, "type", what,
			"file", sanitize(req.filename), "transfers", s.hostTransfers[host],
			"maxConnectionsPerHost", set.cfg.MaxConnectionsPerHost)
		s.sendLocked(from, encodeError(errNotDefined, "Server busy"))
		return admission{}, false
	}

	s.lastKey++
	s.activeClients[client] = struct{}{}
	s.hostTransfers[host]++
	s.pending++
	return admission{key: s.lastKey, client: client, host: host}, true
}

// release gives a reserved slot back.
func (s *Server) release(a admission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, held := s.activeClients[a.client]; !held {
		return
	}
	delete(s.activeClients, a.client)
	delete(s.transfers, a.key)
	if remaining := s.hostTransfers[a.host] - 1; remaining > 0 {
		s.hostTransfers[a.host] = remaining
	} else {
		delete(s.hostTransfers, a.host)
	}
	if s.pending > 0 {
		s.pending--
	}
}

// begin turns a reservation into a running transfer.
func (s *Server) begin(a admission, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transfers[a.key] = cancel
	if s.pending > 0 {
		s.pending--
	}
}

// ActiveTransfers reports how many transfers are running, for tests.
func (s *Server) ActiveTransfers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.transfers)
}

func (s *Server) handleRead(ctx context.Context, set *settings, req request, from net.Addr) {
	if !set.cfg.AllowRead {
		s.refused(from, "RRQ", req, "tftp.allowRead is off")
		s.sendTo(from, encodeError(errAccessViolation, "Access violation"))
		return
	}
	slot, ok := s.admit(set, req, from, "RRQ")
	if !ok {
		return
	}

	target := s.root.Resolve("/", req.filename)
	if !target.Valid {
		s.release(slot)
		s.refused(from, "RRQ", req, "the path leaves the base folder")
		s.sendTo(from, encodeError(errAccessViolation, "Access violation"))
		return
	}
	info, err := os.Stat(target.Path)
	if err != nil || !info.Mode().IsRegular() {
		s.release(slot)
		if err != nil {
			s.refused(from, "RRQ", req, "file not found")
		} else {
			s.refused(from, "RRQ", req, "not a regular file")
		}
		s.sendTo(from, encodeError(errFileNotFound, "File not found"))
		return
	}
	file, err := os.Open(target.Path)
	if err != nil {
		s.log.Warn("tftp cannot open the file", "client", slot.client,
			"file", target.Virtual, "error", err)
		s.release(slot)
		s.sendTo(from, encodeError(errAccessViolation, "Access violation"))
		return
	}

	s.log.Debug("tftp serving file", "client", slot.client,
		"file", sanitize(req.filename), "size", info.Size())
	s.startRead(ctx, set, slot, req, from, file, info.Size())
}

func (s *Server) handleWrite(ctx context.Context, set *settings, req request, from net.Addr) {
	if !set.cfg.AllowWrite {
		s.refused(from, "WRQ", req, "tftp.allowWrite is off")
		s.sendTo(from, encodeError(errAccessViolation, "Access violation"))
		return
	}
	slot, ok := s.admit(set, req, from, "WRQ")
	if !ok {
		return
	}
	fail := func(code errorCode, message, reason string) {
		s.release(slot)
		s.refused(from, "WRQ", req, reason)
		s.sendTo(from, encodeError(code, message))
	}

	// A client that announces its size upfront can be turned away before a
	// single byte reaches the disk.
	if set.cfg.MaxFileSize > 0 {
		if value, present := req.option("tsize"); present {
			if announced, valid := parseNumericOption(value, true); valid && announced > set.cfg.MaxFileSize {
				fail(errDiskFull, fmt.Sprintf("File exceeds the maximum of %d bytes", set.cfg.MaxFileSize),
					fmt.Sprintf("the announced size %d exceeds tftp.maxFileSize %d", announced, set.cfg.MaxFileSize))
				return
			}
		}
	}

	target := s.root.Resolve("/", req.filename)
	if !target.Valid {
		fail(errAccessViolation, "Access violation", "the path leaves the base folder")
		return
	}
	if _, err := os.Stat(target.Path); err == nil && !set.cfg.AllowOverwrite {
		fail(errFileExists, "File already exists", "the file exists and tftp.allowOverwrite is off")
		return
	}

	dir := filepath.Dir(target.Path)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		if !set.cfg.AllowCreateDirectory {
			fail(errAccessViolation, "Access violation", "the folder does not exist and tftp.allowCreateDirectory is off")
			return
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			s.log.Warn("tftp cannot create the folder", "client", slot.client,
				"folder", filepath.Dir(target.Virtual), "error", err)
			fail(errAccessViolation, "Access violation", "cannot create the folder")
			return
		}
		s.log.Info("tftp mkdir", "client", slot.client, "folder", filepath.Dir(target.Virtual))
	}

	// The upload is written beside its destination and renamed over it when it
	// is complete. A transfer that is abandoned halfway then leaves neither an
	// empty file where there was none, nor a truncated one where the client was
	// replacing something that was already there.
	file, err := os.CreateTemp(dir, ".go-fs-upload-*")
	if err != nil {
		s.log.Warn("tftp cannot create the upload file", "client", slot.client,
			"folder", filepath.Dir(target.Virtual), "error", err)
		fail(errAccessViolation, "Access violation", "cannot create the file")
		return
	}

	s.log.Debug("tftp accepting write", "client", slot.client, "file", sanitize(req.filename))
	s.startWrite(ctx, set, slot, req, from, file, target.Path)
}

// transferSocket opens the ephemeral socket a transfer runs on.
func (s *Server) transferSocket() (*net.UDPConn, error) {
	network := s.network()
	if network == "udp" {
		// match the family of the request socket
		if addr, ok := s.conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.To4() != nil {
			network = "udp4"
		}
	}
	return net.ListenUDP(network, nil)
}

func (s *Server) sendTo(to net.Addr, packet []byte) {
	if s.conn == nil {
		return
	}
	if _, err := s.conn.WriteTo(packet, to); err != nil {
		s.log.Debug("tftp send failed", "client", clientKey(to), "error", err)
	}
}

// sendLocked is sendTo for callers that already hold the mutex.
func (s *Server) sendLocked(to net.Addr, packet []byte) {
	if s.conn == nil {
		return
	}
	_, _ = s.conn.WriteTo(packet, to)
}

func clientKey(addr net.Addr) string {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return net.JoinHostPort(prettyAddr(udp.IP.String()), strconv.Itoa(udp.Port))
	}
	return addr.String()
}

func hostKey(addr net.Addr) string {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return prettyAddr(udp.IP.String())
	}
	return addr.String()
}

// prettyAddr strips the IPv4 mapped IPv6 prefix, so that addresses read and
// compare the same on a dual stack socket.
func prettyAddr(address string) string {
	return strings.TrimPrefix(address, "::ffff:")
}

func addressOf(addr net.Addr) string {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return prettyAddr(udp.IP.String())
	}
	return ""
}

func portOf(addr net.Addr) int {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.Port
	}
	return 0
}

// sameClient reports whether a datagram came from the transfer's peer.
func sameClient(a, b net.Addr) bool {
	return clientKey(a) == clientKey(b)
}

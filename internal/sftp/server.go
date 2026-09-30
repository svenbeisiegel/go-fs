// Package sftp implements the SFTP server: the SFTP subsystem of an SSH
// server, confined to a base folder and governed by the same per account
// permissions as the FTP server.
//
// The SSH transport comes from golang.org/x/crypto/ssh and the SFTP protocol
// from github.com/pkg/sftp, driven through NewRequestServer with the handlers
// in handlers.go. The alternative, sftp.NewServer, would serve the real
// filesystem with no confinement and no permission checks at all.
package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/service"
	"go-fs/internal/vfs"
)

// Server accepts SSH connections and serves the SFTP subsystem on them.
type Server struct {
	// snapshot holds what a reload may swap. Every read goes through
	// settings(), so a live session keeps what it started under.
	snapshot atomic.Pointer[settings]
	root     *vfs.Root
	log      *slog.Logger

	ssh *ssh.ServerConfig

	listener net.Listener

	wg sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	shutdown bool
}

// New prepares a server. The base folder, and any per user base folder, has to
// exist; every authorized key has to parse, so that a typo in one is reported
// at startup rather than silently never matching.
// settings is the part of the server a reload can replace.
type settings struct {
	cfg   config.SFTP
	users map[string]*account
}

func (s *Server) settings() *settings {
	return s.snapshot.Load()
}

// Reload swaps the accounts and the limits. The port, the folder and the host
// key cannot change under a running listener, so those report ErrNeedsRestart.
func (s *Server) Reload(cfg config.SFTP, accounts []config.User) error {
	current := s.settings().cfg
	if cfg.Enabled != current.Enabled || cfg.Port != current.Port ||
		cfg.Address != current.Address ||
		cfg.Basefolder != current.Basefolder || cfg.HostKey != current.HostKey {
		return service.ErrNeedsRestart
	}
	users, err := buildAccounts(accounts, s.root)
	if err != nil {
		// a broken account leaves the running one in place
		return err
	}
	s.snapshot.Store(&settings{cfg: cfg, users: users})
	return nil
}

// New prepares a server. accounts are the [[users]] entries that set sftp,
// which the supervisor hands over already filtered.
func New(cfg config.SFTP, accounts []config.User, logger *slog.Logger) (*Server, error) {
	root, err := vfs.New(cfg.Basefolder)
	if err != nil {
		return nil, fmt.Errorf("sftp.basefolder: %w", err)
	}

	users, err := buildAccounts(accounts, root)
	if err != nil {
		return nil, err
	}

	signer, err := hostKey(cfg, logger)
	if err != nil {
		return nil, err
	}

	server := &Server{
		root:  root,
		log:   logger,
		conns: make(map[net.Conn]struct{}),
	}
	server.snapshot.Store(&settings{cfg: cfg, users: users})
	server.ssh = &ssh.ServerConfig{
		PasswordCallback:  server.authenticatePassword,
		PublicKeyCallback: server.authenticatePublicKey,
		ServerVersion:     "SSH-2.0-go-fs",
	}
	server.ssh.AddHostKey(signer)
	return server, nil
}

// Start binds the listener and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	set := s.settings().cfg
	listener, err := net.Listen("tcp", net.JoinHostPort(set.Address, strconv.Itoa(set.Port)))
	if err != nil {
		return err
	}
	s.listener = listener
	s.log.Info("sftp listening", "protocol", "ssh",
		"address", addressOf(listener.Addr()), "port", portOf(listener.Addr()))

	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.accept(ctx)
	}()
	return nil
}

// Addr reports the bound address, which is useful when port 0 was asked for.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Shutdown closes the listener and drops every open connection.
func (s *Server) Shutdown(context.Context) error {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil
	}
	s.shutdown = true
	open := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		open = append(open, c)
	}
	s.mu.Unlock()

	if s.listener != nil {
		_ = s.listener.Close()
	}
	for _, c := range open {
		_ = c.Close()
	}
	s.wg.Wait()
	return nil
}

// Connections reports how many connections are open, for tests.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) accept(ctx context.Context) {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.log.Error("sftp accept failed", "error", err)
			continue
		}

		s.mu.Lock()
		if s.shutdown {
			s.mu.Unlock()
			_ = raw.Close()
			return
		}
		if len(s.conns) >= s.settings().cfg.MaxConnections {
			s.mu.Unlock()
			s.log.Info("sftp connection refused, too many connections",
				"client", raw.RemoteAddr().String(), "maxConnections", s.settings().cfg.MaxConnections)
			_ = raw.Close()
			continue
		}
		s.conns[raw] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, raw)
				s.mu.Unlock()
				_ = raw.Close()
			}()
			s.serve(raw)
		}()
	}
}

// serve runs the SSH handshake and then the session channels of one client.
func (s *Server) serve(raw net.Conn) {
	remote := raw.RemoteAddr().String()
	log := s.log.With("client", remote)
	log.Debug("sftp connection established", "total", s.Connections())
	defer log.Debug("sftp connection closed")

	// one snapshot for this connection, so a reload does not change the rules
	// under a live session
	set := s.settings()

	conn := raw
	if set.cfg.IdleTimeout > 0 {
		conn = &idleConn{Conn: raw, timeout: time.Duration(set.cfg.IdleTimeout) * time.Second}
	}

	handshake, chans, reqs, err := ssh.NewServerConn(conn, s.ssh)
	if err != nil {
		var denied *ssh.ServerAuthError
		if errors.As(err, &denied) {
			// the client gave up after every method it tried was refused. A
			// refused password has a record of its own above this one; a
			// refused key only a debug one, since clients offer every key they
			// have, so this is the one line at info that says a key login
			// failed
			log.Info("sftp connection closed by authenticating client",
				"address", addressOnly(remote), "attempts", len(denied.Errors))
			return
		}
		// anything else is ordinary: a port scan, a client that gave up, a
		// client with no algorithm in common
		log.Debug("sftp handshake failed", "error", err)
		return
	}
	defer func() { _ = handshake.Close() }()
	log.Debug("sftp handshake complete", "user", handshake.User(),
		"clientVersion", string(handshake.ClientVersion()))

	user := set.users[handshake.User()]
	if user == nil {
		// the callbacks refuse an unknown name, so this cannot normally happen
		log.Error("sftp session without an account", "user", handshake.User())
		return
	}
	log = log.With("user", user.name)
	log.Info("sftp login", "address", addressOnly(remote), "total", s.Connections())
	connected := time.Now()
	defer func() {
		log.Info("sftp logoff", "address", addressOnly(remote),
			"duration", time.Since(connected).Round(time.Millisecond))
	}()

	// global requests, keepalives among them, are answered but never acted on
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			// port forwarding is what is asked for here, and refused: this is
			// a file server, not a tunnel
			log.Info("sftp channel refused", "type", newChannel.ChannelType())
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are served")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Debug("sftp cannot accept the channel", "error", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveSession(channel, requests, user, log)
		}()
	}
}

// serveSession waits for the sftp subsystem request on one session channel.
// Every other request type, "shell" and "exec" in particular, is refused: this
// is a file server, not a shell host.
func (s *Server) serveSession(channel ssh.Channel, requests <-chan *ssh.Request, user *account, log *slog.Logger) {
	defer func() { _ = channel.Close() }()

	started := false
	for req := range requests {
		granted := false
		if req.Type == "subsystem" && subsystemName(req.Payload) == "sftp" && !started {
			granted = true
			started = true
		} else if req.Type == "shell" || req.Type == "exec" || req.Type == "subsystem" {
			// a client asking for a shell has the wrong idea of this server,
			// and the operator wants to know that somebody tried
			log.Info("sftp request refused", "type", req.Type, "subsystem", subsystemName(req.Payload))
		} else {
			// pty-req, env, window-change: what an interactive client sends
			// before asking for a shell, and nothing to act on
			log.Debug("sftp request ignored", "type", req.Type)
		}
		if req.WantReply {
			_ = req.Reply(granted, nil)
		}
		if !granted {
			continue
		}

		log.Debug("sftp subsystem started")
		server := sftp.NewRequestServer(channel, s.handlers(user.name, log))
		if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
			log.Debug("sftp session ended", "error", err)
		} else {
			log.Debug("sftp session ended")
		}
		_ = server.Close()
		return
	}
}

// subsystemName reads the name out of a "subsystem" request payload, which is
// one SSH string: a four byte length followed by the name.
func subsystemName(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	length := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if length < 0 || 4+length > len(payload) {
		return ""
	}
	return string(payload[4 : 4+length])
}

// idleConn closes a connection that has been silent for too long. The deadline
// is pushed forward on every read, which is the same rule the FTP control
// connection follows.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func addressOf(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return addr.String()
}

func portOf(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

func addressOnly(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

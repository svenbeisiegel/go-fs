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
	"slices"
	"strconv"
	"strings"
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

	// signer is the host key, which a reload cannot change: clients remember
	// it.
	signer ssh.Signer

	listener net.Listener

	wg sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	perHost  map[string]int
	shutdown bool
}

// settings is the part of the server a reload can replace.
type settings struct {
	cfg   config.SFTP
	ssh   config.SSH
	users map[string]*account
	// server is the SSH configuration built from cfg and ssh, once per
	// snapshot rather than once per connection.
	server *ssh.ServerConfig
}

func (s *Server) settings() *settings {
	return s.snapshot.Load()
}

// Reload swaps the accounts, the limits and the algorithms. The port, the
// folder and the host key cannot change under a running listener, so those
// report ErrNeedsRestart.
func (s *Server) Reload(cfg config.SFTP, sshCfg config.SSH, accounts []config.User) error {
	current := s.settings()
	if cfg.Enabled != current.cfg.Enabled || cfg.Port != current.cfg.Port ||
		cfg.Address != current.cfg.Address ||
		cfg.Basefolder != current.cfg.Basefolder || cfg.HostKey != current.cfg.HostKey {
		return service.ErrNeedsRestart
	}
	next, err := s.newSettings(cfg, sshCfg, accounts)
	if err != nil {
		// a broken account leaves the running one in place
		return err
	}
	if !slices.Equal(sshCfg.Insecure(), current.ssh.Insecure()) {
		warnInsecure(s.log, sshCfg)
	}
	s.snapshot.Store(next)
	return nil
}

// New prepares a server. accounts are the [[users]] entries that set sftp,
// which the supervisor hands over already filtered. The base folder, and any
// per user base folder, has to exist; every authorized key has to parse, so
// that a typo in one is reported at startup rather than silently never
// matching.
func New(cfg config.SFTP, sshCfg config.SSH, accounts []config.User, logger *slog.Logger) (*Server, error) {
	root, err := vfs.New(cfg.Basefolder)
	if err != nil {
		return nil, fmt.Errorf("sftp.basefolder: %w", err)
	}

	signer, err := hostKey(cfg, logger)
	if err != nil {
		return nil, err
	}

	server := &Server{
		root:    root,
		log:     logger,
		signer:  signer,
		conns:   make(map[net.Conn]struct{}),
		perHost: make(map[string]int),
	}
	set, err := server.newSettings(cfg, sshCfg, accounts)
	if err != nil {
		return nil, err
	}
	server.snapshot.Store(set)
	warnInsecure(logger, sshCfg)
	return server, nil
}

func (s *Server) newSettings(cfg config.SFTP, sshCfg config.SSH, accounts []config.User) (*settings, error) {
	users, err := buildAccounts(accounts, s.root)
	if err != nil {
		return nil, err
	}
	server, err := s.serverConfig(sshCfg)
	if err != nil {
		return nil, err
	}
	return &settings{cfg: cfg, ssh: sshCfg, users: users, server: server}, nil
}

// serverConfig is the SSH side of the server: the algorithms offered, the
// login limits and the banner.
func (s *Server) serverConfig(sshCfg config.SSH) (*ssh.ServerConfig, error) {
	server := &ssh.ServerConfig{
		Config:                  sshCfg.Transport(),
		PublicKeyAuthAlgorithms: sshCfg.PublicKeyAuths(),
		MaxAuthTries:            sshCfg.MaxAuthTries,
		PasswordCallback:        s.authenticatePassword,
		PublicKeyCallback:       s.authenticatePublicKey,
		ServerVersion:           "SSH-2.0-go-fs",
	}
	if banner := sshCfg.BannerText(); banner != "" {
		server.BannerCallback = func(ssh.ConnMetadata) string { return banner }
	}
	signer, err := hostKeySigner(s.signer, sshCfg.HostKeys())
	if err != nil {
		return nil, err
	}
	server.AddHostKey(signer)
	return server, nil
}

// hostKeySigner limits the signatures the host key is made with to the
// allowed host key algorithms. That only narrows anything for an RSA key,
// which can sign with SHA-1 as ssh-rsa as well as with SHA-2; any other key
// has exactly one algorithm, and a list without it leaves the server nothing
// to identify itself with.
func hostKeySigner(signer ssh.Signer, allowed []string) (ssh.Signer, error) {
	keyType := signer.PublicKey().Type()
	candidates := []string{keyType}
	if keyType == ssh.KeyAlgoRSA {
		candidates = []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	}
	var usable []string
	for _, algorithm := range candidates {
		if slices.Contains(allowed, algorithm) {
			usable = append(usable, algorithm)
		}
	}
	if len(usable) == 0 {
		return nil, fmt.Errorf("general.ssh.hostKeyAlgorithms allows none of %s, "+
			"which is all the %s host key can sign with", strings.Join(candidates, ", "), keyType)
	}
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok || len(usable) == len(candidates) {
		return signer, nil
	}
	return ssh.NewSignerWithAlgorithms(algorithmSigner, usable)
}

// warnInsecure names the legacy algorithms the configuration lets in, which
// were listed on purpose but are worth being reminded of.
func warnInsecure(logger *slog.Logger, sshCfg config.SSH) {
	if insecure := sshCfg.Insecure(); len(insecure) > 0 {
		logger.Warn("sftp offers algorithms with known weaknesses, as general.ssh lists them",
			"algorithms", strings.Join(insecure, "; "))
	}
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

		set := s.settings()
		host := addressOnly(raw.RemoteAddr().String())
		s.mu.Lock()
		if s.shutdown {
			s.mu.Unlock()
			_ = raw.Close()
			return
		}
		if len(s.conns) >= set.cfg.MaxConnections {
			s.mu.Unlock()
			s.log.Info("sftp connection refused, too many connections",
				"client", raw.RemoteAddr().String(), "maxConnections", set.cfg.MaxConnections)
			_ = raw.Close()
			continue
		}
		if limit := set.ssh.MaxConnectionsPerHost; limit > 0 && s.perHost[host] >= limit {
			s.mu.Unlock()
			s.log.Info("sftp connection refused, too many connections from this address",
				"client", raw.RemoteAddr().String(), "maxConnectionsPerHost", limit)
			_ = raw.Close()
			continue
		}
		s.conns[raw] = struct{}{}
		s.perHost[host]++
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, raw)
				if s.perHost[host]--; s.perHost[host] <= 0 {
					delete(s.perHost, host)
				}
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

	expired := loginGrace(raw, time.Duration(set.ssh.LoginGraceTime)*time.Second)
	handshake, chans, reqs, err := ssh.NewServerConn(raw, set.server)
	if expired() {
		// the timer closed the connection under the handshake, or just after
		// it, which leaves nothing to serve either way
		if handshake != nil {
			_ = handshake.Close()
		}
		log.Info("sftp login timed out", "address", addressOnly(remote),
			"loginGraceTime", set.ssh.LoginGraceTime)
		return
	}
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
		var negotiation *ssh.AlgorithmNegotiationError
		if errors.As(err, &negotiation) {
			// an old client the secure defaults turn away, which the operator
			// can let in by listing what it offers in general.ssh
			log.Info("sftp client has no algorithm in common", "address", addressOnly(remote),
				"for", negotiation.What, "clientOffers", strings.Join(negotiation.RequestedAlgorithms, ","))
			return
		}
		// anything else is ordinary: a port scan, a client that gave up
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

	seen := &activity{}
	seen.touch()
	if timeout := time.Duration(set.cfg.IdleTimeout) * time.Second; timeout > 0 {
		stop := watchIdle(timeout, seen, func() {
			log.Info("sftp connection idle, closing it", "idleTimeout", set.cfg.IdleTimeout)
			_ = handshake.Close()
		})
		defer stop()
	}
	if interval := time.Duration(set.ssh.KeepAliveInterval) * time.Second; interval > 0 {
		done := make(chan struct{})
		defer close(done)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			keepAlive(handshake, interval, set.ssh.KeepAliveCountMax, done, log)
		}()
	}

	var sessions atomic.Int32
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			// port forwarding is what is asked for here, and refused: this is
			// a file server, not a tunnel
			log.Info("sftp channel refused", "type", newChannel.ChannelType())
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are served")
			continue
		}
		if int(sessions.Load()) >= set.ssh.MaxSessions {
			log.Info("sftp session refused, too many sessions", "maxSessions", set.ssh.MaxSessions)
			_ = newChannel.Reject(ssh.ResourceShortage, "too many sessions")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Debug("sftp cannot accept the channel", "error", err)
			continue
		}
		sessions.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer sessions.Add(-1)
			s.serveSession(activeChannel{Channel: channel, seen: seen}, requests, user, set, log)
		}()
	}
}

// serveSession waits for the sftp subsystem request on one session channel.
// Every other request type, "shell" and "exec" in particular, is refused: this
// is a file server, not a shell host.
func (s *Server) serveSession(channel activeChannel, requests <-chan *ssh.Request, user *account, set *settings, log *slog.Logger) {
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
		// the allocator reuses the buffers of the packets rather than making
		// one per read and write, which on loopback makes a transfer 30 to 40
		// percent faster (BenchmarkTransfer); the handlers keep no slice they
		// are handed beyond the call, which is what it relies on
		server := sftp.NewRequestServer(channel, s.handlers(user.name, log),
			sftp.WithRSMaxTxPacket(uint32(set.ssh.MaxPacketSize)), sftp.WithRSAllocator())
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

// loginGrace closes a connection that has not logged in within timeout. The
// function it returns stops the clock and reports whether it had run out;
// with timeout 0 it never does.
func loginGrace(conn net.Conn, timeout time.Duration) func() bool {
	if timeout <= 0 {
		return func() bool { return false }
	}
	var fired atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		fired.Store(true)
		_ = conn.Close()
	})
	return func() bool {
		timer.Stop()
		return fired.Load()
	}
}

// activity is when a connection last carried SFTP traffic from its client,
// which is what idleTimeout measures. Keepalive answers and other SSH
// traffic do not count, or a client answering keepalives would never be idle.
//
// It replaces a read deadline pushed forward on every read of the socket,
// which costs a timer reset per few kilobytes of a transfer; a store of the
// time is far cheaper, and the clock is looked at only when it might have
// run out.
type activity struct {
	last atomic.Int64
}

func (a *activity) touch() { a.last.Store(time.Now().UnixNano()) }

func (a *activity) idle() time.Duration { return time.Since(time.Unix(0, a.last.Load())) }

// activeChannel is a session channel that notes when its client sent
// something.
type activeChannel struct {
	ssh.Channel
	seen *activity
}

func (c activeChannel) Read(b []byte) (int, error) {
	n, err := c.Channel.Read(b)
	if n > 0 {
		c.seen.touch()
	}
	return n, err
}

// watchIdle calls expire once seen has been idle for timeout. It looks only
// when the time could have run out, and sleeps again for whatever is left
// when it has not. The function it returns stops the watch.
func watchIdle(timeout time.Duration, seen *activity, expire func()) func() {
	var mu sync.Mutex
	stopped := false
	var timer *time.Timer
	check := func() {
		idle := seen.idle()
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		if idle < timeout {
			timer.Reset(timeout - idle)
			return
		}
		stopped = true
		go expire()
	}
	mu.Lock()
	timer = time.AfterFunc(timeout, check)
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		timer.Stop()
	}
}

// keepAlive asks the client for a sign of life every interval and closes the
// connection when countMax intervals pass without one. Any answer counts,
// including the refusal that is what OpenSSH, PuTTY and WinSCP send to a
// request they do not implement. One request is out at a time, so a client
// that stopped reading is not sent a pile of them. It returns when done is
// closed.
func keepAlive(conn ssh.Conn, interval time.Duration, countMax int, done <-chan struct{}, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// buffered, so that an answer arriving after the end does not block
	answered := make(chan struct{}, 1)
	pending := false
	missed := 0
	for {
		select {
		case <-done:
			return
		case <-answered:
			pending = false
			missed = 0
		case <-ticker.C:
			if pending {
				missed++
				if missed >= countMax {
					log.Info("sftp client stopped answering keepalives, closing the connection",
						"keepAliveInterval", interval.Seconds(), "keepAliveCountMax", countMax)
					_ = conn.Close()
					return
				}
				continue
			}
			pending = true
			go func() {
				if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err == nil {
					answered <- struct{}{}
				}
			}()
		}
	}
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

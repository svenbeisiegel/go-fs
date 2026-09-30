// Package ftp implements the FTP server: RFC 959 with the extensions of
// RFC 2228 (AUTH, PBSZ, PROT), RFC 2389 (FEAT, OPTS), RFC 2428 (EPRT, EPSV),
// RFC 3659 (MLST, MLSD, MDTM, SIZE, REST) and the RFC 775 X aliases.
package ftp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"go-fs/internal/config"
	"go-fs/internal/service"
	"go-fs/internal/tlsconf"
	"go-fs/internal/vfs"
)

// Server accepts control connections on the plain and, when configured, on the
// implicit TLS port.
type Server struct {
	// snapshot holds what a reload may swap. Every read goes through
	// settings(), and a connection takes one snapshot when it is accepted, so
	// a reload cannot change the rules under a half-finished command sequence.
	snapshot atomic.Pointer[settings]
	root     *vfs.Root
	log      *slog.Logger
	tls      *tls.Config

	plain  net.Listener
	secure net.Listener

	wg sync.WaitGroup

	mu       sync.Mutex
	conns    map[*conn]struct{}
	shutdown bool
}

// New prepares a server. The base folder, and any per user base folder, has to
// exist. When TLS is enabled without a certificate one is generated, so that a
// published private key never has to ship with the program.
// settings is the part of the server a reload can replace.
type settings struct {
	cfg  config.FTP
	ftps config.FTPS
	// users are the accounts that may log in here: the [[users]] entries
	// that set ftp, which the supervisor hands over already filtered.
	users []config.User
}

func (s *Server) settings() *settings {
	return s.snapshot.Load()
}

// Reload swaps the accounts and the limits. The ports, the folder and the
// certificate cannot change under a running listener, so those report
// ErrNeedsRestart.
func (s *Server) Reload(cfg config.FTP, ftps config.FTPS, users []config.User) error {
	current := s.settings()
	if cfg.Enabled != current.cfg.Enabled || cfg.Port != current.cfg.Port ||
		cfg.Address != current.cfg.Address ||
		cfg.Basefolder != current.cfg.Basefolder ||
		ftps.Enabled != current.ftps.Enabled || ftps.Port != current.ftps.Port ||
		ftps.Cert != current.ftps.Cert || ftps.Key != current.ftps.Key {
		return service.ErrNeedsRestart
	}
	if err := checkUserFolders(users); err != nil {
		// a broken account leaves the running one in place
		return err
	}
	if cfg.PassiveMinPort != current.cfg.PassiveMinPort ||
		cfg.PassiveMaxPort != current.cfg.PassiveMaxPort ||
		cfg.MaxConnections != current.cfg.MaxConnections {
		warnNarrowPassiveRange(cfg, s.log)
	}
	s.snapshot.Store(&settings{cfg: cfg, ftps: ftps, users: users})
	return nil
}

// warnNarrowPassiveRange reports a passive range that cannot hold one port per
// connection. It is a legitimate setup — it caps how many transfers run at
// once — but also an easy mistake, so it is said out loud rather than left to
// turn up as a transfer that finds no free port. It is checked on a reload too,
// since the web interface is a way to narrow the range without a restart.
func warnNarrowPassiveRange(cfg config.FTP, logger *slog.Logger) {
	width := cfg.PassiveMaxPort - cfg.PassiveMinPort + 1
	if width >= cfg.MaxConnections {
		return
	}
	logger.Warn("ftp.passiveMinPort to ftp.passiveMaxPort holds fewer ports than "+
		"ftp.maxConnections allows connections, so a passive transfer may find none free",
		"ports", width, "maxConnections", cfg.MaxConnections)
}

// checkUserFolders reports a per user base folder that cannot be served. The
// account is named rather than numbered: the list is the file's filtered down
// to this server, so its positions are not the file's.
func checkUserFolders(users []config.User) error {
	for _, user := range users {
		if user.Basefolder == "" {
			continue
		}
		if _, err := vfs.New(user.Basefolder); err != nil {
			return fmt.Errorf("users %q basefolder: %w", user.Username, err)
		}
	}
	return nil
}

func New(cfg config.FTP, ftps config.FTPS, users []config.User, logger *slog.Logger) (*Server, error) {
	root, err := vfs.New(cfg.Basefolder)
	if err != nil {
		return nil, fmt.Errorf("ftp.basefolder: %w", err)
	}
	if err := checkUserFolders(users); err != nil {
		return nil, err
	}

	server := &Server{
		root:  root,
		log:   logger,
		conns: make(map[*conn]struct{}),
	}
	server.snapshot.Store(&settings{cfg: cfg, ftps: ftps, users: users})
	warnNarrowPassiveRange(cfg, logger)
	if ftps.Enabled {
		server.tls, err = tlsconf.Build(ftps.Cert, ftps.Key, "ftps.cert", "ftps.key", logger)
		if err != nil {
			return nil, err
		}
	}
	return server, nil
}

// Start binds the listeners and serves until ctx is cancelled.
// The two listeners are independent: ftp.enabled serves the plain control
// port, ftps.enabled the implicit TLS one, and either may be on alone.
func (s *Server) Start(ctx context.Context) error {
	set := s.settings()
	if !set.cfg.Enabled && !set.ftps.Enabled {
		return errors.New("neither ftp nor ftps is enabled")
	}

	if set.cfg.Enabled {
		plain, err := net.Listen("tcp",
			net.JoinHostPort(set.cfg.Address, strconv.Itoa(set.cfg.Port)))
		if err != nil {
			return err
		}
		s.plain = plain
		s.log.Info("ftp listening", "protocol", "tcp",
			"address", addressOf(plain.Addr()), "port", portOf(plain.Addr()))
	}

	if set.ftps.Enabled {
		secure, err := tls.Listen("tcp",
			net.JoinHostPort(set.cfg.Address, strconv.Itoa(set.ftps.Port)), s.tls)
		if err != nil {
			if s.plain != nil {
				_ = s.plain.Close()
			}
			return err
		}
		s.secure = secure
		s.log.Info("ftp listening", "protocol", "tls",
			"address", addressOf(secure.Addr()), "port", portOf(secure.Addr()))
	}

	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()

	if s.plain != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.accept(ctx, s.plain, false)
		}()
	}
	if s.secure != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.accept(ctx, s.secure, true)
		}()
	}
	return nil
}

// Addr reports the bound plain address, which is useful when port 0 was asked
// for.
func (s *Server) Addr() net.Addr {
	if s.plain == nil {
		return nil
	}
	return s.plain.Addr()
}

// SecureAddr reports the bound implicit TLS address.
func (s *Server) SecureAddr() net.Addr {
	if s.secure == nil {
		return nil
	}
	return s.secure.Addr()
}

// Shutdown closes the listeners and drops every open connection.
func (s *Server) Shutdown(context.Context) error {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil
	}
	s.shutdown = true
	open := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		open = append(open, c)
	}
	s.mu.Unlock()

	if s.plain != nil {
		_ = s.plain.Close()
	}
	if s.secure != nil {
		_ = s.secure.Close()
	}
	for _, c := range open {
		// a transfer in flight is blocked moving bytes over the data
		// connection, which closing the control connection does not reach:
		// without this, Shutdown waits below for a client that may never read
		// again, and with it a reload that has to rebind the listener waits too
		c.abortTransfer()
		c.close()
	}
	s.wg.Wait()
	return nil
}

// Connections reports how many control connections are open, for tests.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) accept(ctx context.Context, listener net.Listener, secure bool) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.log.Error("ftp accept failed", "error", err)
			continue
		}

		s.mu.Lock()
		if s.shutdown {
			s.mu.Unlock()
			_ = raw.Close()
			return
		}
		// maxConnections is a limit on control connections, as in the original
		if limit := s.settings().cfg.MaxConnections; len(s.conns) >= limit {
			s.mu.Unlock()
			s.log.Info("ftp connection refused, too many connections",
				"client", raw.RemoteAddr().String(), "maxConnections", limit)
			_ = raw.Close()
			continue
		}
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(ctx, raw, secure)
		}()
	}
}

func (s *Server) register(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[c] = struct{}{}
}

func (s *Server) unregister(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

// listenData binds a passive data listener on the configured port range.
// Binding the real listener directly leaves no window in which the port can be
// taken by somebody else.
func (s *Server) listenData(set *settings) (net.Listener, int, error) {
	var last error
	for port := set.cfg.PassiveMinPort; port <= set.cfg.PassiveMaxPort; port++ {
		// the data ports follow the control port onto the same interface
		listener, err := net.Listen("tcp",
			net.JoinHostPort(set.cfg.Address, strconv.Itoa(port)))
		if err == nil {
			return listener, port, nil
		}
		last = err
	}
	// the last refusal is named: a range of ports the process may not bind
	// fails for a reason other than every port being taken, and the error
	// says which
	return nil, 0, fmt.Errorf("no free data port between ftp.passiveMinPort %d and "+
		"ftp.passiveMaxPort %d: %w", set.cfg.PassiveMinPort, set.cfg.PassiveMaxPort, last)
}

// normalizeAddress strips the IPv4 mapped IPv6 prefix, so addresses compare and
// print the same regardless of the socket family they arrived on.
func normalizeAddress(address string) string {
	return strings.TrimPrefix(address, "::ffff:")
}

func hostOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return normalizeAddress(addr.String())
	}
	return normalizeAddress(host)
}

func addressOf(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return normalizeAddress(tcp.IP.String())
	}
	return hostOf(addr)
}

func portOf(addr net.Addr) int {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

func isLoopback(address string) bool {
	ip := net.ParseIP(normalizeAddress(address))
	return ip != nil && ip.IsLoopback()
}

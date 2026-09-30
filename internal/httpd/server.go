// Package httpd implements the HTTP file server: browsing and downloading with
// GET, uploading with PUT, removing with DELETE, creating a folder with MKCOL
// and renaming with MOVE, with Basic and Digest authentication for programs
// and a login page with session cookies for browsers.
//
// It is a port of an Express server, so the reply shapes and the authentication
// rules are the ones that server produced. The browsable listing is not: it is
// this server's own page, and the assets it needs are inlined into it so that
// every URL stays a path in the served folder. The legacy
// dls_directory_reader endpoint still answers exactly what it always did. The
// package is named httpd rather than http so that it can import net/http.
package httpd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go-fs/internal/admin"
	"go-fs/internal/config"
	"go-fs/internal/logging"
	"go-fs/internal/service"
	"go-fs/internal/tlsconf"
	"go-fs/internal/vfs"
)

// readerPath is the legacy listing endpoint one client asks for by name.
var readerPath = regexp.MustCompile(`/dls_directory_reader\.(php|asp)$`)

// The WebDAV verbs this server answers, which net/http has no constants for.
// They are used rather than an endpoint of their own because every URL here is
// a path in the served folder: a /api/ prefix would shadow a real name.
const (
	methodMkcol = "MKCOL"
	methodMove  = "MOVE"
)

// Server serves the file tree over HTTP, over TLS, or over both.
type Server struct {
	// snapshot holds what a reload may swap. Every request takes one snapshot
	// at the top of ServeHTTP and is served entirely by it.
	snapshot atomic.Pointer[settings]
	root     *vfs.Root
	log      *slog.Logger

	// tokens signs and reads the session tokens a logged in browser carries.
	tokens *signer
	// nonceKey signs the digest nonces this server hands out, so that a nonce
	// carries its own age and needs nothing to be remembered about it.
	nonceKey []byte
	// logins counts the wrong passwords each client address has sent, and
	// locks the ones that sent too many.
	logins *loginTracker
	// admin is the interface that edits the configuration file, served under
	// the go-fs marker to a session of an account that sets isAdmin. It is nil
	// when there is no file to edit, which is what a test builds.
	admin *admin.Handler

	plain  net.Listener
	secure net.Listener
	server *http.Server

	wg sync.WaitGroup
	// done is closed by Shutdown, so that what runs on its own — the retention
	// sweep — stops for a shutdown that was asked for directly rather than by
	// cancelling the context Start was given.
	done chan struct{}

	mu       sync.Mutex
	shutdown bool

	// uploadLocks serializes the finishing chunk of a chunked upload per
	// target path; see uploadLock in handlers.go.
	uploadLocks sync.Map
}

// New prepares a server. The base folder has to exist and every configured
// regular expression has to compile, so that a typo is reported at startup
// rather than at the first request that would have matched.
// settings is the part of the server a reload can replace: the section and
// everything compiled from it.
type settings struct {
	cfg            config.HTTP
	https          config.HTTPS
	accounts       []*account
	protectedPaths []*regexp.Regexp
	// proxies are http.trustedProxies compiled, the addresses whose
	// X-Forwarded-For and X-Forwarded-Proto are believed.
	proxies []netip.Prefix
}

func (s *Server) settings() *settings {
	return s.snapshot.Load()
}

// newSettings compiles a section into what the request path needs. users are
// the [[users]] entries that set http, which the supervisor hands over already
// filtered.
func newSettings(cfg config.HTTP, https config.HTTPS, users []config.User) (*settings, error) {
	accounts, err := buildAccounts(users)
	if err != nil {
		return nil, err
	}
	protected := make([]*regexp.Regexp, 0, len(cfg.PathsRequireAuth))
	for i, pattern := range cfg.PathsRequireAuth {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("http.pathsRequireAuth[%d]: %w", i, err)
		}
		protected = append(protected, compiled)
	}
	proxies := make([]netip.Prefix, 0, len(cfg.TrustedProxies))
	for i, entry := range cfg.TrustedProxies {
		prefix, err := config.ParseProxy(entry)
		if err != nil {
			return nil, fmt.Errorf("http.trustedProxies[%d]: %w", i, err)
		}
		proxies = append(proxies, prefix)
	}
	return &settings{cfg: cfg, https: https, accounts: accounts,
		protectedPaths: protected, proxies: proxies}, nil
}

// Reload swaps the accounts, the paths and the limits that are read per
// request. The ports, the folder, the certificate and the settings baked into
// the http.Server and its listener at Start report ErrNeedsRestart.
func (s *Server) Reload(cfg config.HTTP, https config.HTTPS, users []config.User) error {
	current := s.settings()
	if cfg.Enabled != current.cfg.Enabled || cfg.Port != current.cfg.Port ||
		cfg.Address != current.cfg.Address ||
		cfg.Basefolder != current.cfg.Basefolder ||
		cfg.MaxConnections != current.cfg.MaxConnections ||
		cfg.SessionTokenSecret != current.cfg.SessionTokenSecret ||
		cfg.ReadTimeout != current.cfg.ReadTimeout ||
		cfg.WriteTimeout != current.cfg.WriteTimeout ||
		cfg.IdleTimeout != current.cfg.IdleTimeout ||
		https.Enabled != current.https.Enabled || https.Port != current.https.Port ||
		https.Cert != current.https.Cert || https.Key != current.https.Key {
		return service.ErrNeedsRestart
	}
	next, err := newSettings(cfg, https, users)
	if err != nil {
		// a broken account or pattern leaves the running one in place
		return err
	}
	// the token lifetime needs nothing done to it: it is read from the
	// snapshot when a token is minted, so a reload changes what is issued from
	// here on and leaves a live token with the expiry it was signed with. The
	// login lock is the same: its two settings are read at every failure, and
	// an address that is locked stays locked for as long as it was told
	s.snapshot.Store(next)
	return nil
}

// New prepares a server. configPath is the file the admin interface edits;
// empty leaves the interface out.
func New(cfg config.HTTP, https config.HTTPS, users []config.User, configPath string, logger *slog.Logger) (*Server, error) {
	root, err := vfs.New(cfg.Basefolder)
	if err != nil {
		return nil, fmt.Errorf("http.basefolder: %w", err)
	}

	set, err := newSettings(cfg, https, users)
	if err != nil {
		return nil, err
	}

	nonceKey := make([]byte, 32)
	if _, err := rand.Read(nonceKey); err != nil {
		return nil, err
	}

	tokens, err := newSigner(cfg.SessionTokenSecret, logger)
	if err != nil {
		return nil, err
	}

	server := &Server{
		root:     root,
		log:      logger,
		tokens:   tokens,
		nonceKey: nonceKey,
		logins:   newLoginTracker(),
		done:     make(chan struct{}),
	}
	if configPath != "" {
		// built whether or not the switch is on: the switch is read from the
		// snapshot on every request, so a reload can flip it without a restart
		server.admin, err = admin.New(configPath, logger)
		if err != nil {
			return nil, err
		}
	}
	server.snapshot.Store(set)
	server.server = &http.Server{
		Handler:      server,
		ReadTimeout:  seconds(cfg.ReadTimeout),
		WriteTimeout: seconds(cfg.WriteTimeout),
		IdleTimeout:  seconds(cfg.IdleTimeout),
		// the headers are bounded even where the body is not, so a connection
		// that dribbles a request line forever does not hold a slot
		ReadHeaderTimeout: headerTimeout,
		// what net/http reports on its own: a handler that panicked lands at
		// error, a client that failed its TLS handshake in the trace
		ErrorLog: logging.HTTPErrorLog(logger, "http"),
		// each connection is recorded as it comes and goes, so a client that
		// "cannot connect" can be told apart from one whose request failed
		ConnState: server.connState,
	}
	return server, nil
}

// connState is the http.Server's report of a connection's life. Only the
// ends of it are recorded: the states in between are per request, and the
// request has a record of its own.
func (s *Server) connState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		s.log.Debug("http connection established", "client", conn.RemoteAddr().String())
	case http.StateClosed, http.StateHijacked:
		s.log.Debug("http connection closed", "client", conn.RemoteAddr().String())
	}
}

// Start binds the listeners and serves until ctx is cancelled. The two
// listeners are independent: http.enabled serves the plain port, https.enabled
// the TLS one, and either may be on alone.
func (s *Server) Start(ctx context.Context) error {
	set := s.settings()
	if !set.cfg.Enabled && !set.https.Enabled {
		return errors.New("neither http nor https is enabled")
	}

	if set.cfg.Enabled {
		plain, err := net.Listen("tcp",
			net.JoinHostPort(set.cfg.Address, strconv.Itoa(set.cfg.Port)))
		if err != nil {
			return err
		}
		s.plain = limited(plain, set.cfg.MaxConnections)
		s.log.Info("http listening", "protocol", "http",
			"address", listenAddress(plain), "port", listenPort(plain))
	}

	if set.https.Enabled {
		tlsConfig, err := tlsconf.Build(set.https.Cert, set.https.Key, "https.cert", "https.key", s.log)
		if err != nil {
			s.closeListeners()
			return err
		}
		raw, err := net.Listen("tcp",
			net.JoinHostPort(set.cfg.Address, strconv.Itoa(set.https.Port)))
		if err != nil {
			s.closeListeners()
			return err
		}
		// the connection limit goes underneath the TLS listener: net/http
		// recognises a connection as TLS by its type, so a wrapper around the
		// *tls.Conn would leave Request.TLS empty
		secure := tls.NewListener(limited(raw, set.cfg.MaxConnections), tlsConfig)
		s.secure = secure
		s.log.Info("http listening", "protocol", "https",
			"address", listenAddress(secure), "port", listenPort(secure))
	}

	s.warnAboutTheAdminInterface(set)

	go func() {
		<-ctx.Done()
		_ = s.Shutdown(context.Background())
	}()

	for _, listener := range []net.Listener{s.plain, s.secure} {
		if listener == nil {
			continue
		}
		s.wg.Add(1)
		go func(listener net.Listener) {
			defer s.wg.Done()
			if err := s.server.Serve(listener); err != nil &&
				!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				s.log.Error("http serve failed", "error", err)
			}
		}(listener)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runCleanup(ctx)
	}()
	return nil
}

// warnAboutTheAdminInterface says, at the moment the listeners are bound, what
// is worth knowing about the interface that edits the configuration file: that
// it is on but nobody can reach it, and that it is reachable over plain HTTP
// from beyond this host, where the admin session and every password on the
// page cross the network in the clear. Neither is refused: the first is how a
// fresh file starts out, and the second is what a proxy that terminates TLS in
// front of this server looks like.
func (s *Server) warnAboutTheAdminInterface(set *settings) {
	if s.admin == nil || !set.cfg.EnableAdminInterface {
		return
	}
	admins := 0
	for _, user := range set.accounts {
		if user.isAdmin {
			admins++
		}
	}
	if admins == 0 {
		s.log.Warn("http.enableAdminInterface is on but no account sets isAdmin, " +
			"so nobody can reach the admin interface")
	}
	if set.cfg.Enabled && !isLoopback(set.cfg.Address) {
		s.log.Warn("the admin interface is reachable over plain http on an address that is "+
			"not the loopback one, so the admin session and every password on its page "+
			"cross the network in the clear unless a proxy terminates TLS in front of it; "+
			"serve it over https instead", "address", set.cfg.Address, "port", set.cfg.Port)
	}
}

// isLoopback reports an address that only the host itself can reach. An empty
// address binds every interface, so it is not one.
func isLoopback(address string) bool {
	if address == "" {
		return false
	}
	parsed := net.ParseIP(address)
	return parsed != nil && parsed.IsLoopback()
}

// Addr reports the bound plain address, which is useful when port 0 was asked
// for.
func (s *Server) Addr() net.Addr {
	if s.plain == nil {
		return nil
	}
	return s.plain.Addr()
}

// SecureAddr reports the bound TLS address.
func (s *Server) SecureAddr() net.Addr {
	if s.secure == nil {
		return nil
	}
	return s.secure.Addr()
}

// Shutdown closes the listeners and drops every open connection.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil
	}
	s.shutdown = true
	close(s.done)
	s.mu.Unlock()

	_ = s.server.Close()
	s.closeListeners()
	s.wg.Wait()
	return nil
}

func (s *Server) closeListeners() {
	for _, listener := range []net.Listener{s.plain, s.secure} {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

// ServeHTTP resolves the path once, authenticates, authorizes and dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// one snapshot for the whole request, so a reload halfway through cannot
	// authenticate against one account list and authorize against another
	set := s.settings()
	// client keeps the port, which is what ties the records of one connection
	// together on a busy server, as it does for the FTP trace
	s.log.Debug("http request", "method", r.Method, "url", r.URL.RequestURI(),
		"client", r.RemoteAddr, "proto", r.Proto, "tls", r.TLS != nil,
		"userAgent", r.UserAgent(), "contentLength", r.ContentLength)

	// the answer is recorded when it is complete, with what the handler
	// decided and how long it took: one line per request, which is what the
	// question "what happened at 14:32" is answered from
	recorder := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
	started := time.Now()
	defer func() {
		s.log.Debug("http response", "method", r.Method, "url", r.URL.Path,
			"client", r.RemoteAddr, "status", recorder.status, "bytes", recorder.bytes,
			"took", time.Since(started).Round(time.Millisecond))
	}()
	w = recorder

	target := s.root.Resolve("/", r.URL.Path)
	if !target.Valid {
		// a path that leaves the served folder is answered as a path that is
		// not there, which is what it is from the client's side
		s.log.Debug("http path refused", "url", r.URL.Path)
		http.NotFound(w, r)
		return
	}

	// the login endpoints come before authentication: the login page for a
	// folder that needs an account has to be reachable without one, and POST
	// is protected by default
	if action := sessionAction(r); action != "" {
		s.handleSession(set, w, r, target, action)
		return
	}
	// so does the admin interface, which decides for itself who may be here
	if admin.IsAction(r.URL.Query().Get(sessionParam)) {
		s.handleAdmin(set, w, r)
		return
	}

	cred, ok := s.authenticate(set, w, r, target.Virtual)
	if !ok {
		return
	}
	user := cred.user
	act := actionOf(r.Method, target)
	if !s.permits(set, user, r.Method, target.Virtual, act) {
		s.log.Debug("http request not allowed for the account",
			"user", nameOf(user), "method", r.Method, "action", act, "path", target.Virtual)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.handleGet(set, w, r, target, cred)
	case http.MethodPut:
		if !s.sameSite(set, w, r) {
			return
		}
		s.handlePut(set, w, r, target, user, act == actOverwrite)
	case http.MethodDelete:
		if !s.sameSite(set, w, r) {
			return
		}
		s.handleDelete(set, w, r, target, user)
	case methodMkcol:
		if !s.sameSite(set, w, r) {
			return
		}
		s.handleMkcol(set, w, r, target, user)
	case methodMove:
		if !s.sameSite(set, w, r) {
			return
		}
		s.handleMove(set, w, r, target, user)
	case http.MethodPost:
		if !readerPath.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		s.handleDirectoryReader(set, w, r, target)
	default:
		s.log.Debug("http method not allowed", "method", r.Method, "url", r.URL.Path)
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE, POST, MKCOL, MOVE")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// responseRecorder remembers the status and the size of an answer for its
// record. Unwrap hands the real writer to http.ResponseController, so that a
// handler that needs to flush or set a deadline still can.
type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (r *responseRecorder) WriteHeader(status int) {
	if !r.wrote {
		r.status = status
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// headerTimeout is how long the request line and the headers may take. The
// body has its own limit in readTimeout, which is off for uploads that take
// longer than that; this one is not, because no client needs a minute to send
// its headers.
const headerTimeout = 30 * time.Second

// limited caps how many connections a listener hands out at once.
func limited(listener net.Listener, max int) net.Listener {
	if max < 1 {
		return listener
	}
	return &limitedListener{Listener: listener, slots: make(chan struct{}, max)}
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func seconds(value int) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}

func listenAddress(listener net.Listener) string {
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return listener.Addr().String()
}

func listenPort(listener net.Listener) int {
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

// nameOf is the account a request was answered for, for the transfer records. A
// public request has none, which is what the dash says.
func nameOf(user *account) string {
	if user == nil {
		return "-"
	}
	return user.name
}

// addressOf is the address the connection came from, without its port. It is
// what the connection records use; everything that says who a request is from
// uses clientAddress, which looks through a trusted proxy.
func addressOf(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

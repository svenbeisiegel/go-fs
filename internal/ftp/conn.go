package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/vfs"
)

// handler runs one command. arg is everything after the first space, trimmed.
type handler func(c *conn, arg string)

type dataMode int

const (
	dataNone dataMode = iota
	dataActive
	dataPassive
)

// conn is one control connection.
//
// A reader goroutine owns the input side and hands complete command lines to
// the command loop. It answers two commands itself: AUTH, because it has to
// swap the reader for the TLS one at exactly the right moment, and ABOR, which
// has to reach a running transfer while the command loop is busy moving bytes.
type conn struct {
	server *Server
	// set is the snapshot this connection was accepted under, so a reload
	// cannot change the rules under a half-finished command sequence.
	set *settings
	log *slog.Logger

	ctrl   net.Conn
	reader *bufio.Reader

	remoteAddr string
	localAddr  string

	writeMu sync.Mutex

	// session state, owned by the command loop. authenticated is the one the
	// reader goroutine reads too, when it decides whether AUTH is still its to
	// answer, so it is the one that has to be safe for two goroutines.
	authenticated atomicBool
	loggedIn      bool
	username      string
	perms         config.Permissions
	root          *vfs.Root
	cwd           string

	asciiMode  bool
	renameFrom string
	// renameFromVirtual is the client's view of renameFrom, for the record
	renameFromVirtual string
	restOffset        int64
	pbszDone          bool
	protected         bool
	epsvAll           bool
	mlstFacts         map[string]bool

	// secure is set once the control connection carries TLS.
	secure atomicBool

	// data channel
	mode       dataMode
	activeHost string
	activePort int
	passive    net.Listener
	dataCh     chan net.Conn

	transfer transferState

	closeOnce sync.Once
	quit      bool

	// connected and commands are for the logoff record: how long the session
	// lasted and how much it did
	connected time.Time
	commands  int
}

// transferState lets ABOR reach a transfer that is already running.
type transferState struct {
	mu       sync.Mutex
	active   bool
	aborted  bool
	cancel   context.CancelFunc
	dataConn net.Conn
}

type atomicBool struct {
	mu    sync.Mutex
	value bool
}

func (b *atomicBool) get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.value
}

func (b *atomicBool) set(value bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.value = value
}

// command is what the reader hands to the command loop.
type command struct {
	line string
	err  error
}

func (s *Server) serve(ctx context.Context, raw net.Conn, secure bool) {
	set := s.settings()
	cfg := set.cfg
	c := &conn{
		server:     s,
		set:        set,
		ctrl:       raw,
		reader:     bufio.NewReaderSize(raw, cfg.MaxCommandLength+2),
		remoteAddr: hostOf(raw.RemoteAddr()),
		localAddr:  hostOf(raw.LocalAddr()),
		cwd:        "/",
		root:       s.root,
		mlstFacts:  defaultFacts(),
		connected:  time.Now(),
	}
	c.secure.set(secure)
	c.log = s.log.With("client", net.JoinHostPort(c.remoteAddr, strconv.Itoa(portOf(raw.RemoteAddr()))))

	s.register(c)
	defer func() {
		c.closeData()
		c.close()
		s.unregister(c)
		if c.loggedIn {
			c.log.Info("ftp logoff", "user", c.username, "address", c.remoteAddr,
				"total", s.Connections(), "commands", c.commands,
				"duration", time.Since(c.connected).Round(time.Millisecond))
		}
		c.log.Debug("ftp connection closed", "commands", c.commands,
			"duration", time.Since(c.connected).Round(time.Millisecond))
	}()

	c.log.Debug("ftp connection established", "secure", secure, "total", s.Connections())
	c.reply("220", "Welcome")
	c.loop(ctx)
}

func (c *conn) loop(ctx context.Context) {
	commands := make(chan command, 8)
	go c.readLoop(commands)

	for {
		select {
		case <-ctx.Done():
			return
		case next, ok := <-commands:
			if !ok {
				return
			}
			if next.err != nil {
				switch {
				case errors.Is(next.err, errCommandTooLong):
					c.reply("500", "Command line too long")
				case errors.Is(next.err, errIdleTimeout):
					c.log.Debug("ftp control connection idle timeout")
					c.reply("421", "Timeout, closing control connection")
				}
				return
			}
			c.dispatch(next.line)
			if c.quit {
				return
			}
		}
	}
}

var (
	errCommandTooLong = errors.New("command line too long")
	errIdleTimeout    = errors.New("idle timeout")
)

// readLoop owns the input side of the control connection.
func (c *conn) readLoop(commands chan<- command) {
	defer close(commands)
	for {
		c.touch()
		line, err := c.readLine()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				commands <- command{err: errIdleTimeout}
				return
			}
			if errors.Is(err, errCommandTooLong) {
				c.log.Debug("ftp command line too long", "limit", c.set.cfg.MaxCommandLength)
				commands <- command{err: err}
				return
			}
			switch {
			case errors.Is(err, io.EOF):
				c.log.Debug("ftp client closed the control connection")
			case errors.Is(err, net.ErrClosed):
				// closed from this side: QUIT, a shutdown or a failed login
			default:
				c.log.Debug("ftp control connection read failed", "error", err)
			}
			return
		}

		name := strings.ToUpper(strings.TrimSpace(strings.SplitN(line, " ", 2)[0]))
		switch name {
		case "ABOR":
			// a running transfer takes it, otherwise it is a normal command
			if c.abortTransfer() {
				continue
			}
		case "AUTH":
			// only reachable before authentication, so no transfer can be in
			// flight and the reader may answer and upgrade on the spot
			if !c.authenticated.get() {
				c.handleAuth(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), name)))
				continue
			}
		}
		commands <- command{line: line}
	}
}

// readLine reads one CRLF terminated command. Pipelined commands arrive one
// call at a time and a command split across segments is reassembled.
//
// The reader is sized to the command limit, so a client that never sends a
// terminator fills the buffer and is refused as soon as it passes the limit,
// rather than being allowed to grow without bound.
func (c *conn) readLine() (string, error) {
	limit := c.set.cfg.MaxCommandLength
	var line []byte
	for {
		chunk, err := c.reader.ReadSlice('\n')
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			if len(line) > limit {
				return "", errCommandTooLong
			}
			continue
		}
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() && c.transferActive() {
				// A client moving bytes on the data connection owes nothing on
				// the control connection until it is done, so a transfer longer
				// than idleTimeout must not be read as an idle session. What has
				// been read is kept, so a command that straddles the deadline is
				// not lost, and ABOR still reaches the transfer.
				c.touch()
				continue
			}
			return "", err
		}
		text := strings.TrimRight(string(line), "\r\n")
		if len(text) > limit {
			return "", errCommandTooLong
		}
		return text, nil
	}
}

// touch refreshes the idle timeout of the control connection.
func (c *conn) touch() {
	if c.set.cfg.IdleTimeout <= 0 {
		_ = c.ctrl.SetReadDeadline(time.Time{})
		return
	}
	_ = c.ctrl.SetReadDeadline(time.Now().Add(time.Duration(c.set.cfg.IdleTimeout) * time.Second))
}

// dispatch parses and runs one command line.
func (c *conn) dispatch(line string) {
	name, arg, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
	name = strings.ToUpper(strings.TrimSpace(name))
	arg = strings.TrimSpace(arg)
	if name == "" {
		return
	}

	c.commands++
	logged := strings.TrimSpace(line)
	if name == "PASS" {
		logged = "PASS ***"
	}
	c.log.Debug("ftp <", "command", logged)

	table := authCommands
	if !c.authenticated.get() {
		table = preAuthCommands
	} else if !c.refreshPermissions() {
		// the account was taken out of the configuration while this session was
		// open, so the session goes with it rather than keeping what it had
		c.log.Info("ftp account is no longer configured, closing the session",
			"user", c.username)
		c.replyAndClose("421", "Account no longer available, closing control connection")
		return
	}
	run, ok := table[name]
	if !ok {
		if c.authenticated.get() {
			c.log.Debug("ftp command not implemented", "command", name)
			c.reply("500", "Command not implemented")
		} else {
			c.log.Debug("ftp command refused before login", "command", name)
			c.replyAndClose("530", "Not logged in")
		}
		return
	}
	run(c, arg)
}

// reply writes a single line answer.
func (c *conn) reply(code, message string) {
	c.writeReply(code, " ", message)
}

// replyMulti writes a multi line answer whose continuation and closing lines
// the caller has already formatted.
func (c *conn) replyMulti(code, message string) {
	c.writeReply(code, "-", message)
}

// replyAndClose answers and then ends the connection.
func (c *conn) replyAndClose(code, message string) {
	c.writeReply(code, " ", message)
	c.quit = true
}

func (c *conn) writeReply(code, delimiter, message string) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.log.Debug("ftp >", "reply", code+delimiter+message)
	_ = c.ctrl.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(c.ctrl, code+delimiter+message+"\r\n"); err != nil {
		c.log.Debug("ftp write failed", "error", err)
	}
	_ = c.ctrl.SetWriteDeadline(time.Time{})
}

func (c *conn) close() {
	c.closeOnce.Do(func() {
		_ = c.ctrl.Close()
	})
}

// handleAuth answers AUTH and, for TLS, upgrades the control connection.
func (c *conn) handleAuth(arg string) {
	arg = strings.ToUpper(strings.TrimSpace(arg))
	if arg != "TLS" && arg != "SSL" {
		c.reply("504", "Unsupported auth type "+arg)
		return
	}
	if c.server.tls == nil {
		c.log.Debug("ftp AUTH refused, ftps is not enabled", "type", arg)
		c.reply("504", "Unsupported auth type "+arg)
		return
	}
	c.reply("234", "Using authentication type "+arg)

	secure := tls.Server(c.ctrl, c.server.tls)
	_ = secure.SetDeadline(time.Now().Add(30 * time.Second))
	if err := secure.Handshake(); err != nil {
		c.log.Info("ftp tls handshake failed", "error", err)
		c.close()
		return
	}
	_ = secure.SetDeadline(time.Time{})

	c.writeMu.Lock()
	c.ctrl = secure
	c.writeMu.Unlock()
	c.reader = bufio.NewReaderSize(secure, c.set.cfg.MaxCommandLength+2)
	c.secure.set(true)
	state := secure.ConnectionState()
	c.log.Debug("ftp control connection is secure",
		"tls", tls.VersionName(state.Version), "cipher", tls.CipherSuiteName(state.CipherSuite))
}

// beginTransfer marks a transfer as running so that ABOR can reach it.
func (c *conn) beginTransfer(data net.Conn) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c.transfer.mu.Lock()
	c.transfer.active = true
	c.transfer.aborted = false
	c.transfer.cancel = cancel
	c.transfer.dataConn = data
	c.transfer.mu.Unlock()
	return ctx
}

// transferActive reports whether a transfer is running on this connection.
func (c *conn) transferActive() bool {
	c.transfer.mu.Lock()
	defer c.transfer.mu.Unlock()
	return c.transfer.active
}

// endTransfer clears the transfer and reports whether it was aborted.
func (c *conn) endTransfer() bool {
	c.transfer.mu.Lock()
	defer c.transfer.mu.Unlock()
	c.transfer.active = false
	if c.transfer.cancel != nil {
		c.transfer.cancel()
		c.transfer.cancel = nil
	}
	c.transfer.dataConn = nil
	return c.transfer.aborted
}

// abortTransfer is called by the reader when ABOR arrives. It reports whether a
// transfer took it; closing the data connection unblocks the copy at once.
func (c *conn) abortTransfer() bool {
	c.transfer.mu.Lock()
	defer c.transfer.mu.Unlock()
	if !c.transfer.active {
		return false
	}
	c.transfer.aborted = true
	if c.transfer.cancel != nil {
		c.transfer.cancel()
	}
	if c.transfer.dataConn != nil {
		_ = c.transfer.dataConn.Close()
	}
	return true
}

// isSamePeer reports whether an address belongs to the client of this control
// connection. A loopback client is allowed to use any loopback address, both
// families reach the same host anyway.
func (c *conn) isSamePeer(address string) bool {
	address = normalizeAddress(address)
	return address == c.remoteAddr || (isLoopback(address) && isLoopback(c.remoteAddr))
}

func defaultFacts() map[string]bool {
	facts := make(map[string]bool, len(supportedFacts))
	for _, fact := range supportedFacts {
		facts[fact] = true
	}
	return facts
}

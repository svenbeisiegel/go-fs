package ftp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	errNoDataChannel  = errors.New("no data channel")
	errDataTimeout    = errors.New("the data connection was not established")
	errDataConnection = errors.New("the data connection failed")
)

func (c *conn) dataTimeout() time.Duration {
	return time.Duration(c.set.cfg.DataTimeout) * time.Second
}

// closeData drops the passive listener and any connection waiting on it.
func (c *conn) closeData() {
	if c.passive != nil {
		_ = c.passive.Close()
		c.passive = nil
	}
	if c.dataCh != nil {
		select {
		case waiting := <-c.dataCh:
			if waiting != nil {
				_ = waiting.Close()
			}
		default:
		}
		c.dataCh = nil
	}
}

// listenPassive binds a passive data listener and starts accepting the one
// connection it is meant to take.
func (c *conn) listenPassive() (int, error) {
	c.closeData()
	c.mode = dataNone

	listener, port, err := c.server.listenData(c.set)
	if err != nil {
		return 0, err
	}
	c.passive = listener
	c.mode = dataPassive
	c.dataCh = make(chan net.Conn, 1)

	channel := c.dataCh
	go func() {
		for {
			accepted, err := listener.Accept()
			if err != nil {
				return
			}
			// Only the client that asked for the data channel may use it,
			// otherwise a third party could read or inject transfer data.
			if !c.set.cfg.AllowForeignDataConnection && !c.isSamePeer(hostOf(accepted.RemoteAddr())) {
				c.log.Debug("ftp rejected data connection", "from", hostOf(accepted.RemoteAddr()))
				_ = accepted.Close()
				continue
			}
			// stop accepting further connections on this passive port
			_ = listener.Close()
			c.log.Debug("ftp data connection established", "from", hostOf(accepted.RemoteAddr()))
			select {
			case channel <- accepted:
			default:
				_ = accepted.Close()
			}
			return
		}
	}()
	return port, nil
}

// openData returns the data connection for a transfer.
func (c *conn) openData() (net.Conn, error) {
	switch c.mode {
	case dataActive:
		c.log.Debug("ftp opening active data connection",
			"address", c.activeHost, "port", c.activePort,
			"sourcePort", c.set.cfg.ActiveSourcePort,
			"secure", c.secure.get(), "protected", c.protected)
		dialer := net.Dialer{Timeout: c.dataTimeout()}
		if source := c.set.cfg.ActiveSourcePort; source != 0 {
			// a nil IP is the wildcard of whichever family the target is in,
			// so one setting serves an IPv4 and an IPv6 client alike
			dialer.LocalAddr = &net.TCPAddr{Port: source}
			dialer.Control = reuseAddr
		}
		dialed, err := dialer.Dial("tcp", net.JoinHostPort(c.activeHost, strconv.Itoa(c.activePort)))
		if err != nil {
			if source := c.set.cfg.ActiveSourcePort; source != 0 {
				// naming the port matters here: a privileged one the process
				// may not bind, or one another process holds, fails the dial
				// for a reason that has nothing to do with the client
				return nil, fmt.Errorf("%w from ftp.activeSourcePort %d: %w",
					errDataConnection, source, err)
			}
			return nil, fmt.Errorf("%w: %w", errDataConnection, err)
		}
		return c.secureData(dialed), nil

	case dataPassive:
		select {
		case accepted := <-c.dataCh:
			return c.secureData(accepted), nil
		case <-time.After(c.dataTimeout()):
			return nil, errDataTimeout
		}
	}
	return nil, errNoDataChannel
}

// secureData wraps a data connection when PROT P is in effect.
func (c *conn) secureData(raw net.Conn) net.Conn {
	if !c.secure.get() || !c.protected || c.server.tls == nil {
		return raw
	}
	c.log.Debug("ftp data connection is secure")
	return tls.Server(raw, c.server.tls)
}

// withData runs work over a fresh data connection and answers the client. work
// returns the reply for a successful transfer.
func (c *conn) withData(opening string, work func(data net.Conn) (code, message string)) {
	if c.mode == dataNone {
		c.reply("501", "Command failed")
		return
	}
	if opening == "" {
		opening = "Opening data channel"
	}
	c.reply("150", opening)

	mode := "active"
	if c.mode == dataPassive {
		mode = "passive"
	}
	data, err := c.openData()
	// a data channel is used once, the client asks for a new one per transfer
	c.mode = dataNone
	c.closeData()
	if err != nil {
		// the classic FTP failure, and nearly always a firewall or a NAT
		// between the two ends: it is reported with what was tried so that the
		// side at fault can be told
		c.log.Info("ftp data connection failed", "user", c.username, "mode", mode,
			"timeout", c.dataTimeout(), "error", err)
		c.reply("425", "Cannot open the data connection")
		return
	}

	data = c.boundTransfer(data)
	c.beginTransfer(data)
	code, message := work(data)
	_ = data.Close()
	aborted := c.endTransfer()

	if aborted {
		c.reply("426", "Connection closed; transfer aborted")
		c.reply("226", "Abort successful")
		return
	}
	c.reply(code, message)
}

// boundTransfer bounds a transfer by how long it may move nothing, rather than
// by how long it may take. A flat deadline has to be generous enough for the
// largest file anyone will ever fetch, which makes it useless against a client
// that opens the data connection and then stops reading: that one would hold a
// control slot until the deadline, and with maxConnections slots in total a
// handful of them is the whole server. An idle bound costs a legitimate
// transfer nothing, however long it runs, as long as it keeps moving.
//
// The wrapper costs the sendfile path a plaintext download would otherwise
// take, since the deadline has to be refreshed between reads rather than once
// around a copy the kernel makes on its own. That is the trade: one buffer copy
// against a stalled client holding a connection slot for as long as it likes.
func (c *conn) boundTransfer(data net.Conn) net.Conn {
	timeout := time.Duration(c.set.cfg.TransferIdleTimeout) * time.Second
	if timeout <= 0 {
		_ = data.SetDeadline(time.Time{})
		return data
	}
	return &idleData{Conn: data, timeout: timeout}
}

// idleData pushes the deadline forward on every read and write, so it measures
// a stall rather than the length of the transfer.
type idleData struct {
	net.Conn
	timeout time.Duration
}

func (d *idleData) Read(b []byte) (int, error) {
	_ = d.Conn.SetReadDeadline(time.Now().Add(d.timeout))
	return d.Conn.Read(b)
}

func (d *idleData) Write(b []byte) (int, error) {
	_ = d.Conn.SetWriteDeadline(time.Now().Add(d.timeout))
	return d.Conn.Write(b)
}

// isDataTargetAllowed reports whether an active data connection may be opened.
//
// An active data connection may only target the client that issued the command,
// otherwise the server can be abused to reach third parties on the client's
// behalf (RFC 2577).
func (c *conn) isDataTargetAllowed(address string, port int) bool {
	if port < 1024 || port > 65535 {
		return false
	}
	return c.set.cfg.AllowFtpBounce || c.isSamePeer(address)
}

// cmdPort handles PORT.
func cmdPort(c *conn, arg string) {
	if c.epsvAll {
		c.reply("501", "EPSV ALL in effect")
		return
	}
	c.mode = dataNone
	c.closeData()

	parts := strings.Split(arg, ",")
	if len(parts) != 6 {
		c.reply("501", "Port command failed")
		return
	}
	numbers := make([]int, 6)
	for i, part := range parts {
		value, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || value < 0 || value > 255 {
			c.reply("501", "Port command failed")
			return
		}
		numbers[i] = value
	}
	address := fmt.Sprintf("%d.%d.%d.%d", numbers[0], numbers[1], numbers[2], numbers[3])
	port := numbers[4]*256 + numbers[5]

	if !c.isDataTargetAllowed(address, port) {
		c.log.Debug("ftp PORT refused, the target is not the client", "address", address, "port", port)
		c.reply("501", "Port command not allowed")
		return
	}
	c.activeHost, c.activePort, c.mode = address, port, dataActive
	c.reply("200", "Port command successful")
}

// cmdEprt handles EPRT.
func cmdEprt(c *conn, arg string) {
	if c.epsvAll {
		c.reply("501", "EPSV ALL in effect")
		return
	}
	c.mode = dataNone
	c.closeData()

	parts := strings.Split(arg, "|")
	if len(parts) != 5 {
		c.reply("501", "Extended port command failed")
		return
	}
	address := parts[2]
	port, err := strconv.Atoi(parts[3])
	if err != nil || net.ParseIP(address) == nil {
		c.reply("501", "Extended port command failed")
		return
	}
	if !c.isDataTargetAllowed(address, port) {
		c.log.Debug("ftp EPRT refused, the target is not the client", "address", address, "port", port)
		c.reply("501", "Extended port command not allowed")
		return
	}
	c.activeHost, c.activePort, c.mode = address, port, dataActive
	c.reply("200", "Extended Port command successful")
}

// cmdPasv handles PASV.
func cmdPasv(c *conn, _ string) {
	if c.epsvAll {
		c.reply("501", "EPSV ALL in effect")
		return
	}
	// A PASV reply names the address the client should connect back to. That
	// is the address the control connection arrived on, unless something
	// translates in between and ftp.passiveAddress says what clients see.
	advertised := c.set.cfg.PassiveAddress
	if advertised == "" {
		advertised = c.localAddr
	}
	// PASV can only name an IPv4 address, an IPv6 client has to use EPSV
	ip := net.ParseIP(advertised)
	if ip == nil || ip.To4() == nil {
		c.log.Debug("ftp PASV refused, the advertised address is not IPv4", "address", advertised)
		c.reply("522", "Network protocol not supported, use (2)")
		return
	}
	port, err := c.listenPassive()
	if err != nil {
		c.log.Warn("ftp cannot open a passive data port", "error", err)
		c.reply("501", "Passive command failed")
		return
	}
	c.log.Debug("ftp listening for a data connection", "port", port)
	octets := strings.ReplaceAll(ip.To4().String(), ".", ",")
	c.reply("227", fmt.Sprintf("Entering passive mode (%s,%d,%d)", octets, port/256, port%256))
}

// cmdEpsv handles EPSV.
func cmdEpsv(c *conn, arg string) {
	parameter := strings.ToUpper(strings.TrimSpace(arg))
	// EPSV ALL promises the client will only use EPSV from now on, so every
	// other data setup command has to be refused (RFC 2428).
	if parameter == "ALL" {
		c.epsvAll = true
		c.reply("200", "EPSV ALL command successful")
		return
	}
	if parameter != "" && parameter != "1" && parameter != "2" {
		c.reply("522", "Network protocol not supported, use (1,2)")
		return
	}
	port, err := c.listenPassive()
	if err != nil {
		c.log.Warn("ftp cannot open a passive data port", "error", err)
		c.reply("501", "Extended passive command failed")
		return
	}
	c.log.Debug("ftp listening for a data connection", "port", port)
	c.reply("229", fmt.Sprintf("Entering extended passive mode (|||%d|)", port))
}

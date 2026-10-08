// Package remote reaches other servers on behalf of go-fs: the hosts the file
// listing sends files to, whether the user typed the login in or picked a
// server the admin interface stored. It holds what both need, reading a
// login, asking a host for its key and logging in to it, so that the listing
// and the admin interface check a login the same way.
//
// A protocol is one of config.ServerTypes; each has its own file here, and the
// functions of this file pick it by Login.Type.
package remote

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go-fs/internal/config"
)

// Login is what reaching a host takes.
type Login struct {
	// Type is the protocol, one of config.ServerTypes.
	Type     string
	Host     string
	Port     int
	Username string
	Password string
	// HostKey is the fingerprint of the key that was accepted, for a protocol
	// whose host shows one.
	HostKey string
	// Server is the name of the stored server the login is, "" for one that
	// was typed in. What goes wrong names it, since only an administrator can
	// change the login of a server.
	Server string
}

// FromServer is the login of a stored server.
func FromServer(s config.Server) Login {
	return Login{Type: s.Type, Host: s.Host, Port: s.Port, Username: s.Username,
		Password: s.Password, HostKey: s.HostKeyFingerprint, Server: s.Name}
}

// ConfigServer is the login as the entry of the file that stores it, under
// name.
func (l Login) ConfigServer(name string) config.Server {
	return config.Server{Name: name, Type: l.Type, Host: l.Host, Port: l.Port, Username: l.Username,
		Password: l.Password, HostKeyFingerprint: l.HostKey}
}

// Checked reads a login: the type defaults to SFTP, the host loses the brackets
// of an IPv6 address and the port defaults to that of the type. keyOnly is a
// login only asked for the key of its host, which needs no username.
func (l Login) Checked(keyOnly bool) (Login, error) {
	if l.Type == "" {
		l.Type = config.ServerTypeSFTP
	}
	kind, ok := config.ServerTypeOf(l.Type)
	if !ok {
		return Login{}, fmt.Errorf("%q is not a protocol go-fs knows", l.Type)
	}
	host, err := config.RemoteHost(l.Host)
	if err != nil {
		return Login{}, err
	}
	l.Host = host
	if l.Port == 0 {
		l.Port = kind.DefaultPort
	}
	if l.Port < 1 || l.Port > 65535 {
		return Login{}, fmt.Errorf("%d is not a port", l.Port)
	}
	if keyOnly {
		return l, nil
	}
	l.Username = strings.TrimSpace(l.Username)
	if l.Username == "" {
		return Login{}, errors.New("name the user to log in as")
	}
	l.HostKey = strings.TrimSpace(l.HostKey)
	if kind.HostKey && !strings.HasPrefix(l.HostKey, "SHA256:") {
		return Login{}, errors.New("accept the key of the host first")
	}
	return l, nil
}

// Address is where the host is dialled.
func (l Login) Address() string {
	return net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
}

// Shown is the host as a page and the log show it, without the port it has
// when none is named.
func (l Login) Shown() string {
	if kind, ok := config.ServerTypeOf(l.Type); ok && l.Port == kind.DefaultPort {
		if strings.Contains(l.Host, ":") {
			return "[" + l.Host + "]"
		}
		return l.Host
	}
	return l.Address()
}

// Where is a path of the host as a page shows it.
func (l Login) Where(p string) string {
	return l.Type + "://" + l.Shown() + p
}

// HostKey asks a host for its key, without offering it any login: the
// handshake is broken off once the key is seen. It answers the type of the key
// and its SHA-256 fingerprint.
func HostKey(ctx context.Context, l Login, sshCfg config.SSH) (keyType, fingerprint string, err error) {
	switch l.Type {
	case config.ServerTypeSFTP:
		return sshHostKey(ctx, l, sshCfg)
	}
	return "", "", fmt.Errorf("a host reached by %s shows no key", l.Type)
}

// Test logs in to a host, to find whether the login works, and logs out again.
func Test(ctx context.Context, l Login, sshCfg config.SSH) error {
	switch l.Type {
	case config.ServerTypeSFTP:
		conn, client, err := OpenSFTP(ctx, l, sshCfg)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		defer func() { _ = client.Close() }()
		if _, err := client.Getwd(); err != nil {
			return fmt.Errorf("%s: %w", l.Shown(), err)
		}
		return nil
	}
	return fmt.Errorf("%q is not a protocol go-fs knows", l.Type)
}

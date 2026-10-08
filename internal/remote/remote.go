// Package remote reaches other servers on behalf of go-fs: the hosts the file
// listing sends files to, whether the user typed the login in or picked a
// server the admin interface stored. It holds what both need, reading a
// login, asking a host for its key and logging in to it, so that the listing
// and the admin interface check a login the same way.
//
// A protocol is one of config.ServerTypes; each has its own file here, and the
// functions of this file pick it by Login.Type. What is done on a host, once
// logged in to, is done through FS, which each protocol implements.
package remote

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
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
	// URL and Token are what a protocol reached by an address and a Bearer
	// token logs in with, in place of the host, the port and the login.
	URL   string
	Token string
	// VaultPath is the folder of the host that is a vault of Cryptomator,
	// "" for none, and VaultPassword what unlocks it: once logged in, what
	// is done on the host is done in the vault, encrypted (see vaultFS).
	VaultPath     string
	VaultPassword string
	// Server is the name of the stored server the login is, "" for one that
	// was typed in. What goes wrong names it, since only an administrator can
	// change the login of a server.
	Server string
}

// FromServer is the login of a stored server.
func FromServer(s config.Server) Login {
	return Login{Type: s.Type, Host: s.Host, Port: s.Port, Username: s.Username,
		Password: s.Password, HostKey: s.HostKeyFingerprint, URL: s.URL, Token: s.Token,
		VaultPath: s.VaultPath, VaultPassword: s.VaultPassword, Server: s.Name}
}

// ConfigServer is the login as the entry of the file that stores it, under
// name.
func (l Login) ConfigServer(name string) config.Server {
	return config.Server{Name: name, Type: l.Type, Host: l.Host, Port: l.Port, Username: l.Username,
		Password: l.Password, HostKeyFingerprint: l.HostKey, URL: l.URL, Token: l.Token,
		VaultPath: l.VaultPath, VaultPassword: l.VaultPassword}
}

// Checked reads a login: the type defaults to SFTP, the host loses the brackets
// of an IPv6 address and the port defaults to that of the type. keyOnly is a
// login only asked for the key of its host, which needs no username. A login
// by token is its address, as config.ArtifactoryURL reads it, and the token,
// and nothing of the rest.
func (l Login) Checked(keyOnly bool) (Login, error) {
	if l.Type == "" {
		l.Type = config.ServerTypeSFTP
	}
	kind, ok := config.ServerTypeOf(l.Type)
	if !ok {
		return Login{}, fmt.Errorf("%q is not a protocol go-fs knows", l.Type)
	}
	if kind.Token {
		return l.checkedToken(kind, keyOnly)
	}
	l.URL, l.Token = "", ""
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
	return l.checkedVault()
}

// checkedVault reads the vault of a login: a path of the host, made
// absolute and clean, that needs a password, or no vault and no password.
func (l Login) checkedVault() (Login, error) {
	vault, err := config.VaultPath(l.VaultPath)
	if err != nil {
		return Login{}, err
	}
	l.VaultPath = vault
	if l.VaultPath == "" {
		l.VaultPassword = ""
	} else if l.VaultPassword == "" {
		return Login{}, errors.New("type the password of the vault")
	}
	return l, nil
}

// checkedToken reads a login by an address and a token.
func (l Login) checkedToken(kind config.ServerType, keyOnly bool) (Login, error) {
	if keyOnly {
		return Login{}, fmt.Errorf("a server reached by %s shows no key", kind.Label)
	}
	address, err := config.ArtifactoryURL(l.URL)
	if err != nil {
		return Login{}, err
	}
	l.URL = address
	l.Token = strings.TrimSpace(l.Token)
	if l.Token == "" {
		return Login{}, errors.New("paste the token to log in with")
	}
	l.Host, l.Port, l.Username, l.Password, l.HostKey = "", 0, "", "", ""
	return l.checkedVault()
}

// byToken reports a login by an address and a token.
func (l Login) byToken() bool {
	kind, ok := config.ServerTypeOf(l.Type)
	return ok && kind.Token
}

// Who is who the host knows the login as, in what a page says it may not do:
// the user, or the token.
func (l Login) Who() string {
	if l.byToken() {
		return "the token"
	}
	return l.Username
}

// Address is where the host is dialled.
func (l Login) Address() string {
	return net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
}

// Shown is the host as a page and the log show it, without the port it has
// when none is named.
func (l Login) Shown() string {
	if l.byToken() {
		if u, err := url.Parse(l.URL); err == nil && u.Host != "" {
			return u.Host
		}
		return l.URL
	}
	if kind, ok := config.ServerTypeOf(l.Type); ok && l.Port == kind.DefaultPort {
		if strings.Contains(l.Host, ":") {
			return "[" + l.Host + "]"
		}
		return l.Host
	}
	return l.Address()
}

// Where is a path of the host as a page shows it; one in a vault is shown
// in the folder of the vault, by its cleartext name.
func (l Login) Where(p string) string {
	if l.VaultPath != "" {
		p = strings.TrimSuffix(l.VaultPath, "/") + p
	}
	if l.byToken() {
		return l.URL + p
	}
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
	fsys, err := Open(ctx, l, sshCfg)
	if err != nil {
		return err
	}
	defer func() { _ = fsys.Close() }()
	home, err := fsys.Resolve("")
	if err != nil {
		return fmt.Errorf("%s: %w", l.Shown(), err)
	}
	if _, err := fsys.Stat(home); err != nil {
		if l.byToken() {
			// what the token was refused with names the host already
			return err
		}
		return fmt.Errorf("%s: %w", l.Shown(), err)
	}
	return nil
}

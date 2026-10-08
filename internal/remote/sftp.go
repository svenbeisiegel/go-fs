package remote

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
)

// HandshakeTimeout bounds the connection and the handshake with a host, which
// one that does not answer would hold.
const HandshakeTimeout = 30 * time.Second

// errHostKeyShown ends the handshake that only asks for the key of a host.
var errHostKeyShown = errors.New("host key shown")

// ErrHostKeyChanged is a host that shows a key other than the one accepted.
var ErrHostKeyChanged = errors.New("the host key is not the one that was accepted")

// sshConnect dials a host and runs the handshake, within HandshakeTimeout.
// The connection is cut as soon as ctx ends, which is what stops whatever
// waits on it.
func sshConnect(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// sshHostKey asks an SSH host for its key, with the same algorithms as the
// login that follows, so that the key shown is the kind the login is shown too.
func sshHostKey(ctx context.Context, l Login, sshCfg config.SSH) (string, string, error) {
	var seen ssh.PublicKey
	conn, err := sshConnect(ctx, l.Address(), &ssh.ClientConfig{
		Config:            sshCfg.ClientTransport(),
		HostKeyAlgorithms: sshCfg.HostKeys(),
		User:              "go-fs",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errHostKeyShown
		},
	})
	if conn != nil {
		_ = conn.Close()
	}
	if seen == nil {
		if err == nil {
			err = errors.New("no host key was shown")
		}
		return "", "", Failure(l, err)
	}
	return seen.Type(), ssh.FingerprintSHA256(seen), nil
}

// OpenSFTP logs in to a host, provided it shows the key that was accepted,
// and opens its SFTP, with the algorithms [general.ssh] allows. The
// connection lives as long as ctx.
func OpenSFTP(ctx context.Context, l Login, sshCfg config.SSH) (*ssh.Client, *sftp.Client, error) {
	password := l.Password
	login := &ssh.ClientConfig{
		Config:            sshCfg.ClientTransport(),
		HostKeyAlgorithms: sshCfg.HostKeys(),
		User:              l.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			// what many hosts ask a password by instead
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != l.HostKey {
				return ErrHostKeyChanged
			}
			return nil
		},
	}
	conn, err := sshConnect(ctx, l.Address(), login)
	if err != nil {
		return nil, nil, Failure(l, err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("%s offers no SFTP: %w", l.Shown(), err)
	}
	return conn, client, nil
}

// Failure says why a host could not be reached or logged in to, in the words
// a page shows.
func Failure(l Login, err error) error {
	var negotiation *ssh.AlgorithmNegotiationError
	switch {
	case errors.As(err, &negotiation):
		return fmt.Errorf("%s offers no %s that general.ssh allows; it offers %s",
			l.Shown(), negotiation.What, strings.Join(negotiation.RequestedAlgorithms, ", "))
	case errors.Is(err, ErrHostKeyChanged) && l.Server != "":
		return fmt.Errorf("the key of %s is not the one saved for the server %s; "+
			"an administrator has to edit the server and accept the key it shows now", l.Shown(), l.Server)
	case errors.Is(err, ErrHostKeyChanged):
		return fmt.Errorf("the key of %s is not the one that was accepted; connect again to see the one it shows now", l.Shown())
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%s refused the login of %s", l.Shown(), l.Username)
	}
	return fmt.Errorf("%s: %w", l.Shown(), err)
}

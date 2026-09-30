package sftp

import (
	"fmt"
	"log/slog"

	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
)

// hostKey returns the signer the SSH server identifies itself with.
//
// As with the TLS certificate of the FTPS listener, a key that is not
// configured is generated for this run, which keeps the server usable without
// any setup at the cost of a key that changes on every restart: every client
// that remembers host keys reports the change. The warning says so, and the
// configuration documents how to produce a stable value.
//
// A generated key is made as the value the file would hold and then read back,
// so that a generated key and a configured one go down the same path.
func hostKey(cfg config.SFTP, logger *slog.Logger) (ssh.Signer, error) {
	if cfg.HostKey != "" {
		signer, err := parseHostKey(cfg.HostKey)
		if err != nil {
			return nil, fmt.Errorf("sftp.hostkey: %w", err)
		}
		// the fingerprint is what a client shows when it asks whether to
		// trust the host, and what it reports when the key changed, so it is
		// said once so that either can be checked against the log
		logger.Info("sftp host key loaded", "type", signer.PublicKey().Type(),
			"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
		return signer, nil
	}

	generated, err := config.GenerateHostKey()
	if err != nil {
		return nil, fmt.Errorf("sftp: cannot generate a host key: %w", err)
	}
	signer, err := parseHostKey(generated)
	if err != nil {
		return nil, fmt.Errorf("sftp: cannot generate a host key: %w", err)
	}
	logger.Warn("no sftp.hostkey configured, generated a temporary host key; "+
		"it changes on every restart, so clients will report a changed host key",
		"type", signer.PublicKey().Type(),
		"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}

// parseHostKey turns a configured hostkey value into a signer. config.DecodeHostKey
// reports which of the things that can be wrong with the value is wrong,
// because "invalid key" on its own does not tell a truncated paste from a
// passphrase protected key.
func parseHostKey(value string) (ssh.Signer, error) {
	decoded, err := config.DecodeHostKey(value)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(decoded)
}

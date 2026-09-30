package sftp

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/secrets"
	"go-fs/internal/vfs"
)

// account is one resolved entry of [[users]] that sets sftp: its credentials,
// its rights and the folder it sees.
type account struct {
	name     string
	password string
	keys     []ssh.PublicKey
	perms    config.Permissions
	root     *vfs.Root
}

// canPassword reports whether this account may be asked for a password at all.
// An account without one is not open to any password: SSH has no equivalent of
// the FTP anonymous login, so allowLoginWithoutPassword is not honoured here.
func (a *account) canPassword() bool { return a.password != "" }

// buildAccounts resolves the configured users once, at startup, so that a
// malformed key or a missing folder is an error the operator sees immediately
// instead of a login that never succeeds. An error names the account rather
// than its position: the list is the file's filtered down to this server.
func buildAccounts(users []config.User, serverRoot *vfs.Root) (map[string]*account, error) {
	accounts := make(map[string]*account, len(users))
	for _, user := range users {
		if _, taken := accounts[user.Username]; taken {
			return nil, fmt.Errorf("users %q is configured twice", user.Username)
		}

		resolved := &account{
			name:     user.Username,
			password: user.Password,
			perms:    user.Permissions(),
			root:     serverRoot,
		}
		if user.Basefolder != "" {
			root, err := vfs.New(user.Basefolder)
			if err != nil {
				return nil, fmt.Errorf("users %q basefolder: %w", user.Username, err)
			}
			resolved.root = root
		}
		for k, entry := range user.AuthorizedKeys {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry))
			if err != nil {
				return nil, fmt.Errorf("users %q authorizedKeys[%d]: %w", user.Username, k, err)
			}
			resolved.keys = append(resolved.keys, key)
		}
		if !resolved.canPassword() && len(resolved.keys) == 0 {
			return nil, fmt.Errorf("users %q has neither a password nor an authorized key, "+
				"so it could never log in", user.Username)
		}
		accounts[user.Username] = resolved
	}
	return accounts, nil
}

func (s *Server) account(name string) *account {
	return s.settings().users[name]
}

var errDenied = errors.New("authentication failed")

// authenticatePassword answers the SSH password method. The reply to a wrong
// password is delayed, as in FTP, so that guessing costs the attacker time.
func (s *Server) authenticatePassword(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	log := s.log.With("client", meta.RemoteAddr().String(), "user", meta.User(), "method", "password")
	user := s.account(meta.User())
	if user != nil && user.canPassword() && secrets.Match(string(password), user.password) {
		log.Debug("sftp authentication", "success", true)
		return &ssh.Permissions{}, nil
	}
	// why it failed is for the trace, since the answer to the client must
	// not say whether the account exists
	switch {
	case user == nil:
		log.Debug("sftp authentication", "success", false, "reason", "no such account")
	case !user.canPassword():
		log.Debug("sftp authentication", "success", false, "reason", "the account has no password, only keys")
	default:
		log.Debug("sftp authentication", "success", false, "reason", "wrong password")
	}
	// the same record the FTP and HTTP servers write for a refused password
	log.Info("sftp login refused", "address", addressOnly(meta.RemoteAddr().String()))
	if delay := s.settings().cfg.LoginFailureDelay; delay > 0 {
		time.Sleep(time.Duration(delay) * time.Second)
	}
	return nil, errDenied
}

// authenticatePublicKey answers the SSH public key method. The offered key is
// compared against the account's authorized keys; the SSH layer has already
// checked that the client holds the matching private key.
func (s *Server) authenticatePublicKey(meta ssh.ConnMetadata, offered ssh.PublicKey) (*ssh.Permissions, error) {
	// the fingerprint is what the client's own ssh-keygen -l prints, so the
	// two can be compared when a key that should match does not
	log := s.log.With("client", meta.RemoteAddr().String(), "user", meta.User(),
		"method", "publickey", "keyType", offered.Type(), "fingerprint", ssh.FingerprintSHA256(offered))
	user := s.account(meta.User())
	if user != nil {
		wire := offered.Marshal()
		for _, allowed := range user.keys {
			if allowed.Type() == offered.Type() && secrets.MatchBytes(allowed.Marshal(), wire) {
				log.Debug("sftp authentication", "success", true)
				return &ssh.Permissions{}, nil
			}
		}
	}
	// a client offers every key it has before the right one, so a refused
	// key is ordinary and stays in the trace
	if user == nil {
		log.Debug("sftp authentication", "success", false, "reason", "no such account")
	} else {
		log.Debug("sftp authentication", "success", false,
			"reason", "the key is not authorized for the account", "authorizedKeys", len(user.keys))
	}
	return nil, errDenied
}

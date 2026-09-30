package ftp

import (
	"time"

	"go-fs/internal/config"
	"go-fs/internal/secrets"
	"go-fs/internal/vfs"
)

type loginType int

const (
	loginNone loginType = iota
	loginPassword
	loginNoPassword
)

// users are the accounts as they are configured right now.
//
// The rest of the connection runs on the snapshot it was accepted under, so a
// reload cannot change a limit or a timeout under a half-finished command
// sequence. The accounts are the deliberate exception: a right taken away, or
// an account removed, has to reach a session that is already open, otherwise
// revoking access would mean waiting for the client to hang up.
func (c *conn) users() []config.User {
	return c.server.settings().users
}

// validateLoginType decides how the named user may log in. Accounts come from
// the configured user list; a name that is not listed cannot log in. Anonymous
// access is one of those accounts, named "anonymous" with
// allowLoginWithoutPassword set, and gets no special treatment here.
func (c *conn) validateLoginType() loginType {
	for _, user := range c.users() {
		if user.Username != c.username {
			continue
		}
		permissions := user.Permissions()
		if permissions.LoginNoPassword {
			c.applyPermissions(permissions)
			return loginNoPassword
		}
		return loginPassword
	}
	return loginNone
}

// authenticateUser checks the password and applies the account's rights.
func (c *conn) authenticateUser(password string) bool {
	success := false

	for _, user := range c.users() {
		if user.Username != c.username {
			continue
		}
		permissions := user.Permissions()
		if permissions.LoginNoPassword || secrets.Match(password, user.Password) {
			c.applyPermissions(permissions)
			success = true
		}
		break
	}

	c.log.Debug("ftp authentication", "user", c.username, "success", success)
	if !success {
		c.log.Info("ftp login refused", "user", c.username, "address", c.remoteAddr)
	}
	return success
}

// refreshPermissions re-reads the rights of the logged in account and reports
// whether it is still configured. It runs before every command of a logged in
// session, so a permission taken away applies to the next command the client
// sends and an account that was removed can do nothing more.
func (c *conn) refreshPermissions() bool {
	for _, user := range c.users() {
		if user.Username != c.username {
			continue
		}
		permissions := user.Permissions()
		if permissions.Basefolder == c.perms.Basefolder {
			// the folder is what costs a stat and a symlink walk, so it is only
			// resolved again when it actually changed
			c.perms = permissions
			return true
		}
		c.applyPermissions(permissions)
		// the folder underneath moved, so where the client stands may not exist
		// in the new one
		c.cwd = "/"
		return true
	}
	return false
}

// applyPermissions installs the rights of an account, including its own base
// folder when it has one.
func (c *conn) applyPermissions(permissions config.Permissions) {
	c.perms = permissions
	if permissions.Basefolder == "" {
		c.root = c.server.root
		return
	}
	root, err := vfs.New(permissions.Basefolder)
	if err != nil {
		c.log.Error("ftp cannot use the base folder of the user",
			"user", c.username, "basefolder", permissions.Basefolder, "error", err)
		c.root = c.server.root
		return
	}
	c.root = root
}

// cmdUser handles USER.
func cmdUser(c *conn, arg string) {
	c.username = arg
	switch c.validateLoginType() {
	case loginNoPassword:
		c.authenticated.set(true)
		c.reply("232", "User logged in")
		c.markLoggedIn()
	default:
		// A name that is not configured is answered exactly as one that is, so
		// that the reply does not say which accounts exist. It fails at PASS
		// instead, after the same delay a wrong password takes.
		c.reply("331", "Password required for "+c.username)
	}
}

// cmdPass handles PASS.
func cmdPass(c *conn, arg string) {
	if c.authenticateUser(arg) {
		c.authenticated.set(true)
		c.reply("230", "Logged on")
		c.markLoggedIn()
		return
	}
	// Answer a wrong password only after a delay, so that guessing passwords
	// costs the attacker time.
	if delay := c.set.cfg.LoginFailureDelay; delay > 0 {
		time.Sleep(time.Duration(delay) * time.Second)
	}
	c.replyAndClose("530", "Username or password incorrect")
}

func (c *conn) markLoggedIn() {
	c.loggedIn = true
	c.log.Info("ftp login", "user", c.username, "address", c.remoteAddr,
		"total", c.server.Connections())
}

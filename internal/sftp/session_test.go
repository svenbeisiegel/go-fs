package sftp

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
)

func TestPasswordLogin(t *testing.T) {
	server := newServer(t, nil)

	client := login(t, server)
	if _, err := client.Getwd(); err != nil {
		t.Fatalf("a logged in client has to work: %v", err)
	}

	if record := server.logs.find("sftp login"); record == nil {
		t.Error("a login has to be reported")
	} else if record["user"] != "john" {
		t.Errorf("login record = %v", record)
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	server := newServer(t, nil)

	if _, err := dial(t, server, "john", ssh.Password("wrong")); err == nil {
		t.Error("a wrong password has to be refused")
	}
	if _, err := dial(t, server, "stranger", ssh.Password("doe")); err == nil {
		t.Error("an unconfigured user has to be refused")
	}
}

func TestPublicKeyLogin(t *testing.T) {
	signer, authorized := newKeyPair(t)
	other, _ := newKeyPair(t)

	server := newServer(t, func(cfg *sftpConfig) {
		user := fullUser("john", "")
		user.AuthorizedKeys = []string{authorized}
		cfg.Users = []config.User{user}
	})

	if _, err := dial(t, server, "john", ssh.PublicKeys(signer)); err != nil {
		t.Fatalf("the authorized key has to be accepted: %v", err)
	}
	if _, err := dial(t, server, "john", ssh.PublicKeys(other)); err == nil {
		t.Error("an unknown key has to be refused")
	}
	// the account has no password, so the password method cannot let anyone in
	if _, err := dial(t, server, "john", ssh.Password("")); err == nil {
		t.Error("an account without a password must not accept one")
	}
}

// A key and a password on the same account are both usable.
func TestBothAuthenticationMethods(t *testing.T) {
	signer, authorized := newKeyPair(t)
	server := newServer(t, func(cfg *sftpConfig) {
		user := fullUser("john", "doe")
		user.AuthorizedKeys = []string{authorized}
		cfg.Users = []config.User{user}
	})

	if _, err := dial(t, server, "john", ssh.PublicKeys(signer)); err != nil {
		t.Errorf("the key has to work: %v", err)
	}
	if _, err := dial(t, server, "john", ssh.Password("doe")); err != nil {
		t.Errorf("the password has to work: %v", err)
	}
}

// An account that could never log in is a configuration error, not a server
// that quietly refuses every attempt.
func TestNewRejectsAnAccountWithoutCredentials(t *testing.T) {
	cfg := config.Default().SFTP
	cfg.Basefolder = t.TempDir()
	users := []config.User{{Username: "john", SFTP: true}}
	if _, err := New(cfg, users, discardLogger()); err == nil {
		t.Error("an account with neither a password nor a key has to be refused")
	} else if !strings.Contains(err.Error(), "never log in") {
		t.Errorf("error = %v", err)
	}
}

func TestNewRejectsABrokenAuthorizedKey(t *testing.T) {
	cfg := config.Default().SFTP
	cfg.Basefolder = t.TempDir()
	users := []config.User{{Username: "john", SFTP: true, AuthorizedKeys: []string{"ssh-ed25519 not-a-key"}}}
	if _, err := New(cfg, users, discardLogger()); err == nil {
		t.Error("a malformed authorized key has to be refused at startup")
	}
}

func TestNewRejectsMissingFolders(t *testing.T) {
	cfg := config.Default().SFTP
	cfg.Basefolder = t.TempDir() + "/nope"
	if _, err := New(cfg, []config.User{fullUser("john", "doe")}, discardLogger()); err == nil {
		t.Error("a missing base folder has to be refused")
	}

	cfg = config.Default().SFTP
	cfg.Basefolder = t.TempDir()
	user := fullUser("john", "doe")
	user.Basefolder = t.TempDir() + "/nope"
	if _, err := New(cfg, []config.User{user}, discardLogger()); err == nil {
		t.Error("a missing user base folder has to be refused")
	}
}

func TestDuplicateAccountIsRejected(t *testing.T) {
	cfg := config.Default().SFTP
	cfg.Basefolder = t.TempDir()
	users := []config.User{fullUser("john", "doe"), fullUser("john", "other")}
	if _, err := New(cfg, users, discardLogger()); err == nil {
		t.Error("the same username twice has to be refused")
	}
}

// This is a file server: a session may ask for the sftp subsystem and nothing
// else.
func TestShellAndExecAreRefused(t *testing.T) {
	server := newServer(t, nil)
	client, err := dial(t, server, "john", ssh.Password("doe"))
	if err != nil {
		t.Fatal(err)
	}

	for _, run := range []struct {
		name string
		do   func(*ssh.Session) error
	}{
		{"shell", func(s *ssh.Session) error { return s.Shell() }},
		{"exec", func(s *ssh.Session) error { return s.Run("id") }},
	} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("%s: opening a session: %v", run.name, err)
		}
		if err := run.do(session); err == nil {
			t.Errorf("%s has to be refused", run.name)
		}
		_ = session.Close()
	}
}

func TestPerUserBasefolder(t *testing.T) {
	own := t.TempDir()
	server := newServer(t, func(cfg *sftpConfig) {
		user := fullUser("john", "doe")
		user.Basefolder = own
		cfg.Users = []config.User{user}
	})
	server.write(t, "theirs.txt", "theirs")
	if err := writeFile(own+"/mine.txt", "mine"); err != nil {
		t.Fatal(err)
	}

	client := login(t, server)
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "mine.txt" {
		t.Fatalf("the user has to see its own folder, got %v", names(entries))
	}
}

func TestMaxConnections(t *testing.T) {
	server := newServer(t, func(cfg *sftpConfig) { cfg.MaxConnections = 1 })

	first := login(t, server)
	if _, err := first.Getwd(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := dial(t, server, "john", ssh.Password("doe"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a second connection has to be refused")
		}
	case <-time.After(5 * time.Second):
		t.Error("the second connection was neither served nor refused")
	}
}

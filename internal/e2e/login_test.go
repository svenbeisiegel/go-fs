package e2e

import (
	"strings"
	"testing"

	"go-fs/internal/config"
)

func TestCredentialsAreCheckedOnEveryProtocol(t *testing.T) {
	c := newCluster(t, []config.User{account("john", "doe", allRights...)}, nil)

	for _, proto := range protocols {
		t.Run(proto.name, func(t *testing.T) {
			if _, err := proto.login(t, c, "john", "doe"); err != nil {
				t.Errorf("the right password was refused: %v", err)
			}
			// "doe " is left out: an FTP command line loses its trailing
			// spaces before the server sees it, so over FTP it is "doe"
			for _, wrong := range []struct{ name, password string }{
				{"john", "wrong"},
				{"john", ""},
				{"john", "DOE"},
				{"JOHN", "doe"},
				{"nobody", "doe"},
			} {
				if _, err := proto.login(t, c, wrong.name, wrong.password); err == nil {
					t.Errorf("%q/%q was let in", wrong.name, wrong.password)
				}
			}
		})
	}
}

// ftp, sftp and http switch an account on for one protocol each; an account
// that one of them leaves off does not exist there at all.
func TestProtocolSwitchesAreIndependent(t *testing.T) {
	only := func(name string, protocol string) config.User {
		user := account(name, "secret", allRights...)
		user.HTTP = protocol == "http"
		user.FTP = protocol == "ftp"
		user.SFTP = protocol == "sftp"
		return user
	}
	c := newCluster(t, []config.User{only("webonly", "http"), only("ftponly", "ftp"), only("sftponly", "sftp")}, nil)

	for _, user := range []string{"webonly", "ftponly", "sftponly"} {
		for _, proto := range protocols {
			want := strings.HasPrefix(user, proto.name) || (user == "webonly" && proto.name == "http")
			_, err := proto.login(t, c, user, "secret")
			if got := err == nil; got != want {
				t.Errorf("%s over %s: logged in=%v, want %v (err: %v)", user, proto.name, got, want, err)
			}
		}
	}
}

// An account without a password logs in over FTP by name alone when it sets
// allowLoginWithoutPassword, and not otherwise. SFTP and HTTP accounts must
// have a password (or an SFTP key), which Validate enforces.
func TestPasswordlessLoginIsExplicit(t *testing.T) {
	anonymous := config.User{Username: "anonymous", FTP: true,
		AllowLoginWithoutPassword: new(true), AllowUserFileRetrieve: new(true)}
	closed := config.User{Username: "closed", FTP: true, AllowUserFileRetrieve: new(true)}
	c := newCluster(t, []config.User{anonymous, closed}, nil)

	if _, err := loginFTP(t, c, "anonymous", ""); err != nil {
		t.Errorf("the passwordless account was refused: %v", err)
	}
	for _, password := range []string{"", "anything"} {
		if _, err := loginFTP(t, c, "closed", password); err == nil {
			t.Errorf("an account without a password and without the switch logged in with %q", password)
		}
	}

	cfg := c.cfg
	cfg.Users = []config.User{{Username: "web", HTTP: true, Paths: []string{"^/.*"}}}
	if err := cfg.Validate(); err == nil {
		t.Error("an http account without a password has to be refused by Validate")
	}
	cfg.Users = []config.User{{Username: "ssh", SFTP: true}}
	if err := cfg.Validate(); err == nil {
		t.Error("an sftp account with neither password nor key has to be refused by Validate")
	}
}

// A reload that takes a right away, or the whole account, applies to the
// sessions that are already open and not only to the next login: an operator
// who removes an account expects it gone.
func TestAReloadReachesOpenSessions(t *testing.T) {
	c := newCluster(t, []config.User{account("john", "doe", allRights...)}, nil)
	c.write(t, "/file.txt", seed)

	sessions := map[string]client{}
	for _, proto := range protocols {
		cl, err := proto.login(t, c, "john", "doe")
		if err != nil {
			t.Fatalf("%s login: %v", proto.name, err)
		}
		sessions[proto.name] = cl
	}
	token, err := loginHTTPSession(t, c, "john", "doe")
	if err != nil {
		t.Fatal(err)
	}
	sessions["http session token"] = token

	for name, cl := range sessions {
		if _, err := cl.get("/file.txt"); err != nil {
			t.Fatalf("%s before the reload: %v", name, err)
		}
	}

	c.reload(t, []config.User{account("john", "doe", without(retrieve)...)})
	for name, cl := range sessions {
		if _, err := cl.get("/file.txt"); err == nil {
			t.Errorf("%s still downloads after retrieve was taken away", name)
		}
		if err := cl.put("/still-there.txt", written); err != nil {
			t.Errorf("%s lost a right the reload kept: %v", name, err)
		}
		c.reset(t)
		c.write(t, "/file.txt", seed)
	}

	c.reload(t, []config.User{account("jane", "roe", allRights...)})
	for name, cl := range sessions {
		if err := cl.put("/after-removal.txt", written); err == nil {
			t.Errorf("%s still uploads after the account was removed", name)
		}
	}
	for _, proto := range protocols {
		if _, err := proto.login(t, c, "john", "doe"); err == nil {
			t.Errorf("%s: a removed account logged in", proto.name)
		}
	}
}

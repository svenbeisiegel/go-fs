package remote_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/remote"
	"go-fs/internal/remote/remotetest"
)

func sshConfig() config.SSH {
	return config.Default().General.SSH
}

func TestLoginIsChecked(t *testing.T) {
	login, err := remote.Login{Host: " [2001:db8::1] ", Username: " alice ", HostKey: "SHA256:x"}.Checked(false)
	if err != nil {
		t.Fatal(err)
	}
	if login.Type != config.ServerTypeSFTP || login.Host != "2001:db8::1" || login.Port != 22 || login.Username != "alice" {
		t.Errorf("the login reads %+v", login)
	}
	if login.Shown() != "[2001:db8::1]" || login.Address() != "[2001:db8::1]:22" {
		t.Errorf("the host is shown as %q at %q", login.Shown(), login.Address())
	}
	login.Port = 2222
	if login.Shown() != "[2001:db8::1]:2222" || login.Where("/in") != "sftp://[2001:db8::1]:2222/in" {
		t.Errorf("the host on another port is shown as %q, %q", login.Shown(), login.Where("/in"))
	}

	// the key alone needs no more than the host
	if _, err := (remote.Login{Host: "example.com"}).Checked(true); err != nil {
		t.Errorf("a key asked for alone was refused: %v", err)
	}
	for name, login := range map[string]remote.Login{
		"no host":          {Username: "u", HostKey: "SHA256:x"},
		"a URL":            {Host: "sftp://example.com", Username: "u", HostKey: "SHA256:x"},
		"a login in host":  {Host: "u@example.com", Username: "u", HostKey: "SHA256:x"},
		"a path in host":   {Host: "example.com/in", Username: "u", HostKey: "SHA256:x"},
		"a port too high":  {Host: "example.com", Port: 70000, Username: "u", HostKey: "SHA256:x"},
		"no username":      {Host: "example.com", HostKey: "SHA256:x"},
		"no key":           {Host: "example.com", Username: "u"},
		"another protocol": {Type: "gopher", Host: "example.com", Username: "u", HostKey: "SHA256:x"},
	} {
		if _, err := login.Checked(false); err == nil {
			t.Errorf("a login with %s was accepted", name)
		}
	}
}

func TestServerRoundTrips(t *testing.T) {
	server := config.Server{Name: "backup", Type: config.ServerTypeSFTP, Host: "example.com", Port: 2222,
		Username: "alice", Password: "secret", HostKeyFingerprint: "SHA256:x",
		VaultPath: "/vaults/team", VaultPassword: "pw"}
	login := remote.FromServer(server)
	if login.Server != "backup" {
		t.Errorf("the login of a server is named %q", login.Server)
	}
	if back := login.ConfigServer("backup"); !reflect.DeepEqual(back, server) {
		t.Errorf("the server came back as %+v", back)
	}
}

func TestHostKeyAndLogin(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	ctx := context.Background()
	login := remote.Login{Type: config.ServerTypeSFTP, Host: host.Host, Port: host.Port}

	keyType, fingerprint, err := remote.HostKey(ctx, login, sshConfig())
	if err != nil {
		t.Fatal(err)
	}
	if keyType != ssh.KeyAlgoED25519 || fingerprint != host.Fingerprint {
		t.Errorf("the host showed %s %s, want %s", keyType, fingerprint, host.Fingerprint)
	}
	if n := host.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered for the key alone", n)
	}

	login.Username, login.Password, login.HostKey = "alice", "secret", host.Fingerprint
	if err := remote.Test(ctx, login, sshConfig()); err != nil {
		t.Errorf("the right login failed: %v", err)
	}

	wrong := login
	wrong.Password = "wrong"
	if err := remote.Test(ctx, wrong, sshConfig()); err == nil || !strings.Contains(err.Error(), "refused the login of alice") {
		t.Errorf("a wrong password answered %v", err)
	}

	before := host.Logins.Load()
	other := login
	other.HostKey = "SHA256:somebodyElse"
	if err := remote.Test(ctx, other, sshConfig()); err == nil || !strings.Contains(err.Error(), "not the one that was accepted") {
		t.Errorf("another key answered %v", err)
	}
	other.Server = "backup"
	if err := remote.Test(ctx, other, sshConfig()); err == nil ||
		!strings.Contains(err.Error(), "an administrator has to edit the server") {
		t.Errorf("another key of a stored server answered %v", err)
	}
	if host.Logins.Load() != before {
		t.Error("a login was offered to a host with another key")
	}
}

func TestFailureNamesTheAlgorithms(t *testing.T) {
	login := remote.Login{Type: config.ServerTypeSFTP, Host: "example.com", Port: 22}
	err := remote.Failure(login, &ssh.AlgorithmNegotiationError{What: "key exchange",
		RequestedAlgorithms: []string{"diffie-hellman-group14-sha1"}})
	if !strings.Contains(err.Error(), "example.com offers no key exchange that general.ssh allows") ||
		!strings.Contains(err.Error(), "diffie-hellman-group14-sha1") {
		t.Errorf("the failure reads %v", err)
	}
	if err := remote.Failure(login, errors.New("connection refused")); err.Error() != "example.com: connection refused" {
		t.Errorf("another failure reads %v", err)
	}
}

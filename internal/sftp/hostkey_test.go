package sftp

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
)

// A configured host key is the one clients see, and it is the same after a
// restart. That is the whole point of configuring one.
func TestConfiguredHostKeyIsStable(t *testing.T) {
	encoded, public := newHostKey(t)
	want := ssh.FingerprintSHA256(public)

	for _, run := range []string{"first start", "restart"} {
		server := newServer(t, func(cfg *sftpConfig) { cfg.HostKey = encoded })

		var seen string
		client, err := ssh.Dial("tcp", server.Addr().String(), &ssh.ClientConfig{
			User: "john",
			Auth: []ssh.AuthMethod{ssh.Password("doe")},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				seen = ssh.FingerprintSHA256(key)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", run, err)
		}
		_ = client.Close()
		if seen != want {
			t.Errorf("%s: host key %s, want %s", run, seen, want)
		}
	}
}

// Without one a key is generated for the run, so two servers differ and the
// operator is warned about it.
func TestGeneratedHostKeyChangesAndWarns(t *testing.T) {
	first := newServer(t, nil)
	second := newServer(t, nil)

	if record := first.logs.find("no sftp.hostkey configured, generated a temporary host key; " +
		"it changes on every restart, so clients will report a changed host key"); record == nil {
		t.Error("a generated host key has to be reported")
	}

	if fingerprintOf(t, first) == fingerprintOf(t, second) {
		t.Error("two servers without a configured key must not share one")
	}
}

func fingerprintOf(t *testing.T, server *testServer) string {
	t.Helper()
	var seen string
	client, err := ssh.Dial("tcp", server.Addr().String(), &ssh.ClientConfig{
		User: "john",
		Auth: []ssh.AuthMethod{ssh.Password("doe")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(key)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	return seen
}

func TestParseHostKey(t *testing.T) {
	encoded, public := newHostKey(t)
	pem, err := config.DecodeHostKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	// base64 of the PEM, which is what the configuration documents
	signer, err := parseHostKey(encoded)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(public) {
		t.Error("the decoded key is not the one that was encoded")
	}

	// the PEM itself, for a key pasted into a multi-line string
	if _, err := parseHostKey(string(pem)); err != nil {
		t.Errorf("raw PEM has to be accepted too: %v", err)
	}

	// and base64 that a tool wrapped across lines
	wrapped := strings.Join([]string{encoded[:40], encoded[40:]}, "\n")
	if _, err := parseHostKey(wrapped); err != nil {
		t.Errorf("wrapped base64 has to be accepted: %v", err)
	}
}

func TestParseHostKeyReportsWhatIsWrong(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"not base64", "this is not base64!!", "neither base64 nor PEM"},
		{"base64 of something else", base64.StdEncoding.EncodeToString([]byte("hello")), "does not decode to a PEM"},
		{"a public key", base64.StdEncoding.EncodeToString([]byte("-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n")), "not a private key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseHostKey(tc.value)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

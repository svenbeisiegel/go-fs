package config

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEmptyAlgorithmListsAreTheSecureDefault(t *testing.T) {
	secure := ssh.SupportedAlgorithms()
	cfg := Default().General.SSH
	transport := cfg.Transport()
	for name, got := range map[string][2][]string{
		"keyExchanges":        {transport.KeyExchanges, secure.KeyExchanges},
		"ciphers":             {transport.Ciphers, secure.Ciphers},
		"macs":                {transport.MACs, secure.MACs},
		"publicKeyAlgorithms": {cfg.PublicKeyAuths(), secure.PublicKeyAuths},
		"hostKeyAlgorithms":   {cfg.HostKeys(), secure.HostKeys},
	} {
		if !slices.Equal(got[0], got[1]) {
			t.Errorf("%s = %v, want %v", name, got[0], got[1])
		}
	}
	for _, weak := range []string{ssh.InsecureKeyExchangeDH14SHA1, ssh.InsecureHMACSHA196, ssh.KeyAlgoRSA} {
		if slices.Contains(transport.KeyExchanges, weak) || slices.Contains(transport.MACs, weak) ||
			slices.Contains(cfg.PublicKeyAuths(), weak) || slices.Contains(cfg.HostKeys(), weak) {
			t.Errorf("%s is in the default", weak)
		}
	}
	if found := cfg.Insecure(); len(found) != 0 {
		t.Errorf("the default lists nothing insecure, Insecure = %v", found)
	}
}

func TestALegacyAlgorithmIsAcceptedAndReported(t *testing.T) {
	cfg := Default().General.SSH
	cfg.KeyExchanges = []string{ssh.KeyExchangeCurve25519, ssh.InsecureKeyExchangeDH14SHA1}
	cfg.PublicKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSA}
	if err := cfg.validate(); err != nil {
		t.Fatalf("a legacy algorithm may be listed: %v", err)
	}
	want := []string{
		"general.ssh.keyExchanges: " + ssh.InsecureKeyExchangeDH14SHA1,
		"general.ssh.publicKeyAlgorithms: " + ssh.KeyAlgoRSA,
	}
	if got := cfg.Insecure(); !slices.Equal(got, want) {
		t.Errorf("Insecure = %v, want %v", got, want)
	}
	// a list is taken as it is, in its order
	if got := cfg.Transport().KeyExchanges; !slices.Equal(got, cfg.KeyExchanges) {
		t.Errorf("keyExchanges = %v, want %v", got, cfg.KeyExchanges)
	}
}

func TestTheClientPrefersChaChaWithoutAESInstructions(t *testing.T) {
	saved := hasAESGCM
	defer func() { hasAESGCM = saved }()
	cfg := Default().General.SSH

	hasAESGCM = func() bool { return false }
	if got := cfg.ClientTransport().Ciphers; got[0] != ssh.CipherChaCha20Poly1305 || len(got) != len(ssh.SupportedAlgorithms().Ciphers) {
		t.Errorf("without AES instructions the ciphers are %v, want chacha20-poly1305 first", got)
	}
	// the server list is not reordered: there the client's order decides
	if got := cfg.Transport().Ciphers; !slices.Equal(got, ssh.SupportedAlgorithms().Ciphers) {
		t.Errorf("server ciphers = %v", got)
	}

	hasAESGCM = func() bool { return true }
	if got := cfg.ClientTransport().Ciphers; !slices.Equal(got, ssh.SupportedAlgorithms().Ciphers) {
		t.Errorf("with AES instructions the ciphers are %v, want the library's order", got)
	}

	// a list that is set is the operator's order, whatever the processor
	hasAESGCM = func() bool { return false }
	cfg.Ciphers = []string{ssh.CipherAES256GCM, ssh.CipherChaCha20Poly1305}
	if got := cfg.ClientTransport().Ciphers; !slices.Equal(got, cfg.Ciphers) {
		t.Errorf("a listed order was changed to %v", got)
	}
}

func TestTheBannerEndsEveryLineWithCRLF(t *testing.T) {
	cfg := Default().General.SSH
	if cfg.BannerText() != "" {
		t.Error("no banner by default")
	}
	cfg.Banner = []string{"one", "two"}
	if got := cfg.BannerText(); got != "one\r\ntwo\r\n" {
		t.Errorf("banner = %q", got)
	}
}

func TestTheSSHSectionIsDocumented(t *testing.T) {
	docs := TemplateDocs()
	if !strings.Contains(docs["general.ssh"], "2 MB") {
		t.Errorf("general.ssh = %q, want the window limit explained", docs["general.ssh"])
	}
	for _, key := range []string{"keyExchanges", "ciphers", "macs", "publicKeyAlgorithms", "hostKeyAlgorithms",
		"loginGraceTime", "maxAuthTries", "maxSessions", "maxConnectionsPerHost", "keepAliveInterval",
		"keepAliveCountMax", "maxPacketSize", "banner"} {
		if docs["general.ssh."+key] == "" {
			t.Errorf("general.ssh.%s has no description in the template", key)
		}
	}
}

func TestAFileWithoutTheSSHSectionGetsTheDefaults(t *testing.T) {
	path, _ := writeConfig(t, `
[ftp]
basefolder = "{{folder}}"

[tftp]
enabled = false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := Default().General.SSH; cfg.General.SSH.LoginGraceTime != want.LoginGraceTime ||
		cfg.General.SSH.MaxPacketSize != want.MaxPacketSize || cfg.General.SSH.KeepAliveInterval != want.KeepAliveInterval {
		t.Errorf("general.ssh = %+v, want the defaults %+v", cfg.General.SSH, want)
	}
}

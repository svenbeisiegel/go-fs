package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// authorizedKey is one line as ssh-keygen would write it, for a fresh key.
func authorizedKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func writeConfig(t *testing.T, body string) (path string, folder string) {
	t.Helper()
	folder = t.TempDir()
	path = filepath.Join(t.TempDir(), "go-fs.toml")
	body = strings.ReplaceAll(body, "{{folder}}", strings.ReplaceAll(folder, `\`, `\\`))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, folder
}

func TestLoadAppliesDefaults(t *testing.T) {
	path, _ := writeConfig(t, `
[ftp]
basefolder = "{{folder}}"
port = 2121

[tftp]
enabled = false
basefolder = "{{folder}}"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FTP.Port != 2121 {
		t.Errorf("port = %d, want 2121", cfg.FTP.Port)
	}
	// everything not mentioned keeps its default
	if cfg.FTP.PassiveMinPort != 1024 {
		t.Errorf("passiveMinPort = %d, want the default 1024", cfg.FTP.PassiveMinPort)
	}
	if cfg.FTP.IdleTimeout != 600 || cfg.FTP.MaxCommandLength != 4096 {
		t.Errorf("timeouts lost their defaults: %+v", cfg.FTP)
	}
	if cfg.FTP.AllowFtpBounce || cfg.FTP.AllowForeignDataConnection {
		t.Error("the protective defaults have to stay off")
	}
	if cfg.General.LogLevel != "info" || cfg.General.LogFormat != "text" {
		t.Errorf("log defaults lost: %+v", cfg.General)
	}
	if !cfg.HTTP.EnableAdminInterface {
		t.Error("the admin interface has to be on by default")
	}
	if !cfg.HTTP.EnableS3 {
		t.Error("the S3 API has to be on by default")
	}
	if cfg.HTTP.RegistryBaseFolder != "" {
		t.Error("the registry has to be off by default")
	}
	if !cfg.HTTP.RegistryAnonymousRead {
		t.Error("pulling from the registry has to be public by default")
	}
}

func TestUserPermissionDefaults(t *testing.T) {
	path, _ := writeConfig(t, `
[ftp]
basefolder = "{{folder}}"

[[users]]
username = "john"
password = "doe"
ftp = true

[[users]]
username = "jane"
ftp = true
allowLoginWithoutPassword = true
allowUserFileRetrieve = true

[tftp]
enabled = false
basefolder = "{{folder}}"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("got %d users, want 2", len(cfg.Users))
	}

	// an entry that sets nothing is granted nothing
	john := cfg.Users[0].Permissions()
	if john.FileCreate || john.FileRetrieve || john.FileOverwrite ||
		john.FileDelete || john.FolderCreate || john.FolderDelete {
		t.Errorf("john should have no permission by default: %+v", john)
	}
	if john.LoginNoPassword {
		t.Error("allowLoginWithoutPassword defaults to false")
	}

	// and what is granted explicitly is honoured
	jane := cfg.Users[1].Permissions()
	if !jane.LoginNoPassword {
		t.Error("jane should be allowed to log in without a password")
	}
	if !jane.FileRetrieve {
		t.Error("jane had allowUserFileRetrieve = true")
	}
	if jane.FileCreate {
		t.Error("jane's unset permissions stay false")
	}
}

func TestValidateRejectsBadConfiguration(t *testing.T) {
	folder := t.TempDir()
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"bad log level", func(c *Config) { c.General.LogLevel = "chatty" }, "general.logLevel"},
		{"bad log format", func(c *Config) { c.General.LogFormat = "xml" }, "general.logFormat"},
		{"admin without http", func(c *Config) {
			c.Users = []User{{Username: "root", Password: "x", FTP: true, IsAdmin: true}}
		}, "isAdmin but not http"},
		{"nothing enabled", func(c *Config) { c.FTP.Enabled = false; c.TFTP.Enabled = false }, "nothing to do"},
		{"ftp port", func(c *Config) { c.FTP.Port = 0 }, "ftp.port"},
		{"passive range reversed", func(c *Config) {
			c.FTP.PassiveMinPort = 50100
			c.FTP.PassiveMaxPort = 50000
		}, "is above ftp.passiveMaxPort"},
		{"passive port out of range", func(c *Config) { c.FTP.PassiveMaxPort = 70000 }, "ftp.passiveMaxPort"},
		{"active source port out of range", func(c *Config) { c.FTP.ActiveSourcePort = 70000 }, "ftp.activeSourcePort"},
		{"missing basefolder", func(c *Config) { c.FTP.Basefolder = filepath.Join(folder, "nope") }, "ftp.basefolder"},
		{"ftps port", func(c *Config) { c.FTPS.Enabled = true; c.FTPS.Port = 0 }, "ftps.port"},
		{"half a tls pair", func(c *Config) { c.FTPS.Enabled = true; c.FTPS.Cert = "cert.pem" }, "together"},
		{"user without name", func(c *Config) { c.Users = []User{{Password: "x", FTP: true}} }, "no username"},
		{"s3 without password", func(c *Config) {
			c.Users = []User{{Username: "keys", S3: true}}
		}, "no password, which s3 needs"},
		{"s3 access key with a slash", func(c *Config) {
			c.Users = []User{{Username: "team/keys", Password: "x", S3: true}}
		}, "S3 access key cannot hold a slash"},
		{"s3 paths", func(c *Config) {
			c.Users = []User{{Username: "keys", Password: "x", S3: true, Paths: []string{"("}}}
		}, "users[0].paths[0]"},
		{"user basefolder", func(c *Config) {
			c.Users = []User{{Username: "john", FTP: true, Basefolder: filepath.Join(folder, "nope")}}
		}, "users[0].basefolder"},
		{"sftp port", func(c *Config) { c.SFTP.Enabled = true; c.SFTP.Port = 0 }, "sftp.port"},
		{"sftp basefolder", func(c *Config) { c.SFTP.Enabled = true; c.SFTP.Basefolder = "" }, "sftp.basefolder"},
		{"sftp host key", func(c *Config) {
			c.SFTP.Enabled = true
			c.SFTP.Basefolder = folder
			c.SFTP.HostKey = "not a key"
		}, "sftp.hostkey"},
		{"broken authorized key", func(c *Config) {
			c.Users = []User{{Username: "max", SFTP: true, AuthorizedKeys: []string{
				"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample max@laptop",
			}}}
		}, "users[0].authorizedKeys[0]"},
		{"sftp account with no way in", func(c *Config) {
			c.Users = []User{{Username: "max", SFTP: true}}
		}, "never log in"},
		{"http port", func(c *Config) { c.HTTP.Enabled = true; c.HTTP.Port = 0 }, "http.port"},
		{"https port", func(c *Config) { c.HTTPS.Enabled = true; c.HTTPS.Port = 0 }, "https.port"},
		{"half an https pair", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTPS.Enabled = true
			c.HTTPS.Cert = "cert.pem"
		}, "together"},
		{"http basefolder", func(c *Config) { c.HTTP.Enabled = true }, "http.basefolder"},
		// an http account is checked whether or not http is enabled: the entry
		// is what is wrong, and it stays wrong on the day http is switched on
		{"http user without a password", func(c *Config) {
			c.Users = []User{{Username: "john", HTTP: true}}
		}, "no password"},
		{"broken user path pattern", func(c *Config) {
			c.Users = []User{{Username: "john", Password: "doe", HTTP: true, Paths: []string{"([bad"}}}
		}, "users[0].paths[0]"},
		{"token without a name", func(c *Config) {
			c.Tokens = []Token{{Hash: HashToken("a")}}
		}, "tokens[0] has no name"},
		{"token configured twice", func(c *Config) {
			c.Tokens = []Token{{Name: "ci", Hash: HashToken("a")}, {Name: "ci", Hash: HashToken("b")}}
		}, "tokens[1]: \"ci\" is configured twice"},
		{"token without a hash", func(c *Config) {
			c.Tokens = []Token{{Name: "ci"}}
		}, "hash has to be"},
		{"token hash that is not hex", func(c *Config) {
			c.Tokens = []Token{{Name: "ci", Hash: strings.Repeat("z", 64)}}
		}, "hash has to be"},
		{"two tokens with one hash", func(c *Config) {
			c.Tokens = []Token{{Name: "a", Hash: HashToken("x")}, {Name: "b", Hash: HashToken("x")}}
		}, "same hash"},
		{"token expiry", func(c *Config) {
			c.Tokens = []Token{{Name: "ci", Hash: HashToken("a"), Expires: "tomorrow"}}
		}, "RFC 3339"},
		{"broken token path pattern", func(c *Config) {
			c.Tokens = []Token{{Name: "ci", Hash: HashToken("a"), Paths: []string{"([bad"}}}
		}, "tokens[0].paths[0]"},
		{"broken protected path pattern", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.PathsRequireAuth = []string{"([bad"}
		}, "http.pathsRequireAuth[0]"},
		{"cleanup without a path", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.Cleanup = []Cleanup{{Keep: 3}}
		}, "http.cleanup[0] has no path"},
		{"ftp bind address", func(c *Config) { c.FTP.Address = "not-an-address" }, "ftp.address"},
		{"ftp passive address", func(c *Config) { c.FTP.PassiveAddress = "2001:db8::1" }, "ftp.passiveAddress"},
		{"ftp data timeout", func(c *Config) { c.FTP.DataTimeout = 0 }, "ftp.dataTimeout"},
		{"ftp transfer idle timeout", func(c *Config) { c.FTP.TransferIdleTimeout = -1 }, "ftp.transferIdleTimeout"},
		{"http bind address", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.Address = "nope"
		}, "http.address"},
		{"http session token lifetime", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.SessionTokenLifetime = 0
		}, "http.httpSessionTokenLifetime"},
		{"http session cap", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.SessionMaxLifetime = 0
		}, "http.httpSessionMaxLifetime"},
		{"http session token secret that is not base64", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.SessionTokenSecret = "not base64 at all!!"
		}, "http.httpSessionTokenSecret"},
		{"http session token secret that is too short", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.SessionTokenSecret = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}, "at least 32"},
		{"http login attempts negative", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.LoginAttempts = -1
		}, "http.loginAttempts"},
		{"http login lockout zero", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.LoginLockout = 0
		}, "http.loginLockout"},
		{"http trusted proxy that is not an address", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.TrustedProxies = []string{"10.0.0.0/8", "proxy.example"}
		}, "http.trustedProxies[1]"},
		{"sftp bind address", func(c *Config) {
			c.SFTP.Enabled = true
			c.SFTP.Basefolder = folder
			c.SFTP.Address = "nope"
		}, "sftp.address"},
		{"duplicate account", func(c *Config) {
			c.Users = []User{{Username: "john", FTP: true}, {Username: "john", FTP: true}}
		}, "configured twice"},
		// one name is one account whatever it logs in to, so the same name
		// cannot be listed once per server either
		{"duplicate account across servers", func(c *Config) {
			c.Users = []User{
				{Username: "john", Password: "a", FTP: true}, {Username: "john", Password: "b", HTTP: true},
			}
		}, "configured twice"},
		{"registry without password", func(c *Config) {
			c.Users = []User{{Username: "ci", Registry: true}}
		}, "no password, which registry needs"},
		{"registry username with a colon", func(c *Config) {
			c.Users = []User{{Username: "ci:bot", Password: "x", Registry: true}}
		}, "cannot hold a colon"},
		{"relative registry folder", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.RegistryBaseFolder = "registry"
		}, "http.registryBaseFolder \"registry\" has to be an absolute path"},
		{"missing registry folder", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.RegistryBaseFolder = filepath.Join(folder, "nope")
		}, "http.registryBaseFolder"},
		{"registry folder inside the served folder", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.RegistryBaseFolder = mkdir(t, folder, "registry")
		}, "overlaps ftp.basefolder"},
		{"registry folder is the served folder", func(c *Config) {
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = folder
			c.HTTP.RegistryBaseFolder = folder
		}, "overlaps"},
		{"registry folder holding the http folder", func(c *Config) {
			outer := t.TempDir()
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = mkdir(t, outer, "served")
			c.HTTP.RegistryBaseFolder = outer
		}, "overlaps http.basefolder"},
		{"registry folder inside an account's folder", func(c *Config) {
			own := t.TempDir()
			c.HTTP.Enabled = true
			c.HTTP.Basefolder = t.TempDir()
			c.Users = []User{{Username: "john", FTP: true, Basefolder: own}}
			c.HTTP.RegistryBaseFolder = mkdir(t, own, "registry")
		}, "overlaps users[0].basefolder"},
		{"tftp type", func(c *Config) { c.TFTP.Type = "sctp" }, "tftp.type"},
		{"tftp block size", func(c *Config) { c.TFTP.MaxBlockSize = 4 }, "tftp.maxBlockSize"},
		{"tftp maxTimeout below timeout", func(c *Config) { c.TFTP.Timeout = 30; c.TFTP.MaxTimeout = 10 }, "maxTimeout"},
		{"unknown cipher", func(c *Config) { c.General.SSH.Ciphers = []string{"aes128-gmc"} },
			`general.ssh.ciphers: "aes128-gmc" is not one of`},
		{"cipher listed twice", func(c *Config) {
			c.General.SSH.Ciphers = []string{"aes128-ctr", "aes128-ctr"}
		}, `general.ssh.ciphers lists "aes128-ctr" twice`},
		{"cipher in the key exchanges", func(c *Config) {
			c.General.SSH.KeyExchanges = []string{"aes128-ctr"}
		}, "general.ssh.keyExchanges"},
		{"unknown public key algorithm", func(c *Config) {
			c.General.SSH.PublicKeyAlgorithms = []string{"ssh-dss2"}
		}, "general.ssh.publicKeyAlgorithms"},
		{"no sessions", func(c *Config) { c.General.SSH.MaxSessions = 0 }, "general.ssh.maxSessions"},
		{"no auth tries", func(c *Config) { c.General.SSH.MaxAuthTries = 0 }, "general.ssh.maxAuthTries"},
		{"negative grace time", func(c *Config) { c.General.SSH.LoginGraceTime = -1 }, "general.ssh.loginGraceTime"},
		{"no keepalive count", func(c *Config) { c.General.SSH.KeepAliveCountMax = 0 }, "general.ssh.keepAliveCountMax"},
		{"small packet size", func(c *Config) { c.General.SSH.MaxPacketSize = 1024 }, "general.ssh.maxPacketSize"},
		{"large packet size", func(c *Config) { c.General.SSH.MaxPacketSize = 1 << 20 }, "general.ssh.maxPacketSize"},
		{"grace time within the failure delay", func(c *Config) {
			c.SFTP.Enabled = true
			c.SFTP.Basefolder = folder
			c.SFTP.LoginFailureDelay = 5
			c.General.SSH.LoginGraceTime = 5
		}, "general.ssh.loginGraceTime has to be longer than sftp.loginFailureDelay"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.FTP.Basefolder = folder
			cfg.TFTP.Basefolder = folder
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// mkdir makes a folder inside another and returns its path.
func mkdir(t *testing.T, parent, name string) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateAcceptsARegistryFolderOfItsOwn(t *testing.T) {
	parent := t.TempDir()
	cfg := Default()
	cfg.FTP.Basefolder = mkdir(t, parent, "served")
	cfg.TFTP.Basefolder = cfg.FTP.Basefolder
	cfg.HTTP.Enabled = true
	cfg.HTTP.Basefolder = cfg.FTP.Basefolder
	// a sibling whose name starts like the served folder's is not inside it
	cfg.HTTP.RegistryBaseFolder = mkdir(t, parent, "served-registry")
	cfg.Users = []User{{Username: "ci", Password: "secret", Registry: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if users := cfg.HTTPServerUsers(); len(users) != 1 || users[0].Username != "ci" {
		t.Errorf("a registry-only account is not handed to the http server: %+v", users)
	}
}

// An entry that switches no server on is not an error: it is an account kept
// without being served. And what one server needs is not asked of an account
// that does not log in to it.
func TestValidateAcceptsAccountsAsTheyAreMeant(t *testing.T) {
	folder := t.TempDir()
	cfg := Default()
	cfg.FTP.Basefolder = folder
	cfg.TFTP.Basefolder = folder
	cfg.Users = []User{
		{Username: "parked", Password: "x"},
		// no password is fine on ftp and sftp when a key is there, and on ftp
		// with anonymous login; only http insists on one
		{Username: "anonymous", FTP: true, AllowLoginWithoutPassword: new(true)},
		{Username: "keys", SFTP: true, AuthorizedKeys: []string{authorizedKey(t)}},
		{Username: "john", Password: "doe", FTP: true, SFTP: true, HTTP: true},
		// an admin is an http account
		{Username: "root", Password: "x", HTTP: true, IsAdmin: true},
		// an s3 account needs no http, and the same name may be on both
		{Username: "s3keys", Password: "x", S3: true},
		{Username: "both", Password: "x", HTTP: true, S3: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.FTPUsers(); len(got) != 2 || got[0].Username != "anonymous" || got[1].Username != "john" {
		t.Errorf("FTPUsers = %v", names(got))
	}
	if got := cfg.SFTPUsers(); len(got) != 2 || got[0].Username != "keys" {
		t.Errorf("SFTPUsers = %v", names(got))
	}
	if got := cfg.HTTPUsers(); len(got) != 3 || got[0].Username != "john" || got[1].Username != "root" {
		t.Errorf("HTTPUsers = %v", names(got))
	}
	if got := cfg.S3Users(); len(got) != 2 || got[0].Username != "s3keys" || got[1].Username != "both" {
		t.Errorf("S3Users = %v", names(got))
	}
	// the http server serves both, and tells them apart itself
	if got := cfg.HTTPServerUsers(); len(got) != 4 {
		t.Errorf("HTTPServerUsers = %v", names(got))
	}
}

func names(users []User) []string {
	found := make([]string, 0, len(users))
	for _, user := range users {
		found = append(found, user.Username)
	}
	return found
}

func TestTemplateRoundTrips(t *testing.T) {
	folder := t.TempDir()
	// the shipped template points at /srv, redirect it at a folder that exists
	body := strings.ReplaceAll(string(Template()), "/srv/files", strings.ReplaceAll(folder, `\`, `\\`))

	path := filepath.Join(t.TempDir(), "go-fs.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("the shipped template has to load: %v", err)
	}

	// the template has to state the defaults it documents
	defaults := Default()
	if cfg.FTP.Port != defaults.FTP.Port || cfg.FTP.PassiveMinPort != defaults.FTP.PassiveMinPort ||
		cfg.TFTP.MaxBlockSize != defaults.TFTP.MaxBlockSize || cfg.TFTP.MaxTimeout != defaults.TFTP.MaxTimeout {
		t.Error("the template disagrees with the built-in defaults")
	}

	// the template leaves every server on general.basefolder
	if cfg.General.Basefolder != folder {
		t.Errorf("general.basefolder = %q, want %q", cfg.General.Basefolder, folder)
	}
	for name, got := range map[string]string{
		"ftp":  cfg.FTP.Basefolder,
		"sftp": cfg.SFTP.Basefolder,
		"http": cfg.HTTP.Basefolder,
		"tftp": cfg.TFTP.Basefolder,
	} {
		if got != folder {
			t.Errorf("%s.basefolder = %q, want the general %q", name, got, folder)
		}
	}

	// and writing it back has to produce something that loads again
	out := filepath.Join(t.TempDir(), "written.toml")
	if err := Save(out, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(out)
	if err != nil {
		t.Fatalf("a saved configuration has to load again: %v", err)
	}
	if reloaded.FTP.Port != cfg.FTP.Port || reloaded.TFTP.MaxBlockSize != cfg.TFTP.MaxBlockSize {
		t.Error("values were lost writing the configuration back")
	}
}

func TestSaveKeepsExplicitUserFlags(t *testing.T) {
	folder := t.TempDir()
	cfg := Default()
	cfg.FTP.Basefolder = folder
	cfg.TFTP.Basefolder = folder
	yes := true
	cfg.Users = []User{{Username: "john", Password: "doe", FTP: true, AllowUserFileDelete: &yes}}

	path := filepath.Join(t.TempDir(), "saved.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	permissions := reloaded.Users[0].Permissions()
	if !permissions.FileDelete {
		t.Error("an explicit true was lost on the way through the file")
	}
	if permissions.FileCreate {
		t.Error("an unset permission should still deny after a round trip")
	}

	// a switch that is off and a key another server would read stay out of the
	// file, so an ftp account is written as an ftp account and nothing more
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, account, _ := strings.Cut(string(written), "[[users]]")
	account, _, _ = strings.Cut(account, "\n[")
	for _, unwanted := range []string{"sftp", "http", "paths", "cookie", "authorizedKeys", "registry"} {
		if strings.Contains(account, unwanted) {
			t.Errorf("the saved account mentions %q:\n%s", unwanted, account)
		}
	}
	if !reloaded.Users[0].FTP || reloaded.Users[0].SFTP || reloaded.Users[0].HTTP {
		t.Errorf("switches after a round trip: %+v", reloaded.Users[0])
	}

	cfg.Users = []User{{Username: "ci", Password: "secret", Registry: true}}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if reloaded, err = Load(path); err != nil {
		t.Fatal(err)
	}
	if !reloaded.Users[0].Registry {
		t.Error("registry = true was lost on the way through the file")
	}
}

func TestDecodeHostKey(t *testing.T) {
	// a real key, because the value is now parsed rather than only recognised
	encoded, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	decodedPEM, err := DecodeHostKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	pem := string(decodedPEM)

	for _, value := range []string{encoded, pem, encoded[:20] + "\n" + encoded[20:]} {
		decoded, err := DecodeHostKey(value)
		if err != nil {
			t.Fatalf("%.20q: %v", value, err)
		}
		if string(decoded) != strings.TrimSpace(pem) && string(decoded) != pem {
			t.Errorf("%.20q decoded to %q", value, decoded)
		}
	}

	for _, value := range []string{"", "not base64 !!", base64.StdEncoding.EncodeToString([]byte("hello"))} {
		if _, err := DecodeHostKey(value); err == nil {
			t.Errorf("%q has to be refused", value)
		}
	}
}

func TestGeneralBasefolderIsTheFallback(t *testing.T) {
	shared := t.TempDir()
	own := t.TempDir()
	path, _ := writeConfig(t, `
[general]
basefolder = "`+strings.ReplaceAll(shared, `\`, `\\`)+`"

[ftp]
basefolder = "`+strings.ReplaceAll(own, `\`, `\\`)+`"

[sftp]
enabled = true
port = 2222

[[sftp.users]]
username = "john"
password = "doe"

[tftp]
enabled = true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// a section that names its own folder keeps it
	if cfg.FTP.Basefolder != own {
		t.Errorf("ftp.basefolder = %q, want its own %q", cfg.FTP.Basefolder, own)
	}
	// the others fall back
	if cfg.SFTP.Basefolder != shared || cfg.TFTP.Basefolder != shared {
		t.Errorf("sftp %q and tftp %q should both be the general %q",
			cfg.SFTP.Basefolder, cfg.TFTP.Basefolder, shared)
	}
}

func TestGeneralBasefolderHasToBeAbsolute(t *testing.T) {
	cfg := Default()
	cfg.General.Basefolder = "relative/path"
	cfg.FTP.Basefolder = t.TempDir()
	cfg.TFTP.Basefolder = cfg.FTP.Basefolder
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error = %v, want one about an absolute path", err)
	}
}

// TestParseLeavesTheFallbackAlone is what the admin interface depends on:
// Parse says what the file says, and only Resolved hands the fallback out.
func TestParseLeavesTheFallbackAlone(t *testing.T) {
	folder := t.TempDir()
	cfg, err := Parse([]byte("[general]\nbasefolder = " + strconv.Quote(folder) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FTP.Basefolder != "" {
		t.Errorf("Parse resolved ftp.basefolder to %q", cfg.FTP.Basefolder)
	}
	if resolved := cfg.Resolved(); resolved.FTP.Basefolder != folder {
		t.Errorf("Resolved left ftp.basefolder as %q", resolved.FTP.Basefolder)
	}
	// the copy is not shared with the original
	if cfg.FTP.Basefolder != "" {
		t.Error("Resolved changed the configuration it was called on")
	}
}

// A password out of this project's own documentation is a password anyone can
// look up, so a configuration that still holds one says so before it serves.
func TestDocumentedPasswordsAreReported(t *testing.T) {
	cfg := Default()
	cfg.Users = []User{
		{Username: "john", Password: "doe", FTP: true},
		{Username: "jane", Password: "chosen", FTP: true},
		{Username: "max", Password: "mustermann", HTTP: true},
	}

	found := cfg.ExampleAccounts()
	if len(found) != 2 {
		t.Fatalf("found %v, want the two documented ones", found)
	}
	if !strings.Contains(found[0], "john") || !strings.Contains(found[1], "max") {
		t.Errorf("found %v", found)
	}

	// the shipped template has no live account at all, so it reports none
	template, err := Parse(Template())
	if err != nil {
		t.Fatal(err)
	}
	if got := template.ExampleAccounts(); len(got) != 0 {
		t.Errorf("the shipped template still has a documented password: %v", got)
	}
	if len(template.Users) != 0 {
		t.Errorf("the shipped template defines %d accounts, it should define none",
			len(template.Users))
	}
	if len(template.Tokens) != 0 {
		t.Errorf("the shipped template defines %d tokens, it should define none",
			len(template.Tokens))
	}
}

// A token is stored as its hash, and a valid token is accepted with its
// rights as granted and nothing more.
func TestTokens(t *testing.T) {
	plain, hash, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "gofs_") || hash != HashToken(plain) || !ValidTokenHash(hash) {
		t.Errorf("token %q hash %q", plain, hash)
	}
	if other, _, _ := GenerateToken(); other == plain {
		t.Error("two tokens came out the same")
	}

	yes := true
	token := Token{Name: "ci", Hash: hash, AllowUserFileRetrieve: &yes,
		Expires: "2030-01-02T03:04:05Z", Paths: []string{"^/.*"}}
	perms := token.Permissions()
	if !perms.FileRetrieve || perms.FileCreate || perms.FileDelete {
		t.Errorf("permissions %+v", perms)
	}
	if at, ok := token.ExpiresAt(); !ok || at.Year() != 2030 {
		t.Errorf("expires %v %v", at, ok)
	}
	if _, ok := (Token{}).ExpiresAt(); ok {
		t.Error("a token without an expiry expires")
	}

	cfg := Default()
	cfg.FTP.Basefolder = t.TempDir()
	cfg.TFTP.Basefolder = cfg.FTP.Basefolder
	cfg.Tokens = []Token{token}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a valid token was refused: %v", err)
	}
}

func TestServers(t *testing.T) {
	valid := Server{Name: "backup", Type: ServerTypeSFTP, Host: "sftp.example.com", Port: 2222,
		Username: "alice", Password: "secret", HostKeyFingerprint: "SHA256:abc"}
	check := func(servers ...Server) error {
		cfg := Default()
		cfg.FTP.Basefolder = t.TempDir()
		cfg.TFTP.Basefolder = cfg.FTP.Basefolder
		cfg.Servers = servers
		return cfg.Validate()
	}
	if err := check(valid); err != nil {
		t.Errorf("a valid server was refused: %v", err)
	}
	v6 := valid
	v6.Host, v6.Port = "2001:db8::1", 0
	if err := check(v6); err != nil {
		t.Errorf("an IPv6 server on the default port was refused: %v", err)
	}
	for name, change := range map[string]func(*Server){
		"no name":            func(s *Server) { s.Name = "" },
		"a name with spaces": func(s *Server) { s.Name = " backup" },
		"the name Manual":    func(s *Server) { s.Name = "manual" },
		"no type":            func(s *Server) { s.Type = "" },
		"an unknown type":    func(s *Server) { s.Type = "gopher" },
		"no host":            func(s *Server) { s.Host = "" },
		"a URL for a host":   func(s *Server) { s.Host = "sftp://sftp.example.com" },
		"a login in a host":  func(s *Server) { s.Host = "alice@sftp.example.com" },
		"a host in brackets": func(s *Server) { s.Host = "[2001:db8::1]" },
		"a port out of range": func(s *Server) {
			s.Port = 70000
		},
		"no username":    func(s *Server) { s.Username = "" },
		"no fingerprint": func(s *Server) { s.HostKeyFingerprint = "" },
	} {
		server := valid
		change(&server)
		if err := check(server); err == nil {
			t.Errorf("a server with %s was accepted", name)
		}
	}
	other := valid
	other.Name = "BACKUP"
	if err := check(valid, other); err == nil {
		t.Error("two servers of one name, in another case, were accepted")
	}

	if got, ok := FindServer([]Server{valid}, "Backup"); !ok || got != valid {
		t.Errorf("FindServer found %+v, %v", got, ok)
	}
	if _, ok := FindServer([]Server{valid}, "other"); ok {
		t.Error("FindServer found a server that is not there")
	}
	if host, err := RemoteHost(" [::1] "); err != nil || host != "::1" {
		t.Errorf("RemoteHost read %q, %v", host, err)
	}

	smb := Server{Name: "files", Type: ServerTypeSMB, Host: "files.example.com", Username: `CORP\alice`, Password: "secret"}
	if err := check(valid, smb); err != nil {
		t.Errorf("a valid SMB server without a fingerprint was refused: %v", err)
	}
	for name, change := range map[string]func(*Server){
		"no host":     func(s *Server) { s.Host = "" },
		"no username": func(s *Server) { s.Username = "" },
	} {
		server := smb
		change(&server)
		if err := check(server); err == nil {
			t.Errorf("an SMB server with %s was accepted", name)
		}
	}

	artifactory := Server{Name: "artifacts", Type: ServerTypeArtifactory,
		URL: "https://acme.jfrog.io/artifactory", Token: "secret"}
	if err := check(valid, artifactory); err != nil {
		t.Errorf("a valid Artifactory was refused: %v", err)
	}
	for name, change := range map[string]func(*Server){
		"no url":               func(s *Server) { s.URL = "" },
		"a url without scheme": func(s *Server) { s.URL = "acme.jfrog.io/artifactory" },
		"a url not read":       func(s *Server) { s.URL = "https://acme.jfrog.io" },
		"a url with a slash":   func(s *Server) { s.URL = "https://acme.jfrog.io/artifactory/" },
		"no token":             func(s *Server) { s.Token = " " },
	} {
		server := artifactory
		change(&server)
		if err := check(server); err == nil {
			t.Errorf("an Artifactory with %s was accepted", name)
		}
	}
}

// A server allows downloading unless it is switched off, and everything else
// only once it is switched on.
func TestServerRights(t *testing.T) {
	yes, no := true, false
	if got, want := (Server{}).Rights(), (ServerRights{Download: true}); got != want {
		t.Errorf("a server allows %+v by default, want %+v", got, want)
	}
	all := Server{AllowDownload: &no, AllowUpload: &yes, AllowCreate: &yes, AllowDelete: &yes, AllowRename: &yes}
	if got, want := all.Rights(), (ServerRights{Upload: true, Create: true, Delete: true, Rename: true}); got != want {
		t.Errorf("a server allows %+v, want %+v", got, want)
	}
}

func TestArtifactoryURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://acme.jfrog.io":                   "https://acme.jfrog.io/artifactory",
		" https://ACME.jfrog.io/ ":                "https://acme.jfrog.io/artifactory",
		"https://acme.jfrog.io/artifactory/":      "https://acme.jfrog.io/artifactory",
		"http://10.0.0.5:8082/artifactory":        "http://10.0.0.5:8082/artifactory",
		"https://proxy.example.com/repo/":         "https://proxy.example.com/repo",
		"https://[2001:db8::1]:8443/artifactory/": "https://[2001:db8::1]:8443/artifactory",
	} {
		if got, err := ArtifactoryURL(raw); err != nil || got != want {
			t.Errorf("ArtifactoryURL(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"", "acme.jfrog.io", "ftp://acme.jfrog.io", "https://", "https://alice:pw@acme.jfrog.io",
		"https://acme.jfrog.io/artifactory?x=1", "https://acme.jfrog.io/#top",
	} {
		if got, err := ArtifactoryURL(raw); err == nil {
			t.Errorf("ArtifactoryURL(%q) was read as %q", raw, got)
		}
	}
}

// go-fs.example.toml in the repository root is the same file the binary embeds
// and -init writes, which is what the README says it is. Nothing copies one to
// the other, so this is what stops them drifting apart — an example that still
// held live accounts after the template stopped would be worse than no example
// at all.
func TestTheExampleFileIsTheTemplate(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "go-fs.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(example, Template()) {
		t.Error("go-fs.example.toml and internal/config/template.toml have drifted apart; " +
			"copy the template over the example")
	}
}

// A file written for an older version still loads: a key no field claims is
// ignored rather than refused, and RetiredKeys is what tells its author.
func TestARetiredKeyIsStillAccepted(t *testing.T) {
	folder := t.TempDir()
	file := []byte("[general]\nbasefolder = " + strconv.Quote(folder) +
		"\n\n[http]\nenabled = true\nsessionTimeout = 86400\n")

	cfg, err := Parse(file)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Resolved().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.HTTP.SessionTokenLifetime != Default().HTTP.SessionTokenLifetime {
		t.Errorf("lifetime = %d, want the default %d",
			cfg.HTTP.SessionTokenLifetime, Default().HTTP.SessionTokenLifetime)
	}
}

// The accounts a file listed under its servers are not read any more. They are
// not refused either: the file loads with no accounts, and RetiredKeys says
// where they went.
func TestPerServerAccountsAreRetired(t *testing.T) {
	folder := t.TempDir()
	file := []byte("[general]\nbasefolder = " + strconv.Quote(folder) +
		"\n\n[[ftp.users]]\nusername = \"john\"\npassword = \"doe\"\n" +
		"\n[[http.users]]\nusername = \"max\"\npassword = \"mustermann\"\n")

	cfg, err := Parse(file)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Resolved().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(cfg.Users) != 0 {
		t.Errorf("Users = %v, want none: the old tables are not read", names(cfg.Users))
	}
	found := RetiredKeys(file)
	if len(found) != 2 {
		t.Fatalf("RetiredKeys = %v, want the two old tables", found)
	}
	if !strings.Contains(found[0], "ftp.users") || !strings.Contains(found[0], "[[users]]") ||
		!strings.Contains(found[1], "http.users") {
		t.Errorf("RetiredKeys = %q", found)
	}
}

func TestRetiredKeysAreReported(t *testing.T) {
	found := RetiredKeys([]byte("[http]\nsessionTimeout = 86400\n"))
	if len(found) != 1 {
		t.Fatalf("RetiredKeys = %v, want one entry", found)
	}
	if !strings.Contains(found[0], "http.sessionTimeout") ||
		!strings.Contains(found[0], "http.httpSessionTokenLifetime") {
		t.Errorf("RetiredKeys = %q, want it to name both the old and the new key", found[0])
	}
	// the [log] section and the admin listener moved, each key naming where to
	old := "[general]\nadminInterfaceEnabled = true\nadminUsername = \"admin\"\n[log]\nlevel = \"debug\"\n"
	found = RetiredKeys([]byte(old))
	if len(found) != 3 {
		t.Fatalf("RetiredKeys = %v, want three entries", found)
	}
	for _, want := range []string{
		"general.adminInterfaceEnabled is ignored, use http.enableAdminInterface",
		"general.adminUsername is ignored, use [[users]] with isAdmin = true",
		"log.level is ignored, use general.logLevel",
	} {
		if !strings.Contains(strings.Join(found, "\n"), want) {
			t.Errorf("RetiredKeys = %q, want %q", found, want)
		}
	}
	// [[users]] is an array of tables; a key set in any entry is reported once
	users := "[[users]]\nusername = \"john\"\ncookie = true\n" +
		"[[users]]\nusername = \"jane\"\ncookie = true\ncookiePath = \"/public/\"\n"
	found = RetiredKeys([]byte(users))
	if len(found) != 2 {
		t.Fatalf("RetiredKeys = %v, want two entries", found)
	}
	for _, want := range []string{"users.cookie is ignored", "users.cookiePath is ignored"} {
		if !strings.Contains(strings.Join(found, "\n"), want) {
			t.Errorf("RetiredKeys = %q, want %q", found, want)
		}
	}
	if found := RetiredKeys(Template()); len(found) != 0 {
		t.Errorf("the template sets a retired key: %v", found)
	}
	if found := RetiredKeys([]byte("this is not toml at all")); found != nil {
		t.Errorf("RetiredKeys of an unreadable file = %v, want nothing", found)
	}
}

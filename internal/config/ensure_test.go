package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// ensureIn writes body as a configuration file, ensures its generated secrets
// and returns what the file says afterwards.
func ensureIn(t *testing.T, body string) (Config, string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "go-fs.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	ensured, generated, err := EnsureSecrets(path, cfg)
	if err != nil {
		t.Fatalf("EnsureSecrets: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return ensured, string(written), generated
}

// rereadSecrets parses what was written and checks that it holds the secrets
// EnsureSecrets returned, each one usable.
func rereadSecrets(t *testing.T, written string, cfg Config) Config {
	t.Helper()
	reread, err := Parse([]byte(written))
	if err != nil {
		t.Fatalf("the written file does not parse: %v\n%s", err, written)
	}
	if reread.HTTP.ShareLinkSecret != cfg.HTTP.ShareLinkSecret ||
		reread.HTTP.SessionTokenSecret != cfg.HTTP.SessionTokenSecret {
		t.Errorf("the file holds other secrets than were returned:\n%s", written)
	}
	if len(cfg.HTTP.ShareLinkSecret) < MinShareSecret {
		t.Errorf("share secret = %q", cfg.HTTP.ShareLinkSecret)
	}
	if _, err := DecodeSessionSecret(cfg.HTTP.SessionTokenSecret); err != nil {
		t.Errorf("session secret %q: %v", cfg.HTTP.SessionTokenSecret, err)
	}
	return reread
}

func TestEnsureSecretsFillsTheEmptyKeys(t *testing.T) {
	body := "# top comment\n[http]\n# the key below\nshareLinkSecret = \"\"\nport = 9080\n" +
		"# and this one\nhttpSessionTokenSecret = \"\"\n\n[[users]]\nusername = \"john\"\n"
	cfg, written, generated := ensureIn(t, body)
	if !slices.Equal(generated, []string{"http.shareLinkSecret", "http.httpSessionTokenSecret"}) {
		t.Fatalf("generated = %v", generated)
	}
	want := strings.Replace(body, `shareLinkSecret = ""`,
		`shareLinkSecret = "`+cfg.HTTP.ShareLinkSecret+`"`, 1)
	want = strings.Replace(want, `httpSessionTokenSecret = ""`,
		`httpSessionTokenSecret = "`+cfg.HTTP.SessionTokenSecret+`"`, 1)
	if written != want {
		t.Errorf("the file is\n%s\nwant\n%s", written, want)
	}
	if reread := rereadSecrets(t, written, cfg); reread.HTTP.Port != 9080 {
		t.Errorf("port = %d", reread.HTTP.Port)
	}
}

func TestEnsureSecretsAddsTheKeysToTheSection(t *testing.T) {
	body := "[general]\nlogLevel = \"info\"\n\n[http] # served\nport = 9081\n\n[[http.cleanup]]\npath = \"/tmp\"\n"
	cfg, written, _ := ensureIn(t, body)
	if !strings.Contains(written, "[http] # served\n"+
		"httpSessionTokenSecret = \""+cfg.HTTP.SessionTokenSecret+"\"\n"+
		"shareLinkSecret = \""+cfg.HTTP.ShareLinkSecret+"\"\n"+
		"port = 9081\n") {
		t.Errorf("the keys are not the first of [http]:\n%s", written)
	}
	if reread := rereadSecrets(t, written, cfg); len(reread.HTTP.Cleanup) != 1 {
		t.Errorf("cleanup = %+v", reread.HTTP.Cleanup)
	}
}

func TestEnsureSecretsAppendsTheSection(t *testing.T) {
	body := "# only general\n[general]\nlogLevel = \"info\""
	cfg, written, _ := ensureIn(t, body)
	if !strings.HasPrefix(written, body+"\n") {
		t.Errorf("what was there changed:\n%s", written)
	}
	if strings.Count(written, "[http]") != 1 {
		t.Errorf("[http] was added more than once:\n%s", written)
	}
	if reread := rereadSecrets(t, written, cfg); reread.General.LogLevel != "info" {
		t.Errorf("logLevel = %q", reread.General.LogLevel)
	}
}

func TestEnsureSecretsInTheTemplate(t *testing.T) {
	cfg, written, generated := ensureIn(t, string(Template()))
	if len(generated) != 2 {
		t.Errorf("generated = %v", generated)
	}
	for _, key := range []string{"shareLinkSecret = ", "httpSessionTokenSecret = "} {
		if strings.Count(written, key) != 1 {
			t.Errorf("the template now sets %q %d times", key, strings.Count(written, key))
		}
	}
	rereadSecrets(t, written, cfg)
}

func TestEnsureSecretsLeavesSetSecretsAlone(t *testing.T) {
	session, err := GenerateSessionSecret()
	if err != nil {
		t.Fatal(err)
	}
	body := "[http]\nshareLinkSecret = \"" + strings.Repeat("s", 40) + "\"\n" +
		"httpSessionTokenSecret = \"" + session + "\"\n"
	cfg, written, generated := ensureIn(t, body)
	if generated != nil || written != body || cfg.HTTP.ShareLinkSecret != strings.Repeat("s", 40) ||
		cfg.HTTP.SessionTokenSecret != session {
		t.Errorf("generated = %v, file = %q", generated, written)
	}
}

// a file that set only one of them, as one written before the session secret
// was generated does, is given the other and keeps the one it has
func TestEnsureSecretsFillsOnlyTheMissingOne(t *testing.T) {
	body := "[http]\nshareLinkSecret = \"" + strings.Repeat("s", 40) + "\"\nhttpSessionTokenSecret = \"\"\n"
	cfg, written, generated := ensureIn(t, body)
	if !slices.Equal(generated, []string{"http.httpSessionTokenSecret"}) {
		t.Fatalf("generated = %v", generated)
	}
	if cfg.HTTP.ShareLinkSecret != strings.Repeat("s", 40) {
		t.Errorf("the share secret changed to %q", cfg.HTTP.ShareLinkSecret)
	}
	rereadSecrets(t, written, cfg)
}

func TestEnsureSecretsKeepsTheFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes")
	}
	path := filepath.Join(t.TempDir(), "go-fs.toml")
	if err := os.WriteFile(path, []byte("[http]\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureSecrets(path, Default()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}
}

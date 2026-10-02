package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ensureIn writes body as a configuration file, ensures its share secret and
// returns what the file says afterwards.
func ensureIn(t *testing.T, body string) (Config, string, bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "go-fs.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	ensured, generated, err := EnsureShareSecret(path, cfg)
	if err != nil {
		t.Fatalf("EnsureShareSecret: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return ensured, string(written), generated
}

func TestEnsureShareSecretFillsTheEmptyKey(t *testing.T) {
	body := "# top comment\n[http]\n# the key below\nshareLinkSecret = \"\"\nport = 9080\n\n[[users]]\nusername = \"john\"\n"
	cfg, written, generated := ensureIn(t, body)
	if !generated {
		t.Fatal("nothing was generated")
	}
	if len(cfg.HTTP.ShareLinkSecret) < MinShareSecret {
		t.Fatalf("secret = %q", cfg.HTTP.ShareLinkSecret)
	}
	want := strings.Replace(body, `shareLinkSecret = ""`,
		`shareLinkSecret = "`+cfg.HTTP.ShareLinkSecret+`"`, 1)
	if written != want {
		t.Errorf("the file is\n%s\nwant\n%s", written, want)
	}
	reread, err := Parse([]byte(written))
	if err != nil || reread.HTTP.ShareLinkSecret != cfg.HTTP.ShareLinkSecret || reread.HTTP.Port != 9080 {
		t.Errorf("reread = %+v, %v", reread.HTTP, err)
	}
}

func TestEnsureShareSecretAddsTheKeyToTheSection(t *testing.T) {
	body := "[general]\nlogLevel = \"info\"\n\n[http] # served\nport = 9081\n\n[[http.cleanup]]\npath = \"/tmp\"\n"
	cfg, written, _ := ensureIn(t, body)
	if !strings.Contains(written, "[http] # served\nshareLinkSecret = \""+cfg.HTTP.ShareLinkSecret+"\"\nport = 9081\n") {
		t.Errorf("the key is not the first of [http]:\n%s", written)
	}
	reread, err := Parse([]byte(written))
	if err != nil || reread.HTTP.ShareLinkSecret != cfg.HTTP.ShareLinkSecret || len(reread.HTTP.Cleanup) != 1 {
		t.Errorf("reread = %+v, %v", reread.HTTP, err)
	}
}

func TestEnsureShareSecretAppendsTheSection(t *testing.T) {
	body := "# only general\n[general]\nlogLevel = \"info\""
	cfg, written, _ := ensureIn(t, body)
	if !strings.HasPrefix(written, body+"\n") {
		t.Errorf("what was there changed:\n%s", written)
	}
	reread, err := Parse([]byte(written))
	if err != nil || reread.HTTP.ShareLinkSecret != cfg.HTTP.ShareLinkSecret || reread.General.LogLevel != "info" {
		t.Errorf("reread = %+v, %v", reread, err)
	}
}

func TestEnsureShareSecretInTheTemplate(t *testing.T) {
	cfg, written, _ := ensureIn(t, string(Template()))
	if strings.Count(written, "shareLinkSecret = ") != 1 {
		t.Errorf("the template now sets the key %d times", strings.Count(written, "shareLinkSecret = "))
	}
	reread, err := Parse([]byte(written))
	if err != nil || reread.HTTP.ShareLinkSecret != cfg.HTTP.ShareLinkSecret {
		t.Errorf("reread secret = %q, %v", reread.HTTP.ShareLinkSecret, err)
	}
}

func TestEnsureShareSecretLeavesASetSecretAlone(t *testing.T) {
	body := "[http]\nshareLinkSecret = \"" + strings.Repeat("s", 40) + "\"\n"
	cfg, written, generated := ensureIn(t, body)
	if generated || written != body || cfg.HTTP.ShareLinkSecret != strings.Repeat("s", 40) {
		t.Errorf("generated = %v, file = %q", generated, written)
	}
}

func TestEnsureShareSecretKeepsTheFileMode(t *testing.T) {
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
	if _, _, err := EnsureShareSecret(path, Default()); err != nil {
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

func TestShortShareSecretIsRefused(t *testing.T) {
	cfg := Default()
	cfg.HTTP.Basefolder = t.TempDir()
	cfg.HTTP.ShareLinkSecret = "short"
	if err := cfg.validateHTTP(); err == nil || !strings.Contains(err.Error(), "shareLinkSecret") {
		t.Errorf("validateHTTP = %v", err)
	}
	cfg.HTTP.ShareLinkSecret = strings.Repeat("x", MinShareSecret)
	if err := cfg.validateHTTP(); err != nil {
		t.Errorf("validateHTTP = %v", err)
	}
}

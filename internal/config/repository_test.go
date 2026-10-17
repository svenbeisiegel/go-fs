package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go-fs/internal/features"
)

// testSigningKey is the key the tests of internal/rpm sign with, as the file
// holds it.
func testSigningKey(t *testing.T) string {
	t.Helper()
	armored, err := os.ReadFile(filepath.Join("..", "rpm", "testdata", "foreign.asc"))
	if err != nil {
		t.Fatal(err)
	}
	return Encode(armored)
}

func TestRepositories(t *testing.T) {
	skipWithout(t, features.RPM)
	folder := t.TempDir()
	mkdir(t, folder, "rpm")
	mkdir(t, filepath.Join(folder, "rpm"), "inner")
	mkdir(t, folder, "other")
	key := testSigningKey(t)
	good := Repository{Name: "go-fs", Type: RepositoryTypeRPM, Folder: "/rpm", SigningKey: key, Keep: 5}

	valid := servingConfig(folder)
	valid.Repositories = []Repository{good, {Name: "other.repo", Type: "rpm", Folder: "/other", SigningKey: key,
		PollInterval: 10, URL: "https://files.example.com/other"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid repository is refused: %v", err)
	}

	cases := []struct {
		name   string
		change func(*Repository)
		want   string
	}{
		{"no name", func(r *Repository) { r.Name = "" }, "has no name"},
		{"a space in the name", func(r *Repository) { r.Name = "go fs" }, "letters, digits"},
		{"unknown type", func(r *Repository) { r.Type = "deb" }, `type "deb" is not one of rpm`},
		{"no folder", func(r *Repository) { r.Folder = "" }, "name the folder"},
		{"the top", func(r *Repository) { r.Folder = "/" }, "a folder of its own"},
		{"out of the served folder", func(r *Repository) { r.Folder = "/rpm/../.." }, "leaves the served folder"},
		{"not normalized", func(r *Repository) { r.Folder = "rpm/" }, `has to be "/rpm"`},
		{"missing folder", func(r *Repository) { r.Folder = "/missing" }, "missing"},
		{"no key", func(r *Repository) { r.SigningKey = "" }, "has no signingKey"},
		{"bad key", func(r *Repository) {
			r.SigningKey = Encode([]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxx\n-----END PGP PRIVATE KEY BLOCK-----\n"))
		}, "signingKey"},
		{"negative keep", func(r *Repository) { r.Keep = -1 }, "keep cannot be negative"},
		{"short interval", func(r *Repository) { r.PollInterval = 1 }, "at least 5 seconds"},
		{"bad url", func(r *Repository) { r.URL = "ftp://x" }, "https:// or http://"},
		{"url with a slash", func(r *Repository) { r.URL = "https://x/rpm/" }, `has to be "https://x/rpm"`},
	}
	for _, c := range cases {
		cfg := servingConfig(folder)
		repo := good
		c.change(&repo)
		cfg.Repositories = []Repository{repo}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}

	twice := servingConfig(folder)
	twice.Repositories = []Repository{good, good}
	twice.Repositories[1].Name = "GO-FS"
	twice.Repositories[1].Folder = "/other"
	if err := twice.Validate(); err == nil || !strings.Contains(err.Error(), "configured twice") {
		t.Errorf("a name twice: %v", err)
	}

	nested := servingConfig(folder)
	nested.Repositories = []Repository{good, good}
	nested.Repositories[1].Name = "inner"
	nested.Repositories[1].Folder = "/rpm/inner"
	if err := nested.Validate(); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("a repository inside another: %v", err)
	}
}

func TestRepositoryInterval(t *testing.T) {
	if got := (Repository{}).Interval(); got != DefaultPollInterval {
		t.Errorf("unset interval = %d", got)
	}
	if got := (Repository{PollInterval: 7}).Interval(); got != 7 {
		t.Errorf("interval = %d", got)
	}
}

func TestPGPKeyMaterial(t *testing.T) {
	skipWithout(t, features.RPM)
	key := testSigningKey(t)
	if _, err := Decode(KindPGPKey, key); err != nil {
		t.Fatal(err)
	}
	if got := Describe(KindPGPKey, key); !strings.HasPrefix(got, "RSA 2048 OpenPGP key ") {
		t.Errorf("describe = %q", got)
	}
	if got := Describe(KindPGPKey, Encode([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))); !strings.HasPrefix(got, "this value ") {
		t.Errorf("describe of something else = %q", got)
	}
}

// testJARKey is one signing key of an fdroid repository for every test,
// since making one takes a while.
var testJARKey = sync.OnceValues(func() (string, error) {
	key, _, err := Generate(KindJARKey, "test")
	return key, err
})

func TestFDroidRepositories(t *testing.T) {
	skipWithout(t, features.FDroid, features.RPM)
	folder := t.TempDir()
	mkdir(t, folder, "android/repo")
	key, err := testJARKey()
	if err != nil {
		t.Fatal(err)
	}
	good := Repository{Name: "android", Type: RepositoryTypeFDroid, Folder: "/android/repo", SigningKey: key,
		URL: "https://files.example.com/android/repo", Title: "Example apps", Icon: "/icon.png"}
	valid := servingConfig(folder)
	valid.Repositories = []Repository{good}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid fdroid repository is refused: %v", err)
	}

	cases := []struct {
		name   string
		change func(*Repository)
		want   string
	}{
		{"no url", func(r *Repository) { r.URL = "" }, "needs its url"},
		{"url not ending in /repo", func(r *Repository) { r.URL = "https://files.example.com/android" }, "end in /repo"},
		{"an OpenPGP key", func(r *Repository) { r.SigningKey = testSigningKey(t) }, "signingKey"},
		{"a long title", func(r *Repository) { r.Title = strings.Repeat("x", 51) }, "at most 50"},
		{"an icon out of the folder", func(r *Repository) { r.Icon = "/../icon.png" }, "leaves the served folder"},
		{"an icon that is no image", func(r *Repository) { r.Icon = "/icon.svg" }, ".png, .jpg or .webp"},
		{"title on rpm", func(r *Repository) { r.Type = RepositoryTypeRPM; r.SigningKey = testSigningKey(t) },
			"for an fdroid repository only"},
	}
	for _, c := range cases {
		cfg := servingConfig(folder)
		repo := good
		c.change(&repo)
		cfg.Repositories = []Repository{repo}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	if got := good.DisplayName(); got != "Example apps" {
		t.Errorf("display name %q", got)
	}
	if got := (Repository{Name: "android"}).DisplayName(); got != "android" {
		t.Errorf("display name without a title %q", got)
	}
}

func TestJARKeyMaterial(t *testing.T) {
	skipWithout(t, features.FDroid)
	key, err := testJARKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(KindJARKey, key); err != nil {
		t.Fatal(err)
	}
	if got := Describe(KindJARKey, key); !strings.HasPrefix(got, "RSA 4096 key, fingerprint ") {
		t.Errorf("describe = %q", got)
	}
	if _, err := Decode(KindJARKey, testSigningKey(t)); err == nil {
		t.Error("an OpenPGP key is taken for the key of an fdroid repository")
	}
	if SigningKeyKind(RepositoryTypeFDroid) != KindJARKey || SigningKeyKind(RepositoryTypeRPM) != KindPGPKey {
		t.Error("the kinds of signing key")
	}
}

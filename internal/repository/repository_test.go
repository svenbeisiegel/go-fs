package repository

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/rpm"
)

// fixtures are the packages internal/rpm builds its tests from. The key they
// are signed with, where they are, is the one these repositories sign with,
// so that a package that is signed already can be told from one that is not.
const fixtures = "../rpm/testdata"

func signingKey(t *testing.T) string {
	t.Helper()
	armored, err := os.ReadFile(filepath.Join(fixtures, "foreign.asc"))
	if err != nil {
		t.Fatal(err)
	}
	return config.Encode(armored)
}

func put(t *testing.T, folder, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(folder, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestRunner(t *testing.T, keep int) (*runner, string) {
	t.Helper()
	base := t.TempDir()
	folder := filepath.Join(base, "rpm")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := newRunner(config.Repository{
		Name: "test", Type: config.RepositoryTypeRPM, Folder: "/rpm",
		SigningKey: signingKey(t), Keep: keep, URL: "https://files.example.com/rpm",
	}, base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return r, folder
}

func listed(t *testing.T, folder string) []string {
	t.Helper()
	files, err := rpm.ReadRepomd(folder)
	if err != nil {
		t.Fatal(err)
	}
	hrefs, err := rpm.PrimaryOf(filepath.Join(folder, files["primary"]))
	if err != nil {
		t.Fatal(err)
	}
	return hrefs
}

func TestUpdateSignsAndLists(t *testing.T) {
	r, folder := newTestRunner(t, 0)
	path := put(t, folder, "hello-1.0-1.x86_64.rpm")
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := listed(t, folder); !slices.Equal(got, []string{"hello-1.0-1.x86_64.rpm"}) {
		t.Fatalf("listed %q", got)
	}
	f, err := rpm.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !f.SignedBy(r.kind.(*rpmKind).key) {
		t.Fatal("the package was not signed")
	}
	for _, name := range []string{"repodata/repomd.xml.asc", "repodata/repomd.xml.key", "test.repo"} {
		if _, err := os.Stat(filepath.Join(folder, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	definition, _ := os.ReadFile(filepath.Join(folder, "test.repo"))
	if !strings.Contains(string(definition), "baseurl=https://files.example.com/rpm\n") {
		t.Errorf("test.repo is\n%s", definition)
	}
}

func TestUpdateLeavesASignedPackageAlone(t *testing.T) {
	r, folder := newTestRunner(t, 0)
	path := put(t, folder, "hello-1.1-1.foreign.x86_64.rpm")
	before, _ := os.ReadFile(path)
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("a package signed with the repository's key was written anew")
	}
}

func TestUpdateWritesOnlyOnChange(t *testing.T) {
	r, folder := newTestRunner(t, 0)
	put(t, folder, "hello-1.0-1.x86_64.rpm")
	if err := r.update(time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(folder, "repodata", "repomd.xml"))
	if err := r.update(time.Unix(1700000100, 0)); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(folder, "repodata", "repomd.xml"))
	if string(first) != string(second) {
		t.Fatal("the metadata was written again with nothing changed")
	}

	put(t, folder, "tool-0.1-1.x86_64.rpm")
	if err := r.update(time.Unix(1700000200, 0)); err != nil {
		t.Fatal(err)
	}
	if got := listed(t, folder); len(got) != 2 {
		t.Fatalf("listed %q after adding one", got)
	}

	os.Remove(filepath.Join(folder, "hello-1.0-1.x86_64.rpm"))
	if err := r.update(time.Unix(1700000300, 0)); err != nil {
		t.Fatal(err)
	}
	if got := listed(t, folder); !slices.Equal(got, []string{"tool-0.1-1.x86_64.rpm"}) {
		t.Fatalf("listed %q after removing one", got)
	}

	// metadata someone removed is written again
	os.RemoveAll(filepath.Join(folder, "repodata"))
	if err := r.update(time.Unix(1700000400, 0)); err != nil {
		t.Fatal(err)
	}
	listed(t, folder)
}

func TestUpdateKeepsTheNewest(t *testing.T) {
	r, folder := newTestRunner(t, 2)
	for _, name := range []string{"hello-1.0-1.x86_64.rpm", "hello-2.0-1.x86_64.rpm", "hello-1.1-1.x86_64.rpm", "tool-0.1-1.x86_64.rpm"} {
		put(t, folder, name)
	}
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(folder, "hello-1.0-1.x86_64.rpm")); !os.IsNotExist(err) {
		t.Error("the oldest version is still there")
	}
	want := []string{"hello-1.1-1.x86_64.rpm", "hello-2.0-1.x86_64.rpm", "tool-0.1-1.x86_64.rpm"}
	if got := listed(t, folder); !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
}

func TestUpdateSkipsAnIncompletePackageUntilItIsWhole(t *testing.T) {
	r, folder := newTestRunner(t, 0)
	data, _ := os.ReadFile(filepath.Join(fixtures, "tool-0.1-1.x86_64.rpm"))
	path := filepath.Join(folder, "tool-0.1-1.x86_64.rpm")
	os.WriteFile(path, data[:len(data)/2], 0o644)
	put(t, folder, "hello-1.0-1.x86_64.rpm")

	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := listed(t, folder); !slices.Equal(got, []string{"hello-1.0-1.x86_64.rpm"}) {
		t.Fatalf("listed %q while one is still arriving", got)
	}
	if _, ok := r.skipped["tool-0.1-1.x86_64.rpm"]; !ok {
		t.Fatalf("the incomplete package is not reported: %v", r.skipped)
	}

	// the rest arrives
	os.WriteFile(path, data, 0o644)
	future := time.Now().Add(time.Minute)
	os.Chtimes(path, future, future)
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := listed(t, folder); len(got) != 2 {
		t.Fatalf("listed %q once it arrived", got)
	}
	if len(r.skipped) != 0 {
		t.Errorf("still skipped: %v", r.skipped)
	}
}

func TestUpdateLooksIntoSubfoldersButNotRepodata(t *testing.T) {
	r, folder := newTestRunner(t, 0)
	os.MkdirAll(filepath.Join(folder, "x86_64"), 0o755)
	os.MkdirAll(filepath.Join(folder, ".hidden"), 0o755)
	put(t, filepath.Join(folder, "x86_64"), "hello-1.0-1.x86_64.rpm")
	put(t, filepath.Join(folder, ".hidden"), "tool-0.1-1.x86_64.rpm")
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := listed(t, folder); !slices.Equal(got, []string{"x86_64/hello-1.0-1.x86_64.rpm"}) {
		t.Fatalf("listed %q", got)
	}
}

func TestManagerReportsAndReloads(t *testing.T) {
	base := t.TempDir()
	os.Mkdir(filepath.Join(base, "one"), 0o755)
	put(t, filepath.Join(base, "one"), "hello-1.0-1.x86_64.rpm")
	cfg := config.Config{
		HTTP: config.HTTP{Basefolder: base},
		Repositories: []config.Repository{{
			Name: "one", Type: config.RepositoryTypeRPM, Folder: "/one", SigningKey: signingKey(t),
		}},
	}
	m, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())

	waitFor(t, func() bool { return Statuses()["one"].Packages == 1 })

	// a change of keep restarts it; a repository taken out is forgotten
	cfg.Repositories[0].Keep = 3
	if err := m.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !Statuses()["one"].Checked.IsZero() })
	cfg.Repositories = nil
	if err := m.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := Statuses()["one"]; ok {
		t.Error("a repository taken out still reports")
	}
}

func waitFor(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

package vfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		cwd, arg string
		want     string
		escaped  bool
	}{
		{"/", "file.txt", "/file.txt", false},
		{"/", "/file.txt", "/file.txt", false},
		{"/sub/", "file.txt", "/sub/file.txt", false},
		{"/sub/", "/file.txt", "/file.txt", false},
		{"/", ".", "/", false},
		{"/", "./sub/.", "/sub", false},
		{"/sub/", "..", "/", false},
		{"/a/b/", "../c", "/a/c", false},
		{"/", "..", "/", true},
		{"/", "../../etc/passwd", "/", true},
		{"/a/", "../../b", "/", true},
		{"/", "sub//file", "/sub/file", false},
		{"/", "", "/", false},
	}
	for _, tc := range cases {
		got, escaped := Normalize(tc.cwd, tc.arg)
		if got != tc.want || escaped != tc.escaped {
			t.Errorf("Normalize(%q, %q) = (%q, %v), want (%q, %v)",
				tc.cwd, tc.arg, got, escaped, tc.want, tc.escaped)
		}
	}
}

func TestResolveStaysInsideBase(t *testing.T) {
	base := t.TempDir()
	root, err := New(base)
	if err != nil {
		t.Fatal(err)
	}

	inside := root.Resolve("/", "file.txt")
	if !inside.Valid {
		t.Errorf("a plain name should be valid, got %+v", inside)
	}
	if inside.Virtual != "/file.txt" {
		t.Errorf("virtual = %q, want /file.txt", inside.Virtual)
	}

	for _, arg := range []string{"../escape", "../../etc/passwd", "/../escape"} {
		if target := root.Resolve("/", arg); target.Valid {
			t.Errorf("%q should not be valid, got %+v", arg, target)
		}
	}
}

func TestContainsRefusesSymlinkOutOfBase(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(base, "link.txt")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "escape")); err != nil {
		t.Fatal(err)
	}

	root, err := New(base)
	if err != nil {
		t.Fatal(err)
	}

	if target := root.Resolve("/", "link.txt"); target.Valid {
		t.Error("a symlink pointing out of the base folder must not be valid")
	}
	// and a file that does not exist yet below a symlinked folder
	if target := root.Resolve("/", "escape/planted.txt"); target.Valid {
		t.Error("writing through a symlinked folder must not be valid")
	}
}

func TestContainsAllowsSymlinkInsideBase(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "real", "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	root, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if target := root.Resolve("/", "link/f.txt"); !target.Valid {
		t.Error("a symlink that stays inside the base folder should be valid")
	}
}

func TestResolveNewFileBelowMissingParents(t *testing.T) {
	base := t.TempDir()
	root, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	// nothing of a/b/c exists yet, it still has to resolve inside the base
	if target := root.Resolve("/", "a/b/c.txt"); !target.Valid {
		t.Errorf("a path below missing folders should be valid, got %+v", target)
	}
}

func TestNewRejectsMissingBase(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("a missing base folder should be an error")
	}
	if _, err := New(""); err == nil {
		t.Error("an empty base folder should be an error")
	}
}

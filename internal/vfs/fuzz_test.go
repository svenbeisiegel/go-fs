package vfs

import (
	"path/filepath"
	"strings"
	"testing"
)

func FuzzNormalize(f *testing.F) {
	for _, seed := range [][2]string{
		{"/", "file.txt"}, {"/sub/", "../x"}, {"/", "../../etc/passwd"},
		{"/a/b/", "./c/../d"}, {"/", "//a///b//"}, {"/", `..\..\x`}, {"", ""},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, cwd, arg string) {
		virtual, escaped := Normalize(cwd, arg)
		if !strings.HasPrefix(virtual, "/") {
			t.Fatalf("Normalize(%q, %q) = %q, not absolute", cwd, arg, virtual)
		}
		if escaped && virtual != "/" {
			t.Fatalf("an escape has to answer the root, got %q", virtual)
		}
		if virtual != "/" {
			for _, segment := range strings.Split(virtual[1:], "/") {
				if segment == "" || segment == "." || segment == ".." {
					t.Fatalf("Normalize(%q, %q) = %q keeps segment %q", cwd, arg, virtual, segment)
				}
			}
		}
		// a normalized path is its own normal form, wherever it is resolved from
		for _, from := range []string{"/", cwd} {
			again, escapedAgain := Normalize(from, virtual)
			if again != virtual || escapedAgain {
				t.Fatalf("Normalize(%q, %q) = (%q, %v), want (%q, false)",
					from, virtual, again, escapedAgain, virtual)
			}
		}
	})
}

func FuzzResolve(f *testing.F) {
	for _, seed := range []string{"file.txt", "../escape", "/a/../../b", "a/./b", `a\..\..\b`, "x::$DATA"} {
		f.Add(seed)
	}
	root, err := New(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, arg string) {
		if strings.ContainsRune(arg, 0) {
			// no filesystem accepts a NUL in a name, and the servers never
			// get one through their protocol parsers
			return
		}
		target := root.Resolve("/", arg)
		if !target.Valid {
			return
		}
		if !root.Contains(target.Path) {
			t.Fatalf("Resolve(%q) is valid, but %q is outside the base", arg, target.Path)
		}
		if target.Path != root.Base() && !strings.HasPrefix(target.Path, root.Base()+string(filepath.Separator)) {
			t.Fatalf("Resolve(%q).Path = %q does not start with the base %q", arg, target.Path, root.Base())
		}
	})
}

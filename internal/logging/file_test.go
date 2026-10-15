package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file is rotated before a record would take it past MaxSize, and no more
// than Keep rotated files are kept.
func TestFileRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "go-fs.log")
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.MaxSize = 20
	f.Keep = 2

	for _, record := range []string{"one 456789\n", "two 456789\n", "three 789\n", "four 6789\n", "five 6789\n"} {
		if _, err := f.Write([]byte(record)); err != nil {
			t.Fatal(err)
		}
	}

	for name, want := range map[string]string{
		"go-fs.log":   "five 6789\n",
		"go-fs.log.1": "three 789\nfour 6789\n",
		"go-fs.log.2": "two 456789\n",
	} {
		got, err := os.ReadFile(filepath.Join(filepath.Dir(path), name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("a third rotated file was kept: %v", err)
	}
}

// A file that is there already is appended to, and its size counts towards
// the next rotation.
func TestFileAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go-fs.log")
	if err := os.WriteFile(path, []byte("earlier\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	logger := NewTo(f, "info", "text")
	logger.Info("later")
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "earlier\n") || !strings.Contains(string(got), "msg=later") {
		t.Errorf("file = %q", got)
	}
	if _, err := f.Write([]byte("closed")); err == nil {
		t.Error("a closed file accepted a write")
	}
}

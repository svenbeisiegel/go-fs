package cleanup

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go-fs/internal/config"
)

func TestCleanupKeepsTheNewest(t *testing.T) {
	base := t.TempDir()
	for i, name := range []string{"old3.iso", "old2.iso", "old1.iso", "new2.iso", "new1.iso"} {
		path := filepath.Join(base, "iso", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(time.Duration(i-10) * time.Hour)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}

	sweeper, err := New(config.General{
		Basefolder: base,
		Cleanup:    []config.Cleanup{{Path: "/iso", Keep: 2}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	sweeper.sweepOnce()

	left, err := os.ReadDir(filepath.Join(base, "iso"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 2 {
		t.Fatalf("%d files left, want 2", len(left))
	}
	kept := map[string]bool{left[0].Name(): true, left[1].Name(): true}
	if !kept["new1.iso"] || !kept["new2.iso"] {
		t.Errorf("the wrong files were kept: %v", kept)
	}
}

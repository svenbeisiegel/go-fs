package config

import (
	"testing"

	"go-fs/internal/features"
)

// skipWithout skips a test of parts of go-fs the binary was built without,
// go-fs-light for one.
func skipWithout(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if !features.Has(name) {
			t.Skipf("built without %s", name)
		}
	}
}

// generateHostKey makes an SSH host key, and skips a test in a binary that
// speaks no SSH, which knows no host key.
func generateHostKey(t *testing.T) string {
	t.Helper()
	key, known, err := Generate(KindSSHKey, "")
	if !known {
		t.Skip("built without SSH")
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

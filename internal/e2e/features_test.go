//go:build !light && !no_ftp && !no_sftpd && !no_sftp_remote

package e2e

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

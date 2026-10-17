package repository

import (
	"fmt"
	"log/slog"
	"time"

	"go-fs/internal/config"
)

// kind is what one type of repository knows: which files are its packages,
// how to read them, and the metadata it writes of them. The runner does the
// rest alike for every type: it looks at the folder, reads a package once,
// prunes the old versions and writes the metadata when something changed.
type kind interface {
	// keyID names the key the repository signs with, in the log.
	keyID() string
	// isPackage reports whether a file is a package, by its name.
	isPackage(name string) bool
	// skipDir reports a folder that is not looked into, by its path in the
	// repository with forward slashes; the metadata, for one.
	skipDir(rel string) bool
	// open reads and checks the package at path.
	open(path string) (release, error)
	// admit makes a package that stays in the repository ready to be
	// listed, the one at href that open read.
	admit(r release, href string) (entry, error)
	// inputs identifies what else the metadata is made of than the
	// packages, "" when nothing.
	inputs(entries []entry) string
	// write writes the metadata of entries.
	write(entries []entry, now time.Time) error
	// written reports whether the metadata is still in the folder, which
	// someone may have removed since it was written.
	written() bool
}

// release is a version of a package, as the runner prunes them.
type release interface {
	// group is the same for the versions of one package.
	group() string
	// version is how the log shows the version.
	version() string
	// compare orders two versions of one package, the older first.
	compare(other release) int
}

// entry is a package the metadata lists.
type entry interface {
	release
	// listing identifies the package as the metadata lists it, so that
	// the metadata is written only when it changed.
	listing() string
}

// newKind makes the kind of repo, which is in folder.
func newKind(repo config.Repository, folder string, logger *slog.Logger) (kind, Status, error) {
	make, ok := kinds[repo.Type]
	if !ok {
		return nil, Status{}, fmt.Errorf("type %q is not one this binary was built with", repo.Type)
	}
	return make(repo, folder, logger)
}

// kinds make the kinds of repository the binary was built with, by their
// type. Each adds itself from a file of its own, kind_rpm.go and
// kind_fdroid.go, which a build tag leaves out together with the modules the
// kind imports.
var kinds = map[string]func(repo config.Repository, folder string, logger *slog.Logger) (kind, Status, error){}

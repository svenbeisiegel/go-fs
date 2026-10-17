// Package features says which of the optional parts of go-fs this binary was
// built with. Each part is left out by a build tag of its own, no_tftp and the
// like, or all at once by the tag light, which builds go-fs-light: the file of
// a part that is left out is not compiled, so neither its code nor the
// modules it imports end up in the binary.
//
// The files of this package that carry the tags only switch the name of their
// part on; the code of the part lives in its own package, behind the same tag.
// Whatever has to know whether a part is there, the validation of the
// configuration, the admin interface, the version, asks here.
package features

import (
	"slices"
	"sort"
	"strings"
)

// The optional parts, by the name the version and the log show.
const (
	// TFTP is the TFTP server.
	TFTP = "tftp"
	// FTP is the FTP server, with FTPS, which is the same server over TLS.
	FTP = "ftp"
	// SFTP is the SFTP server.
	SFTP = "sftp"
	// SFTPRemote is sending files to, and browsing, other hosts by SFTP.
	SFTPRemote = "sftp-remote"
	// SMB is sending files to, and browsing, other hosts by SMB.
	SMB = "smb"
	// RPM is the rpm-md package repository.
	RPM = "rpm"
	// FDroid is the F-Droid package repository.
	FDroid = "fdroid"
)

// built holds the parts this binary has. It is filled by the init functions
// of the tagged files, which run before any package that imports this one
// asks.
var built = map[string]bool{}

func enable(name string) { built[name] = true }

// Has reports whether the binary was built with a part.
func Has(name string) bool { return built[name] }

// SSH reports whether the binary speaks SSH at all, as the SFTP server and
// sending by SFTP do; general.ssh and the authorized keys of a user mean
// nothing without either.
func SSH() bool { return Has(SFTP) || Has(SFTPRemote) }

// Any reports whether the binary has one of the parts a comma separated list
// names, as the feature tag of a field of the configuration lists them. An
// empty list is every binary.
func Any(list string) bool {
	if list == "" {
		return true
	}
	for name := range strings.SplitSeq(list, ",") {
		if Has(strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// List is the parts the binary has, sorted.
func List() []string {
	names := make([]string, 0, len(built))
	for name := range built {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All is every optional part there is, whether built or not.
func All() []string {
	all := []string{TFTP, FTP, SFTP, SFTPRemote, SMB, RPM, FDroid}
	return slices.Sorted(slices.Values(all))
}

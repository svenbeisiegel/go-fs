package config

import (
	"fmt"

	"go-fs/internal/features"
)

// Ignored names what the file switches on that the binary was built without,
// go-fs-light reading the file of go-fs for one: the servers, the stored
// servers and the repositories it leaves alone. None of it stops the file from
// loading; it is said once at startup, so that nobody waits for a server that
// is not there.
func (c Config) Ignored() []string {
	var ignored []string
	if (c.FTP.Enabled || c.FTPS.Enabled) && !features.Has(features.FTP) {
		ignored = append(ignored, "ftp and ftps")
	}
	if c.SFTP.Enabled && !features.Has(features.SFTP) {
		ignored = append(ignored, "sftp")
	}
	if c.TFTP.Enabled && !features.Has(features.TFTP) {
		ignored = append(ignored, "tftp")
	}
	for i, server := range c.Servers {
		if absentServerType(server.Type) {
			ignored = append(ignored, fmt.Sprintf("servers[%d] %q of type %s", i, server.Name, server.Type))
		}
	}
	for i, repo := range c.Repositories {
		if absentRepositoryType(repo.Type) {
			ignored = append(ignored, fmt.Sprintf("repositories[%d] %q of type %s", i, repo.Name, repo.Type))
		}
	}
	return ignored
}

// AbsentServers are the servers of the file whose protocol the binary was
// built without, which it neither offers nor lets anybody edit, and keeps in
// the file as they are when it writes the file.
func (c Config) AbsentServers() []Server {
	var absent []Server
	for _, s := range c.Servers {
		if absentServerType(s.Type) {
			absent = append(absent, s)
		}
	}
	return absent
}

// AbsentRepositories are what AbsentServers is for the repositories.
func (c Config) AbsentRepositories() []Repository {
	var absent []Repository
	for _, repo := range c.Repositories {
		if absentRepositoryType(repo.Type) {
			absent = append(absent, repo)
		}
	}
	return absent
}

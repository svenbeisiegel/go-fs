//go:build !light && !no_sftp_remote

package features

// Sending by SFTP is left out by the tag no_sftp_remote, and by light.
func init() { enable(SFTPRemote) }

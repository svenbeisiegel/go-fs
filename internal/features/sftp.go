//go:build !light && !no_sftpd

package features

// The SFTP server is left out by the tag no_sftpd, and by light.
func init() { enable(SFTP) }

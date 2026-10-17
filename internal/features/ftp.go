//go:build !light && !no_ftp

package features

// The FTP and FTPS server is left out by the tag no_ftp, and by light.
func init() { enable(FTP) }

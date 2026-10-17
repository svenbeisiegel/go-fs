//go:build !light && !no_tftp

package features

// The TFTP server is left out by the tag no_tftp, and by light.
func init() { enable(TFTP) }

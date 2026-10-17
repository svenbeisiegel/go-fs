//go:build !light && !no_smb

package features

// Sending by SMB is left out by the tag no_smb, and by light.
func init() { enable(SMB) }

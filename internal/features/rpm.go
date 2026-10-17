//go:build !light && !no_rpm

package features

// The rpm repository is left out by the tag no_rpm, and by light.
func init() { enable(RPM) }

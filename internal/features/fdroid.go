//go:build !light && !no_fdroid

package features

// The F-Droid repository is left out by the tag no_fdroid, and by light.
func init() { enable(FDroid) }

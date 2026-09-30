//go:build windows

package supervisor

import "os"

// hangupSignals is empty on Windows, which has no hangup: there the file is
// polled and nothing else.
func hangupSignals() []os.Signal {
	return nil
}

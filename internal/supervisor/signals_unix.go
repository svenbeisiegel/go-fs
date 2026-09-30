//go:build !windows

package supervisor

import (
	"os"
	"syscall"
)

// hangupSignals is what asks for a reload on demand.
func hangupSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP}
}

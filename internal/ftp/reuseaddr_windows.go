//go:build windows

package ftp

import "syscall"

// reuseAddr asks for SO_REUSEADDR before the socket is bound, which is what
// makes ftp.activeSourcePort usable at all. See reuseaddr_unix.go for why the
// option is needed.
//
// Windows reads SO_REUSEADDR more loosely than unix does: it lets another
// process bind an address this one is already using, rather than only reusing
// what is left over. That matters for a listener, which could be taken over;
// this is set on the outgoing data socket alone, and never on a listener.
func reuseAddr(_, _ string, c syscall.RawConn) error {
	var setErr error
	if err := c.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return setErr
}

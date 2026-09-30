//go:build !windows

package ftp

import "syscall"

// reuseAddr asks for SO_REUSEADDR before the socket is bound, which is what
// makes ftp.activeSourcePort usable at all.
//
// A fixed source port collides with itself twice over: two transfers running at
// the same time both want to bind it, and one starting within the TIME_WAIT of
// the last connection to the same client wants a socket the kernel is still
// holding. SO_REUSEADDR permits both, since the connections differ in their
// remote end and so remain distinct.
func reuseAddr(_, _ string, c syscall.RawConn) error {
	var setErr error
	if err := c.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return setErr
}

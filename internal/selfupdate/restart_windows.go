package selfupdate

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Restart starts the executable as a new process with the same arguments and
// returns, after which main exits. Windows has no exec: the new process has a
// PID of its own, and whatever started this one sees it end. It stays in this
// console and its process group, so Ctrl+C in a terminal still stops it.
func (u *Updater) Restart() error {
	cmd := exec.Command(u.exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// errorSharingViolation is ERROR_SHARING_VIOLATION, which syscall does not
// name.
const errorSharingViolation syscall.Errno = 32

// renameRetry is how long a rename is retried. A virus scanner opens a new
// executable to look at it the moment it is written, and holds it for a
// moment; a rename in that moment fails with a sharing violation or access
// denied, and succeeds once the scanner lets go.
var renameRetry = 5 * time.Second

func rename(from, to string) error {
	deadline := time.Now().Add(renameRetry)
	for {
		err := os.Rename(from, to)
		if err == nil || time.Now().After(deadline) ||
			!(errors.Is(err, errorSharingViolation) || errors.Is(err, syscall.ERROR_ACCESS_DENIED)) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

//go:build !windows

package main

// start runs go-fs. Outside Windows a service manager such as systemd runs it
// as it runs any other program, and stops it with SIGTERM.
func start() error {
	return run(nil)
}

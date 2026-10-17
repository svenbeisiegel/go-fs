package remote_test

import "go-fs/internal/config"

// sshConfig is the SSH transport of a default configuration.
func sshConfig() config.SSH {
	return config.Default().General.SSH
}

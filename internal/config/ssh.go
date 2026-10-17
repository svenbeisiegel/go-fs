package config

import (
	"errors"
	"fmt"
	"strings"
)

// MinSFTPPacketSize and MaxSFTPPacketSize bound general.ssh.maxPacketSize. The
// lower one is what every SFTP implementation has to accept; the upper one
// leaves room for the packet header inside the largest message pkg/sftp reads.
const (
	MinSFTPPacketSize = 32768
	MaxSFTPPacketSize = 261120
)

// What [general.ssh] says of algorithms only golang.org/x/crypto/ssh knows to
// check, and only a binary that speaks SSH imports it: ssh_algorithms.go, which
// a build tag leaves out with the SFTP server and sending by SFTP, sets these.
// Without it there is nothing to check, nothing insecure and no host key or
// authorized key to read.
var (
	// checkSSHAlgorithms reports an algorithm list that names something the
	// library does not know, or names it twice.
	checkSSHAlgorithms = func(SSH) error { return nil }
	// insecureSSHAlgorithms is what Insecure reports.
	insecureSSHAlgorithms = func(SSH) []string { return nil }
	// checkAuthorizedKey reports an entry of authorizedKeys that is not a
	// key.
	checkAuthorizedKey = func(string) error { return nil }
)

func (s SSH) validate() error {
	// the library ignores a name it does not know, so a typo would quietly
	// take an algorithm away; it is reported here instead
	if err := checkSSHAlgorithms(s); err != nil {
		return err
	}
	if s.LoginGraceTime < 0 {
		return errors.New("general.ssh.loginGraceTime cannot be negative")
	}
	if s.MaxAuthTries < 1 {
		return errors.New("general.ssh.maxAuthTries has to be at least 1")
	}
	if s.MaxSessions < 1 {
		return errors.New("general.ssh.maxSessions has to be at least 1")
	}
	if s.MaxConnectionsPerHost < 0 {
		return errors.New("general.ssh.maxConnectionsPerHost cannot be negative")
	}
	if s.KeepAliveInterval < 0 {
		return errors.New("general.ssh.keepAliveInterval cannot be negative")
	}
	if s.KeepAliveCountMax < 1 {
		return errors.New("general.ssh.keepAliveCountMax has to be at least 1")
	}
	if s.MaxPacketSize < MinSFTPPacketSize || s.MaxPacketSize > MaxSFTPPacketSize {
		return fmt.Errorf("general.ssh.maxPacketSize has to be between %d and %d",
			MinSFTPPacketSize, MaxSFTPPacketSize)
	}
	return nil
}

// Insecure names the listed algorithms the library considers insecure, which
// are worth a warning, as "general.ssh.ciphers: 3des-cbc".
func (s SSH) Insecure() []string { return insecureSSHAlgorithms(s) }

// BannerText is the banner as the protocol carries it, its lines ended with
// CRLF, or "" for none.
func (s SSH) BannerText() string {
	if len(s.Banner) == 0 {
		return ""
	}
	return strings.Join(s.Banner, "\r\n") + "\r\n"
}

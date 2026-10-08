package config

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/cpu"
)

// MinSFTPPacketSize and MaxSFTPPacketSize bound general.ssh.maxPacketSize. The
// lower one is what every SFTP implementation has to accept; the upper one
// leaves room for the packet header inside the largest message pkg/sftp reads.
const (
	MinSFTPPacketSize = 32768
	MaxSFTPPacketSize = 261120
)

// algorithmList is one of the algorithm keys of [general.ssh]: what it holds,
// and what the library would take for it.
type algorithmList struct {
	key      string
	value    []string
	secure   []string
	insecure []string
}

func (s SSH) lists() []algorithmList {
	secure, insecure := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	return []algorithmList{
		{"keyExchanges", s.KeyExchanges, secure.KeyExchanges, insecure.KeyExchanges},
		{"ciphers", s.Ciphers, secure.Ciphers, insecure.Ciphers},
		{"macs", s.MACs, secure.MACs, insecure.MACs},
		{"publicKeyAlgorithms", s.PublicKeyAlgorithms, secure.PublicKeyAuths, insecure.PublicKeyAuths},
		{"hostKeyAlgorithms", s.HostKeyAlgorithms, secure.HostKeys, insecure.HostKeys},
	}
}

// resolved is what the list stands for: itself, or the secure default when it
// is empty.
func (l algorithmList) resolved() []string {
	if len(l.value) == 0 {
		return slices.Clone(l.secure)
	}
	return slices.Clone(l.value)
}

func (s SSH) validate() error {
	// the library ignores a name it does not know, so a typo would quietly
	// take an algorithm away; it is reported here instead
	for _, list := range s.lists() {
		seen := make(map[string]bool, len(list.value))
		for _, name := range list.value {
			if !slices.Contains(list.secure, name) && !slices.Contains(list.insecure, name) {
				return fmt.Errorf("general.ssh.%s: %q is not one of %s", list.key, name,
					strings.Join(append(slices.Clone(list.secure), list.insecure...), ", "))
			}
			if seen[name] {
				return fmt.Errorf("general.ssh.%s lists %q twice", list.key, name)
			}
			seen[name] = true
		}
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

// Transport is the key exchanges, ciphers and MACs to offer, the empty lists
// filled in with the secure defaults.
func (s SSH) Transport() ssh.Config {
	lists := s.lists()
	return ssh.Config{
		KeyExchanges: lists[0].resolved(),
		Ciphers:      lists[1].resolved(),
		MACs:         lists[2].resolved(),
	}
}

// ClientTransport is Transport for go-fs as the client, where the order of
// the ciphers is the one that decides.
func (s SSH) ClientTransport() ssh.Config {
	transport := s.Transport()
	transport.Ciphers = s.clientCiphers()
	return transport
}

// hasAESGCM reports whether the processor has the instructions that make
// AES-GCM fast. It is the test crypto/tls makes for the same choice, and a
// variable so that a test can answer it either way.
var hasAESGCM = func() bool {
	switch runtime.GOARCH {
	case "amd64", "386":
		return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	case "arm64":
		return cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	case "s390x":
		return cpu.S390X.HasAES && cpu.S390X.HasAESGCM
	case "ppc64", "ppc64le":
		return true
	}
	return false
}

// clientCiphers is the cipher list in the order go-fs prefers when it is the
// client. A list that is set is taken as it is. The default puts
// chacha20-poly1305 first on a processor without AES instructions, where it
// is several times faster than AES-GCM.
func (s SSH) clientCiphers() []string {
	ciphers := s.lists()[1].resolved()
	if len(s.Ciphers) > 0 || hasAESGCM() {
		return ciphers
	}
	at := slices.Index(ciphers, ssh.CipherChaCha20Poly1305)
	if at <= 0 {
		return ciphers
	}
	ciphers = slices.Delete(ciphers, at, at+1)
	return slices.Insert(ciphers, 0, ssh.CipherChaCha20Poly1305)
}

// PublicKeyAuths are the kinds of key a client may log in with.
func (s SSH) PublicKeyAuths() []string { return s.lists()[3].resolved() }

// HostKeys are the kinds of host key go-fs accepts as a client.
func (s SSH) HostKeys() []string { return s.lists()[4].resolved() }

// Insecure names the listed algorithms the library considers insecure, which
// are worth a warning, as "general.ssh.ciphers: 3des-cbc".
func (s SSH) Insecure() []string {
	var found []string
	for _, list := range s.lists() {
		for _, name := range list.value {
			if slices.Contains(list.insecure, name) {
				found = append(found, "general.ssh."+list.key+": "+name)
			}
		}
	}
	return found
}

// BannerText is the banner as the protocol carries it, its lines ended with
// CRLF, or "" for none.
func (s SSH) BannerText() string {
	if len(s.Banner) == 0 {
		return ""
	}
	return strings.Join(s.Banner, "\r\n") + "\r\n"
}

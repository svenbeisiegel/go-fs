package httpd

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Behind a reverse proxy every request arrives from the proxy's own address,
// and the client is named in X-Forwarded-For. Those headers are the client's
// to write, so they are read only when the connection itself came from one of
// http.trustedProxies: from anywhere else they are ignored, and a request
// that claims to be forwarded is recorded under the address it really came
// from.

// remoteIP is the address the connection came from, in the one spelling every
// comparison uses: an IPv4 address mapped into IPv6 is unmapped and a zone is
// dropped, so "::ffff:1.2.3.4" and "1.2.3.4" are the same client.
func remoteIP(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

// trustedProxy reports whether an address is one of the configured proxies.
func trustedProxy(set *settings, addr netip.Addr) bool {
	for _, prefix := range set.proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// forwardedBy reports whether the connection behind a request came from a
// trusted proxy, which is what decides whether its forwarding headers are read.
func forwardedBy(set *settings, r *http.Request) bool {
	addr, ok := remoteIP(r)
	return ok && trustedProxy(set, addr)
}

// clientAddress is who a request is from: the connection's address, or, when
// that is a trusted proxy, the client the proxy says it forwarded for.
//
// X-Forwarded-For is a list that every proxy on the way appends to, so the
// leftmost entries are whatever the client itself sent and the rightmost is
// what the last proxy saw. It is walked from the right, past every entry that
// is itself a trusted proxy, and the first that is not is the client. A list
// that holds only proxies, or an entry that is not an address, falls back to
// the connection's own address rather than to a guess.
func clientAddress(set *settings, r *http.Request) string {
	if !forwardedBy(set, r) {
		return addressOf(r)
	}
	var entries []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		entries = append(entries, strings.Split(value, ",")...)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if err != nil {
			return addressOf(r)
		}
		addr = addr.Unmap().WithZone("")
		if !trustedProxy(set, addr) {
			return addr.String()
		}
	}
	return addressOf(r)
}

// secureRequest reports whether the client reached this server over TLS:
// either on this server's own TLS listener, or through a trusted proxy that
// says so in X-Forwarded-Proto. It is what decides whether the session cookie
// is marked Secure. From an address that is not a trusted proxy the header is
// the client's word and is not taken.
func secureRequest(set *settings, r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !forwardedBy(set, r) {
		return false
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

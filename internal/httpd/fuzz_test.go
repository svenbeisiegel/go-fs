package httpd

import (
	"encoding/base64"
	"strings"
	"testing"
)

func FuzzParseBasic(f *testing.F) {
	f.Add("john", "doe")
	f.Add("", "")
	f.Add("jöhn", "p:a:s:s")
	f.Fuzz(func(t *testing.T, name, password string) {
		if strings.Contains(name, ":") {
			// a colon in the name cannot be told from the separator
			return
		}
		header := "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+password))
		gotName, gotPassword, ok := parseBasic(header)
		if !ok || gotName != name || gotPassword != password {
			t.Fatalf("parseBasic(%q) = (%q, %q, %v), want (%q, %q, true)",
				header, gotName, gotPassword, ok, name, password)
		}
	})
}

func FuzzParseBasicHeader(f *testing.F) {
	f.Add("Basic am9objpkb2U=")
	f.Add("Basic !!!")
	f.Add("Basic ")
	f.Fuzz(func(t *testing.T, header string) {
		// whatever arrives, the answer is ok or not and never a panic; the
		// halves are only read when ok is set
		_, _, _ = parseBasic(header)
	})
}

func FuzzParseDigest(f *testing.F) {
	f.Add(`Digest username="john", realm="go-fs", nonce="abc", uri="/a?b=c,d", response="x", qop=auth, nc=00000001`)
	f.Add(`Digest username="jo\"hn"`)
	f.Add(`Digest ,,,=,"`)
	f.Add(`Digest a="unterminated`)
	f.Fuzz(func(t *testing.T, header string) {
		_ = parseDigest(header)
	})
}

// Whatever a quoted value holds, other than the quote and the backslash that
// escapes it, comes back unchanged.
func FuzzParseDigestRoundTrip(f *testing.F) {
	f.Add("john", "/path?x=1,y=2")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, name, uri string) {
		if strings.ContainsAny(name+uri, `"\`) {
			return
		}
		params := parseDigest(`Digest username="` + name + `", uri="` + uri + `", qop=auth`)
		if params["username"] != name || params["uri"] != uri || params["qop"] != "auth" {
			t.Fatalf("parsed %v, want username=%q uri=%q qop=auth", params, name, uri)
		}
	})
}

func FuzzParseContentRange(f *testing.F) {
	for _, seed := range []string{
		"bytes 0-99/100", "bytes 100-199/200", "bytes 5-4/10", "bytes 0-9/10",
		"bytes 0-10/10", "bytes 99999999999999999999-1/2", "bytes */100", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		parsed, ok := parseContentRange(header)
		if !ok {
			return
		}
		if parsed.start < 0 || parsed.start > parsed.end || parsed.end >= parsed.total {
			t.Fatalf("parseContentRange(%q) = %+v, which is not a slice of the file", header, parsed)
		}
	})
}

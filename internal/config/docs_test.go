package config

import (
	"strings"
	"testing"
)

// The admin interface labels its generated form with these, so an empty map
// would leave the whole page undocumented.
func TestTemplateDocs(t *testing.T) {
	docs := TemplateDocs()
	for key, want := range map[string]string{
		"ftp.maxConnections":     "maximum simultaneous control connections",
		"tftp.allowOverwrite":    "allow a write request to replace an existing file",
		"general.reloadInterval": "seconds between two checks of the file",
	} {
		if docs[key] != want {
			t.Errorf("%s is documented as %q, want %q", key, docs[key], want)
		}
	}
	// a table header carries the description of the table itself
	if docs["users"] == "" || docs["sftp"] == "" {
		t.Error("a section or a repeated table has no description")
	}
	// the fields of a commented out example are read as well
	if docs["users.basefolder"] == "" {
		t.Error("a key of a commented out example is not documented")
	}
	// a multi-line array value is not read as prose: the first [[users]]
	// example documents allowUserFileRetrieve along with its siblings, and
	// the key-only example that follows it must not replace that with the
	// lines of its authorizedKeys array
	if got := docs["users.allowUserFileRetrieve"]; strings.Contains(got, "ssh-ed25519") {
		t.Errorf("the lines of an array leaked into a description: %q", got)
	}
	if len(docs) < 50 {
		t.Errorf("only %d keys are documented", len(docs))
	}

	// a comment above a run of keys describes every one of them
	for _, pair := range [][2]string{
		{"users.ftp", "users.sftp"},
		{"users.ftp", "users.http"},
		{"users.allowUserFileCreate", "users.allowUserFolderCreate"},
		{"ftps.cert", "ftps.key"},
		{"https.cert", "https.key"},
		{"http.readTimeout", "http.writeTimeout"},
		{"http.readTimeout", "http.idleTimeout"},
		{"tftp.maxConnections", "tftp.maxConnectionsPerHost"},
		{"tftp.allowRead", "tftp.allowWrite"},
	} {
		if docs[pair[0]] == "" || docs[pair[0]] != docs[pair[1]] {
			t.Errorf("%s and %s do not share a description: %q and %q",
				pair[0], pair[1], docs[pair[0]], docs[pair[1]])
		}
	}
	// a blank line ends the run: port says nothing about serving the plain port
	if docs["ftp.port"] != "" {
		t.Errorf("ftp.port inherited %q", docs["ftp.port"])
	}
	// prose that begins with a bracket or with "http = true" is neither a
	// table nor a key: the [http] intro and the keys that follow an example
	// array stay where they belong
	if !strings.HasPrefix(docs["http"], "The HTTP file server") {
		t.Errorf("the [http] section is described as %q", docs["http"])
	}
	if !strings.HasPrefix(docs["http.trustedProxies"], "Addresses or CIDR ranges") {
		t.Errorf("http.trustedProxies is described as %q", docs["http.trustedProxies"])
	}
	for key := range docs {
		if strings.ContainsAny(key, " \"[]") {
			t.Errorf("a line of prose was read as a table: %q", key)
		}
	}
	// what is set apart by a blank line, or follows a key, is for the file
	// alone: the shell hints are not shown in the browser
	for _, key := range []string{"ftps.cert", "sftp.hostkey", "http.httpSessionTokenSecret"} {
		if strings.Contains(docs[key], "base64 <") || strings.Contains(docs[key], "/dev/urandom") {
			t.Errorf("%s carries its shell hint: %q", key, docs[key])
		}
	}
}

// TestParseTemplateDocs pins the reading of the file down on a snippet: what a
// comment covers, what ends it, and what is not a key or a table although it
// looks like one at first glance.
func TestParseTemplateDocs(t *testing.T) {
	src := `# A note for the reader of the file.
#
# The section itself. It mentions that
# http = true, whose owner decides, and an example
# ["10.0.0.0/8", "127.0.0.1"] of a list.
[demo]
# both halves of one thing
first = ""
second = ""

third = 3
# only this one
fourth = "x"

fifth = [
  "a = b",
]
sixth = true
# a hint for the file, after the key

seventh = false
`
	docs := parseTemplateDocs([]byte(src))
	want := map[string]string{
		"demo": "The section itself. It mentions that http = true, whose owner decides, and an example " +
			`["10.0.0.0/8", "127.0.0.1"] of a list.`,
		"demo.first":  "both halves of one thing",
		"demo.second": "both halves of one thing",
		"demo.fourth": "only this one",
	}
	for key, text := range want {
		if docs[key] != text {
			t.Errorf("%s is %q, want %q", key, docs[key], text)
		}
	}
	for _, key := range []string{"demo.third", "demo.fifth", "demo.sixth", "demo.seventh"} {
		if docs[key] != "" {
			t.Errorf("%s is %q, want nothing", key, docs[key])
		}
	}
	if len(docs) != len(want) {
		t.Errorf("read %v, want exactly %v", docs, want)
	}
}

// TestDocs covers the fallback: a field the template does not mention is
// described by the comment above it in the source.
func TestDocs(t *testing.T) {
	docs := Docs()
	if docs["User.Paths"] == "" {
		t.Error("User.Paths has no description")
	}
	if len(docs) < 20 {
		t.Errorf("only %d fields are documented", len(docs))
	}
}

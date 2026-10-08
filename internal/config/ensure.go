package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// generatedSecret is a key of [http] that the file is given at the first start
// when it does not set one, because a key that changes at every restart breaks
// whatever was signed with the previous one.
type generatedSecret struct {
	key      string
	get      func(*Config) *string
	generate func() (string, error)
}

// generatedSecrets are the keys EnsureSecrets fills: the share link key, so a
// link handed out survives a restart, and the session token key, so a browser
// that logged in stays logged in across a restart, an update and a change
// that rebuilds the HTTP service.
var generatedSecrets = []generatedSecret{
	{"shareLinkSecret", func(c *Config) *string { return &c.HTTP.ShareLinkSecret }, GenerateShareSecret},
	{"httpSessionTokenSecret", func(c *Config) *string { return &c.HTTP.SessionTokenSecret }, GenerateSessionSecret},
}

// a table or an array of tables: [[http.cleanup]] ends [http] as well
var sectionLine = regexp.MustCompile(`^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(#.*)?$`)

// EnsureSecrets makes sure the file at path sets every secret of [http] that
// is generated rather than configured: http.shareLinkSecret and
// http.httpSessionTokenSecret. cfg is what was loaded from the file; each key
// it already sets is left alone. The others are generated and written into
// the file in one go, and their names are returned.
//
// The file is edited as text rather than written back by the toml marshaller,
// which would drop every comment in it: an empty line for the key in [http]
// gets the value, a section without the key gets it as its first line, and a
// file without the section gets both appended. The result is parsed again
// before anything is written, so a file whose layout this does not understand
// is left alone and reported rather than broken.
func EnsureSecrets(path string, cfg Config) (Config, []string, error) {
	var missing []generatedSecret
	for _, secret := range generatedSecrets {
		if *secret.get(&cfg) == "" {
			missing = append(missing, secret)
		}
	}
	if len(missing) == 0 {
		return cfg, nil, nil
	}

	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	}
	info, err := os.Stat(target)
	if err != nil {
		return cfg, nil, err
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return cfg, nil, err
	}

	edited := string(data)
	values := make([]string, len(missing))
	names := make([]string, len(missing))
	for i, secret := range missing {
		value, err := secret.generate()
		if err != nil {
			return cfg, nil, err
		}
		values[i], names[i] = value, "http."+secret.key
		edited = withHTTPKey(edited, secret.key, value)
	}
	check, err := Parse([]byte(edited))
	if err != nil {
		return cfg, nil, fmt.Errorf("%s: adding %s: %w", path, strings.Join(names, ", "), err)
	}
	for i, secret := range missing {
		if *secret.get(&check) != values[i] {
			return cfg, nil, fmt.Errorf("%s: cannot tell where to add %s", path, names[i])
		}
	}

	// written beside the file and renamed over it, so that the watcher never
	// reads it half written
	temp, err := os.CreateTemp(filepath.Dir(target), ".go-fs-config-*")
	if err != nil {
		return cfg, nil, err
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	if _, err := temp.WriteString(edited); err != nil {
		_ = temp.Close()
		return cfg, nil, err
	}
	if err := temp.Close(); err != nil {
		return cfg, nil, err
	}
	if err := os.Chmod(temp.Name(), info.Mode().Perm()); err != nil {
		return cfg, nil, err
	}
	if err := os.Rename(temp.Name(), target); err != nil {
		return cfg, nil, err
	}
	for i, secret := range missing {
		*secret.get(&cfg) = values[i]
	}
	return cfg, names, nil
}

// withHTTPKey is the file with key in [http] set to value.
func withHTTPKey(data, key, value string) string {
	newline := "\n"
	if strings.Contains(data, "\r\n") {
		newline = "\r\n"
	}
	entry := key + " = " + strconv.Quote(value)
	keyLine := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(key) + `\s*=`)
	lines := strings.Split(data, newline)

	section, header := "", -1
	for i, line := range lines {
		if m := sectionLine.FindStringSubmatch(line); m != nil {
			if section == "http" {
				// the section ended without the key
				break
			}
			section = m[1]
			if section == "http" {
				header = i
			}
			continue
		}
		if section == "http" && keyLine.MatchString(line) {
			lines[i] = entry
			return strings.Join(lines, newline)
		}
	}
	if header >= 0 {
		lines = append(lines[:header+1], append([]string{entry}, lines[header+1:]...)...)
		return strings.Join(lines, newline)
	}
	if data != "" && !strings.HasSuffix(data, newline) {
		data += newline
	}
	return data + newline + "[http]" + newline + entry + newline
}

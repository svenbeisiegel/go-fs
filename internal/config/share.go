package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// MinShareSecret is the shortest http.shareLinkSecret accepted. A generated
// one is far longer; this only stops a key typed by hand from being trivial.
const MinShareSecret = 32

// shareSecretBytes is how much randomness is behind a generated secret: 512
// bits, the size of the HMAC-SHA512 it keys.
const shareSecretBytes = 64

// GenerateShareSecret produces a new value for http.shareLinkSecret.
func GenerateShareSecret() (string, error) {
	raw := make([]byte, shareSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

var (
	// a table or an array of tables: [[http.cleanup]] ends [http] as well
	sectionLine = regexp.MustCompile(`^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(#.*)?$`)
	secretLine  = regexp.MustCompile(`^\s*shareLinkSecret\s*=`)
)

// EnsureShareSecret makes sure the file at path sets http.shareLinkSecret, so
// that a share link survives a restart. cfg is what was loaded from it; when
// it already has a secret nothing is done. Otherwise one is generated and
// written into the file, and the second result says so.
//
// The file is edited as text rather than written back by the toml marshaller,
// which would drop every comment in it: an empty shareLinkSecret line in
// [http] gets the value, a section without the key gets it as its first line,
// and a file without the section gets both appended. The result is parsed
// again before anything is written, so a file whose layout this does not
// understand is left alone and reported rather than broken.
func EnsureShareSecret(path string, cfg Config) (Config, bool, error) {
	if cfg.HTTP.ShareLinkSecret != "" {
		return cfg, false, nil
	}
	secret, err := GenerateShareSecret()
	if err != nil {
		return cfg, false, err
	}
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	}
	info, err := os.Stat(target)
	if err != nil {
		return cfg, false, err
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return cfg, false, err
	}

	edited := withShareSecret(string(data), secret)
	check, err := Parse([]byte(edited))
	if err != nil {
		return cfg, false, fmt.Errorf("%s: adding http.shareLinkSecret: %w", path, err)
	}
	if check.HTTP.ShareLinkSecret != secret {
		return cfg, false, fmt.Errorf("%s: cannot tell where to add http.shareLinkSecret", path)
	}

	// written beside the file and renamed over it, so that the watcher never
	// reads it half written
	temp, err := os.CreateTemp(filepath.Dir(target), ".go-fs-config-*")
	if err != nil {
		return cfg, false, err
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	if _, err := temp.WriteString(edited); err != nil {
		_ = temp.Close()
		return cfg, false, err
	}
	if err := temp.Close(); err != nil {
		return cfg, false, err
	}
	if err := os.Chmod(temp.Name(), info.Mode().Perm()); err != nil {
		return cfg, false, err
	}
	if err := os.Rename(temp.Name(), target); err != nil {
		return cfg, false, err
	}
	cfg.HTTP.ShareLinkSecret = secret
	return cfg, true, nil
}

// withShareSecret is the file with http.shareLinkSecret set to secret.
func withShareSecret(data, secret string) string {
	newline := "\n"
	if strings.Contains(data, "\r\n") {
		newline = "\r\n"
	}
	entry := "shareLinkSecret = " + strconv.Quote(secret)
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
		if section == "http" && secretLine.MatchString(line) {
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

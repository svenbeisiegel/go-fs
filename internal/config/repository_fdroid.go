//go:build !light && !no_fdroid

package config

import "go-fs/internal/fdroid"

// The F-Droid repository is left out by the tag no_fdroid, and by light, and
// with it its signing key and the modules that read it.
func init() {
	registerKeyKind(KindJARKey, keyKind{decode: DecodeJARKey, describe: describeJARKey,
		generate: GenerateJARKey})
}

// DecodeJARKey turns a configured signing key of an fdroid repository into
// the PEM it stands for, checked to be one go-fs can sign with.
func DecodeJARKey(value string) ([]byte, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	if _, err := fdroid.Parse(decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

// JARKey parses a configured signing key of an fdroid repository.
func JARKey(value string) (*fdroid.Key, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	return fdroid.Parse(decoded)
}

// GenerateJARKey makes a new signing key for the fdroid repository called
// name, as the value the file holds.
func GenerateJARKey(name string) (string, error) {
	pemBytes, err := fdroid.Generate(name)
	if err != nil {
		return "", err
	}
	return Encode(pemBytes), nil
}

func describeJARKey(value string) string {
	key, err := JARKey(value)
	if err != nil {
		return "this value " + err.Error()
	}
	return key.Describe()
}

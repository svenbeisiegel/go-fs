//go:build !light && !no_rpm

package config

import "go-fs/internal/pgp"

// The rpm repository is left out by the tag no_rpm, and by light, and with it
// its OpenPGP signing key and the module that reads it.
func init() {
	registerKeyKind(KindPGPKey, keyKind{decode: DecodePGPKey, describe: describePGPKey,
		generate: GeneratePGPKey})
}

// DecodePGPKey turns a configured signing key into the armored key it
// stands for, checked to be one go-fs can sign with.
func DecodePGPKey(value string) ([]byte, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	if _, err := pgp.Parse(decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

// PGPKey parses a configured signing key.
func PGPKey(value string) (*pgp.Key, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	return pgp.Parse(decoded)
}

// GeneratePGPKey makes a new signing key for the repository called name, as
// the value the file holds.
func GeneratePGPKey(name string) (string, error) {
	armored, err := pgp.Generate(name)
	if err != nil {
		return "", err
	}
	return Encode(armored), nil
}

func describePGPKey(value string) string {
	key, err := PGPKey(value)
	if err != nil {
		return "this value " + err.Error()
	}
	return key.Describe()
}

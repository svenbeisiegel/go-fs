package config

import "testing"

// A configuration file is written by hand, and by the admin page, so whatever
// it holds has to be answered with an error and never with a panic.
func FuzzParseAndValidate(f *testing.F) {
	f.Add(template)
	f.Add([]byte("[http]\nenabled = true\nport = 0\n"))
	f.Add([]byte("[[users]]\nusername = \"a\"\npaths = [\"(\"]\n"))
	f.Add([]byte("[[users]]\nusername = \"a\"\n[[users]]\nusername = \"a\"\n"))
	f.Add([]byte("[http]\ntrustedProxies = [\"not an address\"]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(data)
		if err != nil {
			return
		}
		_ = cfg.Validate()
		_ = cfg.Resolved().Validate()
	})
}

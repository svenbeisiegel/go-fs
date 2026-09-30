// Command sign makes the key pair go-fs updates are signed with, and signs a
// binary into an update file that go-fs accepts over HTTP.
//
//	go run ./tools/sign -generate
//	GOFS_SIGNING_KEY=... go run ./tools/sign -in dist/go-fs_1.2.0_linux_arm64 -out dist/go-fs_1.2.0_linux_arm64.update
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"go-fs/internal/selfupdate"
)

// keyVariable holds the private key, so that it never appears on a command
// line or in a shell history.
const keyVariable = "GOFS_SIGNING_KEY"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		generate = flag.Bool("generate", false, "print a new key pair and exit")
		in       = flag.String("in", "", "binary to sign")
		out      = flag.String("out", "", "update file to write, the binary with the signature appended")
	)
	flag.Parse()

	if *generate {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		fmt.Println("private key, keep it secret (the " + keyVariable + " secret of the release workflow):")
		fmt.Println(selfupdate.EncodePrivateKey(private))
		fmt.Println()
		fmt.Println("public key, add it as a line of internal/selfupdate/keys.txt:")
		fmt.Println(selfupdate.EncodePublicKey(public))
		fmt.Println()
		fmt.Println("key id:", selfupdate.KeyID(public))
		return nil
	}

	if *in == "" || *out == "" {
		return errors.New("-in and -out are required, or -generate")
	}
	secret := os.Getenv(keyVariable)
	if secret == "" {
		return errors.New(keyVariable + " is not set")
	}
	private, err := selfupdate.DecodePrivateKey(secret)
	if err != nil {
		return err
	}
	return sign(private, *in, *out)
}

// sign writes the update beside its final name and renames it there, so that
// a run that fails halfway leaves no update file that looks complete.
func sign(private ed25519.PrivateKey, in, out string) error {
	source, err := os.Open(in)
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := os.CreateTemp(filepath.Dir(out), ".sign-*")
	if err != nil {
		return err
	}
	defer os.Remove(target.Name())
	if err := selfupdate.Sign(private, source, target); err != nil {
		_ = target.Close()
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	if err := os.Chmod(target.Name(), 0o644); err != nil {
		return err
	}
	if err := os.Rename(target.Name(), out); err != nil {
		return err
	}
	fmt.Printf("signed %s with key %s\n", out,
		selfupdate.KeyID(private.Public().(ed25519.PublicKey)))
	return nil
}

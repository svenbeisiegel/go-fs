package cryptomator

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// created is one vault made for the tests that do not care which, as making
// one runs scrypt.
var created = sync.OnceValues(func() (*Vault, map[string][]byte) {
	v, files, _, err := Create("secret")
	if err != nil {
		panic(err)
	}
	return v, files
})

func TestCreateUnlocks(t *testing.T) {
	v, files := created()
	opened, err := Unlock(files[VaultFile], files[MasterkeyFile], "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.rawKey(), v.rawKey()) {
		t.Error("the unlocked keys are not the created ones")
	}
	if _, err := Unlock(files[VaultFile], files[MasterkeyFile], "wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("a wrong password unlocked with %v", err)
	}
}

func TestUnlockRefuses(t *testing.T) {
	_, files := created()
	if _, err := Unlock([]byte("not a jwt"), files[MasterkeyFile], "secret"); err == nil {
		t.Error("a vault file that is no JWT was taken")
	}
	if _, err := Unlock(files[VaultFile], []byte("{"), "secret"); err == nil {
		t.Error("a key file that is no JSON was taken")
	}
	_, other, _, err := Create("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(other[VaultFile], files[MasterkeyFile], "secret"); err == nil {
		t.Error("a vault file signed with other keys was taken")
	}
	greedy := bytes.Replace(files[MasterkeyFile], []byte(`"scryptCostParam": 32768`), []byte(`"scryptCostParam": 1073741824`), 1)
	if _, err := Unlock(files[VaultFile], greedy, "secret"); err == nil || errors.Is(err, ErrWrongPassword) {
		t.Errorf("a key file asking for a huge scrypt cost failed with %v", err)
	}
}

func TestRecover(t *testing.T) {
	v, files := created()
	key := v.RecoveryKey()
	masterkey, err := Recover(strings.ToLower(key), "new")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Unlock(files[VaultFile], masterkey, "new")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.rawKey(), v.rawKey()) {
		t.Error("the recovered keys are not the vault's")
	}
	mistyped := []byte(key)
	if mistyped[0] == 'A' {
		mistyped[0] = 'B'
	} else {
		mistyped[0] = 'A'
	}
	if _, err := Recover(string(mistyped), "new"); !errors.Is(err, ErrRecoveryKey) {
		t.Errorf("a mistyped recovery key was taken with %v", err)
	}
}

func TestNames(t *testing.T) {
	v, _ := created()
	for _, name := range []string{"a", "report.pdf", "ünïcödé", strings.Repeat("x", 300)} {
		enc := v.EncryptName(name, "dir")
		if enc != v.EncryptName(name, "dir") {
			t.Errorf("%q encrypts differently twice", name)
		}
		if enc == v.EncryptName(name, "other") {
			t.Errorf("%q encrypts the same in another folder", name)
		}
		got, err := v.DecryptName(enc, "dir")
		if err != nil || got != name {
			t.Errorf("%q decrypts to %q, %v", name, got, err)
		}
		if _, err := v.DecryptName(enc, "other"); err == nil {
			t.Errorf("%q decrypts in another folder", name)
		}
		short, shortened := v.Shorten(enc)
		if shortened != (len(enc) > DefaultShorteningThreshold) || shortened == (short == enc) {
			t.Errorf("%q is shortened %v to %q", name, shortened, short)
		}
	}
	// a name in decomposed form is the same name as composed
	if v.EncryptName("ü", "") != v.EncryptName("ü", "") {
		t.Error("a decomposed name encrypts differently from the composed one")
	}
	path := v.DirPath("")
	if len(path) != len("d/XX/")+30 || !strings.HasPrefix(path, "d/") || path[4] != '/' {
		t.Errorf("the root is kept at %q", path)
	}
}

func TestSizes(t *testing.T) {
	for _, n := range []int64{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3 * ChunkSize, 100_000} {
		if got := CleartextSize(CiphertextSize(n)); got != n {
			t.Errorf("%d bytes come back as %d", n, got)
		}
	}
	if CleartextSize(HeaderSize-1) != -1 || CleartextSize(HeaderSize+chunkOverhead) != -1 {
		t.Error("a length no file has was given a size")
	}
}

func encrypt(t testing.TB, v *Vault, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := v.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	// written in pieces that do not line up with the chunks
	for rest := plain; len(rest) > 0; {
		n := min(len(rest), 1000)
		if _, err := w.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestContent(t *testing.T) {
	v, _ := created()
	for _, n := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 100 * 1024} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		sealed := encrypt(t, v, plain)
		if int64(len(sealed)) != CiphertextSize(int64(n)) {
			t.Errorf("%d bytes encrypt to %d, not %d", n, len(sealed), CiphertextSize(int64(n)))
		}
		r, err := v.NewReader(bytes.NewReader(sealed), int64(len(sealed)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%d bytes read back as %d, %v", n, len(got), err)
		}
		for _, at := range []int64{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, int64(n) / 2} {
			if at > int64(n) {
				continue
			}
			if _, err := r.Seek(at, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, plain[at:]) {
				t.Errorf("%d bytes read from %d wrong, %v", n, at, err)
			}
		}
	}
}

func TestContentTampered(t *testing.T) {
	v, _ := created()
	plain := make([]byte, 2*ChunkSize+5)
	sealed := encrypt(t, v, plain)
	for name, damage := range map[string]func([]byte) []byte{
		"a flipped bit": func(b []byte) []byte { b[HeaderSize+ChunkSize+100] ^= 1; return b },
		"a cut end":     func(b []byte) []byte { return b[:len(b)-1] },
		"swapped chunks": func(b []byte) []byte {
			first := append([]byte(nil), b[HeaderSize:HeaderSize+cipherChunkSize]...)
			copy(b[HeaderSize:], b[HeaderSize+cipherChunkSize:HeaderSize+2*cipherChunkSize])
			copy(b[HeaderSize+cipherChunkSize:], first)
			return b
		},
		"a damaged header": func(b []byte) []byte { b[20] ^= 1; return b },
	} {
		damaged := damage(append([]byte(nil), sealed...))
		r, err := v.NewReader(bytes.NewReader(damaged), int64(len(damaged)))
		if err == nil {
			_, err = io.ReadAll(r)
		}
		if err == nil {
			t.Errorf("a file with %s was read", name)
		}
	}
}

func FuzzDecryptName(f *testing.F) {
	v, _ := created()
	f.Add(v.EncryptName("a", ""), "")
	f.Add("AAAA.c9r", "x")
	f.Fuzz(func(t *testing.T, enc, dir string) {
		_, _ = v.DecryptName(enc, dir)
	})
}

func FuzzReader(f *testing.F) {
	v, _ := created()
	f.Add(encrypt(f, v, []byte("hello")))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := v.NewReader(bytes.NewReader(b), int64(len(b)))
		if err == nil {
			_, _ = io.ReadAll(r)
		}
	})
}

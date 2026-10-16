package rpm

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go-fs/internal/pgp"
)

// copyFixture puts a package of testdata into a folder of the test's own,
// where it may be signed in place.
func copyFixture(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

var testKey *pgp.Key

func key(t *testing.T) *pgp.Key {
	t.Helper()
	if testKey == nil {
		armored, err := pgp.Generate("rpm test")
		if err != nil {
			t.Fatal(err)
		}
		if testKey, err = pgp.Parse(armored); err != nil {
			t.Fatal(err)
		}
	}
	return testKey
}

func TestOpenReadsThePackage(t *testing.T) {
	f, err := Open(filepath.Join("testdata", "tool-0.1-1.x86_64.rpm"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	p := f.Package()
	if p.Name != "tool" || p.Arch != "x86_64" || p.Version != "0.1.0" || p.Release != "1" || p.Epoch != "0" {
		t.Errorf("package = %s %s %+v", p.Name, p.Arch, p.EVR)
	}
	if p.Summary != "the tool test package" || p.License != "Apache-2.0" || p.URL != "https://example.com/tool" {
		t.Errorf("summary %q license %q url %q", p.Summary, p.License, p.URL)
	}
	names := func(deps []Dependency) []string {
		var out []string
		for _, d := range deps {
			out = append(out, d.Name+" "+d.Flags+" "+d.Version)
		}
		return out
	}
	if got := names(p.Requires); !slices.Contains(got, "bash  ") || !slices.Contains(got, "/bin/sh  ") {
		t.Errorf("requires = %q", got)
	}
	for _, d := range p.Requires {
		if strings.HasPrefix(d.Name, "rpmlib(") {
			t.Errorf("requires lists %q", d.Name)
		}
	}
	if got := names(p.Provides); !slices.Contains(got, "tool-api EQ 1") {
		t.Errorf("provides = %q", got)
	}
	if got := names(p.Conflicts); !slices.Contains(got, "oldtool LT 2") {
		t.Errorf("conflicts = %q", got)
	}
	var paths []string
	for _, file := range p.Files {
		paths = append(paths, file.Path)
	}
	if !slices.Contains(paths, "/usr/bin/tool") || !slices.Contains(paths, "/etc/tool.conf") {
		t.Errorf("files = %q", paths)
	}
}

func TestVerifyRefusesATruncatedPackage(t *testing.T) {
	dir := t.TempDir()
	path := copyFixture(t, dir, "hello-1.0-1.x86_64.rpm")
	data, _ := os.ReadFile(path)
	os.WriteFile(path, data[:len(data)-10], 0o644)
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("verify = %v, want ErrIncomplete", err)
	}

	// cut inside the header, it does not even open
	os.WriteFile(path, data[:200], 0o644)
	if _, err := Open(path); err == nil {
		t.Fatal("a package cut in its header opened")
	}
}

func TestVerifyRefusesAChangedPayload(t *testing.T) {
	dir := t.TempDir()
	path := copyFixture(t, dir, "hello-1.0-1.x86_64.rpm")
	data, _ := os.ReadFile(path)
	data[len(data)-5] ^= 0xff
	os.WriteFile(path, data, 0o644)
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("verify = %v, want ErrIncomplete", err)
	}
}

func TestSignAnUnsignedPackage(t *testing.T) {
	dir := t.TempDir()
	path := copyFixture(t, dir, "hello-1.0-1.x86_64.rpm")
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.SignedBy(key(t)) {
		t.Fatal("an unsigned package is signed")
	}
	before := f.Header.Raw()
	signed, err := f.Sign(key(t))
	if err != nil {
		t.Fatal(err)
	}
	if !signed.SignedBy(key(t)) {
		t.Fatal("the signed package is not signed by the key")
	}
	if !bytes.Equal(before, signed.Header.Raw()) {
		t.Fatal("signing changed the header")
	}
	if err := signed.Verify(); err != nil {
		t.Fatalf("the signed package does not verify: %v", err)
	}
	if signed.HeaderStart%8 != 0 {
		t.Errorf("the header starts at %d, not on 8 bytes", signed.HeaderStart)
	}
	// what was in the signature header besides is kept
	for _, tag := range []int32{sigSize, sigSHA256, sigPayloadSize} {
		if !bytes.Equal(f.Signature.entries[tag].data, signed.Signature.entries[tag].data) {
			t.Errorf("tag %d changed", tag)
		}
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".*"))
	if len(leftovers) > 0 {
		t.Errorf("left behind %q", leftovers)
	}
	checkWithRPM(t, path)
}

func TestSignReplacesAForeignSignature(t *testing.T) {
	dir := t.TempDir()
	path := copyFixture(t, dir, "hello-1.1-1.foreign.x86_64.rpm")
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Signature.Has(sigRSA) || !f.Signature.Has(sigPGP) {
		t.Fatal("the fixture is not signed")
	}
	if f.SignedBy(key(t)) {
		t.Fatal("a package of another key counts as signed by this one")
	}
	signed, err := f.Sign(key(t))
	if err != nil {
		t.Fatal(err)
	}
	if !signed.SignedBy(key(t)) {
		t.Fatal("not signed by the key")
	}
	if signed.Signature.Has(sigPGP) {
		t.Error("the foreign signature over header and payload is still there")
	}
	if err := signed.Verify(); err != nil {
		t.Fatal(err)
	}
	checkWithRPM(t, path)
}

// checkWithRPM has rpm itself check the signature, where it is installed.
func checkWithRPM(t *testing.T, path string) {
	t.Helper()
	rpmkeys, err := exec.LookPath("rpmkeys")
	if err != nil {
		t.Log("rpmkeys is not installed, the signature is checked by go-fs alone")
		return
	}
	db := t.TempDir()
	public, _ := key(t).Public()
	keyFile := filepath.Join(db, "key.asc")
	os.WriteFile(keyFile, public, 0o644)
	if out, err := exec.Command(rpmkeys, "--dbpath", db, "--import", keyFile).CombinedOutput(); err != nil {
		t.Fatalf("rpmkeys --import: %v\n%s", err, out)
	}
	out, err := exec.Command(rpmkeys, "--dbpath", db, "--checksig", "-v", path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OK") || strings.Contains(string(out), "NOKEY") {
		t.Fatalf("rpmkeys --checksig: %v\n%s", err, out)
	}
}

func TestVercmp(t *testing.T) {
	// from rpm's own tests, tests/rpmvercmp.at
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0", "2.0", -1}, {"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0}, {"2.0", "2.0.1", -1}, {"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1a", 0}, {"2.0.1a", "2.0.1", 1}, {"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p1", 0}, {"5.5p1", "5.5p2", -1}, {"5.5p2", "5.5p1", 1},
		{"5.5p10", "5.5p10", 0}, {"5.5p1", "5.5p10", -1}, {"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1}, {"10.1xyz", "10xyz", 1},
		{"xyz10", "xyz10", 0}, {"xyz10", "xyz10.1", -1}, {"xyz10.1", "xyz10", 1},
		{"xyz.4", "xyz.4", 0}, {"xyz.4", "8", -1}, {"8", "xyz.4", 1},
		{"xyz.4", "2", -1}, {"2", "xyz.4", 1},
		{"5.5p2", "5.6p1", -1}, {"5.6p1", "5.5p2", 1},
		{"5.6p1", "6.5p1", -1}, {"6.5p1", "5.6p1", 1},
		{"6.0.rc1", "6.0", 1}, {"6.0", "6.0.rc1", -1},
		{"10b2", "10a1", 1}, {"10a2", "10b2", -1},
		{"1.0aa", "1.0aa", 0}, {"1.0a", "1.0aa", -1}, {"1.0aa", "1.0a", 1},
		{"10.0001", "10.0001", 0}, {"10.0001", "10.1", 0}, {"10.1", "10.0001", 0},
		{"10.0001", "10.0039", -1}, {"10.0039", "10.0001", 1},
		{"4.999.9", "5.0", -1}, {"5.0", "4.999.9", 1},
		{"20101121", "20101121", 0}, {"20101121", "20101122", -1}, {"20101122", "20101121", 1},
		{"2_0", "2_0", 0}, {"2.0", "2_0", 0}, {"2_0", "2.0", 0},
		{"a", "a", 0}, {"a+", "a+", 0}, {"a+", "a_", 0}, {"a_", "a+", 0},
		{"+a", "+a", 0}, {"+a", "_a", 0}, {"_a", "+a", 0},
		{"+_", "+_", 0}, {"_+", "+_", 0}, {"_+", "_+", 0}, {"+", "_", 0}, {"_", "+", 0},
		{"1.0~rc1", "1.0~rc1", 0}, {"1.0~rc1", "1.0", -1}, {"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1}, {"1.0~rc2", "1.0~rc1", 1},
		{"1.0~rc1~git123", "1.0~rc1~git123", 0}, {"1.0~rc1~git123", "1.0~rc1", -1}, {"1.0~rc1", "1.0~rc1~git123", 1},
		{"1.0^", "1.0^", 0}, {"1.0^", "1.0", 1}, {"1.0", "1.0^", -1},
		{"1.0^git1", "1.0^git1", 0}, {"1.0^git1", "1.0", 1}, {"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1}, {"1.0^git2", "1.0^git1", 1},
		{"1.0^git1", "1.01", -1}, {"1.01", "1.0^git1", 1},
		{"1.0^20160101", "1.0^20160101", 0}, {"1.0^20160101", "1.0.1", -1}, {"1.0.1", "1.0^20160101", 1},
		{"1.0^20160101^git1", "1.0^20160101^git1", 0}, {"1.0^20160102", "1.0^20160101^git1", 1},
		{"1.0^20160101^git1", "1.0^20160102", -1},
		{"1.0~rc1^git1", "1.0~rc1^git1", 0}, {"1.0~rc1^git1", "1.0~rc1", 1}, {"1.0~rc1", "1.0~rc1^git1", -1},
		{"1.0^git1~pre", "1.0^git1~pre", 0}, {"1.0^git1", "1.0^git1~pre", 1}, {"1.0^git1~pre", "1.0^git1", -1},
	}
	for _, c := range cases {
		if got := Vercmp(c.a, c.b); got != c.want {
			t.Errorf("Vercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareEpochFirst(t *testing.T) {
	if Compare(EVR{"1", "1.0", "1"}, EVR{"0", "9.0", "1"}) != 1 {
		t.Error("an epoch does not win over the version")
	}
	if Compare(EVR{"", "1.0", "2"}, EVR{"0", "1.0", "10"}) != -1 {
		t.Error("the release is not compared")
	}
}

func TestWriteRepodata(t *testing.T) {
	dir := t.TempDir()
	var entries []Entry
	for _, name := range []string{"hello-1.0-1.x86_64.rpm", "tool-0.1-1.x86_64.rpm"} {
		path := copyFixture(t, dir, name)
		f, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		e, err := f.Entry(name)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	public, _ := key(t).Public()
	sign := func(data []byte) ([]byte, error) { return key(t).ArmoredSign(bytes.NewReader(data)) }

	first, err := WriteRepodata(dir, entries, public, sign, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	files, err := ReadRepomd(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"primary", "filelists", "other"} {
		if _, err := os.Stat(filepath.Join(dir, files[kind])); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
	listed, err := PrimaryOf(filepath.Join(dir, files["primary"]))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(listed, []string{"hello-1.0-1.x86_64.rpm", "tool-0.1-1.x86_64.rpm"}) {
		t.Errorf("primary lists %q", listed)
	}
	primary := gunzip(t, filepath.Join(dir, files["primary"]))
	for _, want := range []string{
		`<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">`,
		`<rpm:entry name="tool-api" flags="EQ" epoch="0" ver="1"`,
		`<file>/usr/bin/tool</file>`,
		`<file>/etc/tool.conf</file>`,
		`<checksum type="sha256" pkgid="YES">` + entries[0].Checksum + `</checksum>`,
	} {
		if !strings.Contains(primary, want) {
			t.Errorf("primary.xml lacks %s", want)
		}
	}
	if strings.Contains(primary, "/usr/share/hello/hello.sh") {
		t.Error("primary.xml lists a file that is not in a bin folder or /etc")
	}
	if !strings.Contains(gunzip(t, filepath.Join(dir, files["filelists"])), "/usr/share/hello/hello.sh") {
		t.Error("filelists.xml lacks a file")
	}

	// the signature is over repomd.xml as written
	signature, _ := os.ReadFile(filepath.Join(dir, RepodataFolder, RepomdSignature))
	if !bytes.HasPrefix(signature, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Error("repomd.xml.asc is not a signature")
	}
	if written, _ := os.ReadFile(filepath.Join(dir, RepodataFolder, Repomd)); !bytes.Equal(written, first.Repomd) {
		t.Error("repomd.xml is not what was returned")
	}

	// a second and a third build keep the lists of the one before
	entries = entries[:1]
	if _, err := WriteRepodata(dir, entries, public, sign, time.Unix(1700000100, 0)); err != nil {
		t.Fatal(err)
	}
	second, _ := ReadRepomd(dir)
	if _, err := os.Stat(filepath.Join(dir, files["primary"])); err != nil {
		t.Error("the primary.xml of the build before is gone already")
	}
	entries[0].ModTime++
	if _, err := WriteRepodata(dir, entries, public, sign, time.Unix(1700000200, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, files["primary"])); !os.IsNotExist(err) {
		t.Error("the primary.xml of two builds ago is kept")
	}
	if _, err := os.Stat(filepath.Join(dir, second["primary"])); err != nil {
		t.Error("the primary.xml of the build before is gone")
	}

	checkWithCreaterepo(t, dir)
}

func gunzip(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// checkWithCreaterepo has createrepo_c read the metadata back, where it is
// installed: --update reuses what it can parse of it.
func checkWithCreaterepo(t *testing.T, dir string) {
	t.Helper()
	createrepo, err := exec.LookPath("createrepo_c")
	if err != nil {
		t.Log("createrepo_c is not installed, the metadata is checked by go-fs alone")
		return
	}
	if out, err := exec.Command(createrepo, "--update", "--dryrun", dir).CombinedOutput(); err != nil {
		t.Fatalf("createrepo_c cannot read the metadata: %v\n%s", err, out)
	}
}

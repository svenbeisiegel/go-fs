package fdroid

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"go-fs/internal/fdroid/fdroidtest"
)

func init() {
	// a key of the size Generate makes takes seconds
	generateBits = 2048
}

func testKey(t *testing.T) *Key {
	t.Helper()
	pemBytes, err := Generate("test repo")
	if err != nil {
		t.Fatal(err)
	}
	key, err := Parse(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestKey(t *testing.T) {
	pemBytes, err := Generate("test repo")
	if err != nil {
		t.Fatal(err)
	}
	key, err := Parse(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	sum := sha256.Sum256(block.Bytes)
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); key.Fingerprint() != want {
		t.Errorf("fingerprint %s, want the SHA-256 of the certificate %s", key.Fingerprint(), want)
	}
	if key.Name() != "test repo" || !strings.Contains(key.Describe(), key.Fingerprint()) {
		t.Errorf("described as %q", key.Describe())
	}

	other, err := Generate("other")
	if err != nil {
		t.Fatal(err)
	}
	otherCert, _ := pem.Decode(other)
	_, keyOnly := pem.Decode(pemBytes)
	cases := map[string][]byte{
		"no certificate":     keyOnly,
		"no key":             pem.EncodeToMemory(block),
		"two certificates":   append(pem.EncodeToMemory(otherCert), pemBytes...),
		"another key's cert": append(pem.EncodeToMemory(otherCert), keyOnly...),
		"nothing":            []byte("garbage"),
	}
	for name, input := range cases {
		if _, err := Parse(input); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func build(t *testing.T, a fdroidtest.APK) []byte {
	t.Helper()
	data, err := fdroidtest.Build(a)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func read(t *testing.T, data []byte) (*APK, error) {
	t.Helper()
	return Read(bytes.NewReader(data), int64(len(data)))
}

func TestRead(t *testing.T) {
	signer, err := fdroidtest.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	icon := []byte("\x89PNG\r\n\x1a\nicon")
	data := build(t, fdroidtest.APK{
		Package: "org.example.app", VersionCode: 42, VersionName: "1.2.3",
		MinSdk: 24, TargetSdk: 34, Label: "Example",
		Permissions:      []string{"android.permission.INTERNET"},
		PermissionsSdk23: []string{"android.permission.CAMERA"},
		Features:         []string{"android.hardware.camera"},
		ABIs:             []string{"x86_64", "arm64-v8a"},
		Icon:             icon,
		Signer:           signer,
	})
	a, err := read(t, data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := APK{
		PackageName: "org.example.app", VersionCode: 42, VersionName: "1.2.3",
		MinSdkVersion: 24, TargetSdkVersion: 34,
		Permissions:      []Permission{{Name: "android.permission.INTERNET"}},
		PermissionsSdk23: []Permission{{Name: "android.permission.CAMERA"}},
		Features:         []string{"android.hardware.camera"},
		NativeCode:       []string{"arm64-v8a", "x86_64"},
		Signer:           signer.Fingerprint(),
		Label:            "Example",
		Icon:             icon, IconExt: ".png",
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
	}
	if got, _ := json.Marshal(a); !bytes.Equal(got, must(json.Marshal(want))) {
		t.Errorf("read\n%s\nwant\n%s", got, must(json.Marshal(want)))
	}

	v1 := build(t, fdroidtest.APK{Package: "org.example.v1", VersionCode: 1, Scheme: fdroidtest.V1, Signer: signer})
	if a, err := read(t, v1); err != nil || a.Signer != signer.Fingerprint() {
		t.Errorf("a JAR signed APK: signer %v, %v", a, err)
	}
	if a, _ := read(t, v1); a.VersionName != "1" || a.MinSdkVersion != 1 || a.TargetSdkVersion != 1 {
		t.Errorf("the defaults of a bare manifest: %+v", a)
	}

	unsigned := build(t, fdroidtest.APK{Package: "org.example.unsigned", VersionCode: 1, Scheme: fdroidtest.Unsigned})
	if _, err := read(t, unsigned); !errors.Is(err, errNoSigner) {
		t.Errorf("an unsigned APK: %v", err)
	}
	if _, err := read(t, data[:len(data)/2]); !errors.Is(err, ErrIncomplete) {
		t.Errorf("half an APK: %v", err)
	}
	if _, err := read(t, build(t, fdroidtest.APK{Package: "org.example.nocode"})); err == nil {
		t.Error("an APK without a versionCode is read")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// writeAPK puts an APK into folder at href.
func writeAPK(t *testing.T, folder, href string, a fdroidtest.APK) Version {
	t.Helper()
	data := build(t, a)
	path := filepath.Join(folder, filepath.FromSlash(href))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	apk, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return Version{Href: href, Added: time.UnixMilli(1700000000000), APK: apk}
}

func TestWriteIndex(t *testing.T) {
	folder := t.TempDir()
	key := testKey(t)
	signer, err := fdroidtest.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	versions := []Version{
		writeAPK(t, folder, "app-1.apk", fdroidtest.APK{Package: "org.example.app", VersionCode: 1,
			VersionName: "1.0", Label: "Example", Icon: []byte("old icon"), Signer: signer}),
		writeAPK(t, folder, "sub/app-2.apk", fdroidtest.APK{Package: "org.example.app", VersionCode: 2,
			VersionName: "2.0", Label: "Example", Icon: []byte("new icon"), Signer: signer}),
		writeAPK(t, folder, "other.apk", fdroidtest.APK{Package: "org.example.other", VersionCode: 7}),
	}
	versions[1].Added = versions[0].Added.Add(time.Hour)
	// metadata beside the APKs, in the fastlane layout
	meta := filepath.Join(folder, "org.example.app", "en-US")
	os.MkdirAll(filepath.Join(meta, "phoneScreenshots"), 0o755)
	os.MkdirAll(filepath.Join(meta, "changelogs"), 0o755)
	os.WriteFile(filepath.Join(meta, "title.txt"), []byte("Example App\n"), 0o644)
	os.WriteFile(filepath.Join(meta, "short_description.txt"), []byte("Does things"), 0o644)
	os.WriteFile(filepath.Join(meta, "phoneScreenshots", "1.png"), []byte("shot"), 0o644)
	os.WriteFile(filepath.Join(meta, "changelogs", "2.txt"), []byte("New in 2"), 0o644)
	os.WriteFile(filepath.Join(folder, "icon.png"), []byte("repo icon"), 0o644)
	os.MkdirAll(filepath.Join(folder, IconFolder), 0o755)
	os.WriteFile(filepath.Join(folder, IconFolder, "stale.png"), []byte("stale"), 0o644)

	repo := Repo{Name: "Test", Description: "Apps for tests", Address: "https://example.com/fdroid/repo", Icon: "/icon.png"}
	now := time.UnixMilli(1800000000000)
	timestamp, err := WriteIndex(folder, repo, versions, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if timestamp != now.UnixMilli() {
		t.Errorf("timestamp %d, want %d", timestamp, now.UnixMilli())
	}

	entryData := checkJAR(t, filepath.Join(folder, EntryJAR), key)
	var entry Entry
	if err := json.Unmarshal(entryData, &entry); err != nil {
		t.Fatal(err)
	}
	indexData, err := os.ReadFile(filepath.Join(folder, IndexJSON))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(indexData)
	if entry.Index.Name != "/index-v2.json" || entry.Index.SHA256 != hex.EncodeToString(sum[:]) ||
		entry.Index.Size != int64(len(indexData)) || entry.Index.NumPackages != 2 ||
		entry.Timestamp != timestamp || entry.Version != formatVersion {
		t.Errorf("entry.json %+v does not describe the index", entry)
	}

	var index indexV2
	if err := json.Unmarshal(indexData, &index); err != nil {
		t.Fatal(err)
	}
	if index.Repo.Address != repo.Address || index.Repo.Name[DefaultLocale] != "Test" ||
		index.Repo.Description[DefaultLocale] != "Apps for tests" ||
		index.Repo.Icon[DefaultLocale].Name != "/icon.png" || index.Repo.Timestamp != timestamp {
		t.Errorf("repo %+v", index.Repo)
	}
	app := index.Packages["org.example.app"]
	if app.Metadata.Name[DefaultLocale] != "Example App" || app.Metadata.Summary[DefaultLocale] != "Does things" {
		t.Errorf("the texts beside the APK are not listed: %+v", app.Metadata)
	}
	if shots := app.Metadata.Screenshots["phone"][DefaultLocale]; len(shots) != 1 ||
		shots[0].Name != "/org.example.app/en-US/phoneScreenshots/1.png" {
		t.Errorf("screenshots %+v", app.Metadata.Screenshots)
	}
	if icon := app.Metadata.Icon[DefaultLocale]; icon.Name != "/icons/org.example.app.2.png" {
		t.Errorf("the icon of the newest version is not listed: %+v", icon)
	}
	if data, err := os.ReadFile(filepath.Join(folder, IconFolder, "org.example.app.2.png")); err != nil ||
		string(data) != "new icon" {
		t.Errorf("the icon is not written: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(folder, IconFolder, "stale.png")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an icon no version has stays: %v", err)
	}
	if app.Metadata.Added != versions[0].Added.UnixMilli() || app.Metadata.LastUpdated != versions[1].Added.UnixMilli() ||
		app.Metadata.PreferredSigner != signer.Fingerprint() {
		t.Errorf("metadata %+v", app.Metadata)
	}
	if len(app.Versions) != 2 {
		t.Fatalf("versions %+v", app.Versions)
	}
	v2 := app.Versions[versions[1].APK.SHA256]
	if v2.File.Name != "/sub/app-2.apk" || v2.Manifest.VersionCode != 2 || v2.Manifest.VersionName != "2.0" ||
		v2.Manifest.Signer == nil || v2.Manifest.Signer.SHA256[0] != signer.Fingerprint() ||
		v2.WhatsNew[DefaultLocale] != "New in 2" || v2.Manifest.UsesSdk.MinSdkVersion != 1 {
		t.Errorf("version 2 %+v", v2)
	}
	if other := index.Packages["org.example.other"]; other.Metadata.Name != nil || other.Metadata.Icon != nil {
		t.Errorf("an app without a label or an icon: %+v", other.Metadata)
	}

	// written again at the same time, the index is still later than the
	// one before, or the client would take it as unchanged
	again, err := WriteIndex(folder, repo, versions, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if again <= timestamp {
		t.Errorf("the timestamp went from %d to %d", timestamp, again)
	}

	// as Java verifies it, where it is installed; not -strict, which takes
	// a self-signed certificate for an error, and F-Droid pins the one it
	// is by its fingerprint
	if _, err := exec.LookPath("jarsigner"); err == nil {
		out, err := exec.Command("jarsigner", "-verify", filepath.Join(folder, EntryJAR)).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "jar verified") {
			t.Errorf("jarsigner does not verify entry.jar: %v\n%s", err, out)
		}
	}
}

// checkJAR checks entry.jar as the client does, and answers the entry.json
// in it.
func checkJAR(t *testing.T, path string, key *Key) []byte {
	t.Helper()
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	files := map[string][]byte{}
	var names []string
	for _, f := range z.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
		names = append(names, f.Name)
	}
	want := []string{"META-INF/MANIFEST.MF", "META-INF/GOFS.SF", "META-INF/GOFS.RSA", EntryJSON}
	if !slices.Equal(names, want) {
		t.Fatalf("entry.jar holds %v, want %v", names, want)
	}
	manifest, signature := string(files["META-INF/MANIFEST.MF"]), string(files["META-INF/GOFS.SF"])
	for _, text := range []string{manifest, signature} {
		if strings.Contains(text, "SHA1") || strings.Contains(text, "MD5") {
			t.Errorf("a digest the client refuses:\n%s", text)
		}
	}
	if !strings.Contains(manifest, "Name: entry.json\r\nSHA-256-Digest: "+digest(files[EntryJSON])+"\r\n") {
		t.Errorf("the manifest has no digest of entry.json:\n%s", manifest)
	}
	if !strings.Contains(signature, "SHA-256-Digest-Manifest: "+digest([]byte(manifest))+"\r\n") {
		t.Errorf("the signature file has no digest of the manifest:\n%s", signature)
	}
	section := manifest[strings.Index(manifest, "Name: entry.json"):]
	if !strings.Contains(signature, "SHA-256-Digest: "+digest([]byte(section))+"\r\n") {
		t.Errorf("the signature file has no digest of the section of entry.json:\n%s", signature)
	}
	p7, err := pkcs7.Parse(files["META-INF/GOFS.RSA"])
	if err != nil {
		t.Fatal(err)
	}
	p7.Content = files["META-INF/GOFS.SF"]
	if err := p7.Verify(); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
	if len(p7.Certificates) != 1 || !p7.Certificates[0].Equal(key.certificate) {
		t.Errorf("signed with %d certificates, want the key's one", len(p7.Certificates))
	}
	return files[EntryJSON]
}

func TestWrap(t *testing.T) {
	long := "Name: " + strings.Repeat("x", 150)
	wrapped := wrap(long)
	lines := strings.Split(strings.TrimSuffix(wrapped, "\r\n"), "\r\n")
	for i, line := range lines {
		if len(line) > 72 || (i > 0 && !strings.HasPrefix(line, " ")) {
			t.Errorf("line %d %q", i, line)
		}
	}
	joined := lines[0]
	for _, line := range lines[1:] {
		joined += line[1:]
	}
	if joined != long {
		t.Errorf("unwrapped %q", joined)
	}
}

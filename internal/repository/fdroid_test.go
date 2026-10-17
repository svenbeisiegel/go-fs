//go:build !light && !no_fdroid

package repository

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/fdroid"
	"go-fs/internal/fdroid/fdroidtest"
)

// jarKey is one key for every test, since making one takes a while.
var jarKey = sync.OnceValues(func() (string, error) { return config.GenerateJARKey("test") })

func newFDroidRunner(t *testing.T, keep int) (*runner, string) {
	t.Helper()
	key, err := jarKey()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	folder := filepath.Join(base, "android", "repo")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := newRunner(config.Repository{
		Name: "android", Type: config.RepositoryTypeFDroid, Folder: "/android/repo",
		SigningKey: key, Keep: keep, URL: "https://files.example.com/android/repo", Title: "Test apps",
	}, base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return r, folder
}

func putAPK(t *testing.T, folder, href string, a fdroidtest.APK) []byte {
	t.Helper()
	data, err := fdroidtest.Build(a)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(folder, filepath.FromSlash(href))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return data
}

// indexed lists the APKs the index lists, by package name and then file.
func indexed(t *testing.T, folder string) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(folder, fdroid.IndexJSON))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Repo struct {
			Name map[string]string `json:"name"`
		} `json:"repo"`
		Packages map[string]struct {
			Versions map[string]struct {
				File struct {
					Name string `json:"name"`
				} `json:"file"`
			} `json:"versions"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if index.Repo.Name[fdroid.DefaultLocale] != "Test apps" {
		t.Errorf("the repository is called %v, want its title", index.Repo.Name)
	}
	out := map[string][]string{}
	for name, p := range index.Packages {
		for _, v := range p.Versions {
			out[name] = append(out[name], v.File.Name)
		}
		slices.Sort(out[name])
	}
	return out
}

func TestFDroidListsAPKsAsTheyAre(t *testing.T) {
	r, folder := newFDroidRunner(t, 0)
	original := putAPK(t, folder, "apps/one.apk", fdroidtest.APK{Package: "org.example.one", VersionCode: 1})
	putAPK(t, folder, "two.apk", fdroidtest.APK{Package: "org.example.two", VersionCode: 3})
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	got := indexed(t, folder)
	if len(got) != 2 || got["org.example.one"][0] != "/apps/one.apk" || got["org.example.two"][0] != "/two.apk" {
		t.Errorf("indexed %v", got)
	}
	if data, _ := os.ReadFile(filepath.Join(folder, "apps", "one.apk")); string(data) != string(original) {
		t.Error("an APK was changed; it is to keep the signature of its developer")
	}
	if _, err := os.Stat(filepath.Join(folder, fdroid.EntryJAR)); err != nil {
		t.Errorf("no entry.jar: %v", err)
	}
	if r.status.Packages != 2 || r.status.Fingerprint == "" || r.status.KeyID != "" {
		t.Errorf("status %+v", r.status)
	}
}

func TestFDroidKeepsTheNewestVersionCodes(t *testing.T) {
	r, folder := newFDroidRunner(t, 2)
	for _, code := range []int{3, 10, 1} {
		putAPK(t, folder, "app-"+strings.Repeat("v", code)+".apk", fdroidtest.APK{Package: "org.example.app", VersionCode: code})
	}
	putAPK(t, folder, "other.apk", fdroidtest.APK{Package: "org.example.other", VersionCode: 1})
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	got := indexed(t, folder)
	if want := []string{"/app-vvv.apk", "/app-vvvvvvvvvv.apk"}; !slices.Equal(got["org.example.app"], want) {
		t.Errorf("kept %v, want %v", got["org.example.app"], want)
	}
	if _, err := os.Stat(filepath.Join(folder, "app-v.apk")); !os.IsNotExist(err) {
		t.Errorf("the oldest version is still there: %v", err)
	}
	if len(got["org.example.other"]) != 1 {
		t.Errorf("another package was pruned with it: %v", got)
	}
}

func TestFDroidWritesOnChange(t *testing.T) {
	r, folder := newFDroidRunner(t, 0)
	putAPK(t, folder, "one.apk", fdroidtest.APK{Package: "org.example.one", VersionCode: 1})
	first := time.Now()
	if err := r.update(first); err != nil {
		t.Fatal(err)
	}
	if err := r.update(first.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !r.status.Built.Equal(first) {
		t.Errorf("written again with nothing changed, at %v", r.status.Built)
	}

	// a text beside the APKs is a change, as an APK is
	meta := filepath.Join(folder, "org.example.one", "en-US")
	os.MkdirAll(meta, 0o755)
	os.WriteFile(filepath.Join(meta, "short_description.txt"), []byte("Does one thing"), 0o644)
	second := first.Add(2 * time.Minute)
	if err := r.update(second); err != nil {
		t.Fatal(err)
	}
	if !r.status.Built.Equal(second) {
		t.Error("not written again when the metadata of an app changed")
	}
	data, _ := os.ReadFile(filepath.Join(folder, fdroid.IndexJSON))
	if !strings.Contains(string(data), "Does one thing") {
		t.Error("the summary is not in the index")
	}

	// the folder that holds the icons is not looked into for APKs
	putAPK(t, folder, fdroid.IconFolder+"/stray.apk", fdroidtest.APK{Package: "org.example.stray", VersionCode: 1})
	if err := r.update(second.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := indexed(t, folder)["org.example.stray"]; ok {
		t.Error("an APK in the icon folder is listed")
	}
}

func TestFDroidSkipsWhatIsNotAWholeSignedAPK(t *testing.T) {
	r, folder := newFDroidRunner(t, 0)
	whole := putAPK(t, folder, "arriving.apk", fdroidtest.APK{Package: "org.example.app", VersionCode: 1})
	os.WriteFile(filepath.Join(folder, "arriving.apk"), whole[:len(whole)/2], 0o644)
	putAPK(t, folder, "unsigned.apk", fdroidtest.APK{Package: "org.example.unsigned", VersionCode: 1,
		Scheme: fdroidtest.Unsigned})
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.skipped["arriving.apk"], "still be arriving") ||
		!strings.Contains(r.skipped["unsigned.apk"], "not signed") {
		t.Errorf("skipped %v", r.skipped)
	}
	os.WriteFile(filepath.Join(folder, "arriving.apk"), whole, 0o644)
	if err := r.update(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := indexed(t, folder)["org.example.app"]; !ok {
		t.Error("the APK is not listed once it is whole")
	}
}

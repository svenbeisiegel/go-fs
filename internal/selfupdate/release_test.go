package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
)

// fakeGitHub answers the latest release as the GitHub API does, with the
// update files of every platform, and serves them under /download/.
type fakeGitHub struct {
	*httptest.Server
	tag     atomic.Value
	lookups atomic.Int32
	status  atomic.Int32
}

func newFakeGitHub(t *testing.T, tag string) *fakeGitHub {
	t.Helper()
	fake := &fakeGitHub{}
	fake.tag.Store(tag)
	fake.status.Store(http.StatusOK)
	fake.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := fake.tag.Load().(string)
		switch r.URL.Path {
		case "/latest":
			fake.lookups.Add(1)
			if status := int(fake.status.Load()); status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			version := tag[1:]
			fmt.Fprintf(w, `{"tag_name":%q,"html_url":"https://example/releases/%s",
				"published_at":"2026-10-01T10:00:00Z","assets":[
				{"name":"go-fs.toml","browser_download_url":"%s/download/go-fs.toml"}`,
				tag, tag, fake.URL)
			for _, platform := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"},
				{"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}} {
				name := assetName(version, platform[0], platform[1])
				fmt.Fprintf(w, `,{"name":%q,"browser_download_url":"%s/download/%s"}`, name, fake.URL, name)
			}
			fmt.Fprint(w, `]}`)
		case "/download/" + assetName(tag[1:], runtime.GOOS, runtime.GOARCH):
			fmt.Fprint(w, "signed binary")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)
	return fake
}

func releaseUpdater(fake *fakeGitHub, version string) *Updater {
	u := New(version, nil)
	u.releaseAPI = fake.URL + "/latest"
	return u
}

// The latest release is described, compared with the running version, and
// its update file for this platform found and downloaded.
func TestLatest(t *testing.T) {
	fake := newFakeGitHub(t, "v1.2.0")
	u := releaseUpdater(fake, "1.1.9")
	release, err := u.Latest(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	want := assetName("1.2.0", runtime.GOOS, runtime.GOARCH)
	if release.Version != "1.2.0" || release.Current != "1.1.9" || !release.Newer ||
		release.Asset != want || release.URL != "https://example/releases/v1.2.0" ||
		release.Published == "" {
		t.Errorf("release %+v", release)
	}
	if runtime.GOOS == "windows" && release.Asset[len(release.Asset)-11:] != ".exe.update" {
		t.Errorf("windows asset %q", release.Asset)
	}

	body, err := u.Download(context.Background(), release)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	content, _ := io.ReadAll(body)
	if string(content) != "signed binary" {
		t.Errorf("downloaded %q", content)
	}
}

// A lookup is reused until refresh asks for a new one.
func TestLatestCache(t *testing.T) {
	fake := newFakeGitHub(t, "v1.2.0")
	u := releaseUpdater(fake, "1.2.0")
	for range 3 {
		release, err := u.Latest(context.Background(), false)
		if err != nil {
			t.Fatal(err)
		}
		if release.Newer {
			t.Error("the running version is offered as newer")
		}
	}
	if n := fake.lookups.Load(); n != 1 {
		t.Errorf("%d lookups, want 1", n)
	}
	fake.tag.Store("v1.3.0")
	release, err := u.Latest(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if n := fake.lookups.Load(); n != 2 || release.Version != "1.3.0" || !release.Newer {
		t.Errorf("after refresh: %d lookups, release %+v", n, release)
	}
}

// A release with nothing for this platform is described, but cannot be
// downloaded.
func TestLatestNoAsset(t *testing.T) {
	fake := newFakeGitHub(t, "v1.2.0")
	u := releaseUpdater(fake, "1.0.0")
	release, err := u.lookup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release.Asset, release.download = "", ""
	if _, err := u.Download(context.Background(), release); !errors.Is(err, ErrNoAsset) {
		t.Errorf("download: %v", err)
	}
}

// An answer other than the release is unreachable, and so is no answer.
func TestLatestUnreachable(t *testing.T) {
	fake := newFakeGitHub(t, "v1.2.0")
	fake.status.Store(http.StatusForbidden)
	u := releaseUpdater(fake, "1.0.0")
	if _, err := u.Latest(context.Background(), false); !errors.Is(err, ErrUnreachable) {
		t.Errorf("rate limited: %v", err)
	}

	u.releaseAPI = "http://127.0.0.1:1/latest"
	if _, err := u.Latest(context.Background(), true); !errors.Is(err, ErrUnreachable) {
		t.Errorf("nothing listening: %v", err)
	}

	release, err := releaseUpdater(newFakeGitHub(t, "v1.2.0"), "1.0.0").Latest(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	release.download = fake.URL + "/download/missing"
	if _, err := u.Download(context.Background(), release); !errors.Is(err, ErrUnreachable) {
		t.Errorf("missing file: %v", err)
	}
}

func TestNewerVersion(t *testing.T) {
	tests := []struct {
		released, running string
		newer             bool
	}{
		{"0.9.11", "0.9.10", true},
		{"v0.9.11", "0.9.10", true},
		{"0.10.0", "0.9.10", true},
		{"1.0.0", "0.9.10", true},
		{"1.0", "0.9.10", true},
		{"1.0.1", "1.0", true},
		{"0.9.10", "0.9.10", false},
		{"0.9.9", "0.9.10", false},
		{"1.0", "1.0.0", false},
		// a dev build of a release is not offered that release, only the next
		{"0.9.10", "0.9.10-dev-20261005-101010", false},
		{"0.9.10", "0.9.10-dev", false},
		{"0.9.11", "0.9.10-dev", true},
		{"0.9.11-rc1", "0.9.10", true},
		{"nightly", "0.9.10", false},
		{"0.9.11", "", false},
		{"0.9.11", "dev", false},
		{"1..0", "0.9.0", false},
	}
	for _, test := range tests {
		if got := newerVersion(test.released, test.running); got != test.newer {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", test.released, test.running, got, test.newer)
		}
	}
}

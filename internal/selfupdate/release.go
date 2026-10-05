package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Besides taking an upload, the updater can fetch the .update file of the
// latest release itself. Only the source differs: what is downloaded goes
// through Stage like any upload, so it is installed only when it is signed
// with a key built into this binary. Where it came from is not trusted.
//
// The release is looked up when it is asked for, by the admin interface when
// it opens its update tab or by a script, and never in the background.

// releaseAPI is where the latest release is described, in the form of the
// GitHub API. A fork that publishes its own releases sets it at build time:
//
//	go build -ldflags "-X go-fs/internal/selfupdate.releaseAPI=https://api.github.com/repos/<owner>/<repo>/releases/latest"
var releaseAPI = "https://api.github.com/repos/svenbeisiegel/go-fs/releases/latest"

// releaseTTL is how long a lookup is reused. The admin interface asks on
// every load, and GitHub answers only 60 unauthenticated requests an hour.
const releaseTTL = 15 * time.Minute

// lookupTimeout is how long the description of the release may take; the
// download itself is bounded by the request it is made for.
const lookupTimeout = 10 * time.Second

var (
	// ErrUnreachable is a release that could not be looked up or downloaded.
	ErrUnreachable = errors.New("the release could not be fetched")
	// ErrNoAsset is a release that carries no update file for this platform.
	ErrNoAsset = errors.New("the release has no update file for this platform")
)

// Release describes the latest release and how it compares to the running
// binary.
type Release struct {
	// Current is the version running; Version the one released, without the
	// leading v of its tag.
	Current string `json:"current"`
	Version string `json:"version"`
	// Newer is whether Version is above Current.
	Newer     bool   `json:"newer"`
	URL       string `json:"url"`
	Published string `json:"published"`
	// Asset is the update file for this platform, empty when the release
	// has none.
	Asset string `json:"asset"`

	download string
}

// releaseCache is the last lookup and when it was made.
type releaseCache struct {
	at      time.Time
	release Release
	err     error
}

// Latest describes the latest release, from a lookup at most releaseTTL old
// unless refresh asks for a new one.
func (u *Updater) Latest(ctx context.Context, refresh bool) (Release, error) {
	u.releaseMu.Lock()
	defer u.releaseMu.Unlock()
	if !refresh && !u.release.at.IsZero() && time.Since(u.release.at) < releaseTTL {
		return u.release.release, u.release.err
	}
	release, err := u.lookup(ctx)
	u.release = releaseCache{at: time.Now(), release: release, err: err}
	return release, err
}

func (u *Updater) lookup(ctx context.Context) (Release, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.releaseAPI, nil)
	if err != nil {
		return Release{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "go-fs/"+u.version)
	res, err := u.client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("%w: %s answered %s", ErrUnreachable, u.releaseAPI, res.Status)
	}

	var answer struct {
		Tag       string `json:"tag_name"`
		URL       string `json:"html_url"`
		Published string `json:"published_at"`
		Assets    []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&answer); err != nil {
		return Release{}, fmt.Errorf("%w: the answer cannot be read: %v", ErrUnreachable, err)
	}
	version := strings.TrimPrefix(answer.Tag, "v")
	if version == "" {
		return Release{}, fmt.Errorf("%w: the answer names no release", ErrUnreachable)
	}

	release := Release{
		Current:   u.version,
		Version:   version,
		Newer:     newerVersion(version, u.version),
		URL:       answer.URL,
		Published: answer.Published,
	}
	want := assetName(version, runtime.GOOS, runtime.GOARCH)
	for _, asset := range answer.Assets {
		if asset.Name == want && asset.URL != "" {
			release.Asset = asset.Name
			release.download = asset.URL
			break
		}
	}
	return release, nil
}

// assetName is the update file make release writes for a platform.
func assetName(version, goos, goarch string) string {
	name := "go-fs_" + version + "_" + goos + "_" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name + ".update"
}

// Download opens the update file of a release, to be handed to Stage.
func (u *Updater) Download(ctx context.Context, release Release) (io.ReadCloser, error) {
	if release.download == "" {
		return nil, fmt.Errorf("%w: go-fs %s for %s/%s", ErrNoAsset, release.Version,
			runtime.GOOS, runtime.GOARCH)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, release.download, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "go-fs/"+u.version)
	res, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		return nil, fmt.Errorf("%w: %s answered %s", ErrUnreachable, release.Asset, res.Status)
	}
	return res.Body, nil
}

// newerVersion reports whether the released version is above the running
// one. Only the leading numbers count: a dev build of a version is not
// offered the release it was built from, and a version that is not numbers
// at all is never offered anything.
func newerVersion(released, running string) bool {
	a, okA := versionNumbers(released)
	b, okB := versionNumbers(running)
	if !okA || !okB {
		return false
	}
	for i := range max(len(a), len(b)) {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// versionNumbers reads "v1.2.3-anything" as 1, 2, 3.
func versionNumbers(version string) ([]int, bool) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	version, _, _ = strings.Cut(version, "-")
	version, _, _ = strings.Cut(version, "+")
	if version == "" {
		return nil, false
	}
	var numbers []int
	for _, part := range strings.Split(version, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, false
		}
		numbers = append(numbers, n)
	}
	return numbers, true
}

//go:build !light && !no_fdroid

package repository

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/fdroid"
)

// The F-Droid repository is left out by the tag no_fdroid, and by light.
func init() {
	kinds[config.RepositoryTypeFDroid] = func(repo config.Repository, folder string, _ *slog.Logger) (kind, Status, error) {
		key, err := config.JARKey(repo.SigningKey)
		if err != nil {
			return nil, Status{}, fmt.Errorf("signingKey %w", err)
		}
		return &fdroidKind{repo: repo, folder: folder, key: key},
			Status{Fingerprint: key.Fingerprint()}, nil
	}
}

// fdroidKind is an F-Droid repository. Its APKs are not signed again: they
// keep the signature of their developer, and the index is what is signed.
type fdroidKind struct {
	repo   config.Repository
	folder string
	key    *fdroid.Key
}

// apkRelease is an APK that was read, and apkEntry one ready to be listed.
type apkRelease struct{ apk *fdroid.APK }

type apkEntry struct{ fdroid.Version }

func (r *apkRelease) group() string             { return r.apk.PackageName }
func (r *apkRelease) version() string           { return versionOf(r.apk) }
func (r *apkRelease) compare(other release) int { return compareCodes(r.apk, other) }

func (e apkEntry) group() string             { return e.APK.PackageName }
func (e apkEntry) version() string           { return versionOf(e.APK) }
func (e apkEntry) compare(other release) int { return compareCodes(e.APK, other) }
func (e apkEntry) listing() string {
	return fmt.Sprintf("%s %s %d", e.Href, e.APK.SHA256, e.Added.UnixNano())
}

func versionOf(a *fdroid.APK) string { return fmt.Sprintf("%s (%d)", a.VersionName, a.VersionCode) }

func compareCodes(a *fdroid.APK, other release) int {
	var b *fdroid.APK
	switch o := other.(type) {
	case *apkRelease:
		b = o.apk
	case apkEntry:
		b = o.APK
	default:
		return 0
	}
	switch {
	case a.VersionCode < b.VersionCode:
		return -1
	case a.VersionCode > b.VersionCode:
		return 1
	}
	return 0
}

func (k *fdroidKind) keyID() string              { return k.key.Fingerprint() }
func (k *fdroidKind) isPackage(name string) bool { return strings.HasSuffix(name, ".apk") }
func (k *fdroidKind) skipDir(rel string) bool    { return rel == fdroid.IconFolder }

func (k *fdroidKind) open(path string) (release, error) {
	a, err := fdroid.Open(path)
	if err != nil {
		if errors.Is(err, fdroid.ErrIncomplete) {
			return nil, fmt.Errorf("%w; it may still be arriving", fdroid.ErrIncomplete)
		}
		return nil, err
	}
	return &apkRelease{apk: a}, nil
}

// admit lists the APK as it is, from when it was put into the folder.
func (k *fdroidKind) admit(r release, href string) (entry, error) {
	info, err := os.Stat(filepath.Join(k.folder, filepath.FromSlash(href)))
	if err != nil {
		return nil, err
	}
	return apkEntry{fdroid.Version{Href: href, Added: info.ModTime(), APK: r.(*apkRelease).apk}}, nil
}

func (k *fdroidKind) inputs(entries []entry) string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.group()
	}
	return fdroid.Inputs(k.folder, names, strings.TrimPrefix(k.repo.Icon, "/"))
}

func (k *fdroidKind) write(entries []entry, now time.Time) error {
	versions := make([]fdroid.Version, len(entries))
	for i, e := range entries {
		versions[i] = e.(apkEntry).Version
	}
	repo := fdroid.Repo{
		Name:        k.repo.DisplayName(),
		Description: k.repo.Description,
		Address:     k.repo.URL,
		Icon:        k.repo.Icon,
	}
	if _, err := fdroid.WriteIndex(k.folder, repo, versions, k.key, now); err != nil {
		return fmt.Errorf("writing the index: %w", err)
	}
	return nil
}

func (k *fdroidKind) written() bool {
	_, err := os.Stat(filepath.Join(k.folder, fdroid.EntryJAR))
	return err == nil
}

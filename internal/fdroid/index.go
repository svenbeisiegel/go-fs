// Package fdroid is what an F-Droid repository needs: the APKs in a folder
// read for what the index lists of them, the index in version 2 of its
// format, and the signed entry.jar the F-Droid client reads it by.
//
// The client fetches entry.jar from the address of the repository, checks
// that the certificate it is signed with has the fingerprint the repository
// was added with, and reads the name and digest of index-v2.json from the
// entry.json in it. The APKs themselves are not signed again: they keep the
// signature of their developer, which Android checks when it installs one.
// Clients from before 2023 read only the first version of the index, which is
// not written.
package fdroid

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The files a repository is read by.
const (
	EntryJAR   = "entry.jar"
	EntryJSON  = "entry.json"
	IndexJSON  = "index-v2.json"
	IconFolder = "icons"
)

// formatVersion is the version of the index, the one fdroidserver writes.
const formatVersion = 30000

// Repo is what the index says of the repository.
type Repo struct {
	// Name is the name the client shows, and Description the text under
	// it.
	Name        string
	Description string
	// Address is the address of the repository, which ends in /repo.
	Address string
	// Icon is the image of the repository, by its path in the folder; ""
	// when it has none.
	Icon string
}

// Version is an APK the index lists.
type Version struct {
	// Href is the path of the APK in the folder, with forward slashes.
	Href string
	// Added is when the APK was put into the folder.
	Added time.Time
	APK   *APK
}

// WriteIndex writes the index of versions into folder: the icons of the
// apps, index-v2.json, and entry.json and the entry.jar it is signed in. Each
// file is replaced whole, and entry.jar last, so that a client reading the
// repository meanwhile finds the index entry.jar names. It answers the
// timestamp of the index, which is later than that of the one before even
// when the clock is not.
func WriteIndex(folder string, repo Repo, versions []Version, key *Key, now time.Time) (int64, error) {
	timestamp := now.UnixMilli()
	if before, err := ReadEntry(folder); err == nil && before.Timestamp >= timestamp {
		// the client takes an index no later than the one it has as
		// unchanged
		timestamp = before.Timestamp + 1
	}

	byPackage := map[string][]Version{}
	for _, v := range versions {
		byPackage[v.APK.PackageName] = append(byPackage[v.APK.PackageName], v)
	}

	icons, err := writeIcons(folder, byPackage)
	if err != nil {
		return 0, fmt.Errorf("writing the icons: %w", err)
	}

	index := indexV2{
		Repo: repoV2{
			Name:        localizedText{DefaultLocale: repo.Name},
			Address:     repo.Address,
			Timestamp:   timestamp,
			Description: localizedText{},
		},
		Packages: map[string]packageV2{},
	}
	if repo.Description != "" {
		index.Repo.Description[DefaultLocale] = repo.Description
	}
	if repo.Icon != "" {
		f, err := fileOf(folder, strings.TrimPrefix(repo.Icon, "/"))
		if err != nil {
			return 0, fmt.Errorf("the icon of the repository: %w", err)
		}
		index.Repo.Icon = localizedFile{DefaultLocale: f}
	}
	for name, group := range byPackage {
		meta, err := readMetadata(folder, name)
		if err != nil {
			return 0, fmt.Errorf("the metadata of %s: %w", name, err)
		}
		index.Packages[name] = packageOf(group, meta, icons[name])
	}

	data, err := json.Marshal(index)
	if err != nil {
		return 0, err
	}
	if err := writeAtomic(filepath.Join(folder, IndexJSON), data); err != nil {
		return 0, err
	}
	sum := sha256.Sum256(data)
	entry := Entry{
		Timestamp: timestamp,
		Version:   formatVersion,
		Index: entryFile{
			Name:        "/" + IndexJSON,
			SHA256:      hex.EncodeToString(sum[:]),
			Size:        int64(len(data)),
			NumPackages: len(index.Packages),
		},
	}
	entryData, err := json.Marshal(entry)
	if err != nil {
		return 0, err
	}
	jar, err := signJAR(EntryJSON, entryData, key)
	if err != nil {
		return 0, err
	}
	if err := writeAtomic(filepath.Join(folder, EntryJSON), entryData); err != nil {
		return 0, err
	}
	if err := writeAtomic(filepath.Join(folder, EntryJAR), jar); err != nil {
		return 0, err
	}
	return timestamp, nil
}

// packageOf is the entry of the index for the versions of one app.
func packageOf(group []Version, meta metadata, icon *fileV2) packageV2 {
	// the newest first
	slices.SortFunc(group, func(a, b Version) int {
		if c := compareInt(b.APK.VersionCode, a.APK.VersionCode); c != 0 {
			return c
		}
		return strings.Compare(a.Href, b.Href)
	})
	newest := group[0].APK
	p := packageV2{
		Metadata: metadataV2{
			Name:        meta.name,
			Summary:     meta.summary,
			Description: meta.description,
			Video:       meta.video,
			Screenshots: meta.screenshots,
		},
		Versions: map[string]versionV2{},
	}
	if _, ok := p.Metadata.Name[DefaultLocale]; !ok && newest.Label != "" {
		if p.Metadata.Name == nil {
			p.Metadata.Name = localizedText{}
		}
		p.Metadata.Name[DefaultLocale] = newest.Label
	}
	p.Metadata.Icon = meta.graphics["icon"]
	if _, ok := p.Metadata.Icon[DefaultLocale]; !ok && icon != nil {
		if p.Metadata.Icon == nil {
			p.Metadata.Icon = localizedFile{}
		}
		p.Metadata.Icon[DefaultLocale] = *icon
	}
	p.Metadata.FeatureGraphic = meta.graphics["featureGraphic"]
	p.Metadata.PromoGraphic = meta.graphics["promoGraphic"]
	p.Metadata.TVBanner = meta.graphics["tvBanner"]
	if newest.Signer != "" {
		p.Metadata.PreferredSigner = newest.Signer
	}

	for _, v := range group {
		a := v.APK
		added := v.Added.UnixMilli()
		if p.Metadata.Added == 0 || added < p.Metadata.Added {
			p.Metadata.Added = added
		}
		p.Metadata.LastUpdated = max(p.Metadata.LastUpdated, added)
		version := versionV2{
			Added: added,
			File:  fileV2{Name: "/" + v.Href, SHA256: a.SHA256, Size: a.Size},
			Manifest: manifestV2{
				VersionName:   a.VersionName,
				VersionCode:   a.VersionCode,
				UsesSdk:       &usesSdkV2{MinSdkVersion: a.MinSdkVersion, TargetSdkVersion: a.TargetSdkVersion},
				MaxSdkVersion: a.MaxSdkVersion,
				Nativecode:    a.NativeCode,
			},
			WhatsNew: meta.whatsNew(a.VersionCode),
		}
		if a.Signer != "" {
			version.Manifest.Signer = &signerV2{SHA256: []string{a.Signer}}
		}
		for _, perm := range a.Permissions {
			version.Manifest.UsesPermission = append(version.Manifest.UsesPermission, permissionV2(perm))
		}
		for _, perm := range a.PermissionsSdk23 {
			version.Manifest.UsesPermissionSdk23 = append(version.Manifest.UsesPermissionSdk23, permissionV2(perm))
		}
		for _, feature := range a.Features {
			version.Manifest.Features = append(version.Manifest.Features, featureV2{Name: feature})
		}
		// one file is listed once, whichever names it has
		if _, ok := p.Versions[a.SHA256]; !ok {
			p.Versions[a.SHA256] = version
		}
	}
	return p
}

func compareInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// writeIcons writes the icon of the newest version of each app that has one
// into the icon folder, as <packageName>.<versionCode><ext>, removes the
// icons of versions no longer the newest, and answers the entries of the
// icons by app.
func writeIcons(folder string, byPackage map[string][]Version) (map[string]*fileV2, error) {
	dir := filepath.Join(folder, IconFolder)
	out := map[string]*fileV2{}
	wanted := map[string]bool{}
	for name, group := range byPackage {
		newest := slices.MaxFunc(group, func(a, b Version) int {
			return compareInt(a.APK.VersionCode, b.APK.VersionCode)
		}).APK
		if newest.Icon == nil {
			continue
		}
		file := fmt.Sprintf("%s.%d%s", name, newest.VersionCode, newest.IconExt)
		wanted[file] = true
		path := filepath.Join(dir, file)
		if existing, err := os.ReadFile(path); err != nil || !bytes.Equal(existing, newest.Icon) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
			if err := writeAtomic(path, newest.Icon); err != nil {
				return nil, err
			}
		}
		sum := sha256.Sum256(newest.Icon)
		out[name] = &fileV2{Name: "/" + IconFolder + "/" + file,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(newest.Icon))}
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() && !wanted[e.Name()] && !strings.HasPrefix(e.Name(), ".") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// ReadEntry reads the entry.json in folder.
func ReadEntry(folder string) (Entry, error) {
	var entry Entry
	data, err := os.ReadFile(filepath.Join(folder, EntryJSON))
	if err != nil {
		return entry, err
	}
	err = json.Unmarshal(data, &entry)
	return entry, err
}

// writeAtomic replaces the file at path with data, so that a client reads
// the file before or after, never part of it.
func writeAtomic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// The documents, as the client reads them: org.fdroid.index.v2 of
// fdroidclient. Every name of a file is its path from the address of the
// repository, beginning with a slash.

// Entry is entry.json.
type Entry struct {
	Timestamp int64     `json:"timestamp"`
	Version   int64     `json:"version"`
	Index     entryFile `json:"index"`
}

type entryFile struct {
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	NumPackages int    `json:"numPackages"`
}

type (
	localizedText map[string]string
	localizedFile map[string]fileV2
)

type fileV2 struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type indexV2 struct {
	Repo     repoV2               `json:"repo"`
	Packages map[string]packageV2 `json:"packages"`
}

type repoV2 struct {
	Name        localizedText `json:"name"`
	Icon        localizedFile `json:"icon,omitempty"`
	Address     string        `json:"address"`
	Description localizedText `json:"description,omitempty"`
	Timestamp   int64         `json:"timestamp"`
}

type packageV2 struct {
	Metadata metadataV2           `json:"metadata"`
	Versions map[string]versionV2 `json:"versions"`
}

type metadataV2 struct {
	Added           int64                          `json:"added"`
	LastUpdated     int64                          `json:"lastUpdated"`
	Name            localizedText                  `json:"name,omitempty"`
	Summary         localizedText                  `json:"summary,omitempty"`
	Description     localizedText                  `json:"description,omitempty"`
	Video           localizedText                  `json:"video,omitempty"`
	Icon            localizedFile                  `json:"icon,omitempty"`
	FeatureGraphic  localizedFile                  `json:"featureGraphic,omitempty"`
	PromoGraphic    localizedFile                  `json:"promoGraphic,omitempty"`
	TVBanner        localizedFile                  `json:"tvBanner,omitempty"`
	Screenshots     map[string]map[string][]fileV2 `json:"screenshots,omitempty"`
	PreferredSigner string                         `json:"preferredSigner,omitempty"`
}

type versionV2 struct {
	Added    int64         `json:"added"`
	File     fileV2        `json:"file"`
	Manifest manifestV2    `json:"manifest"`
	WhatsNew localizedText `json:"whatsNew,omitempty"`
}

type manifestV2 struct {
	VersionName         string             `json:"versionName"`
	VersionCode         int64              `json:"versionCode"`
	UsesSdk             *usesSdkV2         `json:"usesSdk,omitempty"`
	MaxSdkVersion       int                `json:"maxSdkVersion,omitempty"`
	Signer              *signerV2          `json:"signer,omitempty"`
	UsesPermission      []usesPermissionV2 `json:"usesPermission,omitempty"`
	UsesPermissionSdk23 []usesPermissionV2 `json:"usesPermissionSdk23,omitempty"`
	Nativecode          []string           `json:"nativecode,omitempty"`
	Features            []featureV2        `json:"features,omitempty"`
}

type usesSdkV2 struct {
	MinSdkVersion    int `json:"minSdkVersion"`
	TargetSdkVersion int `json:"targetSdkVersion"`
}

type signerV2 struct {
	SHA256 []string `json:"sha256"`
}

type usesPermissionV2 struct {
	Name          string `json:"name"`
	MaxSdkVersion int    `json:"maxSdkVersion,omitempty"`
}

func permissionV2(p Permission) usesPermissionV2 {
	return usesPermissionV2(p)
}

type featureV2 struct {
	Name string `json:"name"`
}

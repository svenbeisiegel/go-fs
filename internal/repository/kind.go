package repository

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/fdroid"
	"go-fs/internal/pgp"
	"go-fs/internal/rpm"
)

// kind is what one type of repository knows: which files are its packages,
// how to read them, and the metadata it writes of them. The runner does the
// rest alike for every type: it looks at the folder, reads a package once,
// prunes the old versions and writes the metadata when something changed.
type kind interface {
	// keyID names the key the repository signs with, in the log.
	keyID() string
	// isPackage reports whether a file is a package, by its name.
	isPackage(name string) bool
	// skipDir reports a folder that is not looked into, by its path in the
	// repository with forward slashes; the metadata, for one.
	skipDir(rel string) bool
	// open reads and checks the package at path.
	open(path string) (release, error)
	// admit makes a package that stays in the repository ready to be
	// listed, the one at href that open read.
	admit(r release, href string) (entry, error)
	// inputs identifies what else the metadata is made of than the
	// packages, "" when nothing.
	inputs(entries []entry) string
	// write writes the metadata of entries.
	write(entries []entry, now time.Time) error
	// written reports whether the metadata is still in the folder, which
	// someone may have removed since it was written.
	written() bool
}

// release is a version of a package, as the runner prunes them.
type release interface {
	// group is the same for the versions of one package.
	group() string
	// version is how the log shows the version.
	version() string
	// compare orders two versions of one package, the older first.
	compare(other release) int
}

// entry is a package the metadata lists.
type entry interface {
	release
	// listing identifies the package as the metadata lists it, so that
	// the metadata is written only when it changed.
	listing() string
}

// newKind makes the kind of repo, which is in folder.
func newKind(repo config.Repository, folder string, logger *slog.Logger) (kind, Status, error) {
	switch repo.Type {
	case config.RepositoryTypeFDroid:
		key, err := config.JARKey(repo.SigningKey)
		if err != nil {
			return nil, Status{}, fmt.Errorf("signingKey %w", err)
		}
		return &fdroidKind{repo: repo, folder: folder, key: key},
			Status{Fingerprint: key.Fingerprint()}, nil
	default:
		key, err := config.PGPKey(repo.SigningKey)
		if err != nil {
			return nil, Status{}, fmt.Errorf("signingKey %w", err)
		}
		public, err := key.Public()
		if err != nil {
			return nil, Status{}, err
		}
		return &rpmKind{repo: repo, folder: folder, key: key, public: public, log: logger},
			Status{KeyID: key.KeyID()}, nil
	}
}

// rpmKind is an rpm-md repository.
type rpmKind struct {
	repo   config.Repository
	folder string
	key    *pgp.Key
	public []byte
	log    *slog.Logger
}

// rpmRelease is an rpm that was read, and rpmEntry one ready to be listed.
type rpmRelease struct {
	file *rpm.File
	name string
	arch string
	evr  rpm.EVR
}

type rpmEntry struct{ rpm.Entry }

func (r *rpmRelease) group() string   { return r.name + "." + r.arch }
func (r *rpmRelease) version() string { return r.evr.String() }
func (r *rpmRelease) compare(other release) int {
	return rpm.Compare(r.evr, evrOf(other))
}

func (e rpmEntry) group() string   { return e.Name + "." + e.Arch }
func (e rpmEntry) version() string { return e.EVR.String() }
func (e rpmEntry) compare(other release) int {
	return rpm.Compare(e.EVR, evrOf(other))
}
func (e rpmEntry) listing() string { return fmt.Sprintf("%s %s %d", e.Href, e.Checksum, e.ModTime) }

func evrOf(r release) rpm.EVR {
	switch r := r.(type) {
	case *rpmRelease:
		return r.evr
	case rpmEntry:
		return r.EVR
	}
	return rpm.EVR{}
}

func (k *rpmKind) keyID() string              { return k.key.KeyID() }
func (k *rpmKind) isPackage(name string) bool { return strings.HasSuffix(name, ".rpm") }
func (k *rpmKind) skipDir(rel string) bool    { return filepath.Base(rel) == rpm.RepodataFolder }

func (k *rpmKind) open(path string) (release, error) {
	f, err := rpm.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot be read, it may still be arriving: %w", err)
	}
	if err := f.Verify(); err != nil {
		if errors.Is(err, rpm.ErrIncomplete) {
			// the details change while it arrives, and the reason is
			// logged each time it changes
			return nil, fmt.Errorf("%w; it may still be arriving", rpm.ErrIncomplete)
		}
		return nil, err
	}
	if f.IsSource() {
		return nil, errors.New("is a source package, which the repository does not list")
	}
	p := f.Package()
	return &rpmRelease{file: f, name: p.Name, arch: p.Arch, evr: p.EVR}, nil
}

// admit signs the package with the repository's key, where it was not, and
// reads it for the metadata.
func (k *rpmKind) admit(r release, href string) (entry, error) {
	f := r.(*rpmRelease).file
	if !f.SignedBy(k.key) {
		signed, err := f.Sign(k.key)
		if err != nil {
			return nil, fmt.Errorf("cannot be signed: %w", err)
		}
		f = signed
		k.log.Info("repository signed a package", "package", href, "key", k.key.KeyID())
	}
	e, err := f.Entry(href)
	if err != nil {
		return nil, err
	}
	return rpmEntry{e}, nil
}

func (k *rpmKind) inputs([]entry) string { return "" }

func (k *rpmKind) write(entries []entry, now time.Time) error {
	listed := make([]rpm.Entry, len(entries))
	for i, e := range entries {
		listed[i] = e.(rpmEntry).Entry
	}
	if _, err := rpm.WriteRepodata(k.folder, listed, k.public, func(repomd []byte) ([]byte, error) {
		return k.key.ArmoredSign(bytes.NewReader(repomd))
	}, now); err != nil {
		return fmt.Errorf("writing the metadata: %w", err)
	}
	if err := k.writeDefinition(); err != nil {
		return fmt.Errorf("writing the repository definition: %w", err)
	}
	return nil
}

func (k *rpmKind) written() bool {
	_, err := rpm.ReadRepomd(k.folder)
	return err == nil
}

// writeDefinition writes <name>.repo into the folder, when the repository
// knows the address it is reached at.
func (k *rpmKind) writeDefinition() error {
	if k.repo.URL == "" {
		return nil
	}
	definition := fmt.Sprintf(`[%[1]s]
name=%[1]s
baseurl=%[2]s
type=rpm-md
enabled=1
autorefresh=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=%[2]s/repodata/repomd.xml.key
`, k.repo.Name, k.repo.URL)
	path := filepath.Join(k.folder, k.repo.Name+".repo")
	if existing, err := os.ReadFile(path); err == nil && string(existing) == definition {
		return nil
	}
	return os.WriteFile(path, []byte(definition), 0o644)
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

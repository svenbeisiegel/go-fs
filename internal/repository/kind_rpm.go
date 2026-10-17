//go:build !light && !no_rpm

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
	"go-fs/internal/pgp"
	"go-fs/internal/rpm"
)

// The rpm repository is left out by the tag no_rpm, and by light.
func init() {
	kinds[config.RepositoryTypeRPM] = func(repo config.Repository, folder string, logger *slog.Logger) (kind, Status, error) {
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

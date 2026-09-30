package httpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
)

// registryStore is the on-disk layout of the container registry under
// http.registryBaseFolder:
//
//	blobs/<alg>/<hex[0:2]>/<hex>                 every blob and manifest, once
//	repositories/<name>/_manifests/<alg>/<hex>   the manifests a repository holds
//	repositories/<name>/_tags.json               its tags and what they name
//	repositories/<name>/_layers/<alg>/<hex>      the blobs it may serve
//	repositories/<name>/_referrers/<alg>/<hex>/  the manifests whose subject that is
//	_uploads/<id>/                               the uploads in progress
//
// Nothing in it depends on the platform an image is for: the content is
// addressed by its digest alone, a platform is only ever an entry of an index,
// and a layer shared by two images, two architectures or two repositories is
// kept once. The folders that are not repositories start with an underscore,
// which no repository name may, so no name can reach them.
type registryStore struct {
	base string
}

// revision is what a repository records about a manifest it holds: what the
// manifest is served as, and whether the registry built it itself by merging
// the platforms pushed to one tag.
type revision struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Merged    bool   `json:"merged,omitempty"`
}

var errRegistryNotFound = errors.New("not found")

const (
	registryUploadsFolder = "_uploads"
	registryTagsFile      = "_tags.json"
)

func newRegistryStore(folder string) (*registryStore, error) {
	resolved, err := filepath.EvalSymlinks(folder)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q is not a folder", folder)
	}
	return &registryStore{base: resolved}, nil
}

func (st *registryStore) blobPath(d digest.Digest) string {
	hex := d.Encoded()
	return filepath.Join(st.base, "blobs", d.Algorithm().String(), hex[:2], hex)
}

// repoPath is where a repository is kept. The name has been checked against
// repositoryPattern, so it holds nothing but lowercase letters, digits,
// separators and single slashes between components.
func (st *registryStore) repoPath(name string) string {
	return filepath.Join(st.base, "repositories", filepath.FromSlash(name))
}

func (st *registryStore) revisionPath(name string, d digest.Digest) string {
	return filepath.Join(st.repoPath(name), "_manifests", d.Algorithm().String(), d.Encoded())
}

func (st *registryStore) layerPath(name string, d digest.Digest) string {
	return filepath.Join(st.repoPath(name), "_layers", d.Algorithm().String(), d.Encoded())
}

func (st *registryStore) referrersPath(name string, subject digest.Digest) string {
	return filepath.Join(st.repoPath(name), "_referrers", subject.Algorithm().String(), subject.Encoded())
}

func (st *registryStore) uploadsPath() string {
	return filepath.Join(st.base, registryUploadsFolder)
}

func (st *registryStore) uploadPath(id string) string {
	return filepath.Join(st.uploadsPath(), id)
}

// repoExists reports whether anything was ever pushed to a repository.
func (st *registryStore) repoExists(name string) bool {
	info, err := os.Stat(st.repoPath(name))
	return err == nil && info.IsDir()
}

// blobInfo reports a blob of the store, whichever repository it came from.
func (st *registryStore) blobInfo(d digest.Digest) (os.FileInfo, error) {
	info, err := os.Stat(st.blobPath(d))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errRegistryNotFound
	}
	return info, err
}

// repoBlob reports a blob a repository may serve: one it has a link to and
// the store still holds.
func (st *registryStore) repoBlob(name string, d digest.Digest) (os.FileInfo, error) {
	if _, err := os.Stat(st.layerPath(name, d)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errRegistryNotFound
		}
		return nil, err
	}
	return st.blobInfo(d)
}

// linkBlob lets a repository serve a blob. A link that already exists is
// touched, since its age is what tells the garbage collection that a blob was
// just pushed and its manifest may still be on the way.
func (st *registryStore) linkBlob(name string, d digest.Digest) error {
	return touchFile(st.layerPath(name, d))
}

func (st *registryStore) unlinkBlob(name string, d digest.Digest) error {
	err := os.Remove(st.layerPath(name, d))
	if errors.Is(err, fs.ErrNotExist) {
		return errRegistryNotFound
	}
	return err
}

// commitBlob moves a finished upload into the store under its digest. The
// content is what the digest says, so when the store already holds the blob
// the upload is simply dropped; the one that is kept is touched instead, so
// the garbage collection does not take it for an old, unreferenced one in the
// moment before the push links it.
func (st *registryStore) commitBlob(staged string, d digest.Digest) error {
	target := st.blobPath(d)
	if _, err := os.Stat(target); err == nil {
		_ = os.Remove(staged)
		now := time.Now()
		return os.Chtimes(target, now, now)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o644); err != nil {
		return err
	}
	return os.Rename(staged, target)
}

// putBlob stores bytes the registry already holds in memory, a manifest, as a
// blob under their digest in the given algorithm, and returns that digest.
func (st *registryStore) putBlob(data []byte, algorithm digest.Algorithm) (digest.Digest, error) {
	d := algorithm.FromBytes(data)
	if err := os.MkdirAll(st.uploadsPath(), 0o755); err != nil {
		return "", err
	}
	staged, err := os.CreateTemp(st.uploadsPath(), "blob-*")
	if err != nil {
		return "", err
	}
	name := staged.Name()
	if _, err := staged.Write(data); err != nil {
		_ = staged.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := staged.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := st.commitBlob(name, d); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return d, nil
}

// readBlob reads a whole blob, refusing one larger than limit: what is read
// this way is a manifest or an image configuration, never a layer.
func (st *registryStore) readBlob(d digest.Digest, limit int64) ([]byte, error) {
	file, err := os.Open(st.blobPath(d))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errRegistryNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("blob %s is larger than %d bytes", d, limit)
	}
	return data, nil
}

func (st *registryStore) readRevision(name string, d digest.Digest) (revision, error) {
	data, err := os.ReadFile(st.revisionPath(name, d))
	if errors.Is(err, fs.ErrNotExist) {
		return revision{}, errRegistryNotFound
	}
	if err != nil {
		return revision{}, err
	}
	var rev revision
	if err := json.Unmarshal(data, &rev); err != nil {
		return revision{}, fmt.Errorf("revision %s of %s: %w", d, name, err)
	}
	return rev, nil
}

// revisionTime is when a manifest was last pushed to a repository, or merged
// into one: the revision is written anew each time, and nothing else records
// the time.
func (st *registryStore) revisionTime(name string, d digest.Digest) (time.Time, error) {
	info, err := os.Stat(st.revisionPath(name, d))
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, errRegistryNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (st *registryStore) writeRevision(name string, d digest.Digest, rev revision) error {
	data, err := json.Marshal(rev)
	if err != nil {
		return err
	}
	return writeFileAtomic(st.revisionPath(name, d), data)
}

func (st *registryStore) removeRevision(name string, d digest.Digest) error {
	err := os.Remove(st.revisionPath(name, d))
	if errors.Is(err, fs.ErrNotExist) {
		return errRegistryNotFound
	}
	return err
}

// revisions lists the manifests a repository holds.
func (st *registryStore) revisions(name string) ([]digest.Digest, error) {
	root := filepath.Join(st.repoPath(name), "_manifests")
	algorithms, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var found []digest.Digest
	for _, algorithm := range algorithms {
		entries, err := os.ReadDir(filepath.Join(root, algorithm.Name()))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			d := digest.NewDigestFromEncoded(digest.Algorithm(algorithm.Name()), entry.Name())
			if d.Validate() == nil {
				found = append(found, d)
			}
		}
	}
	return found, nil
}

// readTags reads what each tag of a repository names. A repository nothing
// was ever tagged in has none.
//
// The tags are one file rather than a file each because a tag is case
// sensitive and a file name, on the filesystems macOS and Windows use, is
// not: v1 and V1 would be the same file there.
func (st *registryStore) readTags(name string) (map[string]digest.Digest, error) {
	data, err := os.ReadFile(filepath.Join(st.repoPath(name), registryTagsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]digest.Digest{}, nil
	}
	if err != nil {
		return nil, err
	}
	tags := map[string]digest.Digest{}
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, fmt.Errorf("tags of %s: %w", name, err)
	}
	return tags, nil
}

func (st *registryStore) writeTags(name string, tags map[string]digest.Digest) error {
	data, err := json.MarshalIndent(tags, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(st.repoPath(name), registryTagsFile), data)
}

// addReferrer records that a manifest names subject as its subject.
func (st *registryStore) addReferrer(name string, subject, d digest.Digest) error {
	return touchFile(filepath.Join(st.referrersPath(name, subject), referrerFile(d)))
}

func (st *registryStore) removeReferrer(name string, subject, d digest.Digest) {
	_ = os.Remove(filepath.Join(st.referrersPath(name, subject), referrerFile(d)))
}

// referrers lists the manifests whose subject is the given digest, in the
// order of their digests.
func (st *registryStore) referrers(name string, subject digest.Digest) ([]digest.Digest, error) {
	entries, err := os.ReadDir(st.referrersPath(name, subject))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var found []digest.Digest
	for _, entry := range entries {
		algorithm, encoded, ok := strings.Cut(entry.Name(), "-")
		if !ok {
			continue
		}
		d := digest.NewDigestFromEncoded(digest.Algorithm(algorithm), encoded)
		if d.Validate() == nil {
			found = append(found, d)
		}
	}
	return found, nil
}

// referrerFile is a digest as a file name: a colon is not allowed in one on
// Windows.
func referrerFile(d digest.Digest) string {
	return d.Algorithm().String() + "-" + d.Encoded()
}

// repositories lists every repository that holds a manifest, sorted. A folder
// is a repository when it has a _manifests folder; the folders on the way to
// it are the components of its name, and may be repositories themselves.
func (st *registryStore) repositories() ([]string, error) {
	root := filepath.Join(st.base, "repositories")
	var names []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == root {
				return filepath.SkipDir
			}
			return err
		}
		if !entry.IsDir() || path == root {
			return nil
		}
		if strings.HasPrefix(entry.Name(), "_") {
			return filepath.SkipDir
		}
		if info, err := os.Stat(filepath.Join(path, "_manifests")); err == nil && info.IsDir() {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

// touchFile creates an empty file, with the folders it is in, or brings the
// time of one that exists up to now.
func touchFile(path string) error {
	now := time.Now()
	if err := os.Chtimes(path, now, now); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return file.Close()
}

// writeFileAtomic replaces a file with new content in a way that leaves either
// the old content or the new one on disk, never half of it: the content is
// written and synced beside the target, then renamed over it.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := file.Name()
	fail := func(err error) error {
		_ = file.Close()
		_ = os.Remove(name)
		return err
	}
	if _, err := file.Write(data); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

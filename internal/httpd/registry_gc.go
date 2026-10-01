package httpd

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
)

// sweepRegistry keeps the registry folder from growing without bound: it
// removes the uploads nobody finished, and the blobs no manifest refers to
// any more. It runs with the rest of the hourly cleanup.
func (s *Server) sweepRegistry() {
	store := s.settings().registry
	if store == nil {
		return
	}
	cutoff := time.Now().Add(-stagingMaxAge)
	s.sweepRegistryUploads(store, cutoff)
	s.collectRegistryGarbage(store, cutoff)
}

// registryCleanupGrace is how young a blob or a link may be and still be kept
// when the cleanup is run from the registry page. Someone who just deleted a
// tag wants its blobs gone now, not a day later, so it is far shorter than
// stagingMaxAge; it still covers a push under way, whose layers arrive
// minutes before the manifest that refers to them.
const registryCleanupGrace = 10 * time.Minute

// cleanRegistryNow is the cleanup the registry page asks for, and reports how
// many blobs it removed and how many bytes that freed. Uploads are swept as
// the hourly cleanup sweeps them: a slow one is still arriving.
func (s *Server) cleanRegistryNow(store *registryStore) (int, int64) {
	now := time.Now()
	s.sweepRegistryUploads(store, now.Add(-stagingMaxAge))
	return s.collectRegistryGarbage(store, now.Add(-registryCleanupGrace))
}

// sweepRegistryUploads removes the uploads nothing has been added to since
// cutoff. Every chunk touches the data file and rewrites the record, so an
// upload that is still arriving is never taken for an abandoned one.
func (s *Server) sweepRegistryUploads(store *registryStore, cutoff time.Time) {
	folder := store.uploadsPath()
	entries, err := os.ReadDir(folder)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(folder, entry.Name())
		if !newestChange(path).Before(cutoff) {
			continue
		}
		// a loose file is what a manifest being stored left behind when the
		// server stopped halfway through writing it
		if err := os.RemoveAll(path); err != nil {
			s.log.Error("registry cleanup cannot remove an abandoned upload", "path", path, "error", err)
			continue
		}
		s.log.Info("registry cleanup removed an abandoned upload", "path", path, "age", stagingMaxAge)
	}
}

// newestChange is the time a file, or anything directly in a folder, was last
// changed.
func newestChange(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	newest := info.ModTime()
	if !info.IsDir() {
		return newest
	}
	entries, _ := os.ReadDir(path)
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest
}

// collectRegistryGarbage removes the blobs nothing refers to. A blob is kept
// while a manifest of any repository refers to it, directly or through an
// index, and while it or a link to it is younger than cutoff: a push uploads
// the layers before the manifest that refers to them, and this must never
// take them in between. A link of a repository is removed once no manifest of
// that repository refers to it and it is older than cutoff, so the blob can
// go once no repository needs it.
//
// It holds the registry's lock exclusively for the whole run, so no push adds
// a reference to what it is about to remove. Uploads keep arriving meanwhile;
// only finishing one waits. It returns how many blobs it removed and how many
// bytes that freed.
func (s *Server) collectRegistryGarbage(store *registryStore, cutoff time.Time) (int, int64) {
	s.registryMu.Lock()
	defer s.registryMu.Unlock()

	repositories, err := store.repositoryFolders()
	if err != nil {
		s.log.Error("registry cleanup cannot list the repositories", "error", err)
		return 0, 0
	}
	marked := map[digest.Digest]bool{}
	for _, name := range repositories {
		referenced := map[digest.Digest]bool{}
		revisions, err := store.revisions(name)
		if err != nil {
			// what cannot be read cannot be known to be unreferenced
			s.log.Error("registry cleanup cannot read a repository, nothing is collected",
				"repository", name, "error", err)
			return 0, 0
		}
		for _, d := range revisions {
			markManifest(store, d, referenced, 0)
		}
		for d := range referenced {
			marked[d] = true
		}
		for _, link := range store.links(name) {
			switch {
			case referenced[link.digest]:
			case link.changed.After(cutoff):
				marked[link.digest] = true
			default:
				if err := os.Remove(store.layerPath(name, link.digest)); err == nil {
					s.log.Debug("registry cleanup removed an unreferenced link",
						"repository", name, "digest", link.digest.String())
				}
			}
		}
	}

	removed, freed := 0, int64(0)
	blobs := filepath.Join(store.base, "blobs")
	_ = filepath.WalkDir(blobs, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(blobs, path)
		if err != nil {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 3 {
			return nil
		}
		d := digest.NewDigestFromEncoded(digest.Algorithm(parts[0]), parts[2])
		if d.Validate() != nil || marked[d] {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			s.log.Error("registry cleanup cannot remove a blob", "digest", d.String(), "error", err)
			return nil
		}
		// the fan-out folder goes with its last blob; a folder that still
		// holds one is not removed
		_ = os.Remove(filepath.Dir(path))
		removed++
		freed += info.Size()
		s.log.Info("registry cleanup removed an unreferenced blob", "digest", d.String(),
			"bytes", info.Size())
		return nil
	})
	if removed > 0 {
		s.log.Info("registry cleanup done", "blobs", removed, "bytes", freed)
	}
	return removed, freed
}

// markManifest marks a manifest and everything it refers to. depth keeps an
// index that names itself, through whatever chain, from recursing forever.
func markManifest(store *registryStore, d digest.Digest, marked map[digest.Digest]bool, depth int) {
	if marked[d] && depth > 0 || depth > 8 {
		return
	}
	marked[d] = true
	data, err := store.readBlob(d, maxManifestSize)
	if err != nil {
		return
	}
	var doc manifestDoc
	if json.Unmarshal(data, &doc) != nil {
		return
	}
	// the digests were checked when the manifest was pushed, and are again,
	// since one is about to name a file
	if doc.Config != nil {
		marked[doc.Config.Digest] = true
	}
	for _, layer := range doc.Layers {
		marked[layer.Digest] = true
	}
	for _, entry := range doc.Manifests {
		if _, ok := parseBlobDigest(entry.Digest.String()); ok {
			markManifest(store, entry.Digest, marked, depth+1)
		}
	}
}

// blobLink is a blob a repository links to, and when the link was made or
// last touched.
type blobLink struct {
	digest  digest.Digest
	changed time.Time
}

// links lists the blobs a repository links to.
func (st *registryStore) links(name string) []blobLink {
	root := filepath.Join(st.repoPath(name), "_layers")
	algorithms, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var found []blobLink
	for _, algorithm := range algorithms {
		entries, err := os.ReadDir(filepath.Join(root, algorithm.Name()))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			d := digest.NewDigestFromEncoded(digest.Algorithm(algorithm.Name()), entry.Name())
			info, err := entry.Info()
			if d.Validate() != nil || err != nil {
				continue
			}
			found = append(found, blobLink{digest: d, changed: info.ModTime()})
		}
	}
	return found
}

// repositoryFolders lists every repository anything was pushed to, whether it
// holds a manifest yet or only blobs.
func (st *registryStore) repositoryFolders() ([]string, error) {
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
		for _, own := range []string{"_manifests", "_layers", registryTagsFile} {
			if _, err := os.Stat(filepath.Join(path, own)); err == nil {
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				names = append(names, filepath.ToSlash(rel))
				break
			}
		}
		return nil
	})
	return names, err
}

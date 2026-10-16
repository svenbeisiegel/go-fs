package repository

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go-fs/internal/config"
)

// runner keeps one repository.
type runner struct {
	repo config.Repository
	// base is the folder the http server serves, and folder the one of the
	// repository on disk.
	base   string
	folder string
	kind   kind
	log    *slog.Logger

	// quit is closed to stop the runner, and done once it has stopped.
	quit     chan struct{}
	done     chan struct{}
	launched bool

	// known are the packages read so far, by their path in the repository,
	// so that a package is read once rather than at every look.
	known map[string]known
	// listed is what the metadata written last lists, "" before the first
	// time.
	listed string
	// skipped are the files left out at the last look, with the reason,
	// so that a reason is logged when it first comes up and not every look.
	skipped map[string]string
	status  Status
}

// known is a package as it was when it was read.
type known struct {
	size    int64
	modTime time.Time
	entry   entry
}

func newRunner(repo config.Repository, base string, logger *slog.Logger) (*runner, error) {
	folder := config.RepositoryPath(base, repo.Folder)
	log := logger.With("repository", repo.Name)
	k, status, err := newKind(repo, folder, log)
	if err != nil {
		return nil, err
	}
	return &runner{
		repo:    repo,
		base:    base,
		folder:  folder,
		kind:    k,
		log:     log,
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
		known:   map[string]known{},
		skipped: map[string]string{},
		status:  status,
	}, nil
}

// run looks at the folder at once and then every pollInterval until ctx ends
// or stop is called.
func (r *runner) run(ctx context.Context) {
	defer close(r.done)
	r.log.Info("repository started", "type", r.repo.Type, "folder", r.repo.Folder, "key", r.kind.keyID(),
		"pollInterval", r.repo.Interval())
	r.look()
	ticker := time.NewTicker(time.Duration(r.repo.Interval()) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.quit:
			return
		case <-ticker.C:
			r.look()
		}
	}
}

// stop ends the runner and waits for a look in progress to finish, so that
// the one that replaces it never works on the folder at the same time.
func (r *runner) stop() {
	select {
	case <-r.quit:
	default:
		close(r.quit)
	}
	if r.launched {
		<-r.done
	}
}

func (r *runner) stopped() bool {
	select {
	case <-r.quit:
		return true
	default:
		return false
	}
}

// look is one look at the folder.
func (r *runner) look() {
	err := r.update(time.Now())
	if errors.Is(err, errStopped) {
		return
	}
	r.status.Checked = time.Now()
	r.status.Error = ""
	if err != nil {
		r.status.Error = err.Error()
		r.log.Error("the repository cannot be updated", "error", err)
	}
	r.status.Skipped = maps.Clone(r.skipped)
	if !r.stopped() {
		report(r.repo.Name, r.status)
	}
}

// update brings the repository in line with its folder.
func (r *runner) update(now time.Time) error {
	found, err := r.packages()
	if err != nil {
		return err
	}

	// every package is read and checked first, and the old versions pruned,
	// so that only the packages that stay are admitted
	skipped := map[string]string{}
	var candidates []candidate
	for _, href := range found {
		if r.stopped() {
			return errStopped
		}
		c, err := r.read(href)
		if err != nil {
			skipped[href] = err.Error()
			continue
		}
		candidates = append(candidates, c)
	}
	candidates = r.prune(candidates)

	var entries []entry
	current := map[string]known{}
	for _, c := range candidates {
		if r.stopped() {
			return errStopped
		}
		k, err := r.admit(c)
		if err != nil {
			skipped[c.href] = err.Error()
			continue
		}
		current[c.href] = k
		entries = append(entries, k.entry)
	}
	r.known = current
	r.skip(skipped)

	listing := listingOf(entries) + r.kind.inputs(entries)
	if listing == r.listed && r.kind.written() {
		return nil
	}
	if err := r.kind.write(entries, now); err != nil {
		return err
	}
	r.listed = listing
	r.status.Packages = len(entries)
	r.status.Built = now
	r.log.Info("repository metadata written", "packages", len(entries))
	return nil
}

// packages lists the packages in the folder, by their path in it with
// forward slashes. Folders whose name begins with a dot, and the metadata,
// are not looked into.
func (r *runner) packages() ([]string, error) {
	info, err := os.Stat(r.folder)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", r.repo.Folder)
	}
	var found []string
	err = filepath.WalkDir(r.folder, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == r.folder {
				return err
			}
			// a folder that cannot be read is left out rather than
			// failing the whole repository
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path == r.folder {
				return nil
			}
			rel, err := filepath.Rel(r.folder, path)
			if err != nil || strings.HasPrefix(name, ".") || r.kind.skipDir(filepath.ToSlash(rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") || !r.kind.isPackage(name) || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(r.folder, path)
		if err != nil {
			return nil
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	slices.Sort(found)
	return found, err
}

// candidate is a package found in the folder that checked out: either one
// read before, or one read now.
type candidate struct {
	href string
	// before is what was read of it before, when it did not change since,
	// and opened the package read now otherwise.
	before *known
	opened release
}

// release is the version the candidate is.
func (c candidate) release() release {
	if c.before != nil {
		return c.before.entry
	}
	return c.opened
}

// read reads and checks the package at href, from what was read of it
// before when the file did not change since.
func (r *runner) read(href string) (candidate, error) {
	path := filepath.Join(r.folder, filepath.FromSlash(href))
	info, err := os.Stat(path)
	if err != nil {
		return candidate{}, err
	}
	if before, ok := r.known[href]; ok && before.size == info.Size() && before.modTime.Equal(info.ModTime()) {
		return candidate{href: href, before: &before}, nil
	}
	opened, err := r.kind.open(path)
	if err != nil {
		return candidate{}, err
	}
	return candidate{href: href, opened: opened}, nil
}

// admit makes a package that stays in the repository ready to be listed, as
// its kind does: an rpm is signed with the repository's key, where it was
// not, and read for the metadata.
func (r *runner) admit(c candidate) (known, error) {
	if c.before != nil {
		return *c.before, nil
	}
	e, err := r.kind.admit(c.opened, c.href)
	if err != nil {
		return known{}, err
	}
	// admitting may have changed the file, and it is known as it is now
	info, err := os.Stat(filepath.Join(r.folder, filepath.FromSlash(c.href)))
	if err != nil {
		return known{}, err
	}
	return known{size: info.Size(), modTime: info.ModTime(), entry: e}, nil
}

// skip records the files left out at this look, and logs each the first
// time it is left out for its reason.
func (r *runner) skip(now map[string]string) {
	for href, reason := range now {
		if r.skipped[href] != reason {
			r.log.Warn("repository left out a file", "file", href, "reason", reason)
		}
	}
	r.skipped = now
}

// prune removes the versions of each package beyond keep, the oldest first,
// and answers the packages that are left.
func (r *runner) prune(candidates []candidate) []candidate {
	if r.repo.Keep <= 0 {
		return candidates
	}
	groups := map[string][]candidate{}
	for _, c := range candidates {
		group := c.release().group()
		groups[group] = append(groups[group], c)
	}
	removed := map[string]bool{}
	for _, group := range groups {
		if len(group) <= r.repo.Keep {
			continue
		}
		// the newest first; two files of one version stay in the order of
		// their names
		slices.SortStableFunc(group, func(a, b candidate) int { return b.release().compare(a.release()) })
		for _, old := range group[r.repo.Keep:] {
			path := filepath.Join(r.folder, filepath.FromSlash(old.href))
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				r.log.Error("repository cannot remove an old version", "package", old.href, "error", err)
				continue
			}
			removed[old.href] = true
			r.log.Info("repository removed an old version", "package", old.href,
				"version", old.release().version(), "keep", r.repo.Keep)
		}
	}
	if len(removed) == 0 {
		return candidates
	}
	return slices.DeleteFunc(candidates, func(c candidate) bool { return removed[c.href] })
}

// listingOf identifies what metadata lists, so that it is written only when
// that changed.
func listingOf(entries []entry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.listing())
		b.WriteByte('\n')
	}
	return b.String()
}

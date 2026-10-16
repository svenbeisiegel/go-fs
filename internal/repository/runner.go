package repository

import (
	"bytes"
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
	"go-fs/internal/pgp"
	"go-fs/internal/rpm"
)

// runner keeps one repository.
type runner struct {
	repo config.Repository
	// base is the folder the http server serves, and folder the one of the
	// repository on disk.
	base   string
	folder string
	key    *pgp.Key
	public []byte
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
	entry   rpm.Entry
}

func newRunner(repo config.Repository, base string, logger *slog.Logger) (*runner, error) {
	key, err := config.PGPKey(repo.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("signingKey %w", err)
	}
	public, err := key.Public()
	if err != nil {
		return nil, err
	}
	return &runner{
		repo:    repo,
		base:    base,
		folder:  config.RepositoryPath(base, repo.Folder),
		key:     key,
		public:  public,
		log:     logger.With("repository", repo.Name),
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
		known:   map[string]known{},
		skipped: map[string]string{},
		status:  Status{KeyID: key.KeyID()},
	}, nil
}

// run looks at the folder at once and then every pollInterval until ctx ends
// or stop is called.
func (r *runner) run(ctx context.Context) {
	defer close(r.done)
	r.log.Info("repository started", "folder", r.repo.Folder, "key", r.key.KeyID(),
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
	// so that only the packages that stay are signed
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

	var entries []rpm.Entry
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

	listing := listingOf(entries)
	if listing == r.listed && r.written() {
		return nil
	}
	if _, err := rpm.WriteRepodata(r.folder, entries, r.public, func(repomd []byte) ([]byte, error) {
		return r.key.ArmoredSign(bytes.NewReader(repomd))
	}, now); err != nil {
		return fmt.Errorf("writing the metadata: %w", err)
	}
	if err := r.writeDefinition(); err != nil {
		return fmt.Errorf("writing the repository definition: %w", err)
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
			if path != r.folder && (strings.HasPrefix(name, ".") || name == rpm.RepodataFolder) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".rpm") || !d.Type().IsRegular() {
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
	// and file the package read now otherwise.
	before *known
	file   *rpm.File
	name   string
	arch   string
	evr    rpm.EVR
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
		return candidate{href: href, before: &before,
			name: before.entry.Name, arch: before.entry.Arch, evr: before.entry.EVR}, nil
	}

	f, err := rpm.Open(path)
	if err != nil {
		return candidate{}, fmt.Errorf("cannot be read, it may still be arriving: %w", err)
	}
	if err := f.Verify(); err != nil {
		if errors.Is(err, rpm.ErrIncomplete) {
			// the details change while it arrives, and the reason is
			// logged each time it changes
			return candidate{}, fmt.Errorf("%w; it may still be arriving", rpm.ErrIncomplete)
		}
		return candidate{}, err
	}
	if f.IsSource() {
		return candidate{}, errors.New("is a source package, which the repository does not list")
	}
	p := f.Package()
	return candidate{href: href, file: f, name: p.Name, arch: p.Arch, evr: p.EVR}, nil
}

// admit makes a package that stays in the repository ready to be listed:
// signed with the repository's key, where it was not, and read for the
// metadata.
func (r *runner) admit(c candidate) (known, error) {
	if c.before != nil {
		return *c.before, nil
	}
	f := c.file
	if !f.SignedBy(r.key) {
		signed, err := f.Sign(r.key)
		if err != nil {
			return known{}, fmt.Errorf("cannot be signed: %w", err)
		}
		f = signed
		r.log.Info("repository signed a package", "package", c.href, "key", r.key.KeyID())
	}
	info, err := os.Stat(f.Path)
	if err != nil {
		return known{}, err
	}
	entry, err := f.Entry(c.href)
	if err != nil {
		return known{}, err
	}
	return known{size: info.Size(), modTime: info.ModTime(), entry: entry}, nil
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
		groups[c.name+"."+c.arch] = append(groups[c.name+"."+c.arch], c)
	}
	removed := map[string]bool{}
	for _, group := range groups {
		if len(group) <= r.repo.Keep {
			continue
		}
		// the newest first; two files of one version stay in the order of
		// their names
		slices.SortStableFunc(group, func(a, b candidate) int { return rpm.Compare(b.evr, a.evr) })
		for _, old := range group[r.repo.Keep:] {
			path := filepath.Join(r.folder, filepath.FromSlash(old.href))
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				r.log.Error("repository cannot remove an old version", "package", old.href, "error", err)
				continue
			}
			removed[old.href] = true
			r.log.Info("repository removed an old version", "package", old.href,
				"version", old.evr.String(), "keep", r.repo.Keep)
		}
	}
	if len(removed) == 0 {
		return candidates
	}
	return slices.DeleteFunc(candidates, func(c candidate) bool { return removed[c.href] })
}

// listingOf identifies what metadata lists, so that it is written only when
// that changed.
func listingOf(entries []rpm.Entry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%s %s %d\n", e.Href, e.Checksum, e.ModTime)
	}
	return b.String()
}

// written reports whether the metadata is still in the folder, which
// someone may have removed since it was written.
func (r *runner) written() bool {
	_, err := rpm.ReadRepomd(r.folder)
	return err == nil
}

// writeDefinition writes <name>.repo into the folder, when the repository
// knows the address it is reached at.
func (r *runner) writeDefinition() error {
	if r.repo.URL == "" {
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
`, r.repo.Name, r.repo.URL)
	path := filepath.Join(r.folder, r.repo.Name+".repo")
	if existing, err := os.ReadFile(path); err == nil && string(existing) == definition {
		return nil
	}
	return os.WriteFile(path, []byte(definition), 0o644)
}

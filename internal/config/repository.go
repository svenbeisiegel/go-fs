package config

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"go-fs/internal/pgp"
)

// Repository is a package repository go-fs keeps in a folder it serves over
// HTTP. A package put into the folder by any of the servers, or copied there on
// disk, is picked up at the next look at the folder: it is signed with the
// repository's key, the oldest versions of it beyond Keep are removed, and the
// metadata clients read the repository by is written anew and signed. The
// admin interface adds and edits repositories, on the REPOSITORY tab.
type Repository struct {
	// Name names the repository, in the admin interface and as the id of
	// the repository a client adds. Letters, digits, dots, dashes and
	// underscores; unique, whatever its case.
	Name string `toml:"name"`
	// Type is the kind of repository: rpm, for zypper and dnf.
	Type string `toml:"type"`
	// Folder is where the repository is, a folder of http.basefolder as the
	// file listing shows it, such as /rpm/go-fs. It has to exist.
	Folder string `toml:"folder"`
	// SigningKey is the OpenPGP private key the packages and the metadata
	// are signed with, armored and then base64 as the other keys in this
	// file are, without a passphrase. Only RSA keys are accepted. It is kept
	// as it is, so keep this file private.
	SigningKey string `toml:"signingKey"`
	// Keep is how many versions of each package, by name and architecture,
	// stay in the folder; older ones are removed. 0 keeps every version.
	Keep int `toml:"keep"`
	// PollInterval is how often, in seconds, the folder is looked at for
	// packages that were added, replaced or removed. 60 when not set.
	PollInterval int `toml:"pollInterval,omitempty"`
	// URL is where clients reach the folder, such as
	// https://files.example.com/rpm/go-fs. When set, the repository writes
	// <name>.repo into the folder, the definition zypper and dnf add.
	URL string `toml:"url,omitempty"`
}

// DefaultPollInterval is how often a repository's folder is looked at when
// its pollInterval is not set, in seconds.
const DefaultPollInterval = 60

// minPollInterval is the shortest pollInterval accepted: each look reads the
// whole folder.
const minPollInterval = 5

// Interval is how often the folder is looked at, in seconds.
func (r Repository) Interval() int {
	if r.PollInterval == 0 {
		return DefaultPollInterval
	}
	return r.PollInterval
}

// RepositoryType is a kind of repository.
type RepositoryType struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// RepositoryTypeRPM is an rpm-md repository, read by zypper and dnf.
const RepositoryTypeRPM = "rpm"

// RepositoryTypes are the kinds a repository may be. Another one is added here
// and given an implementation in internal/repository.
var RepositoryTypes = []RepositoryType{
	{ID: RepositoryTypeRPM, Label: "rpm (zypper, dnf)"},
}

// RepositoryTypeOf looks a kind of repository up by its ID.
func RepositoryTypeOf(id string) (RepositoryType, bool) {
	for _, t := range RepositoryTypes {
		if t.ID == id {
			return t, true
		}
	}
	return RepositoryType{}, false
}

// repositoryName is what a name may be: it is the id a client gives the
// repository, and the name of the .repo file.
var repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// RepositoryFolder reads the folder of a repository as it is written in the
// file: a path from the top of the served folder, with a slash in front and
// none behind. The top itself is not one: the repository writes into its
// folder.
func RepositoryFolder(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("name the folder")
	}
	if strings.ContainsAny(raw, "\x00\r\n\\") {
		return "", fmt.Errorf("%q is not a folder", raw)
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return "", fmt.Errorf("%q leaves the served folder", raw)
		}
	}
	clean := path.Clean("/" + raw)
	if clean == "/" {
		return "", errors.New("the repository needs a folder of its own, not the top of the served folder")
	}
	return clean, nil
}

// RepositoryPath is where the folder of the repository is on disk, inside
// basefolder, the folder the http server serves.
func RepositoryPath(basefolder, folder string) string {
	return filepath.Join(basefolder, filepath.FromSlash(strings.TrimPrefix(folder, "/")))
}

// RepositoryURL reads the address clients reach a repository at, without a
// slash at its end; "" is none.
func RepositoryURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "", fmt.Errorf("%q is not an address", raw)
	case u.Scheme != "http" && u.Scheme != "https":
		return "", fmt.Errorf("%q has to begin with https:// or http://", raw)
	case u.Host == "":
		return "", fmt.Errorf("%q names no host", raw)
	case u.RawQuery != "" || u.Fragment != "":
		return "", fmt.Errorf("%q has to be the address alone, without a query", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// FindRepository finds a repository by its name, whatever its case.
func FindRepository(repositories []Repository, name string) (Repository, bool) {
	for _, r := range repositories {
		if strings.EqualFold(r.Name, name) {
			return r, true
		}
	}
	return Repository{}, false
}

// validateRepositories checks the package repositories. Their folders are in
// the folder the http server serves, which is where clients read them.
func (c Config) validateRepositories() error {
	names := map[string]bool{}
	var folders []string
	for i, repo := range c.Repositories {
		where := fmt.Sprintf("repositories[%d]", i)
		if repo.Name == "" {
			return fmt.Errorf("%s has no name", where)
		}
		if !repositoryName.MatchString(repo.Name) {
			return fmt.Errorf("%s %q: a name is letters, digits, dots, dashes and underscores", where, repo.Name)
		}
		if names[strings.ToLower(repo.Name)] {
			return fmt.Errorf("%s: %q is configured twice", where, repo.Name)
		}
		names[strings.ToLower(repo.Name)] = true
		where = fmt.Sprintf("%s %q", where, repo.Name)

		if _, ok := RepositoryTypeOf(repo.Type); !ok {
			known := make([]string, len(RepositoryTypes))
			for k, t := range RepositoryTypes {
				known[k] = t.ID
			}
			return fmt.Errorf("%s: type %q is not one of %s", where, repo.Type, strings.Join(known, ", "))
		}
		folder, err := RepositoryFolder(repo.Folder)
		if err != nil {
			return fmt.Errorf("%s: folder: %w", where, err)
		}
		if folder != repo.Folder {
			return fmt.Errorf("%s: folder %q has to be %q", where, repo.Folder, folder)
		}
		if c.HTTP.Basefolder == "" {
			return fmt.Errorf("%s: a repository is in the folder the http server serves, "+
				"and http.basefolder is not set", where)
		}
		onDisk := RepositoryPath(c.HTTP.Basefolder, folder)
		if err := checkFolder(where+": folder", onDisk); err != nil {
			return err
		}
		for k, other := range folders {
			if overlaps(comparablePath(onDisk), comparablePath(other)) {
				return fmt.Errorf("%s: folder %q overlaps the folder of repositories[%d]", where, folder, k)
			}
		}
		folders = append(folders, onDisk)

		if strings.TrimSpace(repo.SigningKey) == "" {
			return fmt.Errorf("%s has no signingKey", where)
		}
		if _, err := DecodePGPKey(repo.SigningKey); err != nil {
			return fmt.Errorf("%s: signingKey %w", where, err)
		}
		if repo.Keep < 0 {
			return fmt.Errorf("%s: keep cannot be negative", where)
		}
		if repo.PollInterval != 0 && repo.PollInterval < minPollInterval {
			return fmt.Errorf("%s: pollInterval has to be at least %d seconds", where, minPollInterval)
		}
		if address, err := RepositoryURL(repo.URL); err != nil {
			return fmt.Errorf("%s: url: %w", where, err)
		} else if address != repo.URL {
			return fmt.Errorf("%s: url %q has to be %q", where, repo.URL, address)
		}
	}
	return nil
}

// KindPGPKey is the OpenPGP signing key of a repository.
const KindPGPKey = "pgpkey"

// DecodePGPKey turns a configured signing key into the armored key it
// stands for, checked to be one go-fs can sign with.
func DecodePGPKey(value string) ([]byte, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	if _, err := pgp.Parse(decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

// PGPKey parses a configured signing key.
func PGPKey(value string) (*pgp.Key, error) {
	decoded, err := DecodePEM(value)
	if err != nil {
		return nil, err
	}
	return pgp.Parse(decoded)
}

// GeneratePGPKey makes a new signing key for the repository called name, as
// the value the file holds.
func GeneratePGPKey(name string) (string, error) {
	armored, err := pgp.Generate(name)
	if err != nil {
		return "", err
	}
	return Encode(armored), nil
}

func describePGPKey(value string) string {
	key, err := PGPKey(value)
	if err != nil {
		return "this value " + err.Error()
	}
	return key.Describe()
}

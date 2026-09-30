// Package vfs confines path operations to a base folder.
//
// Both servers expose a virtual filesystem to their clients: the client sees
// paths below "/", which are mapped onto a configured base folder. Every path
// a client supplies has to be normalized and then checked, so that neither
// ".." segments nor symbolic links can reach out of that folder.
package vfs

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Root is a base folder that client paths are resolved against.
type Root struct {
	base string
}

// New resolves base, following symbolic links, and returns a Root for it. The
// folder must exist, otherwise nothing can be confined to it.
func New(base string) (*Root, error) {
	if base == "" {
		return nil, errors.New("base folder is not set")
	}
	absolute, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New(absolute + " is not a folder")
	}
	// resolve the base once, so that a symlinked base (/tmp and /var are
	// symlinks on macOS) still compares equal to the resolved targets below it
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	return &Root{base: resolved}, nil
}

// Base returns the resolved base folder.
func (r *Root) Base() string {
	return r.base
}

// Target is a client supplied path resolved against a Root.
type Target struct {
	// Virtual is the normalized path as the client sees it, always starting
	// with a slash.
	Virtual string
	// Path is the location on the filesystem. Only meaningful when Valid.
	Path string
	// Valid reports whether the path stays inside the base folder.
	Valid bool
}

// Resolve normalizes arg against the current working directory cwd and maps it
// onto the filesystem.
func (r *Root) Resolve(cwd, arg string) Target {
	virtual, escaped := Normalize(cwd, arg)
	osPath := filepath.Join(r.base, filepath.FromSlash(virtual))
	return Target{
		Virtual: virtual,
		Path:    osPath,
		Valid:   !escaped && r.Contains(osPath),
	}
}

// Contains reports whether osPath stays inside the base folder once symbolic
// links have been resolved. A link inside the base folder that points out of it
// is therefore rejected.
func (r *Root) Contains(osPath string) bool {
	resolved := resolveReal(osPath)
	if resolved == r.base {
		return true
	}
	return strings.HasPrefix(resolved, r.base+string(filepath.Separator))
}

// Normalize resolves "." and ".." segments of a client supplied path against
// the current working directory. It reports separately whether the path tried
// to climb above the root, so that callers can refuse it instead of silently
// working on a clamped path.
func Normalize(cwd, arg string) (virtual string, escaped bool) {
	raw := arg
	if !strings.HasPrefix(arg, "/") {
		raw = cwd + "/" + arg
	}
	stack := make([]string, 0, 8)
	for _, segment := range strings.Split(raw, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			if len(stack) == 0 {
				return "/", true
			}
			stack = stack[:len(stack)-1]
		default:
			stack = append(stack, segment)
		}
	}
	return "/" + strings.Join(stack, "/"), false
}

// IsRoot reports whether the target is the base folder itself. It is the one
// path a client may see but must not remove, rename or change the mode of:
// deleting it would take the served folder with it.
func (t Target) IsRoot() bool {
	return t.Virtual == "/"
}

// AsFolder returns virtual with a trailing slash.
func AsFolder(virtual string) string {
	if strings.HasSuffix(virtual, "/") {
		return virtual
	}
	return virtual + "/"
}

// resolveReal follows symbolic links for the containment check. A path that
// does not exist yet, as when a file is about to be created, is resolved
// through its closest existing ancestor.
func resolveReal(target string) string {
	current := filepath.Clean(target)
	var missing []string
	for {
		if real, err := filepath.EvalSymlinks(current); err == nil {
			if len(missing) == 0 {
				return real
			}
			slices.Reverse(missing)
			return filepath.Join(append([]string{real}, missing...)...)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(target)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

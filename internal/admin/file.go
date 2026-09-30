package admin

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"

	"go-fs/internal/config"
)

// The file is read and written on every request rather than held in memory, so
// that a change made with an editor while the page is open is what the page
// shows, and so that two people editing it cannot silently overwrite a file
// neither of them has seen.

// read parses the configuration file without resolving general.basefolder into
// the sections. What the page edits has to be what the file says: resolving it
// first and writing the result back would turn the one fallback into four
// explicit copies of it.
func (h *Handler) read() (config.Config, error) {
	data, err := os.ReadFile(h.path)
	if err != nil {
		return config.Config{}, err
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return config.Config{}, fmt.Errorf("%s: %w", h.path, err)
	}
	return cfg, nil
}

// target follows a symlinked configuration file, so that writing replaces what
// the link points at rather than the link.
func (h *Handler) target() string {
	resolved, err := filepath.EvalSymlinks(h.path)
	if err != nil {
		return h.path
	}
	return resolved
}

// writable reports whether Apply could succeed, without changing anything: the
// folder has to be writable, because the new file is written beside the old one
// and renamed over it, and so does the file itself.
//
// The file's own permission is checked although the rename does not need it. A
// configuration made read-only was made read-only on purpose, and replacing it
// through a rename anyway would go around that.
func (h *Handler) writable() error {
	path := h.target()
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_ = file.Close()

	probe, err := os.CreateTemp(filepath.Dir(path), ".go-fs-probe-*")
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Dir(path), err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return nil
}

// write replaces the configuration file and reports where the previous one was
// kept.
//
// The previous file is copied aside first, because this rewrite is made by the
// toml marshaller: it writes every key, and the comments that were in the file
// are not in the struct and do not survive. The new file is written beside the
// target and renamed over it, so that the watcher never reads a half-written
// file.
func (h *Handler) write(cfg config.Config) (string, error) {
	if err := h.writable(); err != nil {
		return "", err
	}
	path := h.target()
	data, err := toml.Marshal(cfg)
	if err != nil {
		return "", err
	}

	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	backup := path + ".bak"
	previous, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(backup, previous, mode); err != nil {
		return "", err
	}

	temporary, err := os.CreateTemp(filepath.Dir(path), ".go-fs-config-*")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	defer os.Remove(name)

	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(name, mode); err != nil {
		return "", err
	}
	if err := os.Rename(name, path); err != nil {
		return "", err
	}
	return backup, nil
}

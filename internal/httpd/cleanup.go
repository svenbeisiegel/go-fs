package httpd

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// cleanupInterval is how often the retention sweep runs, as in the Node
// implementation.
const cleanupInterval = time.Hour

// stagingMaxAge is how long a chunked upload's staging file may sit untouched
// before it is swept as abandoned. It is deliberately far larger than any
// realistic idleUploadBody/readTimeout window, so a staging file that
// survives this long really was abandoned rather than merely slow — do not
// shorten this into a race with a legitimately slow but still-active upload.
const stagingMaxAge = 24 * time.Hour

// runCleanup keeps the configured folders, and the chunked-upload staging
// folder, from growing without bound. It is the one thing in the server that
// deletes without a client having asked, so every removal is reported.
// The configuration is read at every sweep rather than at the start, so a
// folder added to it by a reload is swept without a restart, and one taken
// out of it stops being swept at once.
func (s *Server) runCleanup(ctx context.Context) {
	s.cleanupOnce()
	s.sweepStaging()
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-ticker.C:
			s.cleanupOnce()
			s.sweepStaging()
		}
	}
}

// cleanupOnce sweeps every configured folder once.
func (s *Server) cleanupOnce() {
	entries := s.settings().cfg.Cleanup
	if len(entries) == 0 {
		return
	}
	s.log.Debug("http cleanup sweep", "folders", len(entries))
	for _, entry := range entries {
		target := s.root.Resolve("/", entry.Path)
		if !target.Valid {
			s.log.Error("http cleanup path is outside the served folder", "path", entry.Path)
			continue
		}
		listed, err := readDirectory(target.Path)
		if err != nil {
			s.log.Debug("http cleanup cannot read the folder", "path", entry.Path, "error", err)
			continue
		}

		// readDirectory reports folders first and then files newest first, so
		// the files past the ones to keep are the oldest
		files := make([]string, 0, len(listed))
		for _, item := range listed {
			if item.IsFile {
				files = append(files, item.Name)
			}
		}
		if len(files) <= entry.Keep {
			continue
		}
		for _, name := range files[entry.Keep:] {
			path := filepath.Join(target.Path, name)
			if err := os.Remove(path); err != nil {
				s.log.Error("http cleanup cannot remove the file",
					"path", entry.Path+"/"+name, "error", err)
				continue
			}
			s.log.Info("http cleanup removed a file", "path", entry.Path+"/"+name, "keep", entry.Keep)
		}
	}
}

// sweepStaging removes a chunked upload's staging file once it has sat
// untouched for longer than stagingMaxAge, which is the only thing standing
// between an abandoned upload and a staging folder that grows forever: a
// dropped connection or a client that never comes back leaves its staging
// file exactly where handleChunkedPut wrote it, with nothing else to clean
// it up.
func (s *Server) sweepStaging() {
	set := s.settings()
	folder := stagingFolder(set)
	entries, err := os.ReadDir(folder)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Debug("http cleanup cannot read the upload staging folder",
				"path", folder, "error", err)
		}
		return
	}
	cutoff := time.Now().Add(-stagingMaxAge)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(folder, entry.Name())
		if err := os.Remove(path); err != nil {
			s.log.Error("http cleanup cannot remove an orphaned upload", "path", path, "error", err)
			continue
		}
		s.log.Info("http cleanup removed an orphaned upload", "path", path, "age", stagingMaxAge)
	}
}

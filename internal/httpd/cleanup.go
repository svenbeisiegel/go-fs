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

// runCleanup keeps the chunked-upload staging folder and the registry folder
// from growing without bound. Every removal is reported. The folders of
// [[general.cleanup]] are swept by the cleanup package, not here.
func (s *Server) runCleanup(ctx context.Context) {
	s.sweepStaging()
	s.sweepRegistry()
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-ticker.C:
			s.sweepStaging()
			s.sweepRegistry()
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
	s.sweepMultipart(folder, cutoff)
}

// sweepMultipart removes the S3 multipart uploads nothing has been added to
// since cutoff. A folder is touched every time a part lands in it, so an
// upload that is still sending parts is never taken for an abandoned one.
func (s *Server) sweepMultipart(staging string, cutoff time.Time) {
	folder := filepath.Join(staging, multipartFolder)
	entries, err := os.ReadDir(folder)
	if err != nil {
		return
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !entry.IsDir() || info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(folder, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			s.log.Error("http cleanup cannot remove an abandoned s3 upload", "path", path, "error", err)
			continue
		}
		s.log.Info("http cleanup removed an abandoned s3 upload", "path", path, "age", stagingMaxAge)
	}
}

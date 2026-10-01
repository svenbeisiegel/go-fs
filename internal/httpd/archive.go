package httpd

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"

	"go-fs/internal/vfs"
)

// A folder is downloaded as one file: the listing's Download on a folder asks
// for ?go-fs=archive, and the answer is the folder as a tar.xz, packed while it
// is sent. Nothing is staged, so the size is not known up front and the answer
// carries none.
//
// The archive is reached the way the listing of the folder is, so it needs the
// right that listing needs. What is in it is decided entry by entry, as a GET
// of that entry would be: a sub-folder a protected path or the account's own
// paths keep from the requester is left out, rather than handed over because
// the folder above it was not.

const actionArchive = "archive"

// archiveCompression trades a little of the ratio for speed. The default
// dictionary of 8 MB packs what does not compress — media, archives, the
// files a download folder is mostly made of — at about 1.5 MB/s; one of 1 MB
// packs it four to five times as fast and text about as fast as before.
var archiveCompression = xz.WriterConfig{DictCap: 1 << 20, Matcher: lzma.HashTable4}

// archiveName is what the archive of a folder is called, without the
// extension. The served folder is named after the folder on disk.
func (s *Server) archiveName(target vfs.Target) string {
	name := filepath.Base(target.Path)
	if target.IsRoot() {
		name = filepath.Base(s.root.Base())
	}
	// Base answers a lone separator for a folder at the top of the disk
	if name == "" || name == "." || strings.Trim(name, `/\`) == "" {
		return "root"
	}
	return name
}

// handleArchive answers a folder's archive. The folder has been found to be
// one, and the request permitted to read it.
func (s *Server) handleArchive(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, cred credential) {
	// the one refusal that can still be told to the client: once the archive
	// has started, the status is sent
	if _, err := os.ReadDir(target.Path); err != nil {
		s.log.Error("http cannot read the folder", "path", target.Virtual, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	name := s.archiveName(target)
	w.Header().Set("Content-Type", "application/x-xz")
	w.Header().Set("Content-Disposition", disposition(name+".tar.xz"))
	w.Header().Set("Cache-Control", "no-store")
	// what is in it depends on who asks, as the listing does
	w.Header().Set("Vary", "Cookie")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}

	started := time.Now()
	files, err := s.writeArchive(r.Context(), set, cred.user, target, name, w)
	var sent int64
	if recorder, ok := w.(*responseRecorder); ok {
		sent = recorder.bytes
	}
	if err != nil {
		// the status went out with the first byte, so all that is left is to
		// stop: the client is left with an archive that does not end
		if errors.Is(err, context.Canceled) || isClientGone(err) {
			s.log.Info("http archive download failed", "user", nameOf(cred.user), "folder", target.Virtual,
				"files", files, "bytes", sent, "address", clientAddress(set, r),
				"took", time.Since(started).Round(time.Millisecond), "error", err)
			return
		}
		s.log.Error("http archive download failed", "user", nameOf(cred.user), "folder", target.Virtual,
			"files", files, "bytes", sent, "address", clientAddress(set, r), "error", err)
		return
	}
	s.log.Info("http archive download", "user", nameOf(cred.user), "folder", target.Virtual,
		"files", files, "bytes", sent, "address", clientAddress(set, r),
		"took", time.Since(started).Round(time.Millisecond))
}

// writeArchive packs a folder into out as a tar.xz, every entry under name/,
// and reports how many files went in.
//
// Folders go in so that an empty one survives, and files with what is in them.
// A link goes in as the file it points to, where that is a file inside the
// served folder; a link to a folder is left out, which is also what keeps a
// link that points back up from packing the tree forever. Anything else —
// a socket, a device — is not something a download has to carry.
func (s *Server) writeArchive(ctx context.Context, set *settings, user *account, target vfs.Target, name string, out io.Writer) (int, error) {
	compressed, err := archiveCompression.NewWriter(out)
	if err != nil {
		return 0, err
	}
	archive := tar.NewWriter(compressed)

	files := 0
	err = filepath.WalkDir(target.Path, func(osPath string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if osPath == target.Path && entry == nil {
				return walkErr
			}
			// a name that vanished or cannot be read is skipped, as the listing
			// skips it, rather than ending an archive that is half sent
			s.log.Debug("http archive skips an entry it cannot read", "path", osPath, "error", walkErr)
			return nil
		}
		rel, err := filepath.Rel(target.Path, osPath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		virtual := path.Join(target.Virtual, rel)
		inside := path.Join(name, rel)

		if !s.root.Resolve("/", virtual).Valid ||
			!s.permits(set, user, http.MethodGet, virtual, actRead) {
			s.log.Debug("http archive leaves out a path the account may not read",
				"user", nameOf(user), "path", virtual)
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		switch {
		case entry.IsDir():
			info, err := entry.Info()
			if err != nil {
				return fs.SkipDir
			}
			return archive.WriteHeader(archiveHeader(info, inside+"/"))
		case entry.Type().IsRegular(), entry.Type()&fs.ModeSymlink != 0:
			// Stat rather than the entry's own info, so that a link is the
			// file it points to; Resolve above made sure that is inside
			info, err := os.Stat(osPath)
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			added, err := addFile(archive, osPath, info, inside)
			if added {
				files++
			}
			return err
		default:
			return nil
		}
	})
	if err != nil {
		return files, err
	}
	if err := archive.Close(); err != nil {
		return files, err
	}
	return files, compressed.Close()
}

// addFile writes one file into the archive. A file that cannot be opened is
// left out; one that shrinks while it is read ends the archive, because the
// size its header promised can no longer be kept.
func addFile(archive *tar.Writer, osPath string, info fs.FileInfo, inside string) (bool, error) {
	file, err := os.Open(osPath)
	if err != nil {
		return false, nil
	}
	defer func() { _ = file.Close() }()
	header := archiveHeader(info, inside)
	if err := archive.WriteHeader(header); err != nil {
		return false, err
	}
	if _, err := io.CopyN(archive, file, header.Size); err != nil {
		return false, err
	}
	return true, nil
}

// archiveHeader is the header of one entry. The owner is left out: the ids of
// the account the server runs as mean nothing where the archive is unpacked.
func archiveHeader(info fs.FileInfo, inside string) *tar.Header {
	header := &tar.Header{
		Name:    inside,
		Mode:    int64(info.Mode().Perm()),
		ModTime: info.ModTime(),
	}
	if info.IsDir() {
		header.Typeflag = tar.TypeDir
		return header
	}
	header.Typeflag = tar.TypeReg
	header.Size = info.Size()
	return header
}

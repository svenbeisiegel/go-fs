package httpd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-fs/internal/vfs"
)

// handleGet serves a file as a download and a folder as the browsable listing.
func (s *Server) handleGet(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, cred credential) {
	user := cred.user
	info, err := os.Stat(target.Path)
	if err != nil {
		s.log.Debug("http path not found", "path", target.Virtual, "error", err)
		http.NotFound(w, r)
		return
	}

	if info.IsDir() {
		// The links in a listing are relative, so a folder has to be reached
		// with a trailing slash for them to point inside it: without this,
		// /photos would link to /sub/ instead of /photos/sub/.
		if !strings.HasSuffix(r.URL.Path, "/") {
			redirect := *r.URL
			redirect.Path += "/"
			http.Redirect(w, r, redirect.RequestURI(), http.StatusMovedPermanently)
			return
		}
		entries, err := readDirectory(target.Path)
		if err != nil {
			s.log.Error("http cannot read the folder", "path", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		nonce, err := pageNonce()
		if err != nil {
			s.log.Error("http cannot render the listing", "path", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		page, err := listingPage(vfs.AsFolder(target.Virtual), entries,
			parseSort(r.URL.Query()), s.rightsFor(set, user, target.Virtual),
			s.sessionViewFor(set, r, cred), nonce, set.cfg.MaxChunkSize)
		if err != nil {
			s.log.Error("http cannot render the listing", "path", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Content-Security-Policy", contentPolicy(nonce))
		// the page says who is signed in, so a shared cache must not hand one
		// browser's copy to another
		w.Header().Set("Vary", "Cookie")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(page)
		}
		return
	}
	if !info.Mode().IsRegular() {
		s.log.Debug("http path is not a regular file", "path", target.Virtual,
			"mode", info.Mode().String())
		http.NotFound(w, r)
		return
	}

	file, err := os.Open(target.Path)
	if err != nil {
		// the file is there but cannot be read, which is the server's problem
		// rather than the client's, whatever the 404 says
		s.log.Warn("http cannot open the file", "path", target.Virtual, "error", err)
		http.NotFound(w, r)
		return
	}
	defer func() { _ = file.Close() }()

	name := filepath.Base(target.Path)
	w.Header().Set("Content-Disposition", disposition(name))
	w.Header().Set("Content-Type", typeOf(name).Media)
	// ServeContent adds Content-Length and, unlike the Node implementation,
	// answers a range request, so a large download can be resumed
	started := time.Now()
	http.ServeContent(w, r, name, info.ModTime(), file)

	// what was actually sent, not the size of the file: a range request
	// fetches a part, a conditional one nothing at all, and a HEAD only asks
	if recorder, ok := w.(*responseRecorder); ok {
		if r.Method == http.MethodHead || (recorder.status != http.StatusOK &&
			recorder.status != http.StatusPartialContent) {
			s.log.Debug("http file request answered without a body", "file", target.Virtual,
				"status", recorder.status, "method", r.Method)
			return
		}
		s.log.Info("http download", "user", nameOf(user), "file", target.Virtual,
			"bytes", recorder.bytes, "size", info.Size(), "status", recorder.status,
			"address", clientAddress(set, r), "took", time.Since(started).Round(time.Millisecond))
		return
	}
	s.log.Info("http download", "user", nameOf(user), "file", target.Virtual,
		"bytes", info.Size(), "address", clientAddress(set, r))
}

// handlePut stores an uploaded file. A body of octet-stream is the file; a
// multipart body carries it in a part. Folders above it are created.
//
// replace says the dispatch found the name taken and the account allowed to
// replace what is there; without it a name that is taken is refused, as in the
// Node implementation. The file is opened so that the two cannot be confused: a
// create fails on a name taken since the check, rather than truncating it.
func (s *Server) handlePut(set *settings, w http.ResponseWriter, r *http.Request,
	target vfs.Target, user *account, replace bool) {
	if rangeHeader := r.Header.Get("Content-Range"); rangeHeader != "" {
		s.handleChunkedPut(set, w, r, target, user, rangeHeader, replace)
		return
	}
	if info, err := os.Stat(target.Path); err == nil && (!replace || !info.Mode().IsRegular()) {
		// the original falls through to its not-found handler here
		s.log.Debug("http upload refused, the name is taken", "file", target.Virtual)
		http.NotFound(w, r)
		return
	}

	contentType := r.Header.Get("Content-Type")
	binary := strings.Contains(contentType, "application/octet-stream")
	multipart := strings.Contains(contentType, "multipart")
	if !binary && !multipart {
		s.log.Debug("http upload refused, the body is neither octet-stream nor multipart",
			"file", target.Virtual, "contentType", contentType)
		http.NotFound(w, r)
		return
	}

	if err := os.MkdirAll(filepath.Dir(target.Path), 0o755); err != nil {
		s.log.Error("http cannot create the folder", "path", target.Virtual, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// http.Server's own ReadTimeout, if configured, bounds the whole request
	// including the body: fine for the small ones, but it would cap the
	// duration of a large upload the same way WriteTimeout would cap a
	// download, which is why that one is off by default. Overriding it here
	// with a deadline that is pushed forward on every chunk received turns it
	// into what the config actually documents: how long an upload may go
	// without any data arriving, not how long it may take overall.
	if set.cfg.ReadTimeout > 0 {
		r.Body = &idleUploadBody{
			ReadCloser: r.Body,
			controller: http.NewResponseController(w),
			idle:       seconds(set.cfg.ReadTimeout),
		}
	}

	// maxUploadSize is a limit on the file, so the raw body is allowed the
	// wrapping a multipart request puts around it — otherwise the same file
	// would be accepted sent as octet-stream and refused sent as a form.
	//
	// The cap goes on the request body itself rather than on a reader derived
	// from it, because the multipart parser below reads r.Body and would
	// otherwise take a body of any size; what actually reaches the file is
	// counted again further down. A client that declares its length is turned
	// away before any of it is read.
	var limited *limitedBody
	if set.cfg.MaxUploadSize > 0 {
		bodyLimit := set.cfg.MaxUploadSize
		if multipart {
			bodyLimit += multipartEnvelope
		}
		if r.ContentLength > bodyLimit {
			s.tooLarge(set, w, target)
			return
		}
		limited = &limitedBody{ReadCloser: http.MaxBytesReader(w, r.Body, bodyLimit)}
		r.Body = limited
	}
	body := io.Reader(r.Body)

	if multipart {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			// a body cut short by the limit reaches the parser as a truncated
			// one, which it reports as malformed; what the client actually did
			// is send too much, and that is what it is told
			if tooLarge(err) || limited.hit() {
				s.tooLarge(set, w, target)
				return
			}
			s.log.Debug("http cannot read the upload", "error", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		part, _, err := r.FormFile("file")
		if err != nil {
			// the field is called file by the original, but any single file
			// part is taken rather than failing on the name
			part, err = firstFilePart(r)
			if err != nil {
				s.log.Debug("http upload has no file part", "file", target.Virtual, "error", err)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
		}
		defer func() { _ = part.Close() }()
		body = part
	}

	if set.cfg.MaxUploadSize > 0 {
		// one byte past the limit is enough to know it was passed
		body = io.LimitReader(body, set.cfg.MaxUploadSize+1)
	}
	started := time.Now()
	written, err := s.store(target.Path, body, replace)
	if errors.Is(err, os.ErrExist) {
		// taken between the check and the open
		s.log.Debug("http upload refused, the name is taken", "file", target.Virtual)
		http.NotFound(w, r)
		return
	}
	if err == nil && set.cfg.MaxUploadSize > 0 && written > set.cfg.MaxUploadSize {
		_ = os.Remove(target.Path)
		s.tooLarge(set, w, target)
		return
	}
	if err != nil {
		// nothing half written is left behind, whatever went wrong
		_ = os.Remove(target.Path)
		if tooLarge(err) || limited.hit() {
			s.tooLarge(set, w, target)
			return
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || isClientGone(err) {
			// the client went away halfway, which is its doing and no fault
			// of the server: an info record, with what had arrived by then
			s.log.Info("http upload failed", "user", nameOf(user), "file", target.Virtual,
				"bytes", written, "address", clientAddress(set, r),
				"took", time.Since(started).Round(time.Millisecond), "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		s.log.Error("http upload failed", "user", nameOf(user), "file", target.Virtual,
			"bytes", written, "address", clientAddress(set, r), "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	s.log.Info("http upload", "user", nameOf(user), "file", target.Virtual,
		"bytes", written, "replaced", replace, "address", clientAddress(set, r),
		"took", time.Since(started).Round(time.Millisecond))
	w.WriteHeader(http.StatusOK)
}

// contentRange is a parsed "Content-Range: bytes <start>-<end>/<total>"
// header — the request-side convention this server accepts a chunked upload
// with. RFC 9110 defines that header for a response describing what came
// back from a range request; reusing it here as a request header, one PUT
// per chunk to the same URL, is a convention shared with other resumable
// upload schemes, not a claim that this is what the RFC defines it for.
type contentRange struct {
	start, end, total int64
}

var contentRangePattern = regexp.MustCompile(`^bytes (\d+)-(\d+)/(\d+)$`)

// parseContentRange reads a chunk's declared position. end is inclusive and
// has to fall short of total, which is what start==0 and end==total-1 name
// the first and last chunk of an upload by.
func parseContentRange(header string) (contentRange, bool) {
	m := contentRangePattern.FindStringSubmatch(header)
	if m == nil {
		return contentRange{}, false
	}
	start, err1 := strconv.ParseInt(m[1], 10, 64)
	end, err2 := strconv.ParseInt(m[2], 10, 64)
	total, err3 := strconv.ParseInt(m[3], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || start > end || end >= total {
		return contentRange{}, false
	}
	return contentRange{start: start, end: end, total: total}, true
}

// handleChunkedPut stores one piece of an upload sent as a PUT carrying
// Content-Range: the same URL, once per chunk, each naming the slice of the
// file it carries.
//
// The chunk's start has to be exactly the size the staging file already has
// — that size is the only record of how far the upload has gotten, there is
// no session store of any kind. A chunk that does not fit there is refused
// with 416 and told what size would have fit, so a client can resynchronize
// instead of failing outright. The chunk that reaches the last byte
// finalizes the upload by renaming the staging file onto the real target,
// under the same rule about a name that is taken a whole-file PUT enforces:
// refused unless the dispatch found the account allowed to replace it. Every
// chunk is its own request and is judged on its own, so an upload onto a name
// that is taken needs the right on every chunk, and one that is not needs it
// on none.
func (s *Server) handleChunkedPut(set *settings, w http.ResponseWriter, r *http.Request,
	target vfs.Target, user *account, header string, replace bool) {
	if set.cfg.MaxChunkSize <= 0 {
		s.log.Debug("http chunked upload refused, chunking is disabled", "file", target.Virtual)
		http.NotFound(w, r)
		return
	}
	rng, ok := parseContentRange(header)
	if !ok {
		s.log.Debug("http chunked upload has a malformed Content-Range",
			"file", target.Virtual, "header", header)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !strings.Contains(r.Header.Get("Content-Type"), "application/octet-stream") {
		s.log.Debug("http chunked upload refused, the body is not octet-stream",
			"file", target.Virtual, "contentType", r.Header.Get("Content-Type"))
		http.NotFound(w, r)
		return
	}
	if set.cfg.MaxUploadSize > 0 && rng.total > set.cfg.MaxUploadSize {
		s.tooLarge(set, w, target)
		return
	}
	chunkSize := rng.end - rng.start + 1
	if chunkSize > set.cfg.MaxChunkSize {
		s.chunkTooLarge(set, w, target)
		return
	}

	staging := stagingPath(set, target.Virtual)
	lock := s.uploadLock(target.Virtual)
	lock.Lock()
	defer lock.Unlock()

	if rng.start == 0 {
		if info, err := os.Stat(target.Path); err == nil && (!replace || !info.Mode().IsRegular()) {
			s.log.Debug("http upload refused, the name is taken", "file", target.Virtual)
			http.NotFound(w, r)
			return
		}
		if err := os.MkdirAll(filepath.Dir(target.Path), 0o755); err != nil {
			s.log.Error("http cannot create the folder", "path", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		if err := os.MkdirAll(filepath.Dir(staging), 0o700); err != nil {
			s.log.Error("http cannot create the upload staging folder", "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	var alreadyApplied bool
	if rng.start != 0 {
		info, err := os.Stat(staging)
		switch {
		case err == nil && info.Size() == rng.start:
			// continues the upload already in progress
		case err == nil && info.Size() == rng.end+1:
			// this exact chunk already landed — most likely a retry after the
			// response was lost once the bytes were safely written, such as a
			// finalize that failed on what turned out to be the last chunk.
			// Do not write it again: only pick up wherever finishing was
			// interrupted, the same way a client is expected to retry.
			alreadyApplied = true
		case err == nil:
			s.chunkOutOfSync(w, target, info.Size())
			return
		case errors.Is(err, os.ErrNotExist):
			s.chunkOutOfSync(w, target, 0)
			return
		default:
			s.log.Error("http cannot read the upload in progress", "file", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	started := time.Now()
	if !alreadyApplied {
		// the first chunk (re)creates the staging file from empty — a client
		// that restarts an upload from byte zero is allowed to, rather than
		// being stuck behind whatever a previous, abandoned attempt left staged
		flags := os.O_WRONLY | os.O_CREATE | os.O_APPEND
		if rng.start == 0 {
			flags |= os.O_TRUNC
		}
		file, err := os.OpenFile(staging, flags, 0o600)
		if err != nil {
			s.log.Error("http cannot write the upload in progress", "file", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		if set.cfg.ReadTimeout > 0 {
			r.Body = &idleUploadBody{
				ReadCloser: r.Body,
				controller: http.NewResponseController(w),
				idle:       seconds(set.cfg.ReadTimeout),
			}
		}
		limited := &limitedBody{ReadCloser: http.MaxBytesReader(w, r.Body, chunkSize)}
		r.Body = limited

		written, err := io.Copy(file, r.Body)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err == nil && written != chunkSize {
			// the client stopped short of what it said this chunk carried
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			// only the bytes this chunk was supposed to add are undone: a chunk
			// that already landed stays landed, so the client can always retry
			// with the exact same Content-Range
			_ = os.Truncate(staging, rng.start)
			if tooLarge(err) || limited.hit() {
				s.chunkTooLarge(set, w, target)
				return
			}
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || isClientGone(err) {
				s.log.Info("http chunked upload failed", "user", nameOf(user), "file", target.Virtual,
					"start", rng.start, "end", rng.end, "total", rng.total, "bytes", written,
					"address", clientAddress(set, r), "took", time.Since(started).Round(time.Millisecond), "error", err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}
			s.log.Error("http chunked upload failed", "user", nameOf(user), "file", target.Virtual,
				"start", rng.start, "end", rng.end, "total", rng.total, "bytes", written,
				"address", clientAddress(set, r), "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	if rng.end+1 < rng.total {
		s.log.Debug("http chunk stored", "user", nameOf(user), "file", target.Virtual,
			"start", rng.start, "end", rng.end, "total", rng.total, "address", clientAddress(set, r),
			"took", time.Since(started).Round(time.Millisecond))
		w.WriteHeader(http.StatusOK)
		return
	}

	// the last chunk: what is staged has to match what was promised before it
	// is allowed to become the real file
	info, err := os.Stat(staging)
	if err != nil || info.Size() != rng.total {
		s.log.Error("http chunked upload cannot finalize, the staged size does not match",
			"file", target.Virtual, "want", rng.total, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	if info, err := os.Stat(target.Path); err == nil && (!replace || !info.Mode().IsRegular()) {
		// the name was taken while this upload was in progress — the same
		// refusal a whole-file PUT gives; the staged bytes are left in place
		// rather than discarded, in case the client retries under another name
		s.log.Debug("http upload refused, the name is taken", "file", target.Virtual)
		http.NotFound(w, r)
		return
	}
	if err := finalizeUpload(staging, target.Path, replace); err != nil {
		s.log.Error("http cannot finalize the upload", "file", target.Virtual, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	s.log.Info("http upload", "user", nameOf(user), "file", target.Virtual, "bytes", rng.total,
		"chunked", true, "replaced", replace, "address", clientAddress(set, r),
		"took", time.Since(started).Round(time.Millisecond))
	w.WriteHeader(http.StatusCreated)
}

// chunkOutOfSync answers a chunk whose start does not match what the staging
// file already holds, naming the offset that would have been accepted —
// mirroring how a range GET answers an unsatisfiable range — so a client can
// resynchronize instead of treating the whole upload as failed.
func (s *Server) chunkOutOfSync(w http.ResponseWriter, target vfs.Target, have int64) {
	s.log.Debug("http chunk does not continue the upload in progress",
		"file", target.Virtual, "have", have)
	w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", have))
	http.Error(w, fmt.Sprintf("expected the chunk to start at %d", have),
		http.StatusRequestedRangeNotSatisfiable)
}

// chunkTooLarge answers a chunk whose declared or actual size is above
// maxChunkSize — the per-chunk equivalent of tooLarge, which speaks to
// maxUploadSize instead.
func (s *Server) chunkTooLarge(set *settings, w http.ResponseWriter, target vfs.Target) {
	s.log.Debug("http chunk exceeds the maximum chunk size",
		"file", target.Virtual, "maxChunkSize", set.cfg.MaxChunkSize)
	http.Error(w, fmt.Sprintf("a chunk cannot be larger than %d bytes", set.cfg.MaxChunkSize),
		http.StatusRequestEntityTooLarge)
}

// stagingFolder is where a chunked upload's not-yet-finalized bytes live: the
// configured folder, or a fixed one under the OS temp directory when none is
// set.
func stagingFolder(set *settings) string {
	if set.cfg.UploadStagingFolder != "" {
		return set.cfg.UploadStagingFolder
	}
	return filepath.Join(os.TempDir(), "go-fs-uploads")
}

// stagingPath is where one target's chunked upload is staged while it is in
// progress: one file per virtual path, named from a hash of it so the served
// tree's own folder structure needs no mirroring here.
func stagingPath(set *settings, virtual string) string {
	sum := sha256.Sum256([]byte(virtual))
	return filepath.Join(stagingFolder(set), hex.EncodeToString(sum[:])+".part")
}

// finalizeUpload moves a completed chunked upload's staging file onto its
// real target. Rename is tried first — one syscall, no second read of a
// possibly large file — and only falls back to copying the bytes across when
// that fails, which is what a staging folder configured on a different
// filesystem than basefolder causes: the docs already warn against that, but
// a chunked upload should still be able to finish rather than sitting fully
// staged with no way to complete.
//
// replace is whether the target may already exist. The rename replaces what is
// there either way, under the check the caller made a moment earlier and the
// lock it holds; the copy is where the flag is enforced.
func finalizeUpload(staging, target string, replace bool) error {
	if err := os.Rename(staging, target); err == nil {
		return nil
	}
	if err := copyFile(staging, target, replace); err != nil {
		return err
	}
	return os.Remove(staging)
}

// copyFile copies src onto dst. Without replace it refuses a dst that already
// exists, which is what keeps the guarantee the caller's exists check made a
// moment earlier; with it the file is replaced in place.
func copyFile(src, dst string, replace bool) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, openFlags(replace), 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// uploadLock is the mutex serializing chunked-upload state changes for one
// target path, so two requests finishing the same upload at once cannot both
// pass the exists check and race the rename. Entries are never evicted: each
// is one cheap mutex, retained for as many distinct target paths as have ever
// been chunk-uploaded to this server, which is bounded by the size of the
// served tree itself rather than by request volume.
func (s *Server) uploadLock(virtual string) *sync.Mutex {
	value, _ := s.uploadLocks.LoadOrStore(virtual, &sync.Mutex{})
	return value.(*sync.Mutex)
}

// isClientGone reports whether an error reading the body means the client
// closed its side, which net/http reports in a few shapes.
func isClientGone(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "connection reset") ||
		strings.Contains(message, "broken pipe") ||
		strings.Contains(message, "client disconnected")
}

// disposition builds the Content-Disposition of a download.
//
// The plain filename is quoted, which is what every client reads, and it is
// kept to printable ASCII so that the header says what it means whatever the
// file is called. A name that needed changing to fit there is carried beside it
// in the RFC 5987 form, which is how a client that understands it gets the
// real name back.
func disposition(name string) string {
	plain := make([]rune, 0, len(name))
	exact := true
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7F:
			// a control character has no business in a header
			exact = false
		case r > 0x7F:
			exact = false
			plain = append(plain, '_')
		default:
			plain = append(plain, r)
		}
	}
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(string(plain))
	header := `attachment; filename="` + quoted + `"`
	if exact {
		return header
	}
	return header + "; filename*=UTF-8''" + url.PathEscape(name)
}

// multipartEnvelope is how much of a multipart body is not the file: the
// boundaries and the part headers. It is generous — a single file part needs a
// few hundred bytes — because it is an allowance, not a limit of its own.
const multipartEnvelope = 8 << 10

// tooLarge reports the error MaxBytesReader produces, whether it surfaced from
// the multipart parser or from the copy.
func tooLarge(err error) bool {
	var limit *http.MaxBytesError
	return errors.As(err, &limit)
}

// limitedBody remembers that the limit was reached, because the reader that
// hits it is not always the one that reports it: the multipart parser buffers,
// so it sees a body that stops mid-header and calls that malformed rather than
// passing on the error underneath.
type limitedBody struct {
	io.ReadCloser
	exceeded bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if tooLarge(err) {
		b.exceeded = true
	}
	return n, err
}

// hit is safe on a nil receiver, which is what an upload with no limit has.
func (b *limitedBody) hit() bool {
	return b != nil && b.exceeded
}

// idleUploadBody resets the request's read deadline before every read, so it
// times out an upload that stalls rather than one that is merely slow: a
// connection sending a byte every few seconds keeps pushing the deadline
// forward, and only a gap longer than the configured timeout ends it.
type idleUploadBody struct {
	io.ReadCloser
	controller *http.ResponseController
	idle       time.Duration
}

func (b *idleUploadBody) Read(p []byte) (int, error) {
	if err := b.controller.SetReadDeadline(time.Now().Add(b.idle)); err != nil {
		return 0, err
	}
	return b.ReadCloser.Read(p)
}

// tooLarge answers an upload above http.maxUploadSize with the status that
// says so, rather than reporting a server error for what the client did.
func (s *Server) tooLarge(set *settings, w http.ResponseWriter, target vfs.Target) {
	s.log.Debug("http upload exceeds the maximum size",
		"file", target.Virtual, "maxUploadSize", set.cfg.MaxUploadSize)
	http.Error(w, fmt.Sprintf("the upload is larger than the maximum of %d bytes",
		set.cfg.MaxUploadSize), http.StatusRequestEntityTooLarge)
}

// store writes a body to its final name. Without replace a name that is taken
// is an error rather than a file truncated; with it the file is written over.
func (s *Server) store(osPath string, body io.Reader, replace bool) (int64, error) {
	file, err := os.OpenFile(osPath, openFlags(replace), 0o644)
	if err != nil {
		return 0, err
	}
	written, err := io.Copy(file, body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return written, err
}

// openFlags is how an upload opens its target: creating it, and failing if
// the name is taken, or replacing what is there.
func openFlags(replace bool) int {
	if replace {
		return os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	return os.O_WRONLY | os.O_CREATE | os.O_EXCL
}

// firstFilePart takes whatever file part the request carries, whatever the
// field is called.
func firstFilePart(r *http.Request) (multipartFile, error) {
	for _, parts := range r.MultipartForm.File {
		for _, header := range parts {
			return header.Open()
		}
	}
	return nil, http.ErrMissingFile
}

type multipartFile interface {
	io.ReadCloser
	io.ReaderAt
	io.Seeker
}

// handleDelete removes a file, or a folder when it is empty.
func (s *Server) handleDelete(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, user *account) {
	if target.IsRoot() {
		// removing the served folder would take every path with it
		s.log.Debug("http delete refused, the path is the served folder")
		http.NotFound(w, r)
		return
	}
	info, err := os.Stat(target.Path)
	if err != nil {
		s.log.Debug("http delete target not found", "path", target.Virtual, "error", err)
		http.NotFound(w, r)
		return
	}

	switch {
	case info.Mode().IsRegular():
		if err := os.Remove(target.Path); err != nil {
			s.log.Error("http delete failed", "file", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	case info.IsDir():
		entries, err := os.ReadDir(target.Path)
		if err != nil || len(entries) > 0 {
			// a folder with anything in it is not removed, as in the original
			s.log.Debug("http delete refused, the folder is not empty or cannot be read",
				"folder", target.Virtual, "entries", len(entries), "error", err)
			http.NotFound(w, r)
			return
		}
		if err := os.Remove(target.Path); err != nil {
			s.log.Error("http delete failed", "folder", target.Virtual, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	default:
		s.log.Debug("http delete refused, the path is neither a file nor a folder",
			"path", target.Virtual, "mode", info.Mode().String())
		http.NotFound(w, r)
		return
	}

	s.log.Info("http delete", "user", nameOf(user), "path", target.Virtual,
		"folder", info.IsDir(), "bytes", info.Size(), "address", clientAddress(set, r))
	w.WriteHeader(http.StatusOK)
}

// handleMkcol creates a folder, which is the one thing PUT cannot do: it makes
// the folders above a file, so there is no way to ask it for an empty one.
func (s *Server) handleMkcol(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, user *account) {
	if r.ContentLength != 0 {
		// RFC 4918: a body here describes something this server does not know
		s.log.Debug("http mkdir refused, the request has a body", "folder", target.Virtual)
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}
	if target.IsRoot() {
		s.log.Debug("http mkdir refused, the path is the served folder")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := os.Stat(target.Path); err == nil {
		s.log.Debug("http mkdir refused, the path exists", "folder", target.Virtual)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// deliberately not MkdirAll: a typo in the folder above should be an error
	// rather than a tree nobody asked for
	if err := os.Mkdir(target.Path, 0o755); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "Conflict", http.StatusConflict)
			return
		}
		s.log.Error("http mkdir failed", "folder", target.Virtual, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	s.log.Info("http mkdir", "user", nameOf(user), "folder", target.Virtual,
		"address", clientAddress(set, r))
	w.WriteHeader(http.StatusCreated)
}

// handleMove renames a file or a folder in place.
func (s *Server) handleMove(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, user *account) {
	if target.IsRoot() {
		// renaming the served folder would take every path with it
		s.log.Debug("http rename refused, the path is the served folder")
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(target.Path); err != nil {
		s.log.Debug("http rename source not found", "from", target.Virtual, "error", err)
		http.NotFound(w, r)
		return
	}

	destination, ok := s.destinationOf(set, w, r, target, user)
	if !ok {
		return
	}
	if _, err := os.Stat(destination.Path); err == nil {
		// the same refusal PUT makes for a name that is taken, with the status
		// that says which of the two paths was the problem — a bare 404 here
		// cannot be told apart from a source that is not there
		s.log.Debug("http rename refused, the destination exists",
			"from", target.Virtual, "to", destination.Virtual)
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		return
	}

	if err := os.Rename(target.Path, destination.Path); err != nil {
		s.log.Error("http rename failed", "from", target.Virtual,
			"to", destination.Virtual, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	s.log.Info("http rename", "user", nameOf(user), "from", target.Virtual,
		"to", destination.Virtual, "address", clientAddress(set, r))
	w.WriteHeader(http.StatusNoContent)
}

// destinationOf resolves the Destination header of a MOVE.
//
// The header may be an absolute URL or a path, and only the path is read. The
// result has to name something in the same folder: what this offers is a
// rename, and accepting a destination anywhere else would quietly make it a
// move API with a reach nothing here checks for.
func (s *Server) destinationOf(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, user *account) (vfs.Target, bool) {
	header := r.Header.Get("Destination")
	if header == "" {
		s.log.Debug("http rename has no Destination header", "from", target.Virtual)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return vfs.Target{}, false
	}
	parsed, err := url.Parse(header)
	if err != nil || parsed.Path == "" {
		s.log.Debug("http rename Destination header is not a URL", "from", target.Virtual,
			"destination", header, "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return vfs.Target{}, false
	}

	destination := s.root.Resolve("/", parsed.Path)
	if !destination.Valid || destination.IsRoot() {
		s.log.Debug("http rename destination refused", "destination", parsed.Path)
		http.NotFound(w, r)
		return vfs.Target{}, false
	}
	if folderOf(destination.Virtual) != folderOf(target.Virtual) {
		s.log.Debug("http rename crosses folders", "from", target.Virtual,
			"to", destination.Virtual)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return vfs.Target{}, false
	}
	// where the name lands is checked as well as where it came from, so a
	// rename cannot carry a file out of the scope of the account doing it
	if !s.permits(set, user, methodMove, destination.Virtual, actRename) {
		s.log.Debug("http rename destination not allowed for the account",
			"user", nameOf(user), "path", destination.Virtual)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return vfs.Target{}, false
	}
	return destination, true
}

// folderOf is the folder a virtual path sits in.
func folderOf(virtual string) string {
	return path.Dir(strings.TrimSuffix(virtual, "/"))
}

// pageNonce is the one-off value that lets the listing's own style and script
// run under a policy that allows nothing else.
//
// The alphabet is the URL-safe one, which CSP accepts and which survives being
// written into an attribute: standard base64 has a "+" in it, and html/template
// writes that as &#43;, leaving the page and the header naming values that only
// match once a parser has decoded one of them.
func pageNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// contentPolicy closes the listing page off to everything it does not carry
// itself. connect-src has to stay open to this origin: the buttons on the page
// reach the very server that sent it.
//
// form-action is deliberately not set, because the dialogs submit to
// method="dialog", which some browsers check against it even though it never
// leaves the page.
func contentPolicy(nonce string) string {
	return "default-src 'none'; " +
		"style-src 'nonce-" + nonce + "'; " +
		"script-src 'nonce-" + nonce + "'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"base-uri 'none'"
}

// handleDirectoryReader answers the legacy listing endpoint: a form field dir,
// resolved against the folder the request path is in, answered as links.
func (s *Server) handleDirectoryReader(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target) {
	if err := r.ParseForm(); err != nil {
		http.NotFound(w, r)
		return
	}
	folder := r.FormValue("dir")
	if folder == "" {
		s.log.Debug("http directory reader called without a dir")
		http.NotFound(w, r)
		return
	}

	// the request path names the reader script, so the listing is relative to
	// the folder that script sits in
	base := path.Dir(target.Virtual)
	listed := s.root.Resolve(base, folder)
	if !listed.Valid {
		s.log.Debug("http directory reader path refused", "dir", folder)
		http.NotFound(w, r)
		return
	}
	if info, err := os.Stat(listed.Path); err != nil || !info.IsDir() {
		s.log.Debug("http directory reader folder does not exist", "dir", listed.Virtual)
		http.NotFound(w, r)
		return
	}

	entries, err := readDirectory(listed.Path)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(readerPage(folder, entries))
}

package httpd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
)

// An upload is a folder of its own under _uploads, holding the bytes received
// so far and a record of whose they are. The folder is on the same filesystem
// as the blobs, so finishing an upload is a rename.
const (
	uploadDataFile   = "data"
	uploadRecordFile = "state.json"
)

// registryUpload is the record of an upload in progress.
type registryUpload struct {
	Repository string    `json:"repository"`
	Owner      string    `json:"owner"`
	Started    time.Time `json:"started"`
	// Size is how many bytes have been received, which is what the data file
	// holds once every chunk has been written completely.
	Size int64 `json:"size"`
	// Hash is the SHA-256 of those bytes as far as it has got, kept between
	// chunks so that finishing the upload does not read the whole blob again.
	Hash []byte `json:"hash"`
}

// uploadLocation is where an upload is continued.
func (q *registryRequest) uploadLocation(id string) string {
	return "/v2/" + q.route.name + "/blobs/uploads/" + id
}

// uploadRange is the Range header of an upload: the bytes received so far,
// written the way the specification has it, 0-0 when there are none yet.
func uploadRange(size int64) string {
	end := size - 1
	if end < 0 {
		end = 0
	}
	return fmt.Sprintf("0-%d", end)
}

// startUpload opens an upload. With a digest the body is the whole blob and
// the upload is finished at once; with mount and from the blob is linked from
// another repository if it is there, which needs no upload at all.
func (q *registryRequest) startUpload() {
	query := q.r.URL.Query()
	if mount := query.Get("mount"); mount != "" {
		if q.mountBlob(mount, query.Get("from")) {
			return
		}
	}
	id, upload, err := q.createUpload()
	if err != nil {
		q.internal("cannot start an upload", err)
		return
	}
	if value := query.Get("digest"); value != "" {
		d, ok := parseBlobDigest(value)
		if !ok {
			_ = os.RemoveAll(q.store.uploadPath(id))
			q.fail(errDigestInvalid.with(value))
			return
		}
		if failure := q.appendChunk(id, &upload, -1, -1); failure != nil {
			_ = os.RemoveAll(q.store.uploadPath(id))
			q.fail(failure)
			return
		}
		q.completeUpload(id, &upload, d)
		return
	}
	header := q.w.Header()
	header.Set("Location", q.uploadLocation(id))
	header.Set("Range", uploadRange(0))
	header.Set("Docker-Upload-UUID", id)
	header.Set("Content-Length", "0")
	q.w.WriteHeader(http.StatusAccepted)
}

// mountBlob links a blob another repository holds into this one, and answers
// the request when it could.
func (q *registryRequest) mountBlob(mount, from string) bool {
	d, ok := parseBlobDigest(mount)
	if !ok || !validRepository(from) {
		return false
	}
	if _, err := q.store.repoBlob(from, d); err != nil {
		return false
	}
	q.s.registryMu.RLock()
	err := q.store.linkBlob(q.route.name, d)
	q.s.registryMu.RUnlock()
	if err != nil {
		q.internal("cannot mount a blob", err)
		return true
	}
	q.s.log.Info("registry blob mounted", "repository", q.route.name, "from", from,
		"digest", d.String(), "user", nameOf(q.user), "address", clientAddress(q.set, q.r))
	header := q.w.Header()
	header.Set("Location", "/v2/"+q.route.name+"/blobs/"+d.String())
	header.Set("Docker-Content-Digest", d.String())
	header.Set("Content-Length", "0")
	q.w.WriteHeader(http.StatusCreated)
	return true
}

// createUpload makes the folder of a new upload.
func (q *registryRequest) createUpload() (string, registryUpload, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", registryUpload{}, err
	}
	id := hex.EncodeToString(raw)
	state, err := sha256.New().(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return "", registryUpload{}, err
	}
	upload := registryUpload{Repository: q.route.name, Owner: nameOf(q.user),
		Started: time.Now().UTC(), Hash: state}
	folder := q.store.uploadPath(id)
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return "", registryUpload{}, err
	}
	data, err := os.OpenFile(filepath.Join(folder, uploadDataFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = os.RemoveAll(folder)
		return "", registryUpload{}, err
	}
	_ = data.Close()
	if err := q.saveUpload(id, upload); err != nil {
		_ = os.RemoveAll(folder)
		return "", registryUpload{}, err
	}
	return id, upload, nil
}

func (q *registryRequest) saveUpload(id string, upload registryUpload) error {
	data, err := json.Marshal(upload)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(q.store.uploadPath(id), uploadRecordFile), data)
}

// loadUpload reads the record of an upload this request may continue: one of
// this repository, started by the same account. Anything else is answered as
// an upload that does not exist, which is what it is to this client.
func (q *registryRequest) loadUpload(id string) (registryUpload, *registryError) {
	if !uploadIDPattern.MatchString(id) {
		return registryUpload{}, errUploadUnknown.with(id)
	}
	data, err := os.ReadFile(filepath.Join(q.store.uploadPath(id), uploadRecordFile))
	if err != nil {
		return registryUpload{}, errUploadUnknown.with(id)
	}
	var upload registryUpload
	if err := json.Unmarshal(data, &upload); err != nil ||
		upload.Repository != q.route.name || upload.Owner != nameOf(q.user) {
		return registryUpload{}, errUploadUnknown.with(id)
	}
	return upload, nil
}

// parseChunkRange reads the Content-Range of a registry chunk: "start-end" as the
// specification writes it, and the "bytes start-end/total" of RFC 9110 as
// some clients send it.
func parseChunkRange(value string) (start, end int64, ok bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "bytes")
	value = strings.TrimLeft(value, " =")
	value, _, _ = strings.Cut(value, "/")
	first, last, found := strings.Cut(value, "-")
	if !found {
		return 0, 0, false
	}
	start, err1 := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	end, err2 := strconv.ParseInt(strings.TrimSpace(last), 10, 64)
	if err1 != nil || err2 != nil || start < 0 || end < start {
		return 0, 0, false
	}
	return start, end, true
}

// appendChunk writes the request body to the end of an upload. start is where
// the client says the chunk goes, -1 when it does not say, and length how long
// it says it is, -1 likewise. A chunk lands completely or not at all: one that
// fails halfway is cut off again, so the upload stays where it was and the
// client can send the chunk once more.
func (q *registryRequest) appendChunk(id string, upload *registryUpload, start, length int64) *registryError {
	if start >= 0 && start != upload.Size {
		q.w.Header().Set("Range", uploadRange(upload.Size))
		q.w.Header().Set("Location", q.uploadLocation(id))
		return regErr(http.StatusRequestedRangeNotSatisfiable, "BLOB_UPLOAD_INVALID",
			"the chunk does not continue the upload").with(fmt.Sprintf("expected offset %d", upload.Size))
	}
	limit := q.set.cfg.MaxUploadSize
	if limit > 0 && upload.Size+max(length, 0) > limit {
		return errSizeInvalid.with(fmt.Sprintf("a blob cannot be larger than %d bytes", limit))
	}
	path := filepath.Join(q.store.uploadPath(id), uploadDataFile)
	file, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return errUploadUnknown.with(id)
	}
	defer func() { _ = file.Close() }()
	// whatever a chunk that failed before left behind is not part of the
	// upload: the record says how far it got
	if err := file.Truncate(upload.Size); err != nil {
		q.s.log.Error("registry cannot reset an upload", "upload", id, "error", err)
		return errRegistryInternal
	}
	if _, err := file.Seek(upload.Size, io.SeekStart); err != nil {
		return errRegistryInternal
	}
	sum := sha256.New()
	if err := sum.(encoding.BinaryUnmarshaler).UnmarshalBinary(upload.Hash); err != nil {
		q.s.log.Error("registry cannot resume the hash of an upload", "upload", id, "error", err)
		return errRegistryInternal
	}
	var body io.Reader = http.NoBody
	if q.r.Body != nil {
		body = q.r.Body
	}
	if limit > 0 {
		body = io.LimitReader(body, limit-upload.Size+1)
	}
	written, err := io.Copy(io.MultiWriter(file, sum), body)
	undo := func() { _ = file.Truncate(upload.Size) }
	if err != nil {
		undo()
		if isClientGone(err) {
			q.s.log.Info("registry upload interrupted", "repository", q.route.name, "upload", id,
				"user", nameOf(q.user), "address", clientAddress(q.set, q.r), "error", err)
		}
		return errUploadInvalid.with("the chunk could not be read completely")
	}
	if limit > 0 && upload.Size+written > limit {
		undo()
		return errSizeInvalid.with(fmt.Sprintf("a blob cannot be larger than %d bytes", limit))
	}
	if length >= 0 && written != length {
		undo()
		return errUploadInvalid.with(fmt.Sprintf("the chunk holds %d bytes where its range says %d",
			written, length))
	}
	state, err := sum.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		undo()
		return errRegistryInternal
	}
	previous := *upload
	upload.Size += written
	upload.Hash = state
	if err := q.saveUpload(id, *upload); err != nil {
		*upload = previous
		undo()
		q.s.log.Error("registry cannot record an upload", "upload", id, "error", err)
		return errRegistryInternal
	}
	return nil
}

// chunkRange reads where a chunk goes from its Content-Range, if it has one.
func (q *registryRequest) chunkRange() (start, length int64, failure *registryError) {
	value := q.r.Header.Get("Content-Range")
	if value == "" {
		return -1, -1, nil
	}
	first, last, ok := parseChunkRange(value)
	if !ok {
		return 0, 0, regErr(http.StatusRequestedRangeNotSatisfiable, "BLOB_UPLOAD_INVALID",
			"the Content-Range of the chunk cannot be read").with(value)
	}
	return first, last - first + 1, nil
}

// patchUpload adds a chunk to an upload. A chunk without Content-Range is the
// rest of the blob streamed in one request, which is how docker sends a layer.
func (q *registryRequest) patchUpload() {
	id := q.route.ref
	lock := q.uploadLock(id)
	lock.Lock()
	defer lock.Unlock()
	upload, failure := q.loadUpload(id)
	if failure != nil {
		q.fail(failure)
		return
	}
	start, length, failure := q.chunkRange()
	if failure == nil {
		failure = q.appendChunk(id, &upload, start, length)
	}
	if failure != nil {
		q.fail(failure)
		return
	}
	header := q.w.Header()
	header.Set("Location", q.uploadLocation(id))
	header.Set("Range", uploadRange(upload.Size))
	header.Set("Docker-Upload-UUID", id)
	header.Set("Content-Length", "0")
	q.w.WriteHeader(http.StatusAccepted)
}

// finishUpload takes the last chunk, if the request carries one, and turns
// the upload into a blob under the digest the client names.
func (q *registryRequest) finishUpload() {
	id := q.route.ref
	lock := q.uploadLock(id)
	lock.Lock()
	defer lock.Unlock()
	upload, failure := q.loadUpload(id)
	if failure != nil {
		q.fail(failure)
		return
	}
	value := q.r.URL.Query().Get("digest")
	d, ok := parseBlobDigest(value)
	if !ok {
		q.fail(errDigestInvalid.with(value))
		return
	}
	start, length, failure := q.chunkRange()
	if failure == nil {
		failure = q.appendChunk(id, &upload, start, length)
	}
	if failure != nil {
		q.fail(failure)
		return
	}
	q.completeUpload(id, &upload, d)
}

// completeUpload checks the bytes of an upload against the digest the client
// names and moves them into the store. A mismatch ends the upload: the client
// has to start again either way.
func (q *registryRequest) completeUpload(id string, upload *registryUpload, d digest.Digest) {
	started := time.Now()
	folder := q.store.uploadPath(id)
	data := filepath.Join(folder, uploadDataFile)
	actual, err := uploadDigest(data, upload, d.Algorithm())
	if err != nil {
		_ = os.RemoveAll(folder)
		q.internal("cannot hash an upload", err)
		return
	}
	if actual != d {
		_ = os.RemoveAll(folder)
		q.s.log.Info("registry upload refused, the digest does not match", "repository", q.route.name,
			"digest", d.String(), "actual", actual.String(), "user", nameOf(q.user),
			"address", clientAddress(q.set, q.r))
		q.fail(errDigestInvalid.with(d.String()))
		return
	}
	if err := syncFile(data); err != nil {
		_ = os.RemoveAll(folder)
		q.internal("cannot write an upload", err)
		return
	}
	q.s.registryMu.RLock()
	err = q.store.commitBlob(data, d)
	if err == nil {
		err = q.store.linkBlob(q.route.name, d)
	}
	q.s.registryMu.RUnlock()
	_ = os.RemoveAll(folder)
	if err != nil {
		q.internal("cannot store a blob", err)
		return
	}
	q.s.log.Info("registry blob pushed", "repository", q.route.name, "digest", d.String(),
		"bytes", upload.Size, "user", nameOf(q.user), "address", clientAddress(q.set, q.r),
		"took", time.Since(started).Round(time.Millisecond))
	header := q.w.Header()
	header.Set("Location", "/v2/"+q.route.name+"/blobs/"+d.String())
	header.Set("Docker-Content-Digest", d.String())
	header.Set("Content-Length", "0")
	q.w.WriteHeader(http.StatusCreated)
}

// uploadDigest is the digest of an upload's bytes in the given algorithm:
// from the hash kept along the way for SHA-256, by reading the bytes again for
// anything else.
func uploadDigest(path string, upload *registryUpload, algorithm digest.Algorithm) (digest.Digest, error) {
	if algorithm == digest.SHA256 {
		sum := sha256.New()
		if err := sum.(encoding.BinaryUnmarshaler).UnmarshalBinary(upload.Hash); err != nil {
			return "", err
		}
		return digest.NewDigest(algorithm, sum), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	var sum hash.Hash = algorithm.Hash()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return digest.NewDigest(algorithm, sum), nil
}

// syncFile flushes a file to the disk, so that what is renamed into the store
// is there after a crash.
func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// uploadStatus says how far an upload has got.
func (q *registryRequest) uploadStatus() {
	upload, failure := q.loadUpload(q.route.ref)
	if failure != nil {
		q.fail(failure)
		return
	}
	header := q.w.Header()
	header.Set("Location", q.uploadLocation(q.route.ref))
	header.Set("Range", uploadRange(upload.Size))
	header.Set("Docker-Upload-UUID", q.route.ref)
	header.Set("Content-Length", "0")
	q.w.WriteHeader(http.StatusNoContent)
}

// cancelUpload drops an upload and what it has received.
func (q *registryRequest) cancelUpload() {
	id := q.route.ref
	lock := q.uploadLock(id)
	lock.Lock()
	defer lock.Unlock()
	if _, failure := q.loadUpload(id); failure != nil {
		q.fail(failure)
		return
	}
	if err := os.RemoveAll(q.store.uploadPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		q.internal("cannot cancel an upload", err)
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}

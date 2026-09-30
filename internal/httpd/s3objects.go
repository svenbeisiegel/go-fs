package httpd

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// s3GetObject answers GetObject and HeadObject. A key ending with a slash is a
// folder, which S3 serves as an object of no bytes.
func (s *Server) s3GetObject(q *s3Request, obj s3Object) {
	if !q.may(obj.target.Virtual, actRead) {
		q.fail(errAccessDenied)
		return
	}
	info, err := os.Stat(obj.target.Path)
	if err != nil || obj.folder != info.IsDir() || (!obj.folder && !info.Mode().IsRegular()) {
		// "docs" is not the folder "docs/", and "docs/" is not the file "docs"
		q.fail(errNoSuchKey)
		return
	}
	header := q.w.Header()
	header.Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	if obj.folder {
		header.Set("ETag", emptyETag)
		header.Set("Content-Type", "application/x-directory")
		header.Set("Content-Length", "0")
		q.w.WriteHeader(http.StatusOK)
		return
	}

	file, err := os.Open(obj.target.Path)
	if err != nil {
		s.log.Warn("s3 cannot open the file", "path", obj.target.Virtual, "error", err)
		q.fail(errNoSuchKey)
		return
	}
	defer func() { _ = file.Close() }()

	header.Set("ETag", syntheticETag(info))
	header.Set("Content-Type", typeOf(obj.target.Path).Media)
	// what a presigned URL asks the download to be sent as
	for _, name := range []string{"Cache-Control", "Content-Disposition", "Content-Encoding",
		"Content-Language", "Content-Type", "Expires"} {
		if value := q.r.URL.Query().Get("response-" + strings.ToLower(name)); value != "" {
			header.Set(name, value)
		}
	}
	started := time.Now()
	http.ServeContent(q.w, q.r, "", info.ModTime(), file)

	recorder, ok := q.w.(*responseRecorder)
	if q.r.Method == http.MethodHead || !ok ||
		(recorder.status != http.StatusOK && recorder.status != http.StatusPartialContent) {
		return
	}
	s.log.Info("s3 download", "user", q.user.name, "file", obj.target.Virtual,
		"bytes", recorder.bytes, "size", info.Size(), "status", recorder.status,
		"address", clientAddress(q.set, q.r), "took", time.Since(started).Round(time.Millisecond))
}

// s3PutObject answers PutObject. A key ending with a slash creates a folder,
// which is how every S3 client makes one.
func (s *Server) s3PutObject(q *s3Request, obj s3Object) {
	if obj.folder {
		s.s3PutFolder(q, obj)
		return
	}
	info, err := os.Stat(obj.target.Path)
	exists := err == nil
	if exists && info.IsDir() {
		q.fail(errFolderInTheWay)
		return
	}
	act := actCreate
	if exists {
		act = actOverwrite
	}
	if !q.may(obj.target.Virtual, act) {
		q.fail(errAccessDenied)
		return
	}
	if failure := checkWriteConditions(q.r, info, exists); failure != nil {
		q.fail(failure)
		return
	}
	if max := q.set.cfg.MaxUploadSize; max > 0 && declaredSize(q.r) > max {
		q.fail(errTooLarge())
		return
	}

	body, failure := openS3Body(q.r, q.sig)
	if failure != nil {
		q.fail(failure)
		return
	}
	started := time.Now()
	staged, written, failure := s.stageS3Body(q, body, stagingFolder(q.set))
	if failure != nil {
		q.fail(failure)
		return
	}
	defer func() { _ = os.Remove(staged) }()

	replaced, failure := s.placeS3File(q, obj, staged)
	if failure != nil {
		q.fail(failure)
		return
	}
	s.log.Info("s3 upload", "user", q.user.name, "file", obj.target.Virtual, "bytes", written,
		"replaced", replaced, "address", clientAddress(q.set, q.r),
		"took", time.Since(started).Round(time.Millisecond))
	q.w.Header().Set("ETag", body.etag())
	if name, value := body.checksumHeader(); name != "" {
		q.w.Header().Set(name, value)
	}
	q.w.WriteHeader(http.StatusOK)
}

// declaredSize is the size of the object a request says it sends, -1 when it
// does not say.
func declaredSize(r *http.Request) int64 {
	if declared := r.Header.Get("X-Amz-Decoded-Content-Length"); declared != "" {
		if size, err := strconv.ParseInt(declared, 10, 64); err == nil {
			return size
		}
		return -1
	}
	return r.ContentLength
}

func errTooLarge() *s3Error {
	return s3Err(http.StatusBadRequest, "EntityTooLarge",
		"Your proposed upload exceeds the maximum allowed size.")
}

// checkWriteConditions honours If-None-Match: * — create the object only if
// there is none — and If-Match, which the SDKs use for a conditional write.
func checkWriteConditions(r *http.Request, info os.FileInfo, exists bool) *s3Error {
	if match := r.Header.Get("If-None-Match"); match != "" {
		if match == "*" && exists {
			return errPrecondition
		}
		if exists && match == syntheticETag(info) {
			return errPrecondition
		}
	}
	if match := r.Header.Get("If-Match"); match != "" {
		if !exists {
			return errNoSuchKey
		}
		if match != "*" && match != syntheticETag(info) {
			return errPrecondition
		}
	}
	return nil
}

// stageS3Body writes the body of an upload to a new file in folder, and checks
// every hash the request declared once it is complete. Nothing reaches the
// served folder before that: a body whose hash does not match is thrown away
// rather than replacing what was there.
func (s *Server) stageS3Body(q *s3Request, body *s3Body, folder string) (string, int64, *s3Error) {
	if err := os.MkdirAll(folder, 0o700); err != nil {
		s.log.Error("s3 cannot create the upload staging folder", "path", folder, "error", err)
		return "", 0, errInternal
	}
	file, err := os.CreateTemp(folder, "s3-*.part")
	if err != nil {
		s.log.Error("s3 cannot create a staging file", "path", folder, "error", err)
		return "", 0, errInternal
	}
	reader := io.Reader(body)
	limit := q.set.cfg.MaxUploadSize
	if limit > 0 {
		// one byte past the limit is enough to know it was passed
		reader = io.LimitReader(reader, limit+1)
	}
	written, err := io.Copy(file, reader)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	failure := (*s3Error)(nil)
	switch {
	case err != nil:
		failure = bodyError(err)
		s.log.Info("s3 upload failed", "user", q.user.name, "path", q.r.URL.Path,
			"bytes", written, "address", clientAddress(q.set, q.r), "error", err)
	case limit > 0 && written > limit:
		failure = errTooLarge()
	case body.size >= 0 && written != body.size:
		failure = s3Err(http.StatusBadRequest, "IncompleteBody",
			"You did not provide the number of bytes specified by the Content-Length HTTP header.")
	default:
		failure = body.verify()
	}
	if failure != nil {
		_ = os.Remove(file.Name())
		return "", written, failure
	}
	return file.Name(), written, nil
}

// placeS3File moves a staged file onto the file a key names, and reports
// whether it replaced one. The right to create or to replace was checked when
// the request came in; it is checked again under the lock, for a name that was
// taken or freed while the body was arriving.
func (s *Server) placeS3File(q *s3Request, obj s3Object, staged string) (bool, *s3Error) {
	lock := s.uploadLock(obj.target.Path)
	lock.Lock()
	defer lock.Unlock()
	info, err := os.Stat(obj.target.Path)
	exists := err == nil
	if exists && info.IsDir() {
		return false, errFolderInTheWay
	}
	act := actCreate
	if exists {
		act = actOverwrite
	}
	if !q.may(obj.target.Virtual, act) {
		return false, errAccessDenied
	}
	if err := os.MkdirAll(filepath.Dir(obj.target.Path), 0o755); err != nil {
		if errors.Is(err, os.ErrExist) || isNotDir(err) {
			return false, errFileInTheWay
		}
		s.log.Error("s3 cannot create the folder", "path", obj.target.Virtual, "error", err)
		return false, errInternal
	}
	if err := finalizeUpload(staged, obj.target.Path, exists); err != nil {
		s.log.Error("s3 cannot store the upload", "path", obj.target.Virtual, "error", err)
		return false, errInternal
	}
	return exists, nil
}

// isNotDir reports the error MkdirAll gives when a file is where a folder
// above the key would have to be.
func isNotDir(err error) bool {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if info, statErr := os.Stat(pathErr.Path); statErr == nil && !info.IsDir() {
			return true
		}
	}
	return strings.Contains(err.Error(), "not a directory")
}

// s3PutFolder creates the folder a key ending with a slash names, and the
// folders above it. A folder holds no bytes, so the body has to be empty.
func (s *Server) s3PutFolder(q *s3Request, obj s3Object) {
	if !q.may(obj.target.Virtual, actMkdir) {
		q.fail(errAccessDenied)
		return
	}
	body, failure := openS3Body(q.r, q.sig)
	if failure != nil {
		q.fail(failure)
		return
	}
	data, err := io.ReadAll(io.LimitReader(body, 1))
	if err != nil {
		q.fail(bodyError(err))
		return
	}
	if len(data) > 0 {
		q.fail(s3Err(http.StatusBadRequest, "InvalidRequest",
			"A key that ends with a slash is a folder here, and a folder cannot hold data."))
		return
	}
	if failure := body.verify(); failure != nil {
		q.fail(failure)
		return
	}
	if failure := s.makeFolder(q, obj); failure != nil {
		q.fail(failure)
		return
	}
	q.w.Header().Set("ETag", emptyETag)
	q.w.WriteHeader(http.StatusOK)
}

// makeFolder creates the folder of a folder key, which is no error when it
// is already there: S3 overwrites an object as a matter of course.
func (s *Server) makeFolder(q *s3Request, obj s3Object) *s3Error {
	if info, err := os.Stat(obj.target.Path); err == nil {
		if !info.IsDir() {
			return errFileInTheWay
		}
		return nil
	}
	if err := os.MkdirAll(obj.target.Path, 0o755); err != nil {
		if isNotDir(err) {
			return errFileInTheWay
		}
		s.log.Error("s3 mkdir failed", "folder", obj.target.Virtual, "error", err)
		return errInternal
	}
	s.log.Info("s3 mkdir", "user", q.user.name, "folder", obj.target.Virtual,
		"address", clientAddress(q.set, q.r))
	return nil
}

// copySource resolves an x-amz-copy-source, "docs/a.txt" with or without a
// leading slash and URL encoded, to the object it names, which may be in
// another bucket.
func (s *Server) copySource(header string) (s3Object, *s3Error) {
	raw, version, _ := strings.Cut(header, "?")
	if version != "" {
		if id := strings.TrimPrefix(version, "versionId="); id != "null" {
			return s3Object{}, s3Err(http.StatusNotFound, "NoSuchVersion",
				"The specified version does not exist: objects here have no versions.")
		}
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return s3Object{}, s3Err(http.StatusBadRequest, "InvalidArgument",
			"x-amz-copy-source is not URL encoded.")
	}
	name, key, _ := strings.Cut(strings.TrimPrefix(decoded, "/"), "/")
	bucket, found := s.findBucket(name)
	if !found {
		return s3Object{}, errNoSuchBucket
	}
	source, ok := s.resolveKey(bucket, key)
	if !ok {
		return s3Object{}, errNoSuchKey
	}
	return source, nil
}

// s3CopyObject answers CopyObject, which with a DeleteObject after it is how
// every S3 client renames: S3 has no rename of its own. The copy is a copy of
// the bytes, so a client's rename is one too.
func (s *Server) s3CopyObject(q *s3Request, obj s3Object, header string) {
	source, failure := s.copySource(header)
	if failure != nil {
		q.fail(failure)
		return
	}
	if !q.may(source.target.Virtual, actRead) {
		q.fail(errAccessDenied)
		return
	}
	info, err := os.Stat(source.target.Path)
	if err != nil || source.folder != info.IsDir() || (!source.folder && !info.Mode().IsRegular()) {
		q.fail(errNoSuchKey)
		return
	}
	if failure := checkCopyConditions(q.r, info); failure != nil {
		q.fail(failure)
		return
	}

	type copyResult struct {
		XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
		LastModified string   `xml:"LastModified"`
		ETag         string   `xml:"ETag"`
	}
	if source.folder || obj.folder {
		// a folder copies as the empty folder it is to S3, and only onto one
		if source.folder != obj.folder {
			q.fail(s3Err(http.StatusBadRequest, "InvalidRequest",
				"A folder can only be copied onto a key that ends with a slash, and a file onto one that does not."))
			return
		}
		if !q.may(obj.target.Virtual, actMkdir) {
			q.fail(errAccessDenied)
			return
		}
		if failure := s.makeFolder(q, obj); failure != nil {
			q.fail(failure)
			return
		}
		writeS3XML(q.w, http.StatusOK, copyResult{
			LastModified: time.Now().UTC().Format(s3TimeFormat), ETag: emptyETag})
		return
	}

	if source.target.Path == obj.target.Path {
		// copying an object onto itself is how S3 replaces its metadata, of
		// which there is none here to replace
		if !strings.EqualFold(q.r.Header.Get("X-Amz-Metadata-Directive"), "REPLACE") {
			q.fail(s3Err(http.StatusBadRequest, "InvalidRequest",
				"This copy request is illegal because it is trying to copy an object to itself "+
					"without changing the object's metadata, storage class, website redirect location "+
					"or encryption attributes."))
			return
		}
		writeS3XML(q.w, http.StatusOK, copyResult{
			LastModified: info.ModTime().UTC().Format(s3TimeFormat), ETag: syntheticETag(info)})
		return
	}
	target, err := os.Stat(obj.target.Path)
	exists := err == nil
	if exists && target.IsDir() {
		q.fail(errFolderInTheWay)
		return
	}
	act := actCreate
	if exists {
		act = actOverwrite
	}
	if !q.may(obj.target.Virtual, act) {
		q.fail(errAccessDenied)
		return
	}

	staged, etag, failure := s.stageCopy(q, source, stagingFolder(q.set), 0, info.Size())
	if failure != nil {
		q.fail(failure)
		return
	}
	defer func() { _ = os.Remove(staged) }()
	replaced, failure := s.placeS3File(q, obj, staged)
	if failure != nil {
		q.fail(failure)
		return
	}
	s.log.Info("s3 copy", "user", q.user.name, "from", source.target.Virtual, "to", obj.target.Virtual,
		"bytes", info.Size(), "replaced", replaced, "address", clientAddress(q.set, q.r))
	writeS3XML(q.w, http.StatusOK, copyResult{
		LastModified: time.Now().UTC().Format(s3TimeFormat), ETag: etag})
}

// checkCopyConditions honours the conditions a copy may put on its source.
func checkCopyConditions(r *http.Request, info os.FileInfo) *s3Error {
	etag := syntheticETag(info)
	if match := r.Header.Get("X-Amz-Copy-Source-If-Match"); match != "" && match != etag {
		return errPrecondition
	}
	if match := r.Header.Get("X-Amz-Copy-Source-If-None-Match"); match != "" && match == etag {
		return errPrecondition
	}
	if since := r.Header.Get("X-Amz-Copy-Source-If-Unmodified-Since"); since != "" {
		if at, err := http.ParseTime(since); err == nil && info.ModTime().After(at) {
			return errPrecondition
		}
	}
	if since := r.Header.Get("X-Amz-Copy-Source-If-Modified-Since"); since != "" {
		if at, err := http.ParseTime(since); err == nil && !info.ModTime().After(at) {
			return errPrecondition
		}
	}
	return nil
}

// stageCopy copies length bytes of a source object from offset into a new
// file in folder, and reports the file and the ETag of what it holds.
func (s *Server) stageCopy(q *s3Request, source s3Object, folder string, offset, length int64) (string, string, *s3Error) {
	in, err := os.Open(source.target.Path)
	if err != nil {
		s.log.Warn("s3 cannot open the copy source", "path", source.target.Virtual, "error", err)
		return "", "", errNoSuchKey
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(folder, 0o700); err != nil {
		s.log.Error("s3 cannot create the upload staging folder", "path", folder, "error", err)
		return "", "", errInternal
	}
	out, err := os.CreateTemp(folder, "s3-*.part")
	if err != nil {
		s.log.Error("s3 cannot create a staging file", "path", folder, "error", err)
		return "", "", errInternal
	}
	sum := md5.New()
	_, err = io.Copy(io.MultiWriter(out, sum), io.NewSectionReader(in, offset, length))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(out.Name())
		s.log.Error("s3 copy failed", "from", source.target.Virtual, "error", err)
		return "", "", errInternal
	}
	return out.Name(), `"` + hex.EncodeToString(sum.Sum(nil)) + `"`, nil
}

// s3DeleteObject removes what a key names. A key that names nothing is no
// error, as it is not in S3, but a key the account may not delete is refused
// whether or not there is anything there.
//
// A folder key removes the folder when it is empty. One with something in it
// stays: in S3 deleting "docs/" removes the folder object and leaves the keys
// below it, which is what the folder here still holds.
//
// Once something is removed, the folders above it that it leaves empty go as
// well, for an account that may remove folders. That is S3: a folder there is
// only the keys below it, and a client that renames a folder copies and
// deletes every key in it and expects the old folder to be gone after.
func (s *Server) s3DeleteObject(q *s3Request, obj s3Object) *s3Error {
	act := actDeleteFile
	if obj.folder {
		act = actDeleteFolder
	}
	if !q.may(obj.target.Virtual, act) {
		return errAccessDenied
	}
	info, err := os.Stat(obj.target.Path)
	if err != nil || obj.folder != info.IsDir() {
		return nil
	}
	if obj.folder {
		entries, err := os.ReadDir(obj.target.Path)
		if err != nil || len(entries) > 0 {
			return nil
		}
	} else if !info.Mode().IsRegular() {
		return nil
	}
	if err := os.Remove(obj.target.Path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		if obj.folder {
			// filled again between the look and the removal
			return nil
		}
		s.log.Error("s3 delete failed", "path", obj.target.Virtual, "error", err)
		return errInternal
	}
	s.log.Info("s3 delete", "user", q.user.name, "path", obj.target.Virtual, "folder", obj.folder,
		"bytes", info.Size(), "address", clientAddress(q.set, q.r))
	s.pruneFolders(q, obj.target.Virtual)
	return nil
}

// pruneFolders removes the folders above a path that are left empty, up to
// the served folder, and stops at the first one that holds anything or that
// the account may not remove. Removing a folder that is not empty fails, so a
// folder that is filled again meanwhile stays.
func (s *Server) pruneFolders(q *s3Request, virtual string) {
	for folder := folderOf(virtual); folder != "/" && folder != "."; folder = folderOf(folder) {
		if !q.may(folder, actDeleteFolder) {
			return
		}
		target := s.root.Resolve("/", folder)
		if !target.Valid || os.Remove(target.Path) != nil {
			return
		}
		s.log.Info("s3 delete", "user", q.user.name, "path", folder, "folder", true,
			"emptied", true, "address", clientAddress(q.set, q.r))
	}
}

// s3DeleteObjects answers DeleteObjects: up to a thousand keys in one request,
// each deleted as DeleteObject deletes it and reported on its own.
func (s *Server) s3DeleteObjects(q *s3Request) {
	var request struct {
		Quiet   bool `xml:"Quiet"`
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}
	if failure := readS3XML(q, 2<<20, &request); failure != nil {
		q.fail(failure)
		return
	}
	if len(request.Objects) == 0 || len(request.Objects) > 1000 {
		q.fail(s3Err(http.StatusBadRequest, "MalformedXML",
			"A delete request names between 1 and 1000 keys."))
		return
	}
	type deleted struct {
		Key string `xml:"Key"`
	}
	type failed struct {
		Key     string `xml:"Key"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	result := struct {
		XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
		Deleted []deleted `xml:"Deleted"`
		Errors  []failed  `xml:"Error"`
	}{}
	for _, object := range request.Objects {
		obj, ok := s.resolveKey(q.bucket, object.Key)
		failure := errBadKey
		if ok {
			failure = s.s3DeleteObject(q, obj)
		}
		if failure != nil {
			result.Errors = append(result.Errors, failed{Key: object.Key, Code: failure.code,
				Message: failure.message})
			continue
		}
		if !request.Quiet {
			result.Deleted = append(result.Deleted, deleted{Key: object.Key})
		}
	}
	writeS3XML(q.w, http.StatusOK, result)
}

package httpd

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A multipart upload is how every S3 client sends a large file: it is opened,
// its parts are uploaded one request each, in any order and several at once,
// and completing it joins them into the object. Each upload is a folder of its
// own under the upload staging folder, never inside the served one, holding a
// record of whose upload it is and for which key, and one file per part with
// the MD5 of that part beside it.

// multipartFolder is the folder under the upload staging folder that holds
// the uploads in progress.
const multipartFolder = "s3-multipart"

// maxParts is the most parts an upload may have, as in S3.
const maxParts = 10000

// uploadIDPattern is what an upload id looks like. It is checked before the
// id is used as the name of a folder, so that no id can name another one.
var uploadIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var errNoSuchUpload = s3Err(http.StatusNotFound, "NoSuchUpload",
	"The specified multipart upload does not exist. The upload ID might be invalid, "+
		"or the multipart upload might have been aborted or completed.")

// uploadRecord is what the folder of an upload says about it.
type uploadRecord struct {
	Owner     string    `json:"owner"`
	Bucket    string    `json:"bucket"`
	Key       string    `json:"key"`
	Initiated time.Time `json:"initiated"`
}

const uploadRecordName = "upload.json"

func uploadsFolder(set *settings) string {
	return filepath.Join(stagingFolder(set), multipartFolder)
}

func partName(number int) string {
	return fmt.Sprintf("%05d.part", number)
}

// loadUpload finds an upload of the account asking, for the bucket and key it
// is asked about. An upload of another account is one that does not exist.
func (s *Server) loadUpload(q *s3Request, id string, obj s3Object) (string, uploadRecord, *s3Error) {
	if !uploadIDPattern.MatchString(id) {
		return "", uploadRecord{}, errNoSuchUpload
	}
	folder := filepath.Join(uploadsFolder(q.set), id)
	data, err := os.ReadFile(filepath.Join(folder, uploadRecordName))
	if err != nil {
		return "", uploadRecord{}, errNoSuchUpload
	}
	var record uploadRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Owner != q.user.name ||
		record.Bucket != obj.bucket || record.Key != obj.key {
		return "", uploadRecord{}, errNoSuchUpload
	}
	return folder, record, nil
}

// mayWrite checks the right an upload onto a key needs as the file tree is
// right now: to create the file, or to replace it.
func (s *Server) mayWrite(q *s3Request, obj s3Object) *s3Error {
	if obj.folder {
		return s3Err(http.StatusBadRequest, "InvalidArgument",
			"A key that ends with a slash is a folder here, and a folder cannot be uploaded.")
	}
	info, err := os.Stat(obj.target.Path)
	exists := err == nil
	if exists && info.IsDir() {
		return errFolderInTheWay
	}
	act := actCreate
	if exists {
		act = actOverwrite
	}
	if !q.may(obj.target.Virtual, act) {
		return errAccessDenied
	}
	return nil
}

// s3CreateUpload answers CreateMultipartUpload.
func (s *Server) s3CreateUpload(q *s3Request, obj s3Object) {
	if failure := s.mayWrite(q, obj); failure != nil {
		q.fail(failure)
		return
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		q.fail(errInternal)
		return
	}
	id := hex.EncodeToString(raw)
	folder := filepath.Join(uploadsFolder(q.set), id)
	record, _ := json.Marshal(uploadRecord{Owner: q.user.name, Bucket: obj.bucket, Key: obj.key,
		Initiated: time.Now().UTC()})
	if err := os.MkdirAll(folder, 0o700); err != nil {
		s.log.Error("s3 cannot create the upload folder", "path", folder, "error", err)
		q.fail(errInternal)
		return
	}
	if err := os.WriteFile(filepath.Join(folder, uploadRecordName), record, 0o600); err != nil {
		_ = os.RemoveAll(folder)
		s.log.Error("s3 cannot record the upload", "path", folder, "error", err)
		q.fail(errInternal)
		return
	}
	s.log.Debug("s3 multipart upload started", "user", q.user.name, "file", obj.target.Virtual,
		"uploadId", id)
	writeS3XML(q.w, http.StatusOK, struct {
		XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}{Bucket: obj.bucket, Key: obj.key, UploadID: id})
}

// s3UploadPart answers UploadPart, and UploadPartCopy for a part that comes
// from an object already here, which is how a client copies, and so renames,
// a large file.
func (s *Server) s3UploadPart(q *s3Request, obj s3Object, id, number, copySource string) {
	part, err := strconv.Atoi(number)
	if err != nil || part < 1 || part > maxParts {
		q.fail(s3Err(http.StatusBadRequest, "InvalidArgument",
			"Part number must be an integer between 1 and 10000, inclusive."))
		return
	}
	folder, _, failure := s.loadUpload(q, id, obj)
	if failure != nil {
		q.fail(failure)
		return
	}

	var staged, etag string
	if copySource != "" {
		staged, etag, failure = s.stagePartCopy(q, folder, copySource)
		if failure != nil {
			q.fail(failure)
			return
		}
	} else {
		if max := q.set.cfg.MaxUploadSize; max > 0 && declaredSize(q.r) > max {
			q.fail(errTooLarge())
			return
		}
		body, failure := openS3Body(q.r, q.sig)
		if failure != nil {
			q.fail(failure)
			return
		}
		staged, _, failure = s.stageS3Body(q, body, folder)
		if failure != nil {
			q.fail(failure)
			return
		}
		etag = body.etag()
	}

	// the MD5 is written before the part is put in place, so a part that is
	// there always has one; a part sent again replaces both
	partPath := filepath.Join(folder, partName(part))
	if err := os.WriteFile(partPath+".etag", []byte(etag), 0o600); err != nil {
		_ = os.Remove(staged)
		s.log.Error("s3 cannot record the part", "path", partPath, "error", err)
		q.fail(errInternal)
		return
	}
	if err := os.Rename(staged, partPath); err != nil {
		_ = os.Remove(staged)
		s.log.Error("s3 cannot store the part", "path", partPath, "error", err)
		q.fail(errInternal)
		return
	}
	s.log.Debug("s3 part uploaded", "user", q.user.name, "file", obj.target.Virtual,
		"uploadId", id, "part", part)
	if copySource != "" {
		writeS3XML(q.w, http.StatusOK, struct {
			XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyPartResult"`
			LastModified string   `xml:"LastModified"`
			ETag         string   `xml:"ETag"`
		}{LastModified: time.Now().UTC().Format(s3TimeFormat), ETag: etag})
		return
	}
	q.w.Header().Set("ETag", etag)
	q.w.WriteHeader(http.StatusOK)
}

// stagePartCopy copies a part out of an object, the whole of it or the range
// x-amz-copy-source-range names.
func (s *Server) stagePartCopy(q *s3Request, folder, copySource string) (string, string, *s3Error) {
	source, failure := s.copySource(copySource)
	if failure != nil {
		return "", "", failure
	}
	if !q.may(source.target.Virtual, actRead) {
		return "", "", errAccessDenied
	}
	info, err := os.Stat(source.target.Path)
	if err != nil || source.folder || !info.Mode().IsRegular() {
		return "", "", errNoSuchKey
	}
	if failure := checkCopyConditions(q.r, info); failure != nil {
		return "", "", failure
	}
	offset, length := int64(0), info.Size()
	if header := q.r.Header.Get("X-Amz-Copy-Source-Range"); header != "" {
		var first, last int64
		if _, err := fmt.Sscanf(header, "bytes=%d-%d", &first, &last); err != nil ||
			first < 0 || last < first || last >= info.Size() {
			return "", "", s3Err(http.StatusRequestedRangeNotSatisfiable, "InvalidRange",
				"The requested range is not satisfiable.")
		}
		offset, length = first, last-first+1
	}
	return s.stageCopy(q, source, folder, offset, length)
}

// uploadedPart is a part as it is on disk.
type uploadedPart struct {
	number   int
	etag     string
	size     int64
	modified time.Time
}

// listParts reads the parts of an upload, in the order of their numbers.
func listParts(folder string) ([]uploadedPart, error) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return nil, err
	}
	var parts []uploadedPart
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".part")
		if !ok {
			continue
		}
		number, err := strconv.Atoi(name)
		if err != nil {
			// a part being staged, not one that is there yet
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		etag, err := os.ReadFile(filepath.Join(folder, entry.Name()+".etag"))
		if err != nil {
			continue
		}
		parts = append(parts, uploadedPart{number: number, etag: string(etag), size: info.Size(),
			modified: info.ModTime()})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].number < parts[j].number })
	return parts, nil
}

// s3CompleteUpload answers CompleteMultipartUpload: the parts the client
// names, in the order it names them, are joined into the object.
func (s *Server) s3CompleteUpload(q *s3Request, obj s3Object, id string) {
	folder, _, failure := s.loadUpload(q, id, obj)
	if failure != nil {
		q.fail(failure)
		return
	}
	var request struct {
		Parts []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
		} `xml:"Part"`
	}
	if failure := readS3XML(q, 4<<20, &request); failure != nil {
		q.fail(failure)
		return
	}
	if len(request.Parts) == 0 {
		q.fail(s3Err(http.StatusBadRequest, "MalformedXML", "You must specify at least one part."))
		return
	}
	uploaded, err := listParts(folder)
	if err != nil {
		q.fail(errNoSuchUpload)
		return
	}
	byNumber := make(map[int]uploadedPart, len(uploaded))
	for _, part := range uploaded {
		byNumber[part.number] = part
	}
	var total int64
	sums := md5.New()
	chosen := make([]uploadedPart, 0, len(request.Parts))
	for i, wanted := range request.Parts {
		if i > 0 && wanted.PartNumber <= request.Parts[i-1].PartNumber {
			q.fail(s3Err(http.StatusBadRequest, "InvalidPartOrder",
				"The list of parts was not in ascending order. The parts list must be specified in order by part number."))
			return
		}
		part, ok := byNumber[wanted.PartNumber]
		if !ok || !strings.EqualFold(strings.Trim(wanted.ETag, `"`), strings.Trim(part.etag, `"`)) {
			q.fail(s3Err(http.StatusBadRequest, "InvalidPart",
				"One or more of the specified parts could not be found. The part might not have been "+
					"uploaded, or the specified entity tag might not have matched the part's entity tag."))
			return
		}
		raw, _ := hex.DecodeString(strings.Trim(part.etag, `"`))
		sums.Write(raw)
		total += part.size
		chosen = append(chosen, part)
	}
	if max := q.set.cfg.MaxUploadSize; max > 0 && total > max {
		q.fail(errTooLarge())
		return
	}
	if failure := s.mayWrite(q, obj); failure != nil {
		q.fail(failure)
		return
	}

	started := time.Now()
	joined, err := os.CreateTemp(folder, "joined-*")
	if err != nil {
		s.log.Error("s3 cannot join the parts", "path", folder, "error", err)
		q.fail(errInternal)
		return
	}
	defer func() { _ = os.Remove(joined.Name()) }()
	for _, part := range chosen {
		if err = appendFile(joined, filepath.Join(folder, partName(part.number))); err != nil {
			break
		}
	}
	if closeErr := joined.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		s.log.Error("s3 cannot join the parts", "path", folder, "error", err)
		q.fail(errInternal)
		return
	}
	replaced, failure := s.placeS3File(q, obj, joined.Name())
	if failure != nil {
		q.fail(failure)
		return
	}
	_ = os.RemoveAll(folder)

	etag := fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(sums.Sum(nil)), len(chosen))
	s.log.Info("s3 upload", "user", q.user.name, "file", obj.target.Virtual, "bytes", total,
		"parts", len(chosen), "replaced", replaced, "address", clientAddress(q.set, q.r),
		"took", time.Since(started).Round(time.Millisecond))
	writeS3XML(q.w, http.StatusOK, struct {
		XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}{Location: "/" + obj.bucket + "/" + s3Escape(obj.key, true), Bucket: obj.bucket,
		Key: obj.key, ETag: etag})
}

func appendFile(to *os.File, path string) error {
	from, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = from.Close() }()
	_, err = io.Copy(to, from)
	return err
}

// s3AbortUpload answers AbortMultipartUpload, which throws the parts away.
func (s *Server) s3AbortUpload(q *s3Request, obj s3Object, id string) {
	folder, _, failure := s.loadUpload(q, id, obj)
	if failure != nil {
		q.fail(failure)
		return
	}
	if err := os.RemoveAll(folder); err != nil {
		s.log.Error("s3 cannot remove the upload", "path", folder, "error", err)
		q.fail(errInternal)
		return
	}
	s.log.Debug("s3 multipart upload aborted", "user", q.user.name, "file", obj.target.Virtual,
		"uploadId", id)
	q.w.WriteHeader(http.StatusNoContent)
}

// s3ListParts answers ListParts, which a client resuming an upload asks for.
func (s *Server) s3ListParts(q *s3Request, obj s3Object, id string) {
	folder, _, failure := s.loadUpload(q, id, obj)
	if failure != nil {
		q.fail(failure)
		return
	}
	parts, err := listParts(folder)
	if err != nil {
		q.fail(errNoSuchUpload)
		return
	}
	query := q.r.URL.Query()
	marker, _ := strconv.Atoi(query.Get("part-number-marker"))
	maxParts := 1000
	if raw := query.Get("max-parts"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			maxParts = min(n, 1000)
		}
	}
	start := sort.Search(len(parts), func(i int) bool { return parts[i].number > marker })
	parts = parts[start:]
	truncated := len(parts) > maxParts
	if truncated {
		parts = parts[:maxParts]
	}
	type listed struct {
		PartNumber   int    `xml:"PartNumber"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
	}
	result := struct {
		XMLName              xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
		Bucket               string   `xml:"Bucket"`
		Key                  string   `xml:"Key"`
		UploadID             string   `xml:"UploadId"`
		Initiator            s3Owner  `xml:"Initiator"`
		Owner                s3Owner  `xml:"Owner"`
		StorageClass         string   `xml:"StorageClass"`
		PartNumberMarker     int      `xml:"PartNumberMarker"`
		NextPartNumberMarker int      `xml:"NextPartNumberMarker"`
		MaxParts             int      `xml:"MaxParts"`
		IsTruncated          bool     `xml:"IsTruncated"`
		Parts                []listed `xml:"Part"`
	}{Bucket: obj.bucket, Key: obj.key, UploadID: id, Initiator: ownerOf(q.user),
		Owner: ownerOf(q.user), StorageClass: "STANDARD", PartNumberMarker: marker,
		MaxParts: maxParts, IsTruncated: truncated}
	for _, part := range parts {
		result.Parts = append(result.Parts, listed{PartNumber: part.number,
			LastModified: part.modified.UTC().Format(s3TimeFormat), ETag: part.etag, Size: part.size})
		result.NextPartNumberMarker = part.number
	}
	writeS3XML(q.w, http.StatusOK, result)
}

// s3ListUploads answers ListMultipartUploads with the uploads of the account
// asking into the bucket whose key begins with the prefix, which is how a client finds an
// upload it can resume.
func (s *Server) s3ListUploads(q *s3Request) {
	prefix := q.r.URL.Query().Get("prefix")
	type upload struct {
		Key          string  `xml:"Key"`
		UploadID     string  `xml:"UploadId"`
		Initiator    s3Owner `xml:"Initiator"`
		Owner        s3Owner `xml:"Owner"`
		StorageClass string  `xml:"StorageClass"`
		Initiated    string  `xml:"Initiated"`
	}
	var uploads []upload
	entries, _ := os.ReadDir(uploadsFolder(q.set))
	for _, entry := range entries {
		if !entry.IsDir() || !uploadIDPattern.MatchString(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(uploadsFolder(q.set), entry.Name(), uploadRecordName))
		if err != nil {
			continue
		}
		var record uploadRecord
		if json.Unmarshal(data, &record) != nil || record.Owner != q.user.name ||
			record.Bucket != q.bucket || !strings.HasPrefix(record.Key, prefix) {
			continue
		}
		uploads = append(uploads, upload{Key: record.Key, UploadID: entry.Name(),
			Initiator: ownerOf(q.user), Owner: ownerOf(q.user), StorageClass: "STANDARD",
			Initiated: record.Initiated.Format(s3TimeFormat)})
	}
	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key != uploads[j].Key {
			return uploads[i].Key < uploads[j].Key
		}
		return uploads[i].Initiated < uploads[j].Initiated
	})
	writeS3XML(q.w, http.StatusOK, struct {
		XMLName     xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult"`
		Bucket      string   `xml:"Bucket"`
		Prefix      string   `xml:"Prefix"`
		MaxUploads  int      `xml:"MaxUploads"`
		IsTruncated bool     `xml:"IsTruncated"`
		Uploads     []upload `xml:"Upload"`
	}{Bucket: q.bucket, Prefix: prefix, MaxUploads: 1000, Uploads: uploads})
}

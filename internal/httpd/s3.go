package httpd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/vfs"
)

// The S3 API is served on the same listeners as everything else. It is told
// apart by its signature rather than by a path of its own, which is how every
// URL here stays a path in the served folder: a request signed with SigV4 is an
// S3 request, and any other request is what it always was.
//
// Every folder directly in the served folder is a bucket, so the key "a.txt"
// in the bucket "docs" is the file http serves at /docs/a.txt, and the paths
// and rights of an account decide over both alike. A bucket is found by the
// name of its folder ignoring case, since bucket names are written in lower
// case by habit and folder names are not. Only path style addressing is
// served: https://host/docs/a.txt.

// s3TimeFormat is how a time is written in an S3 XML document.
const s3TimeFormat = "2006-01-02T15:04:05.000Z"

// emptyETag is the ETag of an object with no bytes, which is what a folder is
// to S3.
const emptyETag = `"d41d8cd98f00b204e9800998ecf8427e"`

// s3Error is an S3 error response.
type s3Error struct {
	status  int
	code    string
	message string
	// region is what an AuthorizationHeaderMalformed names as the region to
	// sign for
	region string
	// failedLogin says the credentials were wrong, which counts against the
	// address as a wrong password does
	failedLogin bool
}

func s3Err(status int, code, message string) *s3Error {
	return &s3Error{status: status, code: code, message: message}
}

func (e *s3Error) Error() string {
	return e.code + ": " + e.message
}

var (
	errAccessDenied = s3Err(http.StatusForbidden, "AccessDenied", "Access Denied")
	errNoSuchKey    = s3Err(http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
	errNoSuchBucket = s3Err(http.StatusNotFound, "NoSuchBucket",
		"The specified bucket does not exist. A bucket here is a folder directly in the served folder.")
	errBadKey = s3Err(http.StatusBadRequest, "InvalidArgument",
		"The key does not name a path in the served folder: it is empty, climbs out of it, "+
			"or holds an empty, . or .. segment.")
	errNotImplemented = s3Err(http.StatusNotImplemented, "NotImplemented",
		"A header or query you provided implies functionality that is not implemented.")
	errInternal = s3Err(http.StatusInternalServerError, "InternalError",
		"We encountered an internal error. Please try again.")
	errFolderInTheWay = s3Err(http.StatusConflict, "InvalidRequest",
		"A folder of that name is in the way: the file tree cannot hold a file and a folder of one name.")
	errFileInTheWay = s3Err(http.StatusConflict, "InvalidRequest",
		"A file of that name is in the way: the file tree cannot hold a file and a folder of one name.")
	errPrecondition = s3Err(http.StatusPreconditionFailed, "PreconditionFailed",
		"At least one of the pre-conditions you specified did not hold.")
)

// s3Request is one request to the S3 API and what it was resolved to.
type s3Request struct {
	set  *settings
	w    http.ResponseWriter
	r    *http.Request
	sig  *s3Signature
	user *account
	// bucket is the folder the request names, spelled as it is on disk
	bucket string
}

// may reports whether the account may do act to a path. S3 has nothing
// public, so it is the account's paths and rights and nothing else.
func (q *s3Request) may(virtual string, act action) bool {
	return q.user.allows(virtual) && granted(q.user.perms, act)
}

// fail answers with an S3 error. The request is named in the answer as S3
// names it, by its path.
func (q *s3Request) fail(e *s3Error) {
	writeS3Error(q.w, q.r, e)
}

func writeS3Error(w http.ResponseWriter, r *http.Request, e *s3Error) {
	type errorDocument struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource,omitempty"`
		Region    string   `xml:"Region,omitempty"`
		RequestID string   `xml:"RequestId"`
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		// a HEAD has no body to say anything in
		w.WriteHeader(e.status)
		return
	}
	writeS3XML(w, e.status, errorDocument{Code: e.code, Message: e.message, Resource: r.URL.Path,
		Region: e.region, RequestID: w.Header().Get("X-Amz-Request-Id")})
}

// writeS3XML answers with an XML document.
func writeS3XML(w http.ResponseWriter, status int, document any) {
	body, err := xml.Marshal(document)
	if err != nil {
		status, body = http.StatusInternalServerError, nil
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(xml.Header)+len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header)
	_, _ = w.Write(body)
}

// readS3XML reads the small XML document of a request that sends one: a list
// of keys to delete, the parts of an upload. The document is read through the
// body as an upload is, so its hash is checked the same way.
func readS3XML(q *s3Request, limit int64, into any) *s3Error {
	body, failure := openS3Body(q.r, q.sig)
	if failure != nil {
		return failure
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return bodyError(err)
	}
	if int64(len(data)) > limit {
		return s3Err(http.StatusBadRequest, "MalformedXML", "The XML you provided is too large.")
	}
	if failure := body.verify(); failure != nil {
		return failure
	}
	if err := xml.Unmarshal(data, into); err != nil {
		return s3Err(http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.")
	}
	return nil
}

// bodyError is what reading a body failed with, as an S3 error.
func bodyError(err error) *s3Error {
	var failure *s3Error
	if errors.As(err, &failure) {
		return failure
	}
	if tooLarge(err) {
		return s3Err(http.StatusBadRequest, "EntityTooLarge",
			"Your proposed upload exceeds the maximum allowed size.")
	}
	return s3Err(http.StatusBadRequest, "IncompleteBody",
		"You did not provide the number of bytes specified by the Content-Length HTTP header.")
}

func newRequestID() string {
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	return strings.ToUpper(hex.EncodeToString(id))
}

// handleS3 authenticates an S3 request and dispatches it.
func (s *Server) handleS3(set *settings, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Amz-Request-Id", newRequestID())
	if !set.cfg.EnableS3 {
		s.log.Debug("s3 request refused, http.enableS3 is off", "method", r.Method, "path", r.URL.Path,
			"address", clientAddress(set, r))
		writeS3Error(w, r, s3Err(http.StatusForbidden, "AccessDenied",
			"The S3 API is switched off on this server."))
		return
	}
	if remaining, locked := s.lockedOut(set, r); locked {
		s.log.Info("http login refused, the address is locked out", "method", "s3",
			"address", clientAddress(set, r), "remaining", remaining.Round(time.Second))
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter(remaining)))
		writeS3Error(w, r, s3Err(http.StatusServiceUnavailable, "SlowDown",
			"Too many failed logins from your address. Try again later."))
		return
	}
	sig, failure := s.verifyS3(set, r, time.Now())
	if failure != nil {
		if failure.failedLogin {
			s.recordFailure(set, r)
			if delay := set.cfg.LoginFailureDelay; delay > 0 {
				time.Sleep(time.Duration(delay) * time.Second)
			}
		} else {
			s.log.Debug("s3 request refused", "code", failure.code, "message", failure.message,
				"address", clientAddress(set, r))
		}
		writeS3Error(w, r, failure)
		return
	}
	s.logins.clear(clientAddress(set, r))
	s.log.Debug("http authenticated", "user", sig.user.name, "method", "s3",
		"address", clientAddress(set, r), "path", r.URL.Path)

	q := &s3Request{set: set, w: w, r: r, sig: sig, user: sig.user}
	if set.cfg.ReadTimeout > 0 && r.Body != nil {
		// as for a PUT: how long an upload may go without any data arriving,
		// not how long it may take
		r.Body = &idleUploadBody{ReadCloser: r.Body, controller: http.NewResponseController(w),
			idle: seconds(set.cfg.ReadTimeout)}
	}
	s.routeS3(q)
}

// s3Unsupported are the subresources of the S3 API this server does not
// serve. A request for one is answered NotImplemented rather than as the
// request it would be without it, which would do something else entirely.
var s3Unsupported = []string{
	"accelerate", "acl", "analytics", "attributes", "cors", "encryption", "intelligent-tiering",
	"inventory", "legal-hold", "lifecycle", "logging", "metrics", "notification", "object-lock",
	"ownershipControls", "policy", "policyStatus", "publicAccessBlock", "replication",
	"requestPayment", "restore", "retention", "select", "tagging", "torrent", "versions", "website",
}

// routeS3 dispatches by what the path names, the method and the subresource.
func (s *Server) routeS3(q *s3Request) {
	query := q.r.URL.Query()
	has := func(name string) bool {
		_, ok := query[name]
		return ok
	}
	for _, name := range s3Unsupported {
		if has(name) {
			s.log.Debug("s3 subresource not implemented", "subresource", name, "method", q.r.Method)
			q.fail(errNotImplemented)
			return
		}
	}
	// there are no versions but the current one, which is what "null" names
	if version := query.Get("versionId"); has("versionId") && version != "null" {
		s.log.Debug("s3 object version not found", "versionId", version)
		q.fail(s3Err(http.StatusNotFound, "NoSuchVersion",
			"The specified version does not exist: objects here have no versions."))
		return
	}

	name, key, _ := strings.Cut(strings.TrimPrefix(q.r.URL.Path, "/"), "/")
	method := q.r.Method
	if name == "" {
		if method != http.MethodGet {
			q.fail(errNotImplemented)
			return
		}
		s.s3ListBuckets(q)
		return
	}
	bucket, found := s.findBucket(name)
	if !found {
		s.log.Debug("s3 bucket not found", "bucket", name)
		if method == http.MethodPut && key == "" {
			q.fail(s3Err(http.StatusForbidden, "AccessDenied",
				"Buckets cannot be created here: a bucket is a folder directly in the served folder."))
			return
		}
		q.fail(errNoSuchBucket)
		return
	}
	q.bucket = bucket

	switch {
	case key == "":
		switch {
		case method == http.MethodHead:
			q.w.Header().Set("X-Amz-Bucket-Region", config.S3Region)
			q.w.WriteHeader(http.StatusOK)
		case method == http.MethodGet && has("location"):
			s.s3BucketLocation(q)
		case method == http.MethodGet && has("versioning"):
			writeS3XML(q.w, http.StatusOK, struct {
				XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ VersioningConfiguration"`
			}{})
		case method == http.MethodGet && has("uploads"):
			s.s3ListUploads(q)
		case method == http.MethodGet:
			s.s3ListObjects(q)
		case method == http.MethodPut && len(query) == 0 || method == http.MethodPut && has("x-id"):
			s.s3CreateBucket(q)
		case method == http.MethodDelete:
			q.fail(s3Err(http.StatusForbidden, "AccessDenied",
				"The bucket "+q.bucket+" is a folder of the served folder and cannot be removed."))
		case method == http.MethodPost && has("delete"):
			s.s3DeleteObjects(q)
		default:
			q.fail(errNotImplemented)
		}
		return
	}

	obj, ok := s.resolveKey(bucket, key)
	if !ok {
		if method == http.MethodGet || method == http.MethodHead {
			q.fail(errNoSuchKey)
		} else {
			q.fail(errBadKey)
		}
		return
	}
	copySource := q.r.Header.Get("X-Amz-Copy-Source")
	switch {
	case method == http.MethodGet && has("uploadId"):
		s.s3ListParts(q, obj, query.Get("uploadId"))
	case method == http.MethodGet, method == http.MethodHead:
		s.s3GetObject(q, obj)
	case method == http.MethodPut && has("partNumber") && has("uploadId"):
		s.s3UploadPart(q, obj, query.Get("uploadId"), query.Get("partNumber"), copySource)
	case method == http.MethodPut && copySource != "":
		s.s3CopyObject(q, obj, copySource)
	case method == http.MethodPut:
		s.s3PutObject(q, obj)
	case method == http.MethodDelete && has("uploadId"):
		s.s3AbortUpload(q, obj, query.Get("uploadId"))
	case method == http.MethodDelete:
		if failure := s.s3DeleteObject(q, obj); failure != nil {
			q.fail(failure)
			return
		}
		q.w.WriteHeader(http.StatusNoContent)
	case method == http.MethodPost && has("uploads"):
		s.s3CreateUpload(q, obj)
	case method == http.MethodPost && has("uploadId"):
		s.s3CompleteUpload(q, obj, query.Get("uploadId"))
	default:
		q.fail(errNotImplemented)
	}
}

// s3Object is a key resolved against the folder of its bucket.
type s3Object struct {
	bucket string
	key    string
	// folder says the key ends with a slash, which is how S3 names a folder:
	// a key of no bytes that the keys below it are listed under
	folder bool
	target vfs.Target
}

// resolveKey maps a key onto the folder of a bucket. A key the file tree
// cannot hold as it is spelled, one with an empty, a . or a .. segment, is
// refused rather than stored under a name the listing would then report
// differently.
func (s *Server) resolveKey(bucket, key string) (s3Object, bool) {
	if key == "" {
		return s3Object{}, false
	}
	folder := strings.HasSuffix(key, "/")
	trimmed := "/" + bucket + "/" + strings.TrimSuffix(key, "/")
	target := s.root.Resolve("/", trimmed)
	if !target.Valid || target.Virtual != trimmed {
		return s3Object{}, false
	}
	return s3Object{bucket: bucket, key: key, folder: folder, target: target}, true
}

// bucketFolder reports whether a name in the served folder is a folder that
// can be a bucket: one that stays inside the served folder, as a link has to,
// and is named on disk as it is spelled.
func (s *Server) bucketFolder(name string) (os.FileInfo, bool) {
	target := s.root.Resolve("/", "/"+name)
	if !target.Valid || target.Virtual != "/"+name {
		return nil, false
	}
	info, err := os.Stat(target.Path)
	if err != nil || !info.IsDir() {
		return nil, false
	}
	return info, true
}

// findBucket finds the folder a bucket name names, ignoring case, and gives
// its name as it is on disk. Where two folders differ in case only, the one
// spelled as asked wins, and otherwise the first by name.
func (s *Server) findBucket(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	listed, err := os.ReadDir(s.root.Base())
	if err != nil {
		return "", false
	}
	found := ""
	for _, item := range listed {
		if !strings.EqualFold(item.Name(), name) {
			continue
		}
		if _, ok := s.bucketFolder(item.Name()); !ok {
			continue
		}
		if item.Name() == name {
			return name, true
		}
		if found == "" {
			found = item.Name()
		}
	}
	return found, found != ""
}

// s3ListBuckets lists the folders directly in the served folder that the
// account may see.
func (s *Server) s3ListBuckets(q *s3Request) {
	type bucket struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}
	listed, err := os.ReadDir(s.root.Base())
	if err != nil {
		s.log.Error("s3 cannot list the served folder", "error", err)
		q.fail(errInternal)
		return
	}
	buckets := []bucket{}
	for _, item := range listed {
		info, ok := s.bucketFolder(item.Name())
		if !ok || !q.user.allows("/"+item.Name()) {
			continue
		}
		buckets = append(buckets, bucket{Name: item.Name(),
			CreationDate: info.ModTime().UTC().Format(s3TimeFormat)})
	}
	writeS3XML(q.w, http.StatusOK, struct {
		XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
		Owner   s3Owner  `xml:"Owner"`
		Buckets []bucket `xml:"Buckets>Bucket"`
	}{Owner: ownerOf(q.user), Buckets: buckets})
}

// s3BucketLocation names the region, which S3 writes as nothing at all for
// us-east-1.
func (s *Server) s3BucketLocation(q *s3Request) {
	location := config.S3Region
	if location == "us-east-1" {
		location = ""
	}
	writeS3XML(q.w, http.StatusOK, struct {
		XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
		Location string   `xml:",chardata"`
	}{Location: location})
}

// s3CreateBucket answers a request to create a bucket that exists. As
// in us-east-1 on AWS, creating a bucket its owner already has succeeds, which
// is what lets a client that makes sure of its bucket before an upload go on.
func (s *Server) s3CreateBucket(q *s3Request) {
	var configuration struct {
		Location string `xml:"LocationConstraint"`
	}
	if q.r.ContentLength != 0 {
		if failure := readS3XML(q, 64<<10, &configuration); failure != nil {
			q.fail(failure)
			return
		}
	}
	if configuration.Location != "" && configuration.Location != config.S3Region {
		q.fail(s3Err(http.StatusBadRequest, "InvalidLocationConstraint",
			"The specified location-constraint is not valid: the one region is "+config.S3Region+"."))
		return
	}
	q.w.Header().Set("Location", "/"+q.bucket)
	q.w.WriteHeader(http.StatusOK)
}

// s3Owner is who owns what S3 lists: the account asking, since every bucket
// here is shared by every account.
type s3Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

func ownerOf(user *account) s3Owner {
	return s3Owner{ID: user.name, DisplayName: user.name}
}

// escapeKeys is how a listing writes a key: as it is, or URL encoded when the
// client asked for encoding-type=url, which is how a key with characters XML
// 1.0 cannot carry is listed at all.
func escapeKeys(query url.Values) func(string) string {
	if query.Get("encoding-type") == "url" {
		return func(value string) string { return s3Escape(value, true) }
	}
	return func(value string) string { return value }
}

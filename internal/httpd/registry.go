package httpd

import (
	_ "crypto/sha256" // the digest algorithms the registry accepts
	_ "crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
)

// The container registry answers the OCI Distribution Specification v1.1
// under /v2/, which is what docker, podman, buildx and crane push to and pull
// from. It is on when http.registryBaseFolder is set, and keeps everything in
// that folder (see registryStore); it never touches the served folder.

// repositoryPattern is a repository name as the specification allows it:
// lowercase components separated by single slashes. It also keeps a name from
// ever reaching a folder outside its repository, or one of the store's own,
// which all start with an underscore.
var repositoryPattern = regexp.MustCompile(
	`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`)

// tagPattern is a tag as the specification allows it.
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// maxRepositoryName is the longest repository name accepted, the limit other
// registries use, which keeps a name well inside what a path may be.
const maxRepositoryName = 255

// The shapes of a registry path after /v2/. The name is matched greedily, so
// a repository may have a component called blobs or manifests.
var (
	registryManifestPath  = regexp.MustCompile(`^(.+)/manifests/([^/]+)$`)
	registryBlobPath      = regexp.MustCompile(`^(.+)/blobs/([^/]+)$`)
	registryUploadsPath   = regexp.MustCompile(`^(.+)/blobs/uploads/?$`)
	registryUploadPath    = regexp.MustCompile(`^(.+)/blobs/uploads/([^/]+)$`)
	registryTagsPath      = regexp.MustCompile(`^(.+)/tags/list$`)
	registryReferrersPath = regexp.MustCompile(`^(.+)/referrers/([^/]+)$`)
)

// registryRoute is what a registry path asks for.
type registryRoute struct {
	kind string
	// name is the repository, ref the tag, digest or upload id after it.
	name, ref string
}

const (
	routeBase      = "base"
	routeCatalog   = "catalog"
	routeManifest  = "manifest"
	routeBlob      = "blob"
	routeUploads   = "uploads"
	routeUpload    = "upload"
	routeTags      = "tags"
	routeReferrers = "referrers"
	routeToken     = "token"
)

// registryMethods are the methods each kind of path answers. HEAD is answered
// wherever GET is; net/http leaves out the body.
var registryMethods = map[string][]string{
	routeBase:      {http.MethodGet, http.MethodHead},
	routeCatalog:   {http.MethodGet, http.MethodHead},
	routeManifest:  {http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete},
	routeBlob:      {http.MethodGet, http.MethodHead, http.MethodDelete},
	routeUploads:   {http.MethodPost},
	routeUpload:    {http.MethodGet, http.MethodPatch, http.MethodPut, http.MethodDelete},
	routeTags:      {http.MethodGet, http.MethodHead},
	routeReferrers: {http.MethodGet, http.MethodHead},
	routeToken:     {http.MethodGet},
}

// isRegistryPath reports whether a request path belongs to the registry.
func isRegistryPath(path string) bool {
	return path == "/v2" || strings.HasPrefix(path, "/v2/")
}

// parseRegistryPath reads what a path under /v2 asks for.
func parseRegistryPath(path string) (registryRoute, *registryError) {
	rest := strings.TrimPrefix(strings.TrimPrefix(path, "/v2"), "/")
	switch rest {
	case "":
		return registryRoute{kind: routeBase}, nil
	case "_catalog":
		return registryRoute{kind: routeCatalog}, nil
	case strings.TrimPrefix(registryTokenPath, "/v2/"):
		return registryRoute{kind: routeToken}, nil
	}
	var route registryRoute
	if m := registryUploadPath.FindStringSubmatch(rest); m != nil {
		route = registryRoute{kind: routeUpload, name: m[1], ref: m[2]}
	} else if m := registryUploadsPath.FindStringSubmatch(rest); m != nil {
		route = registryRoute{kind: routeUploads, name: m[1]}
	} else if m := registryBlobPath.FindStringSubmatch(rest); m != nil {
		route = registryRoute{kind: routeBlob, name: m[1], ref: m[2]}
	} else if m := registryManifestPath.FindStringSubmatch(rest); m != nil {
		route = registryRoute{kind: routeManifest, name: m[1], ref: m[2]}
	} else if m := registryTagsPath.FindStringSubmatch(rest); m != nil {
		route = registryRoute{kind: routeTags, name: m[1]}
	} else if m := registryReferrersPath.FindStringSubmatch(rest); m != nil {
		route = registryRoute{kind: routeReferrers, name: m[1], ref: m[2]}
	} else {
		return registryRoute{}, regErr(http.StatusNotFound, "NOT_FOUND",
			"this is not a path of the registry API")
	}
	if !validRepository(route.name) {
		return registryRoute{}, regErr(http.StatusBadRequest, "NAME_INVALID",
			"invalid repository name").with(route.name)
	}
	return route, nil
}

func validRepository(name string) bool {
	return len(name) <= maxRepositoryName && repositoryPattern.MatchString(name)
}

// parseBlobDigest reads a digest in one of the algorithms the registry accepts.
func parseBlobDigest(value string) (digest.Digest, bool) {
	d, err := digest.Parse(value)
	if err != nil {
		return "", false
	}
	switch d.Algorithm() {
	case digest.SHA256, digest.SHA512:
		return d, true
	}
	return "", false
}

// registryError is an error of the registry API, answered as the JSON the
// specification defines.
type registryError struct {
	status  int
	code    string
	message string
	detail  any
}

func regErr(status int, code, message string) *registryError {
	return &registryError{status: status, code: code, message: message}
}

// with is the error carrying detail, which says what it was about.
func (e *registryError) with(detail any) *registryError {
	copied := *e
	copied.detail = detail
	return &copied
}

var (
	errBlobUnknown       = regErr(http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
	errUploadUnknown     = regErr(http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "blob upload unknown to registry")
	errUploadInvalid     = regErr(http.StatusBadRequest, "BLOB_UPLOAD_INVALID", "blob upload invalid")
	errDigestInvalid     = regErr(http.StatusBadRequest, "DIGEST_INVALID", "provided digest did not match uploaded content")
	errManifestUnknown   = regErr(http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown to registry")
	errManifestInvalid   = regErr(http.StatusBadRequest, "MANIFEST_INVALID", "manifest invalid")
	errManifestBlob      = regErr(http.StatusBadRequest, "MANIFEST_BLOB_UNKNOWN", "manifest references a blob unknown to registry")
	errNameUnknown       = regErr(http.StatusNotFound, "NAME_UNKNOWN", "repository name not known to registry")
	errSizeInvalid       = regErr(http.StatusRequestEntityTooLarge, "SIZE_INVALID", "provided length did not match content length")
	errTagInvalid        = regErr(http.StatusBadRequest, "TAG_INVALID", "manifest tag did not match URI")
	errPaginationInvalid = regErr(http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "invalid number of results requested")
	errRegistryInternal  = regErr(http.StatusInternalServerError, "UNKNOWN", "unknown error")
)

// writeRegistryError answers with an error of the registry API. A HEAD
// request is answered with the status alone, as it has no body.
func writeRegistryError(w http.ResponseWriter, r *http.Request, e *registryError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Del("Content-Length")
	w.WriteHeader(e.status)
	if r.Method == http.MethodHead {
		return
	}
	entry := map[string]any{"code": e.code, "message": e.message}
	if e.detail != nil {
		entry["detail"] = e.detail
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{entry}})
}

// registryRequest is one request to the registry with what it needs.
type registryRequest struct {
	s     *Server
	set   *settings
	store *registryStore
	w     http.ResponseWriter
	r     *http.Request
	route registryRoute
	// user is the account the request authenticated as, nil for an
	// anonymous pull.
	user *account
}

func (q *registryRequest) fail(e *registryError) {
	writeRegistryError(q.w, q.r, e)
}

// internal answers a failure of the server itself, which is recorded, since
// the client is only told that something went wrong.
func (q *registryRequest) internal(what string, err error) {
	q.s.log.Error("registry "+what, "repository", q.route.name, "user", nameOf(q.user), "error", err)
	q.fail(errRegistryInternal)
}

// handleRegistry authenticates a registry request and dispatches it. The
// token endpoint is the one path that authenticates by itself.
func (s *Server) handleRegistry(set *settings, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	route, failure := parseRegistryPath(r.URL.Path)
	if failure != nil {
		writeRegistryError(w, r, failure)
		return
	}
	if allowed := registryMethods[route.kind]; !slices.Contains(allowed, r.Method) {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		writeRegistryError(w, r, regErr(http.StatusMethodNotAllowed, "UNSUPPORTED",
			"the operation is unsupported"))
		return
	}
	if route.kind == routeToken {
		s.handleRegistryToken(set, w, r)
		return
	}
	user, ok := s.registryAccess(set, w, r, route)
	if !ok {
		return
	}
	if !registryRead(r.Method) && !s.sameSite(set, w, r) {
		return
	}
	if set.cfg.ReadTimeout > 0 && r.Body != nil {
		// as for a PUT: how long an upload may go without any data arriving,
		// not how long it may take
		r.Body = &idleUploadBody{ReadCloser: r.Body, controller: http.NewResponseController(w),
			idle: seconds(set.cfg.ReadTimeout)}
	}
	q := &registryRequest{s: s, set: set, store: set.registry, w: w, r: r, route: route, user: user}
	switch route.kind {
	case routeBase:
		// what a client asks first, to learn that this is a registry and
		// whether it has to log in
		writeJSON(w, http.StatusOK, struct{}{})
	case routeCatalog:
		q.catalog()
	case routeTags:
		q.tags()
	case routeManifest:
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			q.getManifest()
		case http.MethodPut:
			q.putManifest()
		case http.MethodDelete:
			q.deleteManifest()
		}
	case routeBlob:
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			q.getBlob()
		case http.MethodDelete:
			q.deleteBlob()
		}
	case routeUploads:
		q.startUpload()
	case routeUpload:
		switch r.Method {
		case http.MethodGet:
			q.uploadStatus()
		case http.MethodPatch:
			q.patchUpload()
		case http.MethodPut:
			q.finishUpload()
		case http.MethodDelete:
			q.cancelUpload()
		}
	case routeReferrers:
		q.referrersOf()
	}
}

// isUpload reports a path of a blob upload. Asking how far an upload has got
// is a GET, but it is part of a push, and an upload belongs to the account
// that started it, so it takes that account like the rest of the push.
func isUpload(route registryRoute) bool {
	return route.kind == routeUploads || route.kind == routeUpload
}

// registryRead reports a method that only reads.
func registryRead(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// registryAccess decides whether a request may reach the registry, and
// answers it when it may not. A request identifies itself with a registry
// token (see registry_token.go) or with Basic credentials.
//
// A pull is public while http.registryAnonymousRead is on; everything else,
// the status of an upload included, takes an account that sets registry.
// /v2/ itself challenges every request
// that carries nothing, public or not: that answer is where a client learns to
// fetch a token, and without it docker would push with no credentials at all.
// Wrong credentials are refused even on a public pull: a client that sent them
// has to learn that they are wrong, not be served as anyone would be. The
// right password of an account that does not set registry is not a failed
// login, so it is not counted against the address; it is only not enough
// where registry is needed.
func (s *Server) registryAccess(set *settings, w http.ResponseWriter, r *http.Request, route registryRoute) (*account, bool) {
	needsAccount := !registryRead(r.Method) || !set.cfg.RegistryAnonymousRead || isUpload(route)
	header := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(header, "Bearer "):
		user, ok := s.registryBearer(set, strings.TrimPrefix(header, "Bearer "))
		if !ok {
			s.log.Debug("registry token refused", "method", r.Method, "path", r.URL.Path,
				"address", clientAddress(set, r))
			s.registryChallenge(set, w, r, route, true, false)
			return nil, false
		}
		if user == nil && needsAccount {
			s.registryChallenge(set, w, r, route, false, false)
			return nil, false
		}
		return user, true

	case strings.HasPrefix(header, "Basic "):
		if remaining, locked := s.lockedOut(set, r); locked {
			s.log.Info("http login refused, the address is locked out", "method", "registry",
				"address", clientAddress(set, r), "remaining", remaining.Round(time.Second))
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter(remaining)))
			writeRegistryError(w, r, regErr(http.StatusTooManyRequests, "TOOMANYREQUESTS",
				"too many failed logins from your address"))
			return nil, false
		}
		name, password, ok := parseBasic(header)
		if ok {
			if user := matchAccount(set.registryAccounts, name, password); user != nil {
				s.logins.clear(clientAddress(set, r))
				s.log.Debug("http authenticated", "user", user.name, "method", "registry",
					"address", clientAddress(set, r), "path", r.URL.Path)
				return user, true
			}
			if s.otherAccount(set, name, password) {
				if !needsAccount {
					return nil, true
				}
				s.log.Info("registry refused an account that does not set registry", "user", name,
					"method", r.Method, "path", r.URL.Path, "address", clientAddress(set, r))
				writeRegistryError(w, r, regErr(http.StatusForbidden, "DENIED",
					"requested access to the resource is denied"))
				return nil, false
			}
		}
		// the same record every other refused password writes
		s.log.Info("http login refused", "user", name, "method", "registry",
			"address", clientAddress(set, r))
		s.recordFailure(set, r)
		s.registryChallenge(set, w, r, route, false, true)
		return nil, false
	}

	if needsAccount || route.kind == routeBase {
		s.log.Debug("registry authentication required", "method", r.Method, "path", r.URL.Path,
			"address", clientAddress(set, r))
		s.registryChallenge(set, w, r, route, false, false)
		return nil, false
	}
	return nil, true
}

// registryLock is the mutex serializing the changes to one repository or one
// upload. The keys hash onto a fixed set, so however many uploads a server
// sees the locks stay the same few; two keys that share one only wait for
// each other now and then.
//
// Repositories and uploads have a set each, because they are taken in
// different orders around registryMu: a manifest push takes registryMu and
// then its repository, finishing an upload takes the upload and then
// registryMu. With one set, an upload and a repository sharing a lock would
// wait for each other while the garbage collection waited for both.
func registryLock(locks *[64]sync.Mutex, key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &locks[h.Sum32()%uint32(len(locks))]
}

func (q *registryRequest) repoLock() *sync.Mutex {
	return registryLock(&q.s.registryRepositoryLocks, q.route.name)
}

func (q *registryRequest) uploadLock(id string) *sync.Mutex {
	return registryLock(&q.s.registryUploadLocks, id)
}

// warnAboutTheRegistry says that the registry hides a v2 folder of the served
// folder, which is nothing that stops it from working and everything that
// would puzzle whoever put the folder there.
func (s *Server) warnAboutTheRegistry(set *settings) {
	if set.registry == nil {
		return
	}
	if info, err := os.Stat(filepath.Join(s.root.Base(), "v2")); err == nil && info.IsDir() {
		s.log.Warn("the container registry answers /v2, so the folder v2 in http.basefolder "+
			"cannot be reached over http", "basefolder", s.root.Base())
	}
}

// catalog lists the repositories, a page at a time. It is the _catalog
// extension docker's registry introduced, which the specification leaves out
// and every client knows.
func (q *registryRequest) catalog() {
	names, err := q.store.repositories()
	if err != nil {
		q.internal("cannot list the repositories", err)
		return
	}
	page, next, failure := paginate(q.r, names)
	if failure != nil {
		q.fail(failure)
		return
	}
	if next != "" {
		q.w.Header().Set("Link", nextLink("/v2/_catalog", q.r, next))
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"repositories": page})
}

// tags lists the tags of a repository, a page at a time, in lexical order.
func (q *registryRequest) tags() {
	if !q.store.repoExists(q.route.name) {
		q.fail(errNameUnknown.with(q.route.name))
		return
	}
	tags, err := q.store.readTags(q.route.name)
	if err != nil {
		q.internal("cannot read the tags", err)
		return
	}
	names := make([]string, 0, len(tags))
	for tag := range tags {
		names = append(names, tag)
	}
	slices.Sort(names)
	page, next, failure := paginate(q.r, names)
	if failure != nil {
		q.fail(failure)
		return
	}
	if next != "" {
		q.w.Header().Set("Link", nextLink("/v2/"+q.route.name+"/tags/list", q.r, next))
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"name": q.route.name, "tags": page})
}

// paginate cuts a sorted list down to what n and last ask for: the entries
// after last, at most n of them. next is the last entry of the page when there
// are more after it.
func paginate(r *http.Request, sorted []string) (page []string, next string, failure *registryError) {
	query := r.URL.Query()
	if last := query.Get("last"); last != "" {
		at, _ := slices.BinarySearch(sorted, last)
		for at < len(sorted) && sorted[at] <= last {
			at++
		}
		sorted = sorted[at:]
	}
	page = sorted
	if value := query.Get("n"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return nil, "", errPaginationInvalid.with(value)
		}
		if n < len(sorted) {
			page = sorted[:n]
			if n > 0 {
				next = page[n-1]
			}
		}
	}
	if page == nil {
		page = []string{}
	}
	return page, next, nil
}

// nextLink is the Link header that points at the page after this one.
func nextLink(path string, r *http.Request, last string) string {
	query := url.Values{}
	query.Set("last", last)
	if n := r.URL.Query().Get("n"); n != "" {
		query.Set("n", n)
	}
	return fmt.Sprintf(`<%s?%s>; rel="next"`, path, query.Encode())
}

// getBlob serves a blob the repository holds, with ranges.
func (q *registryRequest) getBlob() {
	d, ok := parseBlobDigest(q.route.ref)
	if !ok {
		q.fail(errDigestInvalid.with(q.route.ref))
		return
	}
	info, err := q.store.repoBlob(q.route.name, d)
	if errors.Is(err, errRegistryNotFound) {
		q.fail(errBlobUnknown.with(d.String()))
		return
	}
	if err != nil {
		q.internal("cannot find a blob", err)
		return
	}
	file, err := os.Open(q.store.blobPath(d))
	if err != nil {
		q.internal("cannot open a blob", err)
		return
	}
	defer func() { _ = file.Close() }()
	header := q.w.Header()
	header.Set("Content-Type", "application/octet-stream")
	header.Set("Docker-Content-Digest", d.String())
	header.Set("ETag", `"`+d.String()+`"`)
	// the content of a digest never changes
	header.Set("Cache-Control", "max-age=31536000")
	http.ServeContent(q.w, q.r, "", info.ModTime(), file)
	if q.r.Method == http.MethodGet {
		q.s.log.Debug("registry blob pulled", "repository", q.route.name, "digest", d.String(),
			"bytes", info.Size(), "user", nameOf(q.user), "address", clientAddress(q.set, q.r))
	}
}

// deleteBlob takes a blob out of a repository. What the store holds is left
// to the garbage collection, which removes it once nothing refers to it.
func (q *registryRequest) deleteBlob() {
	d, ok := parseBlobDigest(q.route.ref)
	if !ok {
		q.fail(errDigestInvalid.with(q.route.ref))
		return
	}
	err := q.store.unlinkBlob(q.route.name, d)
	if errors.Is(err, errRegistryNotFound) {
		q.fail(errBlobUnknown.with(d.String()))
		return
	}
	if err != nil {
		q.internal("cannot delete a blob", err)
		return
	}
	q.s.log.Info("registry blob deleted", "repository", q.route.name, "digest", d.String(),
		"user", nameOf(q.user), "address", clientAddress(q.set, q.r))
	q.w.WriteHeader(http.StatusAccepted)
}

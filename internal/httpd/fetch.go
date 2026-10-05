package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"go-fs/internal/vfs"
)

// The listing can fetch a file from a URL into the folder it shows, the way
// the registry page pulls an image: the dialog starts a job on the server,
// which downloads the file while the page asks how far it has got. The file is
// named as the remote names it, by its Content-Disposition or else by the last
// segment of the URL the redirects ended at, and it lands under the rules an
// upload of that name would: created where the account may create, and
// replacing a file only where it may overwrite.
//
// A fetch runs on to its end whether or not a page still asks after it, and
// several can run at once: every listing of a session asks for the fetches
// of its account, wherever they store to, and shows them in its header, so
// that one started before a reload, or in another tab, is still seen.
//
// The server reaches whatever URL it is given, inside the network it is in as
// well as outside, so the dialog is offered to a session of an account and to
// nobody else: not to a folder whose PUT is public, and not to a header or a
// bearer token, which have the API.

const (
	actionFetch     = "fetch"
	actionFetchJob  = "fetch-job"
	actionFetchJobs = "fetch-jobs"
)

// fetchMethods are the methods each endpoint answers.
var fetchMethods = map[string]string{
	actionFetch:     "POST",
	actionFetchJob:  "GET, HEAD, DELETE",
	actionFetchJobs: "GET, HEAD",
}

// fetchAction reports which fetch endpoint a request is for, or "" for any
// other request.
func fetchAction(r *http.Request) string {
	switch action := r.URL.Query().Get(sessionParam); action {
	case actionFetch, actionFetchJob, actionFetchJobs:
		return action
	default:
		return ""
	}
}

// mayFollowFetches decides whether a listing shows the fetches of the account
// looking at it, and whether it may ask for them: a session of an account,
// whether or not it may fetch into this folder.
func mayFollowFetches(cred credential) bool {
	return cred.token && cred.user != nil
}

// mayFetch decides whether the listing of a folder offers Fetch, and whether
// a fetch into it may start.
func mayFetch(cred credential, virtual string) bool {
	return mayFollowFetches(cred) && fetchGranted(cred.user, virtual, actCreate)
}

// fetchGranted is the right an account has to a path, whether or not the
// method needs an account there: a fetch is only ever made by one.
func fetchGranted(user *account, virtual string, act action) bool {
	return user.allows(virtual) && granted(user.perms, act)
}

// handleFetch answers the fetch endpoints, on a folder.
func (s *Server) handleFetch(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, cred credential, action string) {
	w.Header().Set("Cache-Control", "no-store")
	if info, err := os.Stat(target.Path); err != nil || !info.IsDir() {
		http.NotFound(w, r)
		return
	}
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case action == actionFetch && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.fetchStart(set, w, r, target, cred)
	case action == actionFetchJob && read:
		if job := s.fetchJobOf(w, r, cred); job != nil {
			writeJSON(w, http.StatusOK, job.view())
		}
	case action == actionFetchJobs && read:
		if !mayFollowFetches(cred) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, fetchJobsJSON{Jobs: s.fetchJobs(cred.user.name)})
	case action == actionFetchJob && r.Method == http.MethodDelete:
		// stops a fetch that runs, and takes it off the list either way
		if !s.sameSite(set, w, r) {
			return
		}
		job := s.fetchJobOf(w, r, cred)
		if job == nil {
			return
		}
		if job.dismiss() {
			s.log.Info("http fetch stopped", "job", job.id, "what", job.what, "user", cred.user.name)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", fetchMethods[action])
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// fetchJobsJSON is what the page reads of the fetches of its account.
type fetchJobsJSON struct {
	Jobs []registryJobJSON `json:"jobs"`
}

// fetchJobOf finds the fetch a request names, and answers a request for one
// that is not the caller's.
func (s *Server) fetchJobOf(w http.ResponseWriter, r *http.Request, cred credential) *registryJob {
	if !mayFollowFetches(cred) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil
	}
	job := s.job(r.URL.Query().Get("id"), cred.user.name)
	if job == nil || job.kind != jobFetch {
		http.Error(w, "That fetch is not known.", http.StatusNotFound)
		return nil
	}
	return job
}

// fetchBody is the body of a fetch.
type fetchBody struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Headers are what the dialog's text area holds: one Name: value a line.
	Headers string `json:"headers"`
	// SkipVerify takes whatever certificate the remote shows: the dialog's
	// Validate Connection, unticked.
	SkipVerify bool `json:"skipVerify"`
}

// fetchRequest is a fetch that was read and found sound.
type fetchRequest struct {
	url                *url.URL
	header             http.Header
	username, password string
	skipVerify         bool
}

// request reads what a fetch asks for.
func (b fetchBody) request() (fetchRequest, error) {
	raw := strings.TrimSpace(b.URL)
	if raw == "" {
		return fetchRequest{}, errors.New("name the URL to fetch")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fetchRequest{}, fmt.Errorf("%q is not a URL", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fetchRequest{}, errors.New("only an http or https URL can be fetched")
	}
	if u.Host == "" {
		return fetchRequest{}, fmt.Errorf("%q names no host", raw)
	}
	if u.User != nil {
		return fetchRequest{}, errors.New("put the login into the username and password fields rather than the URL")
	}
	// a fragment is the browser's, and never sent
	u.Fragment, u.RawFragment = "", ""
	header, err := parseFetchHeaders(b.Headers)
	if err != nil {
		return fetchRequest{}, err
	}
	username := strings.TrimSpace(b.Username)
	if (username != "" || b.Password != "") && header.Get("Authorization") != "" {
		return fetchRequest{}, errors.New("give either a username and password or an Authorization header, not both")
	}
	return fetchRequest{url: u, header: header, username: username, password: b.Password,
		skipVerify: b.SkipVerify}, nil
}

// maxFetchHeaders bounds the headers a fetch may add.
const maxFetchHeaders = 32

// headerName is a token of RFC 9110, which is what a field name is.
var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// parseFetchHeaders reads the headers of a fetch, one Name: value a line.
// Blank lines are skipped.
func parseFetchHeaders(text string) (http.Header, error) {
	header := http.Header{}
	count := 0
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !found || !headerName.MatchString(name) {
			return nil, fmt.Errorf("line %d of the headers is not Name: value", i+1)
		}
		value = strings.TrimSpace(value)
		for _, c := range value {
			if (c < 0x20 && c != '\t') || c == 0x7f {
				return nil, fmt.Errorf("the value of the %s header has a control character in it", name)
			}
		}
		if canonical := http.CanonicalHeaderKey(name); serverSetHeader(canonical) {
			return nil, fmt.Errorf("the %s header is the server's to set", canonical)
		}
		if count++; count > maxFetchHeaders {
			return nil, fmt.Errorf("a fetch takes at most %d headers", maxFetchHeaders)
		}
		header.Add(name, value)
	}
	return header, nil
}

// serverSetHeader reports whether a header is one the connection itself
// decides, which a fetch may not set.
func serverSetHeader(canonical string) bool {
	switch canonical {
	case "Host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Te", "Trailer", "Keep-Alive":
		return true
	}
	return strings.HasPrefix(canonical, "Proxy-")
}

// shownURL is a URL as the log and the page show it: without a query, which
// may carry a token, and without a login.
func shownURL(u *url.URL) string {
	shown := *u
	shown.User = nil
	shown.RawQuery, shown.ForceQuery = "", false
	shown.Fragment, shown.RawFragment = "", ""
	return shown.String()
}

// fetchClient is what every fetch goes through, and insecureFetchClient
// every fetch that does not validate the connection. They follow redirects as
// the registry client does, keeping the credentials to the origin they were
// given for. The body is not decompressed: a .tar.gz served with a gzip
// Content-Encoding is stored as the .tar.gz it is.
var (
	fetchClient         = &http.Client{Transport: newFetchTransport(remoteTransport), CheckRedirect: keepCredentialsHome}
	insecureFetchClient = &http.Client{Transport: newFetchTransport(insecureRemoteTransport), CheckRedirect: keepCredentialsHome}
)

func newFetchTransport(base http.RoundTripper) http.RoundTripper {
	transport := base.(*http.Transport).Clone()
	transport.DisableCompression = true
	return transport
}

// fetchClientFor is the client of a fetch, by whether it validates the
// connection.
func fetchClientFor(skipVerify bool) *http.Client {
	if skipVerify {
		return insecureFetchClient
	}
	return fetchClient
}

// fetchStart starts a fetch into a folder.
func (s *Server) fetchStart(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, cred credential) {
	folder := vfs.AsFolder(target.Virtual)
	if !mayFetch(cred, folder) {
		s.log.Info("http fetch refused, no session of an account that may create here",
			"user", nameOf(cred.user), "folder", folder, "address", clientAddress(set, r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	user := cred.user
	var body fetchBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxTransferRequest)).Decode(&body); err != nil {
		http.Error(w, "The request could not be read.", http.StatusBadRequest)
		return
	}
	fetch, err := body.request()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	shown := shownURL(fetch.url)
	address := clientAddress(set, r)
	job, err := s.startJob(jobFetch, user.name, shown+" → "+folder, func(ctx context.Context, job *registryJob) (string, error) {
		job.named(cleanFetchedName(fetch.url.Path), folder)
		message, err := s.fetchFile(ctx, set, job, fetch, folder, user, address)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("http fetch failed", "url", shown, "folder", folder, "user", user.name,
				"address", address, "error", err)
		}
		return message, err
	})
	if err == nil {
		s.log.Info("http fetch started", "url", shown, "folder", folder, "headers", len(fetch.header),
			"login", fetch.username != "", "verify", !fetch.skipVerify, "user", user.name, "address", address, "job", job.id)
	}
	s.answerStarted(w, job, err)
}

// fetchFile downloads a file into a folder, and says what it stored.
func (s *Server) fetchFile(ctx context.Context, set *settings, job *registryJob, fetch fetchRequest,
	folder string, user *account, address string) (string, error) {
	started := time.Now()
	getCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	req, err := http.NewRequestWithContext(getCtx, http.MethodGet, fetch.url.String(), nil)
	if err != nil {
		return "", err
	}
	for key, values := range fetch.header {
		req.Header[key] = values
	}
	if fetch.username != "" || fetch.password != "" {
		req.SetBasicAuth(fetch.username, fetch.password)
	}
	res, err := fetchClientFor(fetch.skipVerify).Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			// its message repeats the URL, query and all
			err = urlErr.Err
		}
		return "", fmt.Errorf("%s: %w", fetch.url.Host, withCertificateHint(err))
	}
	defer func() { _ = res.Body.Close() }()
	host := res.Request.URL.Host
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", fmt.Errorf("%s answered %s", host, res.Status)
	}

	name, err := fetchedName(res)
	if err != nil {
		return "", err
	}
	target := s.root.Resolve(folder, name)
	if !target.Valid || vfs.AsFolder(path.Dir(target.Virtual)) != folder {
		return "", fmt.Errorf("a file named %q cannot be stored here", name)
	}
	// asked before the download as well as after it, so that a name that is
	// taken costs nothing
	if _, err := fetchReplaces(target, name, user); err != nil {
		return "", err
	}
	limit := set.cfg.MaxUploadSize
	if limit > 0 && res.ContentLength > limit {
		return "", fetchTooLarge(name, limit)
	}
	job.named(name, "")
	if res.ContentLength > 0 {
		job.plan(0, res.ContentLength)
	}

	staging := stagingFolder(set)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return "", err
	}
	staged, err := os.CreateTemp(staging, "fetch-*")
	if err != nil {
		return "", err
	}
	stagedPath := staged.Name()
	defer func() { _ = os.Remove(stagedPath) }()
	// a temporary file is the owner's alone, and this one is about to be a
	// file of the served folder like an upload
	_ = staged.Chmod(0o644)

	source := io.Reader(res.Body)
	if limit > 0 {
		source = io.LimitReader(res.Body, limit+1)
	}
	job.downloading()
	reader := watch(source, job, cancel)
	written, err := io.Copy(staged, reader)
	reader.done()
	if closeErr := staged.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		if errors.Is(context.Cause(getCtx), errStalled) {
			return "", fmt.Errorf("%s from %s: %w", name, host, errStalled)
		}
		return "", fmt.Errorf("%s from %s: %w", name, host, err)
	}
	if limit > 0 && written > limit {
		return "", fetchTooLarge(name, limit)
	}

	lock := s.uploadLock(target.Path)
	lock.Lock()
	defer lock.Unlock()
	replace, err := fetchReplaces(target, name, user)
	if err != nil {
		return "", err
	}
	if err := finalizeUpload(stagedPath, target.Path, replace); err != nil {
		return "", err
	}
	s.log.Info("http fetch", "user", user.name, "url", shownURL(fetch.url), "file", target.Virtual,
		"bytes", written, "replaced", replace, "address", address,
		"took", time.Since(started).Round(time.Millisecond))
	return fmt.Sprintf("Fetched %s (%s) into %s.", name, readableSize(written), folder), nil
}

// fetchReplaces decides whether a fetch may store its file, and whether that
// replaces one that is there.
func fetchReplaces(target vfs.Target, name string, user *account) (bool, error) {
	info, err := os.Stat(target.Path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return false, fmt.Errorf("%q is taken here by something that is not a file", name)
	case err == nil:
		if !fetchGranted(user, target.Virtual, actOverwrite) {
			return false, fmt.Errorf("there is already a file named %q here", name)
		}
		return true, nil
	case !errors.Is(err, fs.ErrNotExist):
		return false, err
	}
	if !fetchGranted(user, target.Virtual, actCreate) {
		return false, fmt.Errorf("you may not create %q here", name)
	}
	return false, nil
}

func fetchTooLarge(name string, limit int64) error {
	return fmt.Errorf("%s is larger than the maximum of %d bytes", name, limit)
}

// fetchedName is what a fetched file is called: what its Content-Disposition
// says, or else the last segment of the URL the redirects ended at.
func fetchedName(res *http.Response) (string, error) {
	if value := res.Header.Get("Content-Disposition"); value != "" {
		if _, params, err := mime.ParseMediaType(value); err == nil {
			if name := cleanFetchedName(params["filename"]); name != "" {
				return name, nil
			}
		}
	}
	if name := cleanFetchedName(res.Request.URL.Path); name != "" {
		return name, nil
	}
	return "", fmt.Errorf("%s names no file: the URL does not end in a name and no Content-Disposition gives one",
		res.Request.URL.Host)
}

// cleanFetchedName takes the last segment of a name the remote gave, which is
// all of it that can name a file in this folder, or "" when that is nothing.
func cleanFetchedName(name string) string {
	name = path.Base(strings.ReplaceAll(name, `\`, "/"))
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || name == "/" {
		return ""
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return ""
		}
	}
	return name
}

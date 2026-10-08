package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// A JFrog Artifactory is reached by its REST API, over HTTP or HTTPS, and
// logged in to with a token sent as "Authorization: Bearer <token>". Its
// files are in repositories, so the top of the host, /, lists the
// repositories the token may see as folders, and /<repository>/<path> is a
// file or a folder in one:
//
//	GET    api/repositories                      the repositories, and whether the token works
//	GET    api/storage/<repo>/<path>             what a path is: a folder and its children, or a file
//	GET    api/storage/<repo>/<path>?list&…      a folder with the size and the time of each entry
//	GET    <repo>/<path>                         a file, a range of it where one is asked
//	PUT    <repo>/<path>                         a file, which is there once all of it was taken
//	PUT    <repo>/<path>/                        a folder
//	POST   api/move/<repo>/<path>?to=/<repo>/…   a rename
//	DELETE <repo>/<path>                         a file, or a folder and all that is in it
//
// The listing with sizes and times and the move are of Artifactory Pro and
// the cloud. An Artifactory without them still lists a folder, by its
// children, without their sizes or times; a rename fails with what it says.

// artifactoryAnswerTimeout bounds the wait for the answer to a request once
// it was sent, which for an upload is once all of the file was: Artifactory
// takes the checksums of a large file before it answers.
const artifactoryAnswerTimeout = 5 * time.Minute

// maxArtifactoryAnswer bounds an answer of the REST API that is read whole.
const maxArtifactoryAnswer = 32 << 20

// errNotEmpty is a folder RemoveDir found something in.
var errNotEmpty = errors.New("the folder is not empty")

// artifactoryFS is an Artifactory, logged in to with a token.
type artifactoryFS struct {
	ctx    context.Context
	login  Login
	client *http.Client
	// repos are the repositories, once asked for
	repos []string
}

func openArtifactory(ctx context.Context, l Login) *artifactoryFS {
	dialer := &net.Dialer{Timeout: HandshakeTimeout}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   HandshakeTimeout,
		ResponseHeaderTimeout: artifactoryAnswerTimeout,
		IdleConnTimeout:       time.Minute,
	}
	return &artifactoryFS{ctx: ctx, login: l, client: &http.Client{Transport: transport}}
}

// split is a clean absolute path as the repository and the path in it.
func split(p string) (repo, rest string) {
	p = strings.TrimPrefix(p, "/")
	repo, rest, _ = strings.Cut(p, "/")
	return repo, rest
}

// escaped is a path as it goes into a URL: every name escaped, a ; and a ?
// too, which Artifactory would read as parameters.
func escaped(p string) string {
	names := strings.Split(p, "/")
	for i, name := range names {
		names[i] = url.PathEscape(name)
	}
	return strings.Join(names, "/")
}

func (a *artifactoryFS) itemURL(p string) string    { return a.login.URL + escaped(p) }
func (a *artifactoryFS) storageURL(p string) string { return a.login.URL + "/api/storage" + escaped(p) }

// do sends a request with the token.
func (a *artifactoryFS) do(method, target string, body io.Reader, size int64, header http.Header) (*http.Response, error) {
	if body != nil && size == 0 {
		// an empty body is sent as one, rather than as one of no known length
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(a.ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if body != nil && body != http.NoBody {
		req.ContentLength = size
	}
	for key, values := range header {
		req.Header[key] = values
	}
	req.Header.Set("Authorization", "Bearer "+a.login.Token)
	req.Header.Set("User-Agent", "go-fs")
	resp, err := a.client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("%s: %w", a.login.Shown(), err)
	}
	return resp, nil
}

// getJSON asks the REST API for an answer into into, and answers the
// response's status where that is not a success.
func (a *artifactoryFS) getJSON(target string, into any) (int, error) {
	resp, err := a.do(http.MethodGet, target, nil, 0, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, a.failure(resp)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxArtifactoryAnswer)).Decode(into); err != nil {
		return resp.StatusCode, fmt.Errorf("%s does not answer as an Artifactory at %s: %w", a.login.Shown(), a.login.URL, err)
	}
	return resp.StatusCode, nil
}

// artifactoryErrors is how the REST API says what went wrong: errors by most,
// messages by the move.
type artifactoryErrors struct {
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Messages []struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	} `json:"messages"`
}

func (e artifactoryErrors) text(onlyErrors bool) string {
	var said []string
	for _, item := range e.Errors {
		said = append(said, item.Message)
	}
	for _, item := range e.Messages {
		if !onlyErrors || strings.EqualFold(item.Level, "ERROR") {
			said = append(said, item.Message)
		}
	}
	return strings.Join(said, "; ")
}

// failure reads what a response that is not a success says, wrapping
// fs.ErrNotExist and fs.ErrPermission where it is one of those.
func (a *artifactoryFS) failure(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var said artifactoryErrors
	message := ""
	if json.Unmarshal(body, &said) == nil {
		message = said.text(false)
	}
	if message == "" && !strings.Contains(resp.Header.Get("Content-Type"), "html") {
		message = strings.TrimSpace(string(body))
		if first, _, cut := strings.Cut(message, "\n"); cut {
			message = first
		}
		if len(message) > 200 {
			message = message[:200] + "…"
		}
	}
	if message == "" {
		message = resp.Status
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s refused the token: %s", a.login.Shown(), message)
	case http.StatusForbidden:
		return fmt.Errorf("%s: %w", message, fs.ErrPermission)
	case http.StatusNotFound:
		return fmt.Errorf("%s: %w", message, fs.ErrNotExist)
	}
	return fmt.Errorf("%s answered %s: %s", a.login.Shown(), resp.Status, message)
}

// repositories are the keys of the repositories the token may see, which is
// also what tells whether the token works.
func (a *artifactoryFS) repositories() ([]string, error) {
	if a.repos != nil {
		return a.repos, nil
	}
	var listed []struct {
		Key string `json:"key"`
	}
	status, err := a.getJSON(a.login.URL+"/api/repositories", &listed)
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("%s has no Artifactory at %s", a.login.Shown(), a.login.URL)
	}
	if err != nil {
		return nil, err
	}
	repos := make([]string, 0, len(listed))
	for _, repo := range listed {
		if repo.Key != "" {
			repos = append(repos, repo.Key)
		}
	}
	sort.Strings(repos)
	a.repos = repos
	return repos, nil
}

// artifactorySize is a size, which the REST API gives as a string in the
// information of a file and as a number in a listing.
type artifactorySize int64

func (s *artifactorySize) UnmarshalJSON(b []byte) error {
	text := strings.Trim(string(b), `"`)
	if text == "" || text == "null" {
		*s = 0
		return nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return err
	}
	*s = artifactorySize(n)
	return nil
}

// artifactoryTime reads a time of the REST API, the zero time where there is
// none.
func artifactoryTime(text string) time.Time {
	at, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		// the older ones leave the colon out of the zone
		at, err = time.Parse("2006-01-02T15:04:05.000Z0700", text)
	}
	if err != nil {
		return time.Time{}
	}
	return at
}

// artifactoryItem is what the storage API says of a folder or a file.
type artifactoryItem struct {
	DownloadURI  string           `json:"downloadUri"`
	LastModified string           `json:"lastModified"`
	Size         artifactorySize  `json:"size"`
	Checksums    *json.RawMessage `json:"checksums"`
	Children     *[]struct {
		URI    string `json:"uri"`
		Folder bool   `json:"folder"`
	} `json:"children"`
}

func (i artifactoryItem) folder() bool {
	return i.Children != nil || (i.DownloadURI == "" && i.Checksums == nil)
}

// artifactoryInfo is a file, a folder or a repository of an Artifactory.
type artifactoryInfo struct {
	name string
	size int64
	mod  time.Time
	dir  bool
}

func (i artifactoryInfo) Name() string       { return i.name }
func (i artifactoryInfo) Size() int64        { return i.size }
func (i artifactoryInfo) ModTime() time.Time { return i.mod }
func (i artifactoryInfo) IsDir() bool        { return i.dir }
func (i artifactoryInfo) Sys() any           { return nil }
func (i artifactoryInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}

func (a *artifactoryFS) Resolve(p string) (string, error) {
	return path.Clean("/" + p), nil
}

func (a *artifactoryFS) Stat(p string) (fs.FileInfo, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		if _, err := a.repositories(); err != nil {
			return nil, err
		}
		return artifactoryInfo{name: "/", dir: true}, nil
	}
	var item artifactoryItem
	if _, err := a.getJSON(a.storageURL(p), &item); err != nil {
		return nil, err
	}
	info := artifactoryInfo{name: path.Base(p), mod: artifactoryTime(item.LastModified), dir: item.folder()}
	if !info.dir {
		info.size = int64(item.Size)
	}
	return info, nil
}

func (a *artifactoryFS) Lstat(p string) (fs.FileInfo, error) { return a.Stat(p) }

func (a *artifactoryFS) ReadDir(p string) ([]fs.FileInfo, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		repos, err := a.repositories()
		if err != nil {
			return nil, err
		}
		infos := make([]fs.FileInfo, 0, len(repos))
		for _, repo := range repos {
			infos = append(infos, artifactoryInfo{name: repo, dir: true})
		}
		return infos, nil
	}
	var listed struct {
		Files []struct {
			URI          string          `json:"uri"`
			Size         artifactorySize `json:"size"`
			LastModified string          `json:"lastModified"`
			Folder       bool            `json:"folder"`
		} `json:"files"`
	}
	status, err := a.getJSON(a.storageURL(p)+"?list&deep=0&listFolders=1", &listed)
	switch {
	case err == nil:
		infos := make([]fs.FileInfo, 0, len(listed.Files))
		for _, file := range listed.Files {
			name := strings.Trim(file.URI, "/")
			if name == "" || strings.Contains(name, "/") {
				continue
			}
			info := artifactoryInfo{name: name, mod: artifactoryTime(file.LastModified), dir: file.Folder}
			if !info.dir {
				info.size = int64(file.Size)
			}
			infos = append(infos, info)
		}
		return infos, nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound:
		return nil, err
	}
	// an Artifactory without the listing, which is of Pro, lists the
	// children alone
	return a.children(p)
}

// children lists a folder by what the storage API says of it, which names
// the entries and says which are folders, and no more.
func (a *artifactoryFS) children(p string) ([]fs.FileInfo, error) {
	var item artifactoryItem
	if _, err := a.getJSON(a.storageURL(p), &item); err != nil {
		return nil, err
	}
	if item.Children == nil {
		return nil, fmt.Errorf("%s is not a folder", p)
	}
	infos := make([]fs.FileInfo, 0, len(*item.Children))
	for _, child := range *item.Children {
		name := strings.Trim(child.URI, "/")
		if name == "" || strings.Contains(name, "/") {
			continue
		}
		infos = append(infos, artifactoryInfo{name: name, dir: child.Folder})
	}
	return infos, nil
}

func (a *artifactoryFS) Open(p string) (io.ReadSeekCloser, error) {
	p = path.Clean("/" + p)
	info, err := a.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a folder", p)
	}
	return &artifactoryFile{fs: a, target: a.itemURL(p), size: info.Size()}, nil
}

// inRepository refuses a path that is not in a repository, which what writes
// cannot be: a repository is created, renamed and removed in Artifactory.
func inRepository(p, what string) error {
	if _, rest := split(path.Clean("/" + p)); rest == "" {
		return fmt.Errorf("%s: %w", what, fs.ErrPermission)
	}
	return nil
}

// Put writes a file at once: Artifactory keeps an upload only once all of it
// was taken, and replaces what was there then.
func (a *artifactoryFS) Put(p string, body io.Reader, size int64) (int64, error) {
	p = path.Clean("/" + p)
	if err := inRepository(p, "a file goes into a repository"); err != nil {
		return 0, err
	}
	counted := &countingReader{r: body}
	if size < 0 {
		size = -1
	}
	resp, err := a.do(http.MethodPut, a.itemURL(p), counted, size,
		http.Header{"Content-Type": {"application/octet-stream"}})
	if err != nil {
		return counted.n.Load(), err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return counted.n.Load(), a.failure(resp)
	}
	return counted.n.Load(), nil
}

func (a *artifactoryFS) Mkdir(p string) error {
	p = path.Clean("/" + p)
	if err := inRepository(p, "a repository is created in Artifactory itself"); err != nil {
		return err
	}
	return a.expect(http.MethodPut, a.itemURL(p)+"/", http.StatusOK, http.StatusCreated)
}

func (a *artifactoryFS) Rename(from, to string) error {
	from, to = path.Clean("/"+from), path.Clean("/"+to)
	if err := inRepository(from, "a repository is renamed in Artifactory itself"); err != nil {
		return err
	}
	if err := inRepository(to, "a file goes into a repository"); err != nil {
		return err
	}
	resp, err := a.do(http.MethodPost, a.login.URL+"/api/move"+escaped(from)+"?to="+url.QueryEscape(to), http.NoBody, 0, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return a.failure(resp)
	}
	// a move that failed may still answer 200, and say so in its messages
	var said artifactoryErrors
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&said) == nil {
		if message := said.text(true); message != "" {
			return fmt.Errorf("%s did not move %s: %s", a.login.Shown(), from, message)
		}
	}
	return nil
}

func (a *artifactoryFS) Remove(p string) error {
	p = path.Clean("/" + p)
	if err := inRepository(p, "a repository is removed in Artifactory itself"); err != nil {
		return err
	}
	return a.expect(http.MethodDelete, a.itemURL(p), http.StatusOK, http.StatusNoContent)
}

// RemoveDir looks into the folder first: Artifactory removes a folder with
// all that is in it.
func (a *artifactoryFS) RemoveDir(p string) error {
	p = path.Clean("/" + p)
	if err := inRepository(p, "a repository is removed in Artifactory itself"); err != nil {
		return err
	}
	infos, err := a.ReadDir(p)
	if err != nil {
		return err
	}
	if len(infos) > 0 {
		return errNotEmpty
	}
	return a.expect(http.MethodDelete, a.itemURL(p), http.StatusOK, http.StatusNoContent)
}

// expect sends a request without a body, and fails unless it is answered with
// one of ok.
func (a *artifactoryFS) expect(method, target string, ok ...int) error {
	resp, err := a.do(method, target, http.NoBody, 0, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	for _, status := range ok {
		if resp.StatusCode == status {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			return nil
		}
	}
	return a.failure(resp)
}

func (a *artifactoryFS) Close() error {
	a.client.CloseIdleConnections()
	return nil
}

// artifactoryFile is a file of an Artifactory, read from wherever it was
// sought to: a seek only moves the offset, and the next read asks for the
// file from there on.
type artifactoryFile struct {
	fs     *artifactoryFS
	target string
	size   int64
	offset int64
	body   io.ReadCloser
}

func (f *artifactoryFile) Read(b []byte) (int, error) {
	if f.offset >= f.size {
		return 0, io.EOF
	}
	if f.body == nil {
		if err := f.open(); err != nil {
			return 0, err
		}
	}
	n, err := f.body.Read(b)
	f.offset += int64(n)
	return n, err
}

func (f *artifactoryFile) open() error {
	var header http.Header
	if f.offset > 0 {
		header = http.Header{"Range": {"bytes=" + strconv.FormatInt(f.offset, 10) + "-"}}
	}
	resp, err := f.fs.do(http.MethodGet, f.target, nil, 0, header)
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusPartialContent && f.offset > 0:
	case resp.StatusCode == http.StatusOK:
		// a host that sends all of it is read up to the offset
		if f.offset > 0 {
			if _, err := io.CopyN(io.Discard, resp.Body, f.offset); err != nil {
				_ = resp.Body.Close()
				return err
			}
		}
	default:
		defer func() { _ = resp.Body.Close() }()
		return f.fs.failure(resp)
	}
	f.body = resp.Body
	return nil
}

func (f *artifactoryFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekCurrent:
		offset += f.offset
	case io.SeekEnd:
		offset += f.size
	}
	if offset < 0 {
		return 0, errors.New("seek before the start of the file")
	}
	if offset != f.offset && f.body != nil {
		_ = f.body.Close()
		f.body = nil
	}
	f.offset = offset
	return offset, nil
}

func (f *artifactoryFile) Close() error {
	if f.body == nil {
		return nil
	}
	err := f.body.Close()
	f.body = nil
	return err
}

// countingReader counts what was read through it. The count is atomic: the
// HTTP transport reads a request body on its own goroutine, and may still be
// at it when the response is in.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n.Add(int64(n))
	return n, err
}

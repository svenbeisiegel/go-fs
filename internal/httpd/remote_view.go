package httpd

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"go-fs/internal/config"
	"go-fs/internal/remote"
	"go-fs/internal/vfs"
)

// A stored server can be browsed the way the served folder is: the menu in
// the corner of the header names every server, and the page it opens is the
// listing, of a folder of that server. Downloading, uploading, creating a
// folder, renaming and deleting go through go-fs, which logs in with the
// login the file holds, so the password never reaches the page; sharing and
// sending are left out, since they are about files go-fs serves itself.
//
// Every request is one marker on the root of the served tree, naming the
// server and the path on it, and answers the verbs the listing sends to a
// path of its own:
//
//	/?go-fs=remote&server=<name>&path=<path>
//
// GET lists a folder or downloads a file, or with archive=1 packs a folder as
// the listing's Download does; PUT uploads, whole or in chunks; MKCOL creates
// a folder, MOVE renames and DELETE removes. Each logs in anew: a server is a
// few requests away from a page, and a login held between them would be one
// to keep track of and to end.
//
// Browsing is offered to whoever may send, a session of an account that may
// read, since the server's login reaches as far as a send does. What the
// account may do beyond reading follows its permissions, as it does for the
// served folder; its paths are of the served folder, and say nothing of a
// server's.

const (
	actionRemote = "remote"
	// remoteServerParam and remotePathParam name the server and the path on
	// it.
	remoteServerParam = "server"
	remotePathParam   = "path"
	// remoteArchiveParam asks for a folder as an archive.
	remoteArchiveParam = "archive"
)

// remoteAction reports a request for a stored server.
func remoteAction(r *http.Request) bool {
	return r.URL.Query().Get(sessionParam) == actionRemote
}

// mayBrowseRemote decides whether the menu offers the stored servers, and
// whether one may be browsed.
func mayBrowseRemote(cred credential) bool {
	return mayFollowFetches(cred) && granted(cred.user.perms, actRead)
}

// remoteURL is the link to a path of a stored server, "" for where its login
// starts. The path comes last, so that the page can append an escaped name to
// the link of a folder.
func remoteURL(server, p string) string {
	return "/?" + sessionParam + "=" + actionRemote + "&" + remoteServerParam + "=" + url.QueryEscape(server) +
		"&" + remotePathParam + "=" + url.QueryEscape(p)
}

// remotePath reads a path of a server out of a query: cleaned, and "" for
// where the login starts.
func remotePath(query url.Values) string {
	p := strings.TrimSpace(query.Get(remotePathParam))
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

// remoteRequest is a request for a stored server, once it was found and
// logged in to.
type remoteRequest struct {
	server config.Server
	login  remote.Login
	client *sftp.Client
	user   *account
	// path is the path asked for, "" for where the login starts.
	path    string
	address string
}

// logged is a path of the server as the log shows it.
func (q *remoteRequest) logged(p string) string {
	return q.login.Where(p) + " (server " + q.server.Name + ")"
}

// handleRemote answers a request for a stored server.
func (s *Server) handleRemote(set *settings, w http.ResponseWriter, r *http.Request, cred credential) {
	w.Header().Set("Cache-Control", "no-store")
	// the page says who is signed in, and only a session may see it
	w.Header().Set("Vary", "Cookie")
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	if !mayBrowseRemote(cred) {
		if cred.user == nil && read && browserRequest(r) && (canLogIn(set) || canLogInToRegistry(set)) {
			http.Redirect(w, r, loginURL(r.URL), http.StatusSeeOther)
			return
		}
		s.log.Info("http remote refused, no session of an account that may read",
			"user", nameOf(cred.user), "method", r.Method, "address", clientAddress(set, r))
		if cred.user == nil {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, methodMkcol, methodMove:
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE, MKCOL, MOVE")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !read && !s.sameSite(set, w, r) {
		return
	}

	query := r.URL.Query()
	server, ok := config.FindServer(set.servers, query.Get(remoteServerParam))
	if !ok {
		http.NotFound(w, r)
		return
	}
	q := &remoteRequest{server: server, user: cred.user, path: remotePath(query),
		address: clientAddress(set, r)}
	// a page asked for is a page answered, with what went wrong in it
	page := read && browserRequest(r) && query.Get(remoteArchiveParam) == ""
	fail := func(status int, err error) {
		if page {
			s.remotePage(set, w, r, cred, q, nil, err)
			return
		}
		http.Error(w, err.Error(), status)
	}

	login, err := remote.FromServer(server).Checked(false)
	if err != nil {
		fail(http.StatusBadGateway, fmt.Errorf("the server %s: %w", server.Name, err))
		return
	}
	// only SFTP is browsed so far; another protocol is reached from here
	if login.Type != config.ServerTypeSFTP {
		fail(http.StatusBadGateway, fmt.Errorf("go-fs cannot browse a server reached by %s yet", login.Type))
		return
	}
	q.login = login
	conn, client, err := remote.OpenSFTP(r.Context(), login, set.ssh)
	if err != nil {
		s.log.Warn("http remote cannot log in", "server", server.Name, "user", cred.user.name,
			"address", q.address, "error", err)
		fail(http.StatusBadGateway, err)
		return
	}
	defer func() { _ = conn.Close() }()
	defer func() { _ = client.Close() }()
	q.client = client

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.remoteGet(set, w, r, cred, q, page)
	case http.MethodPut:
		s.remotePut(set, w, r, q)
	case methodMkcol:
		s.remoteMkdir(w, r, q)
	case methodMove:
		s.remoteMove(set, w, r, q)
	case http.MethodDelete:
		s.remoteDelete(w, r, q)
	}
}

// remoteGet lists a folder, packs it, or downloads a file.
func (s *Server) remoteGet(set *settings, w http.ResponseWriter, r *http.Request, cred credential, q *remoteRequest, page bool) {
	p := q.path
	var err error
	if p == "" {
		p, err = q.client.Getwd()
	} else {
		p, err = q.client.RealPath(p)
	}
	var info fs.FileInfo
	if err == nil {
		info, err = q.client.Stat(p)
	}
	if err != nil {
		missing := errors.Is(err, fs.ErrNotExist)
		err = remoteFolderFailure(sendRequest{Login: q.login}, q.path, err)
		switch {
		case page:
			s.remotePage(set, w, r, cred, q, nil, err)
		case missing:
			http.NotFound(w, r)
		default:
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
		return
	}
	q.path = p
	switch {
	case info.IsDir() && r.URL.Query().Get(remoteArchiveParam) != "":
		s.remoteArchive(w, r, q)
	case info.IsDir():
		entries, err := readRemoteDirectory(q.client, p)
		if err != nil {
			err = remoteFolderFailure(sendRequest{Login: q.login}, p, err)
		}
		s.remotePage(set, w, r, cred, q, entries, err)
	case info.Mode().IsRegular():
		s.remoteDownload(set, w, r, q, info)
	default:
		http.NotFound(w, r)
	}
}

// readRemoteDirectory lists a folder of a server as readDirectory lists one
// of the served tree. A link is what it leads to.
func readRemoteDirectory(client *sftp.Client, folder string) ([]entry, error) {
	infos, err := client.ReadDir(folder)
	if err != nil {
		return nil, err
	}
	entries := make([]entry, 0, len(infos))
	for _, info := range infos {
		name := info.Name()
		if name == "." || name == ".." {
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			if target, err := client.Stat(path.Join(folder, name)); err == nil {
				info = target
			}
		}
		found := entry{
			Name:    name,
			IsFile:  info.Mode().IsRegular(),
			Kind:    typeOf(name).Kind,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}
		if info.IsDir() {
			found.Name += "/"
		}
		entries = append(entries, found)
	}
	return entries, nil
}

// remoteRights are what the page of a server offers: what the account may do
// in the served folder, short of sharing and sending, which go-fs does with
// what it serves itself.
func remoteRights(cred credential) rights {
	perms := cred.user.perms
	return rights{
		Upload:       granted(perms, actCreate),
		Mkdir:        granted(perms, actMkdir),
		Rename:       granted(perms, actRename),
		DeleteFile:   granted(perms, actDeleteFile),
		DeleteFolder: granted(perms, actDeleteFolder),
		Downloads:    mayFollowFetches(cred),
	}
}

// remotePlace is a folder of a server, as the listing shows it.
func remotePlace(server, folder string) listingPlace {
	shown := folder
	if !strings.HasSuffix(shown, "/") {
		shown += "/"
	}
	place := listingPlace{
		Path: shown,
		// the transfers are asked after on the root of the served tree
		Folder: "/",
		Crumbs: remoteCrumbs(server, shown),
		Remote: remoteURL(server, shown),
		Query: sessionParam + "=" + actionRemote + "&" + remoteServerParam + "=" + url.QueryEscape(server) +
			"&" + remotePathParam + "=" + url.QueryEscape(shown),
		link: func(item entry) string {
			return remoteURL(server, path.Join(shown, item.bare()))
		},
	}
	if shown != "/" {
		place.Parent = remoteURL(server, path.Dir(strings.TrimSuffix(shown, "/")))
	}
	return place
}

// remoteCrumbs are the links above a folder of a server, as crumbsOf makes
// them for the served tree.
func remoteCrumbs(server, folder string) []crumb {
	crumbs := crumbsOf(folder)
	walked := "/"
	for i := range crumbs {
		if i > 0 {
			walked = path.Join(walked, crumbs[i].Name)
		}
		if crumbs[i].Link != "" {
			crumbs[i].Link = remoteURL(server, walked)
		}
	}
	return crumbs
}

// remotePage renders the listing of a folder of a server, or an empty one that
// says why the folder could not be read.
func (s *Server) remotePage(set *settings, w http.ResponseWriter, r *http.Request, cred credential,
	q *remoteRequest, entries []entry, failure error) {
	nonce, err := pageNonce()
	if err != nil {
		s.log.Error("http cannot render the remote listing", "server", q.server.Name, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	folder := q.path
	if folder == "" {
		folder = "/"
	}
	place := remotePlace(q.server.Name, folder)
	status := http.StatusOK
	if failure != nil {
		entries = nil
		place.Error = failure.Error()
		status = http.StatusBadGateway
		s.log.Info("http remote folder cannot be listed", "server", q.server.Name, "path", folder,
			"user", cred.user.name, "address", q.address, "error", failure)
	}
	who := s.sessionViewFor(set, r, cred)
	who.Page, who.Files, who.Remote = q.server.Name, "/", true
	if who.Admin != "" {
		// from the root rather than with the server's query on it
		who.Admin = adminURL(&url.URL{Path: "/"})
	}
	others := who.Servers[:0:0]
	for _, link := range who.Servers {
		if !strings.EqualFold(link.Name, q.server.Name) {
			others = append(others, link)
		}
	}
	who.Servers = others
	page, err := listingPage(place, entries, parseSort(r.URL.Query()), remoteRights(cred), sendView{},
		who, nonce, set.cfg.MaxChunkSize)
	if err != nil {
		s.log.Error("http cannot render the remote listing", "server", q.server.Name, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Security-Policy", contentPolicy(nonce))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(page)
	}
}

// remoteDownload sends a file of a server, a range of it where one is asked.
func (s *Server) remoteDownload(set *settings, w http.ResponseWriter, r *http.Request, q *remoteRequest, info fs.FileInfo) {
	file, err := q.client.Open(q.path)
	if err != nil {
		http.Error(w, remoteFolderFailure(sendRequest{Login: q.login}, q.path, err).Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = file.Close() }()
	name := path.Base(q.path)
	w.Header().Set("Content-Disposition", disposition(name))
	w.Header().Set("Content-Type", typeOf(name).Media)
	started := time.Now()
	http.ServeContent(w, r, name, info.ModTime(), file)
	if r.Method == http.MethodHead {
		return
	}
	var sent int64
	status := http.StatusOK
	if recorder, ok := w.(*responseRecorder); ok {
		sent, status = recorder.bytes, recorder.status
	}
	if status != http.StatusOK && status != http.StatusPartialContent {
		return
	}
	s.log.Info("http remote download", "user", q.user.name, "file", q.logged(q.path),
		"bytes", sent, "size", info.Size(), "status", status, "address", clientAddress(set, r),
		"took", time.Since(started).Round(time.Millisecond))
}

// remoteArchive sends a folder of a server as a tar.xz, as handleArchive
// sends one of the served tree.
func (s *Server) remoteArchive(w http.ResponseWriter, r *http.Request, q *remoteRequest) {
	name := path.Base(q.path)
	if name == "/" || name == "." || name == "" {
		name = q.server.Name
	}
	w.Header().Set("Content-Type", "application/x-xz")
	w.Header().Set("Content-Disposition", disposition(name+".tar.xz"))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	started := time.Now()
	files, err := packArchive(w, func(archive *tar.Writer) (int, error) {
		return s.walkRemoteArchive(r.Context(), q.client, q.path, name, archive)
	})
	if err != nil {
		s.log.Warn("http remote archive ended early", "user", q.user.name, "folder", q.logged(q.path),
			"files", files, "address", q.address, "error", err)
		return
	}
	s.log.Info("http remote archive", "user", q.user.name, "folder", q.logged(q.path),
		"files", files, "address", q.address, "took", time.Since(started).Round(time.Millisecond))
}

// walkRemoteArchive packs a folder of a server under name/, as writeArchive
// packs one of the served tree: folders so that an empty one survives, files
// with what is in them, a link as the file it leads to and never as a folder.
func (s *Server) walkRemoteArchive(ctx context.Context, client *sftp.Client, folder, name string, archive *tar.Writer) (int, error) {
	files := 0
	walker := client.Walk(folder)
	for walker.Step() {
		if err := ctx.Err(); err != nil {
			return files, err
		}
		if err := walker.Err(); err != nil {
			if walker.Path() == folder {
				return files, err
			}
			s.log.Debug("http remote archive skips an entry it cannot read", "path", walker.Path(), "error", err)
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(walker.Path(), folder), "/")
		inside := path.Join(name, rel)
		info := walker.Stat()
		switch {
		case info.IsDir():
			if err := archive.WriteHeader(archiveHeader(info, inside+"/")); err != nil {
				return files, err
			}
		case info.Mode().IsRegular(), info.Mode()&fs.ModeSymlink != 0:
			target, err := client.Stat(walker.Path())
			if err != nil || !target.Mode().IsRegular() {
				continue
			}
			added, err := addRemoteFile(client, archive, walker.Path(), target, inside)
			if added {
				files++
			}
			if err != nil {
				return files, err
			}
		}
	}
	return files, nil
}

// addRemoteFile writes one file of a server into the archive, as addFile
// writes one of the served tree.
func addRemoteFile(client *sftp.Client, archive *tar.Writer, p string, info fs.FileInfo, inside string) (bool, error) {
	file, err := client.Open(p)
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

// remoteTaken checks the name an upload goes to, and answers the request
// when it may not: a folder is never written over, and a file only by an
// account that may replace files. It reports whether the name is taken.
func (s *Server) remoteTaken(w http.ResponseWriter, r *http.Request, q *remoteRequest) (taken, ok bool) {
	info, err := q.client.Stat(q.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !granted(q.user.perms, actCreate) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return false, false
		}
		return false, true
	case err != nil:
		http.Error(w, remoteFolderFailure(sendRequest{Login: q.login}, q.path, err).Error(), http.StatusBadGateway)
		return false, false
	case !info.Mode().IsRegular():
		s.log.Debug("http remote upload refused, the name is taken", "file", q.logged(q.path))
		http.NotFound(w, r)
		return true, false
	case !granted(q.user.perms, actOverwrite):
		http.Error(w, "Forbidden", http.StatusForbidden)
		return true, false
	}
	return true, true
}

// remotePut uploads a file to a server, whole or in Content-Range chunks as
// handlePut takes one. It is written under a hidden name beside where it goes
// and renamed once all of it is there, as a send is.
func (s *Server) remotePut(set *settings, w http.ResponseWriter, r *http.Request, q *remoteRequest) {
	if q.path == "" || q.path == "/" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	label := vfs.Target{Virtual: q.logged(q.path)}
	if !rawUpload(r.Header.Get("Content-Type")) {
		s.log.Debug("http remote upload refused, the body is not octet-stream",
			"file", label.Virtual, "contentType", r.Header.Get("Content-Type"))
		http.NotFound(w, r)
		return
	}
	if header := r.Header.Get("Content-Range"); header != "" {
		s.remotePutChunk(set, w, r, q, header, label)
		return
	}
	replaced, ok := s.remoteTaken(w, r, q)
	if !ok {
		return
	}
	if set.cfg.ReadTimeout > 0 {
		r.Body = &idleUploadBody{ReadCloser: r.Body, controller: http.NewResponseController(w),
			idle: seconds(set.cfg.ReadTimeout)}
	}
	var limited *limitedBody
	body := io.Reader(r.Body)
	if set.cfg.MaxUploadSize > 0 {
		if r.ContentLength > set.cfg.MaxUploadSize {
			s.tooLarge(set, w, label)
			return
		}
		limited = &limitedBody{ReadCloser: http.MaxBytesReader(w, r.Body, set.cfg.MaxUploadSize)}
		body = limited
	}
	started := time.Now()
	written, err := putRemote(q.client, q.path, body)
	if err != nil {
		if tooLarge(err) || limited.hit() {
			s.tooLarge(set, w, label)
			return
		}
		s.log.Warn("http remote upload failed", "user", q.user.name, "file", label.Virtual,
			"bytes", written, "address", q.address, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	s.log.Info("http remote upload", "user", q.user.name, "file", label.Virtual, "bytes", written,
		"replaced", replaced, "address", q.address, "took", time.Since(started).Round(time.Millisecond))
	w.WriteHeader(http.StatusOK)
}

// remotePutChunk takes one chunk of an upload to a server. The chunks are
// staged here, as handleChunkedPut stages them, and the file goes to the
// server with the last one.
func (s *Server) remotePutChunk(set *settings, w http.ResponseWriter, r *http.Request, q *remoteRequest,
	header string, label vfs.Target) {
	if set.cfg.MaxChunkSize <= 0 {
		http.NotFound(w, r)
		return
	}
	rng, ok := parseContentRange(header)
	if !ok {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if set.cfg.MaxUploadSize > 0 && rng.total > set.cfg.MaxUploadSize {
		s.tooLarge(set, w, label)
		return
	}
	if rng.end-rng.start+1 > set.cfg.MaxChunkSize {
		s.chunkTooLarge(set, w, label.Virtual)
		return
	}
	// keyed by the server and the path on it, so two uploads meet whenever
	// they name the same file, and never meet one of the served tree
	key := "remote:" + strings.ToLower(q.server.Name) + ":" + q.path
	staging := stagingPath(set, key)
	lock := s.uploadLock(key)
	lock.Lock()
	defer lock.Unlock()

	if rng.start == 0 {
		if _, ok := s.remoteTaken(w, r, q); !ok {
			return
		}
		if err := os.MkdirAll(stagingFolder(set), 0o700); err != nil {
			s.log.Error("http cannot create the upload staging folder", "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}
	started := time.Now()
	if !s.writeRangeChunk(set, w, r, staging, rng, q.user, label.Virtual) {
		return
	}
	if rng.end+1 < rng.total {
		w.WriteHeader(http.StatusOK)
		return
	}

	replaced, ok := s.remoteTaken(w, r, q)
	if !ok {
		return
	}
	file, err := os.Open(staging)
	if err != nil {
		s.log.Error("http remote upload cannot read what was staged", "file", label.Virtual, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = file.Close() }()
	if info, err := file.Stat(); err != nil || info.Size() != rng.total {
		s.log.Error("http remote upload cannot finalize, the staged size does not match",
			"file", label.Virtual, "want", rng.total, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	written, err := putRemote(q.client, q.path, file)
	if err != nil {
		s.log.Warn("http remote upload failed", "user", q.user.name, "file", label.Virtual,
			"bytes", written, "address", q.address, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	_ = file.Close()
	_ = os.Remove(staging)
	s.log.Info("http remote upload", "user", q.user.name, "file", label.Virtual, "bytes", written,
		"chunked", true, "replaced", replaced, "address", q.address,
		"took", time.Since(started).Round(time.Millisecond))
	w.WriteHeader(http.StatusCreated)
}

// putRemote writes a file to a server under a hidden name beside where it
// goes, and puts it in place once all of it is there, replacing what is
// there. What was written is taken away again when anything fails.
func putRemote(client *sftp.Client, final string, body io.Reader) (int64, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return 0, err
	}
	part := path.Join(path.Dir(final), "."+path.Base(final)+".go-fs-"+hex.EncodeToString(suffix)+".part")
	out, err := client.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return 0, err
	}
	written, err := out.ReadFromWithConcurrency(body, 0)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = renameRemote(client, part, final)
	}
	if err != nil {
		_ = client.Remove(part)
	}
	return written, err
}

// remoteMkdir creates a folder on a server.
func (s *Server) remoteMkdir(w http.ResponseWriter, r *http.Request, q *remoteRequest) {
	if !granted(q.user.perms, actMkdir) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if q.path == "" || q.path == "/" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := q.client.Lstat(q.path); err == nil {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := q.client.Mkdir(q.path); err != nil {
		s.answerRemoteFailure(w, q, "create the folder", err)
		return
	}
	s.log.Info("http remote mkdir", "user", q.user.name, "folder", q.logged(q.path), "address", q.address)
	w.WriteHeader(http.StatusCreated)
}

// remoteMove renames a file or a folder of a server. The Destination is the
// link of the new name on the same server.
func (s *Server) remoteMove(set *settings, w http.ResponseWriter, r *http.Request, q *remoteRequest) {
	if !granted(q.user.perms, actRename) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	destination, err := url.Parse(r.Header.Get("Destination"))
	if err != nil || q.path == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	query := destination.Query()
	to := remotePath(query)
	if query.Get(sessionParam) != actionRemote || !strings.EqualFold(query.Get(remoteServerParam), q.server.Name) ||
		to == "" || to == "/" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if _, err := q.client.Lstat(q.path); err != nil {
		s.answerRemoteFailure(w, q, "rename", err)
		return
	}
	if _, err := q.client.Lstat(to); err == nil {
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		return
	}
	if err := q.client.Rename(q.path, to); err != nil {
		s.answerRemoteFailure(w, q, "rename", err)
		return
	}
	s.log.Info("http remote rename", "user", q.user.name, "from", q.logged(q.path), "to", to,
		"address", clientAddress(set, r))
	w.WriteHeader(http.StatusCreated)
}

// remoteDelete removes a file, or a folder with nothing in it, of a server.
func (s *Server) remoteDelete(w http.ResponseWriter, r *http.Request, q *remoteRequest) {
	if q.path == "" || q.path == "/" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	info, err := q.client.Lstat(q.path)
	if err != nil {
		s.answerRemoteFailure(w, q, "delete", err)
		return
	}
	if info.IsDir() {
		if !granted(q.user.perms, actDeleteFolder) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		err = q.client.RemoveDirectory(q.path)
	} else {
		if !granted(q.user.perms, actDeleteFile) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		err = q.client.Remove(q.path)
	}
	if err != nil {
		if info.IsDir() {
			// most likely with something still in it, which is how the page
			// reads a 404 on a folder
			s.log.Debug("http remote folder not removed", "folder", q.logged(q.path), "error", err)
			http.NotFound(w, r)
			return
		}
		s.answerRemoteFailure(w, q, "delete", err)
		return
	}
	s.log.Info("http remote delete", "user", q.user.name, "path", q.logged(q.path), "folder", info.IsDir(),
		"address", q.address)
	w.WriteHeader(http.StatusNoContent)
}

// answerRemoteFailure answers what a server refused with the status the page
// reads it by.
func (s *Server) answerRemoteFailure(w http.ResponseWriter, q *remoteRequest, what string, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		http.Error(w, "Not Found", http.StatusNotFound)
	case errors.Is(err, fs.ErrPermission):
		http.Error(w, fmt.Sprintf("%s may not %s %s on %s", q.login.Username, what, q.path, q.login.Shown()),
			http.StatusForbidden)
	default:
		s.log.Warn("http remote request failed", "user", q.user.name, "path", q.logged(q.path),
			"action", what, "address", q.address, "error", err)
		http.Error(w, fmt.Sprintf("%s on %s: %v", q.path, q.login.Shown(), err), http.StatusBadGateway)
	}
}

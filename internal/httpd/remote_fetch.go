package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/remote"
	"go-fs/internal/vfs"
)

// The page of a stored server fetches a file of it into the served tree: the
// other way round from Send File. Its dialog lists the folders of the served
// tree, from the root, for the user to choose where the file goes, and the
// fetch is a job like one from a URL, which the header follows among the
// transfers and which stores the file the way that one does: in the staging
// folder until all of it is there, and then under its name.
//
// Both endpoints are markers on the root of the served tree, as the page of
// the server is:
//
//	GET  /?go-fs=local-browse&path=<folder>
//	POST /?go-fs=remote-fetch&server=<name>&path=<file>   {"folder": "<folder>"}
//
// A folder is listed to whoever may list it in the served tree, and a fetch
// into it is offered as a fetch from a URL is: to a session of an account that
// may create there. The file is read with the login the server was stored
// with, so it is offered to whoever may browse the server.

const (
	actionLocalBrowse = "local-browse"
	actionRemoteFetch = "remote-fetch"
	// localBrowsePathParam names the folder of the served tree to list.
	localBrowsePathParam = "path"
)

// remoteFetchAction reports which endpoint of a fetch from a stored server a
// request is for, or "" for any other request.
func remoteFetchAction(r *http.Request) string {
	switch action := r.URL.Query().Get(sessionParam); action {
	case actionLocalBrowse, actionRemoteFetch:
		return action
	default:
		return ""
	}
}

// handleRemoteFetch answers the endpoints of a fetch from a stored server.
func (s *Server) handleRemoteFetch(set *settings, w http.ResponseWriter, r *http.Request, cred credential, action string) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case action == actionLocalBrowse && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		s.localBrowse(set, w, r, cred)
	case action == actionRemoteFetch && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.remoteFetchStart(set, w, r, cred)
	default:
		if action == actionLocalBrowse {
			w.Header().Set("Allow", "GET, HEAD")
		} else {
			w.Header().Set("Allow", http.MethodPost)
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// localFolderJSON is a folder of the served tree, as the dialog lists it.
type localFolderJSON struct {
	sendFolderJSON
	// Writable says the account may fetch into the folder.
	Writable bool `json:"writable"`
}

// localBrowse lists a folder of the served tree, folders first.
func (s *Server) localBrowse(set *settings, w http.ResponseWriter, r *http.Request, cred credential) {
	if !mayFollowFetches(cred) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	asked := strings.TrimSpace(r.URL.Query().Get(localBrowsePathParam))
	if asked == "" {
		asked = "/"
	}
	target := s.root.Resolve("/", asked)
	if !target.Valid {
		http.NotFound(w, r)
		return
	}
	if info, err := os.Stat(target.Path); err != nil || !info.IsDir() {
		http.NotFound(w, r)
		return
	}
	folder := vfs.AsFolder(target.Virtual)
	if !s.permits(set, cred.user, http.MethodGet, folder, actRead) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	entries, err := readDirectory(target.Path)
	if err != nil {
		s.log.Error("http cannot read the folder", "path", target.Virtual, "error", err)
		http.Error(w, "The folder cannot be read.", http.StatusInternalServerError)
		return
	}
	shown := strings.TrimSuffix(folder, "/")
	if shown == "" {
		shown = "/"
	}
	view := localFolderJSON{
		sendFolderJSON: sendFolderJSON{Path: shown, Entries: []sendEntryJSON{}},
		Writable:       mayFetch(cred, folder),
	}
	if shown != "/" {
		view.Parent = path.Dir(shown)
	}
	// readDirectory has the folders first, the newest files next; the dialog
	// lists files by name, as it does those of a host
	for _, item := range entries {
		if len(view.Entries) == maxSendEntries {
			view.Truncated = true
			break
		}
		if item.isFolder() {
			view.Entries = append(view.Entries, sendEntryJSON{Name: item.bare(), Dir: true})
		} else {
			view.Entries = append(view.Entries, sendEntryJSON{Name: item.Name, Size: item.Size})
		}
	}
	sortFolderEntries(view.Entries)
	writeJSON(w, http.StatusOK, view)
}

// remoteFetchBody is the body of a fetch from a stored server.
type remoteFetchBody struct {
	// Folder is the folder of the served tree to store the file in.
	Folder string `json:"folder"`
}

// remoteFetchStart starts a fetch of a file of a stored server.
func (s *Server) remoteFetchStart(set *settings, w http.ResponseWriter, r *http.Request, cred credential) {
	address := clientAddress(set, r)
	if !mayBrowseRemote(cred) {
		s.log.Info("http remote fetch refused, no session of an account that may read",
			"user", nameOf(cred.user), "address", address)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	query := r.URL.Query()
	server, ok := config.FindServer(serversFor(set, cred.user), query.Get(remoteServerParam))
	if !ok {
		s.logUnadmitted(set, cred, query.Get(remoteServerParam), address)
		http.NotFound(w, r)
		return
	}
	if !server.Rights().Download {
		s.log.Info("http remote fetch refused, the server does not allow downloads",
			"server", server.Name, "user", cred.user.name, "address", address)
		http.Error(w, fmt.Sprintf("the server %s does not allow to download", server.Name), http.StatusForbidden)
		return
	}
	login, err := remote.FromServer(server).Checked(false)
	if err != nil {
		http.Error(w, fmt.Sprintf("the server %s: %v", server.Name, err), http.StatusBadGateway)
		return
	}
	file := remotePath(query)
	if file == "" || file == "/" {
		http.Error(w, "name the file to fetch", http.StatusBadRequest)
		return
	}
	var body remoteFetchBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxTransferRequest)).Decode(&body); err != nil {
		http.Error(w, "The request could not be read.", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.Folder) == "" {
		http.Error(w, "choose the folder to fetch into", http.StatusBadRequest)
		return
	}
	target := s.root.Resolve("/", body.Folder)
	if !target.Valid {
		http.Error(w, "There is no such folder here.", http.StatusBadRequest)
		return
	}
	if info, err := os.Stat(target.Path); err != nil || !info.IsDir() {
		http.Error(w, "There is no such folder here.", http.StatusBadRequest)
		return
	}
	folder := vfs.AsFolder(target.Virtual)
	if !mayFetch(cred, folder) {
		s.log.Info("http remote fetch refused, no session of an account that may create here",
			"user", cred.user.name, "folder", folder, "address", address)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	user := cred.user
	shown := login.Where(file) + " (server " + server.Name + ")"
	job, err := s.startJob(jobFetch, user.name, shown+" → "+folder, func(ctx context.Context, job *registryJob) (string, error) {
		job.named(cleanFetchedName(file), folder)
		message, err := s.remoteFetchFile(ctx, set, job, login, file, folder, user, address)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("http remote fetch failed", "file", shown, "folder", folder, "user", user.name,
				"address", address, "error", err)
		}
		return message, err
	})
	if err == nil {
		s.log.Info("http remote fetch started", "file", shown, "folder", folder, "user", user.name,
			"address", address, "job", job.id)
	}
	s.answerStarted(w, job, err)
}

// remoteFetchFile downloads a file of a stored server into a folder of the
// served tree, and says what it stored.
func (s *Server) remoteFetchFile(ctx context.Context, set *settings, job *registryJob, login remote.Login,
	file, folder string, user *account, address string) (string, error) {
	started := time.Now()
	// the connection lives as long as getCtx, so a fetch that is stopped or
	// stalls is cut at once; a read leaves nothing behind on the server
	getCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	fsys, err := remote.Open(getCtx, login, set.ssh)
	if err != nil {
		return "", err
	}
	defer func() { _ = fsys.Close() }()

	failure := func(err error) error {
		return remoteFolderFailure(sendRequest{Login: login}, file, err)
	}
	p, err := fsys.Resolve(file)
	if err != nil {
		return "", failure(err)
	}
	info, err := fsys.Stat(p)
	if err != nil {
		return "", failure(err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s on %s is not a file", p, login.Shown())
	}

	name := cleanFetchedName(p)
	target := s.root.Resolve(folder, name)
	if name == "" || !target.Valid || vfs.AsFolder(path.Dir(target.Virtual)) != folder {
		return "", fmt.Errorf("a file named %q cannot be stored here", name)
	}
	// asked before the download as well as after it, so that a name that is
	// taken costs nothing
	if _, err := fetchReplaces(target, name, user); err != nil {
		return "", err
	}
	if limit := set.cfg.MaxUploadSize; limit > 0 && info.Size() > limit {
		return "", fetchTooLarge(name, limit)
	}
	job.named(name, "")
	job.plan(0, info.Size())

	source, err := fsys.Open(p)
	if err != nil {
		return "", failure(err)
	}
	defer func() { _ = source.Close() }()
	written, replace, err := s.storeFetched(set, job, stoppable{r: source, ctx: getCtx}, cancel,
		target, name, login.Shown(), user)
	if err != nil {
		if errors.Is(context.Cause(getCtx), errStalled) {
			return "", fmt.Errorf("%s from %s: %w", name, login.Shown(), errStalled)
		}
		return "", err
	}
	if written != info.Size() {
		// the file changed while it was read; what is stored is what was read
		s.log.Warn("http remote fetch read another size than the server named", "file", login.Where(p),
			"named", info.Size(), "read", written)
	}
	s.log.Info("http remote fetch", "user", user.name, "from", login.Where(p)+" (server "+login.Server+")",
		"file", target.Virtual, "bytes", written, "replaced", replace, "address", address,
		"took", time.Since(started).Round(time.Millisecond))
	return fmt.Sprintf("Fetched %s (%s) from %s into %s.", name, readableSize(written), login.Server, folder), nil
}

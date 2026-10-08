package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/remote"
	"go-fs/internal/vfs"
)

// The listing can send a file to another host, the way it fetches one from a
// URL: the dialog starts a job on the server, which uploads the file while the
// page asks how far it has got, and the job is one of the transfers the header
// follows, beside the fetches.
//
// The host is either a server the admin interface stored, which the dialog
// names and nothing more, or one the user types the login of in, Manual. A
// stored server is logged in to with the login and the key the file holds;
// its password and its key never reach the page.
//
// A host reached by SFTP shows a key: before the dialog sends a login typed
// in anywhere, it asks for the key of the host alone, which a handshake shows before any login is offered, and
// the user accepts it; every request after that names the key that was
// accepted, and a host that shows another is not logged in to. The page, not
// the server, remembers which keys were accepted. With the key and the login
// the dialog lists the folders of the remote, for the user to choose where the
// file goes, and the send starts.
//
// A host reached by an address and a token, an Artifactory, shows none, and
// is listed at once.
//
// The file is written so that a send that is stopped or fails never leaves
// half a file under the real name: over SFTP under a hidden name beside
// where it goes, renamed once all of it is there, and to an Artifactory,
// which keeps an upload once all of it was taken. One that is there is
// replaced.
//
// The server reaches whatever host it is given, inside the network it is in
// as well as outside, so a send is offered as a fetch is: to a session of an
// account, and only of a file the account may read.

const (
	actionSendHostKey = "send-hostkey"
	actionSendBrowse  = "send-browse"
	actionSend        = "send"
)

// sendAction reports which send endpoint a request is for, or "" for any
// other request.
func sendAction(r *http.Request) string {
	switch action := r.URL.Query().Get(sessionParam); action {
	case actionSendHostKey, actionSendBrowse, actionSend:
		return action
	default:
		return ""
	}
}

// maySend decides whether the listing of a folder offers Send on its files,
// and whether a file may be sent.
func maySend(cred credential, virtual string) bool {
	return mayFollowFetches(cred) && fetchGranted(cred.user, virtual, actRead)
}

const (
	// sendGrace is how long a send that was stopped has to take its half
	// written file away before its connection is cut.
	sendGrace = 10 * time.Second
	// maxSendEntries bounds what a listing of a remote folder shows.
	maxSendEntries = 2000
)

// handleSend answers the send endpoints, on a file.
func (s *Server) handleSend(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, cred credential, action string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.sameSite(set, w, r) {
		return
	}
	if info, err := os.Stat(target.Path); err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	if !maySend(cred, target.Virtual) {
		s.log.Info("http send refused, no session of an account that may read the file",
			"user", nameOf(cred.user), "file", target.Virtual, "address", clientAddress(set, r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var body sendBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxTransferRequest)).Decode(&body); err != nil {
		http.Error(w, "The request could not be read.", http.StatusBadRequest)
		return
	}
	req, err := body.request(action, set.servers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch action {
	case actionSendHostKey:
		s.sendHostKey(w, r, req)
	case actionSendBrowse:
		s.sendBrowse(w, r, req)
	case actionSend:
		s.sendStart(set, w, r, target, cred.user, req)
	}
}

// sendBody is the body of every send endpoint. A stored server is named by
// Server alone; a login typed in names the rest, and the host key asks only
// for the host and the port of one.
type sendBody struct {
	// Server is the name of a stored server, "" for the login typed in.
	Server string `json:"server,omitempty"`
	// Protocol is what the login typed in reaches the host with, SFTP when
	// not named.
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	// URL and Token are the login typed in of a protocol reached by an
	// address and a token.
	URL   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`
	// HostKey is the fingerprint of the key the user accepted.
	HostKey string `json:"hostKey"`
	// Path is the folder to list, the login's own for "", or the one to send
	// the file into.
	Path string `json:"path"`
}

// sendRequest is a send that was read and found sound.
type sendRequest struct {
	remote.Login
	path string
}

// request reads what a send endpoint asks for. servers are the stored ones a
// body may name.
func (b sendBody) request(action string, servers []config.Server) (sendRequest, error) {
	var req sendRequest
	if name := strings.TrimSpace(b.Server); name != "" {
		if action == actionSendHostKey {
			return sendRequest{}, errors.New("the key of a stored server was accepted when it was stored")
		}
		server, ok := config.FindServer(servers, name)
		if !ok {
			return sendRequest{}, fmt.Errorf("there is no server named %q", name)
		}
		login, err := remote.FromServer(server).Checked(false)
		if err != nil {
			return sendRequest{}, fmt.Errorf("the server %s: %w", server.Name, err)
		}
		req.Login = login
	} else {
		login, err := remote.Login{Type: strings.TrimSpace(b.Protocol), Host: b.Host, Port: b.Port,
			Username: b.Username, Password: b.Password, HostKey: b.HostKey,
			URL: b.URL, Token: b.Token}.Checked(action == actionSendHostKey)
		if err != nil {
			return sendRequest{}, err
		}
		req.Login = login
	}
	if action == actionSendHostKey {
		return req, nil
	}
	if p := strings.TrimSpace(b.Path); p != "" {
		req.path = path.Clean(p)
	}
	if action == actionSend && req.path == "" {
		return sendRequest{}, errors.New("choose the folder to send to")
	}
	return req, nil
}

// logged is a path of the host as the log and the job show it: with the user
// that logs in, and the stored server that login is, if any.
func (r sendRequest) logged(p string) string {
	shown := r.Where(p)
	if r.Username != "" {
		shown = r.Type + "://" + r.Username + "@" + r.Shown() + p
	}
	if r.Server != "" {
		shown += " (server " + r.Server + ")"
	}
	return shown
}

// sendHostKeyJSON is the key a host shows.
type sendHostKeyJSON struct {
	Host        string `json:"host"`
	KeyType     string `json:"keyType"`
	Fingerprint string `json:"fingerprint"`
}

// sendHostKey answers the key of a host. The handshake is broken off once
// the key is seen, so no login is offered to a host nobody accepted yet.
func (s *Server) sendHostKey(w http.ResponseWriter, r *http.Request, req sendRequest) {
	ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
	defer cancel()
	keyType, fingerprint, err := remote.HostKey(ctx, req.Login, s.settings().ssh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, sendHostKeyJSON{Host: req.Shown(), KeyType: keyType, Fingerprint: fingerprint})
}

// sendFolderJSON is a folder of the remote.
type sendFolderJSON struct {
	// Base is the host as the page names a path of it, sftp://host, or the
	// address of an Artifactory.
	Base string `json:"base"`
	Path string `json:"path"`
	// Parent is the folder above, "" at the top.
	Parent  string          `json:"parent,omitempty"`
	Entries []sendEntryJSON `json:"entries"`
	// Truncated says there were more entries than maxSendEntries.
	Truncated bool `json:"truncated,omitempty"`
}

type sendEntryJSON struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
}

// sendBrowse logs in to a host and lists a folder of it, folders first.
func (s *Server) sendBrowse(w http.ResponseWriter, r *http.Request, req sendRequest) {
	ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
	defer cancel()
	fsys, err := remote.Open(ctx, req.Login, s.settings().ssh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = fsys.Close() }()

	folder, err := fsys.Resolve(req.path)
	if err != nil {
		http.Error(w, remoteFolderFailure(req, req.path, err).Error(), http.StatusBadGateway)
		return
	}
	infos, err := fsys.ReadDir(folder)
	if err != nil {
		http.Error(w, remoteFolderFailure(req, folder, err).Error(), http.StatusBadGateway)
		return
	}
	view := sendFolderJSON{Base: req.Where(""), Path: folder, Entries: []sendEntryJSON{}}
	if folder != "/" {
		view.Parent = path.Dir(folder)
	}
	for _, info := range infos {
		if len(view.Entries) == maxSendEntries {
			view.Truncated = true
			break
		}
		name := info.Name()
		dir := info.IsDir()
		entry := sendEntryJSON{Name: name, Dir: dir}
		if !dir {
			entry.Size = info.Size()
		}
		view.Entries = append(view.Entries, entry)
	}
	sort.Slice(view.Entries, func(a, b int) bool {
		ea, eb := view.Entries[a], view.Entries[b]
		if ea.Dir != eb.Dir {
			return ea.Dir
		}
		la, lb := strings.ToLower(ea.Name), strings.ToLower(eb.Name)
		if la != lb {
			return la < lb
		}
		return ea.Name < eb.Name
	})
	writeJSON(w, http.StatusOK, view)
}

// remoteFolderFailure says why a folder of a host could not be read.
func remoteFolderFailure(req sendRequest, folder string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("there is no folder %s on %s", folder, req.Shown())
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s may not read %s on %s", req.Who(), folder, req.Shown())
	}
	return fmt.Errorf("%s on %s: %w", folder, req.Shown(), err)
}

// sendStart starts sending a file.
func (s *Server) sendStart(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, user *account, req sendRequest) {
	address := clientAddress(set, r)
	name := filepath.Base(target.Path)
	shown := req.logged(req.path)
	job, err := s.startJob(jobSend, user.name, target.Virtual+" → "+shown, func(ctx context.Context, job *registryJob) (string, error) {
		job.named(name, req.Where(req.path))
		message, err := s.sendFile(ctx, job, req, target, user, address)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("http send failed", "file", target.Virtual, "to", shown, "user", user.name,
				"address", address, "error", err)
		}
		return message, err
	})
	if err == nil {
		s.log.Info("http send started", "file", target.Virtual, "to", shown, "user", user.name,
			"address", address, "job", job.id)
	}
	s.answerStarted(w, job, err)
}

// sendFile uploads a file into a folder of a host, and says what it sent.
func (s *Server) sendFile(ctx context.Context, job *registryJob, req sendRequest, target vfs.Target,
	user *account, address string) (string, error) {
	started := time.Now()
	name := filepath.Base(target.Path)
	file, err := os.Open(target.Path)
	if err != nil {
		return "", fmt.Errorf("%s cannot be read", name)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a file", name)
	}
	job.plan(0, info.Size())

	sendCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// The connection is cut as soon as the send is stopped while it
	// connects, and sendGrace later once the file is being written: the
	// reader sees the stop at its next read, which leaves the connection to
	// take the half written file away again. One that has not ended by then
	// hangs, and is cut all the same.
	connCtx, cut := context.WithCancel(context.Background())
	defer cut()
	var writing atomic.Bool
	stop := context.AfterFunc(sendCtx, func() {
		if writing.Load() {
			time.AfterFunc(sendGrace, cut)
			return
		}
		cut()
	})
	defer stop()

	fsys, err := remote.Open(connCtx, req.Login, s.settings().ssh)
	if err != nil {
		return "", err
	}
	defer func() { _ = fsys.Close() }()

	folder := req.path
	if st, err := fsys.Stat(folder); err != nil {
		return "", remoteFolderFailure(req, folder, err)
	} else if !st.IsDir() {
		return "", fmt.Errorf("%s on %s is not a folder", folder, req.Shown())
	}
	final := path.Join(folder, name)
	replaced := false
	if st, err := fsys.Stat(final); err == nil {
		if st.IsDir() {
			return "", fmt.Errorf("%s is a folder on %s", final, req.Shown())
		}
		replaced = true
	}

	writing.Store(true)
	job.downloading()
	reader := watch(stoppable{r: file, ctx: sendCtx}, job, cancel)
	written, err := fsys.Put(final, reader, info.Size())
	reader.done()
	if err == nil && written != info.Size() {
		err = fmt.Errorf("%d of %d bytes were written", written, info.Size())
	}
	if err != nil {
		switch {
		case errors.Is(context.Cause(sendCtx), errStalled):
			return "", fmt.Errorf("%s to %s: %w", name, req.Shown(), errStalled)
		case errors.Is(err, fs.ErrPermission):
			return "", fmt.Errorf("%s may not write into %s on %s", req.Who(), folder, req.Shown())
		}
		return "", fmt.Errorf("%s to %s: %w", name, req.Shown(), err)
	}
	s.log.Info("http send", "user", user.name, "file", target.Virtual,
		"to", req.logged(final), "bytes", written, "replaced", replaced,
		"address", address, "took", time.Since(started).Round(time.Millisecond))
	return fmt.Sprintf("Sent %s (%s) to %s.", name, readableSize(written), req.Where(final)), nil
}

// stoppable is a reader that ends once its context does.
type stoppable struct {
	r   io.Reader
	ctx context.Context
}

func (s stoppable) Read(b []byte) (int, error) {
	if err := context.Cause(s.ctx); err != nil {
		return 0, err
	}
	return s.r.Read(b)
}

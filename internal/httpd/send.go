package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/vfs"
)

// The listing can send a file to another host over SFTP, the way it fetches
// one from a URL: the dialog starts a job on the server, which uploads the
// file while the page asks how far it has got, and the job is one of the
// transfers the header follows, beside the fetches.
//
// Before the dialog sends a login anywhere, it asks for the key of the host
// alone, which a handshake shows before any login is offered, and the user
// accepts it; every request after that names the key that was accepted, and
// a host that shows another is not logged in to. The page, not the server,
// remembers which keys were accepted. With the key and the login the dialog
// lists the folders of the remote, for the user to choose where the file
// goes, and the send starts.
//
// The file is written under a hidden name beside where it goes and renamed
// once all of it is there, so that a send that is stopped or fails never
// leaves half a file under the real name; one that is there is replaced.
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
	// sendHandshakeTimeout bounds the connection and the handshake of a send,
	// and of its questions, which a host that does not answer would hold.
	sendHandshakeTimeout = 30 * time.Second
	// sendGrace is how long a send that was stopped has to take its half
	// written file away before its connection is cut.
	sendGrace = 10 * time.Second
	// maxSendEntries bounds what a listing of a remote folder shows.
	maxSendEntries = 2000
	// defaultSFTPPort is where a host is reached when no port is named.
	defaultSFTPPort = 22
)

// errHostKeyShown ends the handshake that only asks for the key of a host.
var errHostKeyShown = errors.New("host key shown")

// errHostKeyChanged is a host that shows a key other than the one accepted.
var errHostKeyChanged = errors.New("the host key is not the one that was accepted")

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
	req, err := body.request(action)
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

// sendBody is the body of every send endpoint. The host key asks only for
// the host and the port.
type sendBody struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	// HostKey is the fingerprint of the key the user accepted.
	HostKey string `json:"hostKey"`
	// Path is the folder to list, the login's own for "", or the one to send
	// the file into.
	Path string `json:"path"`
}

// sendRequest is a send that was read and found sound.
type sendRequest struct {
	host               string
	port               int
	username, password string
	hostKey            string
	path               string
}

// request reads what a send endpoint asks for.
func (b sendBody) request(action string) (sendRequest, error) {
	host := strings.TrimSpace(b.Host)
	// an address of IPv6 may come in the brackets of a URL
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	switch {
	case host == "":
		return sendRequest{}, errors.New("name the host to send to")
	case strings.Contains(host, "://"):
		return sendRequest{}, errors.New("name the host alone, without a scheme")
	case strings.Contains(host, "@"):
		return sendRequest{}, errors.New("put the username into its own field rather than the host")
	case strings.ContainsAny(host, "/ \t\r\n"):
		return sendRequest{}, fmt.Errorf("%q is not a host name", host)
	}
	port := b.Port
	if port == 0 {
		port = defaultSFTPPort
	}
	if port < 1 || port > 65535 {
		return sendRequest{}, fmt.Errorf("%d is not a port", b.Port)
	}
	req := sendRequest{host: host, port: port}
	if action == actionSendHostKey {
		return req, nil
	}
	req.username = strings.TrimSpace(b.Username)
	if req.username == "" {
		return sendRequest{}, errors.New("name the user to log in as")
	}
	req.password = b.Password
	req.hostKey = strings.TrimSpace(b.HostKey)
	if !strings.HasPrefix(req.hostKey, "SHA256:") {
		return sendRequest{}, errors.New("accept the key of the host first")
	}
	if p := strings.TrimSpace(b.Path); p != "" {
		req.path = path.Clean(p)
	}
	if action == actionSend && req.path == "" {
		return sendRequest{}, errors.New("choose the folder to send to")
	}
	return req, nil
}

// address is where the host is dialled.
func (r sendRequest) address() string {
	return net.JoinHostPort(r.host, strconv.Itoa(r.port))
}

// shown is the host as the page and the log show it, without the port it
// has when none is named.
func (r sendRequest) shown() string {
	if r.port == defaultSFTPPort {
		if strings.Contains(r.host, ":") {
			return "[" + r.host + "]"
		}
		return r.host
	}
	return r.address()
}

// where is a remote path as the page shows it.
func (r sendRequest) where(p string) string {
	return "sftp://" + r.shown() + p
}

// sshConnect dials a host and runs the handshake, within
// sendHandshakeTimeout. The connection is cut as soon as ctx ends, which is
// what stops whatever waits on it.
func sshConnect(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, sendHandshakeTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(sendHandshakeTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// openSFTP logs in to the host of a send, provided it shows the key that
// was accepted, and opens its SFTP, with the algorithms [general.ssh]
// allows. The connection lives as long as ctx.
func openSFTP(ctx context.Context, req sendRequest, sshCfg config.SSH) (*ssh.Client, *sftp.Client, error) {
	password := req.password
	login := &ssh.ClientConfig{
		Config:            sshCfg.ClientTransport(),
		HostKeyAlgorithms: sshCfg.HostKeys(),
		User:              req.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			// what many hosts ask a password by instead
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != req.hostKey {
				return errHostKeyChanged
			}
			return nil
		},
	}
	conn, err := sshConnect(ctx, req.address(), login)
	if err != nil {
		return nil, nil, sendFailure(req, err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("%s offers no SFTP: %w", req.shown(), err)
	}
	return conn, client, nil
}

// sendFailure says why a host could not be reached or logged in to, in the
// words the page shows.
func sendFailure(req sendRequest, err error) error {
	var negotiation *ssh.AlgorithmNegotiationError
	switch {
	case errors.As(err, &negotiation):
		return fmt.Errorf("%s offers no %s that general.ssh allows; it offers %s",
			req.shown(), negotiation.What, strings.Join(negotiation.RequestedAlgorithms, ", "))
	case errors.Is(err, errHostKeyChanged):
		return fmt.Errorf("the key of %s is not the one that was accepted; connect again to see the one it shows now", req.shown())
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%s refused the login of %s", req.shown(), req.username)
	}
	return fmt.Errorf("%s: %w", req.shown(), err)
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
	var seen ssh.PublicKey
	// the same algorithms as the login that follows, so that the key shown
	// is the kind the login will be shown too
	sshCfg := s.settings().ssh
	conn, err := sshConnect(ctx, req.address(), &ssh.ClientConfig{
		Config:            sshCfg.ClientTransport(),
		HostKeyAlgorithms: sshCfg.HostKeys(),
		User:              "go-fs",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errHostKeyShown
		},
	})
	if conn != nil {
		_ = conn.Close()
	}
	if seen == nil {
		if err == nil {
			err = errors.New("no host key was shown")
		}
		http.Error(w, sendFailure(req, err).Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, sendHostKeyJSON{Host: req.shown(), KeyType: seen.Type(),
		Fingerprint: ssh.FingerprintSHA256(seen)})
}

// sendFolderJSON is a folder of the remote.
type sendFolderJSON struct {
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
	conn, client, err := openSFTP(ctx, req, s.settings().ssh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = conn.Close() }()
	defer func() { _ = client.Close() }()

	folder := req.path
	if folder == "" {
		folder, err = client.Getwd()
	} else {
		folder, err = client.RealPath(folder)
	}
	if err != nil {
		http.Error(w, remoteFolderFailure(req, req.path, err).Error(), http.StatusBadGateway)
		return
	}
	infos, err := client.ReadDir(folder)
	if err != nil {
		http.Error(w, remoteFolderFailure(req, folder, err).Error(), http.StatusBadGateway)
		return
	}
	view := sendFolderJSON{Path: folder, Entries: []sendEntryJSON{}}
	if folder != "/" {
		view.Parent = path.Dir(folder)
	}
	for _, info := range infos {
		if len(view.Entries) == maxSendEntries {
			view.Truncated = true
			break
		}
		name := info.Name()
		if name == "." || name == ".." {
			continue
		}
		dir := info.IsDir()
		// a link is listed as one, and is a folder when where it leads is
		if info.Mode()&fs.ModeSymlink != 0 {
			if target, err := client.Stat(path.Join(folder, name)); err == nil {
				dir = target.IsDir()
			}
		}
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
		return fmt.Errorf("there is no folder %s on %s", folder, req.shown())
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s may not read %s on %s", req.username, folder, req.shown())
	}
	return fmt.Errorf("%s on %s: %w", folder, req.shown(), err)
}

// sendStart starts sending a file.
func (s *Server) sendStart(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, user *account, req sendRequest) {
	address := clientAddress(set, r)
	name := filepath.Base(target.Path)
	shown := "sftp://" + req.username + "@" + req.shown() + req.path
	job, err := s.startJob(jobSend, user.name, target.Virtual+" → "+shown, func(ctx context.Context, job *registryJob) (string, error) {
		job.named(name, req.where(req.path))
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

	conn, client, err := openSFTP(connCtx, req, s.settings().ssh)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	defer func() { _ = client.Close() }()

	folder := req.path
	if st, err := client.Stat(folder); err != nil {
		return "", remoteFolderFailure(req, folder, err)
	} else if !st.IsDir() {
		return "", fmt.Errorf("%s on %s is not a folder", folder, req.shown())
	}
	final := path.Join(folder, name)
	replaced := false
	if st, err := client.Stat(final); err == nil {
		if st.IsDir() {
			return "", fmt.Errorf("%s is a folder on %s", final, req.shown())
		}
		replaced = true
	}
	part := path.Join(folder, "."+name+".go-fs-"+job.id[:8]+".part")
	writing.Store(true)
	remote, err := client.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return "", fmt.Errorf("%s may not write into %s on %s", req.username, folder, req.shown())
		}
		return "", fmt.Errorf("%s on %s: %w", folder, req.shown(), err)
	}
	stored := false
	defer func() {
		if !stored {
			_ = client.Remove(part)
		}
	}()

	job.downloading()
	reader := watch(stoppable{r: file, ctx: sendCtx}, job, cancel)
	written, err := remote.ReadFromWithConcurrency(reader, 0)
	reader.done()
	if closeErr := remote.Close(); err == nil {
		err = closeErr
	}
	if err == nil && written != info.Size() {
		err = fmt.Errorf("%d of %d bytes were written", written, info.Size())
	}
	if err != nil {
		if errors.Is(context.Cause(sendCtx), errStalled) {
			return "", fmt.Errorf("%s to %s: %w", name, req.shown(), errStalled)
		}
		return "", fmt.Errorf("%s to %s: %w", name, req.shown(), err)
	}
	if err := renameRemote(client, part, final); err != nil {
		return "", fmt.Errorf("%s cannot be put in place on %s: %w", final, req.shown(), err)
	}
	stored = true
	s.log.Info("http send", "user", user.name, "file", target.Virtual,
		"to", "sftp://"+req.username+"@"+req.shown()+final, "bytes", written, "replaced", replaced,
		"address", address, "took", time.Since(started).Round(time.Millisecond))
	return fmt.Sprintf("Sent %s (%s) to %s.", name, readableSize(written), req.where(final)), nil
}

// renameRemote puts a file that was written in place, replacing whatever is
// there: at once where the host can, and else by removing it first. A host
// may offer the rename that replaces and still refuse to replace with it, as
// a server that hands it on to a plain SFTP rename does, so a refusal is
// tried again the other way.
func renameRemote(client *sftp.Client, from, to string) error {
	if _, ok := client.HasExtension("posix-rename@openssh.com"); ok {
		if err := client.PosixRename(from, to); err == nil {
			return nil
		}
	}
	if err := client.Remove(to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return client.Rename(from, to)
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

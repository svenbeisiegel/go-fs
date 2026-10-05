package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go-fs/internal/selfupdate"
)

// The update endpoint takes a new go-fs binary and hands it to the updater,
// which checks it, and once the client has been answered, restarts into it.
// It is served under the go-fs marker for the same reason the admin interface
// is: it reserves no name in the served folder.
//
// Who may use it is decided here and nowhere else: a bearer token that sets
// allowSelfUpdate, which is how a script updates, or the session of an
// account that sets isAdmin, which is how the admin interface does. Basic and
// Digest are refused for the reason the admin interface refuses them: a
// header is sent along with everything, a session and a token are credentials
// someone set up for the purpose.
//
// GET describes the running binary, so that a script can pick the update file
// built for it; PUT or POST uploads one.
//
// With release=latest the same endpoint is about the latest release instead:
// GET describes it and says whether it is newer, which is what the admin
// interface asks when it opens, and PUT or POST has go-fs download its update
// file and install it as if it had been uploaded. refresh skips the lookup
// the updater keeps for a while.

const actionUpdate = "update"

// restartDelay is how long the answer to an accepted update has to reach the
// client before the shutdown closes the connection it travels on.
var restartDelay = 250 * time.Millisecond

// downloadTimeout is how long the update file of a release may take to
// download and check.
const downloadTimeout = 10 * time.Minute

// Updater is what the endpoint needs of selfupdate.Updater, an interface so
// that a test can stand in for it without replacing any binary.
type Updater interface {
	Current() selfupdate.Info
	Stage(ctx context.Context, body io.Reader) (selfupdate.Staged, error)
	Request()
	Latest(ctx context.Context, refresh bool) (selfupdate.Release, error)
	Download(ctx context.Context, release selfupdate.Release) (io.ReadCloser, error)
}

// SetUpdater gives the server the updater its endpoint hands uploads to.
// Without one the endpoint does not exist.
func (s *Server) SetUpdater(updater Updater) {
	s.updater = updater
}

// handleUpdate guards the endpoint and serves it.
func (s *Server) handleUpdate(set *settings, w http.ResponseWriter, r *http.Request) {
	if s.updater == nil || !set.cfg.EnableSelfUpdate {
		// switched off, the marker names nothing
		s.log.Debug("http self update is not enabled", "address", clientAddress(set, r))
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	address := clientAddress(set, r)
	cred := s.identify(set, w, r)
	switch {
	case cred.rejected:
		s.refuseBearer(set, w)
		return
	case cred.locked:
		s.refuseLocked(set, w, r)
		return
	case cred.user == nil:
		s.log.Info("http self update refused, no credentials", "credentials", cred.method,
			"address", address)
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=%q", set.cfg.Realm))
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	case !mayUpdate(cred):
		s.log.Warn("http self update refused, the credentials do not allow it",
			"user", cred.user.name, "credentials", cred.method, "address", address)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	latest := r.URL.Query().Get("release") == "latest"
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if latest {
			s.describeRelease(set, w, r, cred.user.name)
			return
		}
		writeJSON(w, http.StatusOK, s.updater.Current())
	case http.MethodPut, http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		if latest {
			s.installRelease(set, w, r, cred.user.name)
			return
		}
		s.acceptUpdate(set, w, r, cred.user.name)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// mayUpdate reports whether a credential is one the endpoint accepts: a
// bearer token that sets allowSelfUpdate, or an admin's session.
func mayUpdate(cred credential) bool {
	if cred.method == "bearer" {
		return cred.user.perms.SelfUpdate
	}
	return cred.token && cred.user.isAdmin
}

// acceptUpdate reads the upload and hands it on to be staged.
func (s *Server) acceptUpdate(set *settings, w http.ResponseWriter, r *http.Request, user string) {
	address := clientAddress(set, r)
	current := s.updater.Current()
	if r.ContentLength > selfupdate.MaxSize {
		s.refuseUpdate(w, user, address, selfupdate.ErrTooLarge)
		return
	}
	// as for an upload, the read timeout is how long the body may stall
	// rather than how long it may take
	body := r.Body
	if set.cfg.ReadTimeout > 0 {
		body = &idleUploadBody{
			ReadCloser: r.Body,
			controller: http.NewResponseController(w),
			idle:       seconds(set.cfg.ReadTimeout),
		}
	}

	s.log.Warn("http self update received", "user", user, "address", address,
		"version", current.Version)
	s.stageAndRestart(w, r, user, address, body, "upload")
}

// describeRelease answers what the latest release is and whether it is newer
// than what runs.
func (s *Server) describeRelease(set *settings, w http.ResponseWriter, r *http.Request, user string) {
	release, err := s.updater.Latest(r.Context(), r.URL.Query().Get("refresh") != "")
	if err != nil {
		s.log.Info("http self update cannot look up the latest release", "user", user,
			"address", clientAddress(set, r), "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, release)
}

// installRelease downloads the update file of the latest release and stages
// it as it would an upload of it.
func (s *Server) installRelease(set *settings, w http.ResponseWriter, r *http.Request, user string) {
	address := clientAddress(set, r)
	release, err := s.updater.Latest(r.Context(), false)
	if err != nil {
		s.refuseUpdate(w, user, address, err)
		return
	}
	s.log.Warn("http self update from the latest release", "user", user, "address", address,
		"version", release.Current, "release", release.Version, "asset", release.Asset)
	// the write timeout would count the download against the answer, which
	// is not written until it is done; the download has its own limit instead
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(r.Context(), downloadTimeout)
	defer cancel()
	body, err := s.updater.Download(ctx, release)
	if err != nil {
		s.refuseUpdate(w, user, address, err)
		return
	}
	defer body.Close()
	s.stageAndRestart(w, r.WithContext(ctx), user, address, body, release.Asset)
}

// stageAndRestart has an update staged, answers and then asks for the
// restart.
func (s *Server) stageAndRestart(w http.ResponseWriter, r *http.Request, user, address string,
	body io.Reader, source string) {
	current := s.updater.Current()
	staged, err := s.updater.Stage(r.Context(), body)
	if err != nil {
		s.refuseUpdate(w, user, address, err)
		return
	}

	s.log.Warn("http self update accepted, restarting", "user", user, "address", address,
		"source", source, "previous", current.Version, "version", staged.Version,
		"key", staged.Key)
	w.Header().Set("Connection", "close")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"previous":   current.Version,
		"version":    staged.Version,
		"restarting": true,
	})
	_ = http.NewResponseController(w).Flush()
	// the shutdown drops every connection, this one included, so the answer
	// is given its moment on the wire first
	go func() {
		time.Sleep(restartDelay)
		s.updater.Request()
	}()
}

// refuseUpdate answers an update that was not accepted with the status that
// says why. The running binary is untouched either way.
func (s *Server) refuseUpdate(w http.ResponseWriter, user, address string, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, selfupdate.ErrUnsigned):
		status = http.StatusBadRequest
	case errors.Is(err, selfupdate.ErrUnknownKey), errors.Is(err, selfupdate.ErrBadSignature),
		errors.Is(err, selfupdate.ErrPlatform), errors.Is(err, selfupdate.ErrNotGoFS):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, selfupdate.ErrTooLarge), tooLarge(err):
		status = http.StatusRequestEntityTooLarge
		err = selfupdate.ErrTooLarge
	case errors.Is(err, selfupdate.ErrBusy):
		status = http.StatusConflict
	case errors.Is(err, selfupdate.ErrNoKeys):
		status = http.StatusServiceUnavailable
	case errors.Is(err, selfupdate.ErrNoAsset):
		status = http.StatusNotFound
	case errors.Is(err, selfupdate.ErrUnreachable):
		status = http.StatusBadGateway
	}
	s.log.Warn("http self update refused", "user", user, "address", address,
		"status", status, "error", err)
	http.Error(w, err.Error(), status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

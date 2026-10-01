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

const actionUpdate = "update"

// restartDelay is how long the answer to an accepted update has to reach the
// client before the shutdown closes the connection it travels on.
var restartDelay = 250 * time.Millisecond

// Updater is what the endpoint needs of selfupdate.Updater, an interface so
// that a test can stand in for it without replacing any binary.
type Updater interface {
	Current() selfupdate.Info
	Stage(ctx context.Context, body io.Reader) (selfupdate.Staged, error)
	Request()
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

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		writeJSON(w, http.StatusOK, s.updater.Current())
	case http.MethodPut, http.MethodPost:
		if !s.sameSite(set, w, r) {
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

// acceptUpdate reads the upload, has it staged, answers and then asks for the
// restart.
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
	staged, err := s.updater.Stage(r.Context(), body)
	if err != nil {
		s.refuseUpdate(w, user, address, err)
		return
	}

	s.log.Warn("http self update accepted, restarting", "user", user, "address", address,
		"previous", current.Version, "version", staged.Version, "key", staged.Key)
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

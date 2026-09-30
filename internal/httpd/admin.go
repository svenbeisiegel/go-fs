package httpd

import (
	"net/http"

	"go-fs/internal/admin"
)

// The admin interface is the page that edits the configuration file, and so
// every password and every private key in it. It is served under the go-fs
// marker like the login and the logout, so it reserves no name in the served
// folder, and nothing about who may see it is left to the interface itself:
// the decision is made here, once, before a request reaches it.
//
// What is required is a session of an account that sets isAdmin. A session and
// nothing else: an Authorization header carrying the same account's password
// is not enough on its own, because a session is what the account established
// through the login form on purpose, while a header is what a program or a
// browser sends along with everything else. A header beside a session for the
// same account is that session, so a browser that still remembers Basic
// credentials is not kept out by them.

// admits reports whether the request behind cred may reach the admin
// interface: it is on, it exists, and the request holds a session of an
// account that sets isAdmin.
func (s *Server) admits(set *settings, cred credential) bool {
	return s.admin != nil && set.cfg.EnableAdminInterface &&
		cred.token && cred.user != nil && cred.user.isAdmin
}

// handleAdmin guards the interface and hands the request over.
func (s *Server) handleAdmin(set *settings, w http.ResponseWriter, r *http.Request) {
	if s.admin == nil || !set.cfg.EnableAdminInterface {
		// switched off, the marker names nothing
		s.log.Debug("http admin interface is not enabled", "address", clientAddress(set, r))
		http.NotFound(w, r)
		return
	}

	cred := s.identify(set, w, r)
	if !cred.token || cred.user == nil {
		s.log.Info("http admin interface refused, no session", "credentials", cred.method,
			"address", clientAddress(set, r))
		w.Header().Set("Cache-Control", "no-store")
		// a browser is sent to log in; a fetch from a page whose session ran
		// out is told plainly, as it is for the file endpoints
		if browserRequest(r) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			http.Redirect(w, r, loginURL(r.URL), http.StatusSeeOther)
			return
		}
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}
	if !cred.user.isAdmin {
		s.log.Warn("http admin interface refused, the account is not an admin",
			"user", cred.user.name, "address", clientAddress(set, r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// the interface checks the content type and the origin of what it is
	// posted; the site check the file endpoints get is applied here as well
	if r.Method == http.MethodPost && !s.sameSite(set, w, r) {
		return
	}

	address := clientAddress(set, r)
	s.log.Info("http admin interface request", "user", cred.user.name,
		"action", r.URL.Query().Get(sessionParam), "method", r.Method, "address", address)
	// the interface writes its own records, and it should name the same
	// client this one does
	s.admin.ServeHTTP(w, r.WithContext(admin.WithClient(r.Context(), address)))
}

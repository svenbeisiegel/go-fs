package httpd

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"go-fs/internal/admin"
	"go-fs/internal/vfs"
)

// The login and logout endpoints do not have paths of their own. Every URL
// this server answers is a path in the served folder — that is why the page's
// style and script are inlined rather than fetched — so a /login would shadow
// a real name, and a suffix would shadow a real file. A query key cannot
// shadow anything: the login page for /private/ is /private/ itself, asked for
// with the marker, which is also why the endpoint needs no "next" parameter
// and so has no open redirect to get wrong.
//
// The price is that the marker is reserved across the whole URL space. That is
// cheaper than reserving names in the folder being served.
const sessionParam = "go-fs"

const (
	actionLogin  = "login"
	actionLogout = "logout"
)

// maxLoginBody is all a login form can possibly be. The endpoint answers
// before anything has authenticated, so what it reads is bounded first.
const maxLoginBody = 8 << 10

// sessionAction reports which endpoint a request is for, or "" for an ordinary
// request. An unknown value is not an action: a file whose name someone put a
// go-fs query on is still that file.
func sessionAction(r *http.Request) string {
	switch action := r.URL.Query().Get(sessionParam); action {
	case actionLogin, actionLogout:
		return action
	default:
		return ""
	}
}

// cleanURL is this request's own URL with the marker taken off, which is the
// only place a login or a logout ever sends the browser.
func cleanURL(u *url.URL) string {
	stripped := *u
	query := stripped.Query()
	query.Del(sessionParam)
	stripped.RawQuery = query.Encode()
	return stripped.RequestURI()
}

// loginURL is this request's own URL with the marker put on.
func loginURL(u *url.URL) string {
	marked := *u
	query := marked.Query()
	query.Set(sessionParam, actionLogin)
	marked.RawQuery = query.Encode()
	return marked.RequestURI()
}

// handleSession routes the two endpoints.
func (s *Server) handleSession(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, action string) {
	if !canLogIn(set) {
		// no account may log in, so these endpoints do not exist here
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	if r.Method == http.MethodPost {
		if !s.sameSite(set, w, r) {
			return
		}
		if action == actionLogin {
			s.handleLogin(set, w, r, target)
		} else {
			s.handleLogout(set, w, r)
		}
		return
	}
	// logging out is never a GET: browsers prefetch links, and a prefetched
	// logout signs people out for reading a page
	if action == actionLogin && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if cred := s.identify(set, w, r); cred.token {
			http.Redirect(w, r, cleanURL(r.URL), http.StatusSeeOther)
			return
		}
		// a locked address is sent here by refuseLocked, so the page says why
		if remaining, locked := s.lockedOut(set, r); locked {
			s.loginPage(w, r, target, lockoutMessage(remaining))
			return
		}
		s.loginPage(w, r, target, "")
		return
	}
	w.Header().Set("Allow", "POST")
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// handleLogin checks what the form posted and hands out a token.
func (s *Server) handleLogin(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target) {
	// multipart is the other content type a cross site form can post, so what
	// is accepted here is narrowed to the one the login form actually sends
	if kind := r.Header.Get("Content-Type"); !strings.HasPrefix(kind, "application/x-www-form-urlencoded") {
		s.log.Debug("http login form has the wrong content type", "contentType", kind,
			"address", clientAddress(set, r))
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}
	// refused before the form is read: nothing it says is looked at
	if remaining, locked := s.lockedOut(set, r); locked {
		s.log.Info("http login refused, the address is locked out", "method", "form",
			"address", clientAddress(set, r), "remaining", remaining.Round(time.Second))
		s.loginPage(w, r, target, lockoutMessage(remaining))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		s.log.Debug("http login form cannot be read", "error", err, "address", clientAddress(set, r))
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := s.checkLogin(set, r.PostFormValue("username"), r.PostFormValue("password"))
	if user == nil {
		s.log.Info("http login refused", "user", r.PostFormValue("username"),
			"method", "form", "address", clientAddress(set, r))
		s.recordFailure(set, r)
		if delay := set.cfg.LoginFailureDelay; delay > 0 {
			time.Sleep(time.Duration(delay) * time.Second)
		}
		// the form comes back with the message rather than a 401: a 401 has to
		// carry WWW-Authenticate, and that is the header that raises the
		// browser's own password box this page exists to replace
		s.loginPage(w, r, target, "That username and password do not match an account.")
		return
	}

	s.logins.clear(clientAddress(set, r))
	if err := s.setSession(set, w, r, user); err != nil {
		s.log.Error("http cannot create a session token", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, cleanURL(r.URL), http.StatusSeeOther)
}

// checkLogin resolves a username and password to the account that may log in
// with them.
func (s *Server) checkLogin(set *settings, name, password string) *account {
	return matchAccount(set.accounts, name, password)
}

// handleLogout drops the token, whatever it named. The token is read only to
// say in the log who logged out.
func (s *Server) handleLogout(set *settings, w http.ResponseWriter, r *http.Request) {
	name := "-"
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if claims, err := s.tokens.read(cookie.Value); err == nil {
			name = claims.Subject
		}
	}
	s.clearSession(w)
	clearCookie(w, legacyCookie)
	s.log.Info("http logout", "user", name, "address", clientAddress(set, r))
	http.Redirect(w, r, cleanURL(r.URL), http.StatusSeeOther)
}

// loginPage renders the form. It answers 200 rather than 401 for the reason
// handleLogin gives, and carries no folder content at all: it is reached
// before anything has authenticated, so there is nothing it may show.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request, target vfs.Target, message string) {
	nonce, err := pageNonce()
	if err != nil {
		s.log.Error("http cannot render the login page", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	page, err := renderLogin(loginData{
		Path:    vfs.AsFolder(target.Virtual),
		Action:  loginURL(r.URL),
		Cancel:  cleanURL(r.URL),
		Message: message,
		Nonce:   nonce,
		Style:   listingStyle,
	})
	if err != nil {
		s.log.Error("http cannot render the login page", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Security-Policy", loginPolicy(nonce))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(page)
	}
}

// loginPolicy is the listing policy with form-action added. The listing cannot
// set it, because its dialogs submit to method="dialog" and some browsers
// check that against it; this page has no dialogs, so it can say that the only
// place it posts to is itself.
func loginPolicy(nonce string) string {
	return contentPolicy(nonce) + "; form-action 'self'"
}

// sessionViewFor is what the listing header says about who is looking at it.
func (s *Server) sessionViewFor(set *settings, r *http.Request, cred credential) sessionView {
	who := sessionView{
		Login:  loginURL(r.URL),
		Logout: logoutURL(r.URL),
	}
	if cred.token && cred.user != nil {
		who.User = cred.user.name
		if s.admits(set, cred) {
			who.Admin = adminURL(r.URL)
		}
		return who
	}
	// someone who authenticated with a header has no session to log out of, so
	// they are offered the login rather than a logout that would clear nothing
	who.CanLogin = canLogIn(set)
	return who
}

// logoutURL is this request's own URL with the logout marker on it.
func logoutURL(u *url.URL) string {
	marked := *u
	query := marked.Query()
	query.Set(sessionParam, actionLogout)
	marked.RawQuery = query.Encode()
	return marked.RequestURI()
}

// adminURL is this request's own URL with the admin marker on it. It is the
// folder being looked at rather than the root, so that the interface opens
// from wherever the Admin button was pressed.
func adminURL(u *url.URL) string {
	marked := *u
	query := marked.Query()
	query.Set(sessionParam, admin.ActionPage)
	marked.RawQuery = query.Encode()
	return marked.RequestURI()
}

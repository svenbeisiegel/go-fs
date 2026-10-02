package httpd

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"go-fs/internal/vfs"
)

// A share link is a file's own URL with ?key= added: an HMAC-SHA512, keyed by
// http.shareLinkSecret, over the file's path, modification time and size. It
// lets anyone holding it download that one file without an account. Nothing
// is stored: the key is computed again from the file as it is now, so a link
// stops working the moment the file is changed, renamed or replaced, and every
// link at once when the secret is.
const (
	// shareParam carries the key of a share link.
	shareParam = "key"
	// actionShare is the marker that hands a signed in account the link to a
	// file: ?go-fs=share.
	actionShare = "share"
)

// shareSecret is the key share links are signed with: the configured one, or
// the one made at this start when the file has none, whose links then last
// until the next restart.
func (s *Server) shareSecret(set *settings) []byte {
	if set.cfg.ShareLinkSecret != "" {
		return []byte(set.cfg.ShareLinkSecret)
	}
	return s.shareFallback
}

// shareKey is the key of the share link to a file as it is now. virtual is
// the path it is reached by, which is what binds the key to the name.
func shareKey(secret []byte, virtual string, info os.FileInfo) string {
	mac := hmac.New(sha512.New, secret)
	mac.Write([]byte(virtual))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(info.ModTime().UnixNano(), 10)))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(info.Size(), 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// sharedFile reports whether a request is the download of a file through a
// share link that is still good. It is only ever a read: any other method, or
// a key on a folder, is not a share link, and neither is a key that no longer
// matches, which leaves the request to be authenticated as any other.
func (s *Server) sharedFile(set *settings, r *http.Request, target vfs.Target) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	key := r.URL.Query().Get(shareParam)
	if key == "" {
		return false
	}
	info, err := os.Stat(target.Path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	expected := shareKey(s.shareSecret(set), target.Virtual, info)
	if !hmac.Equal([]byte(key), []byte(expected)) {
		s.log.Debug("http share key does not match", "file", target.Virtual,
			"address", clientAddress(set, r))
		return false
	}
	return true
}

// handleShare answers ?go-fs=share on a file with the path and query of its
// share link, which the page puts behind its own origin. Only an account may
// hand one out, and only for a file it may read, which the dispatch has
// already decided.
func (s *Server) handleShare(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, cred credential) {
	if cred.user == nil {
		s.log.Debug("http share refused, nobody is signed in", "file", target.Virtual)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	info, err := os.Stat(target.Path)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	key := shareKey(s.shareSecret(set), target.Virtual, info)
	s.log.Info("http share link created", "user", cred.user.name, "file", target.Virtual,
		"address", clientAddress(set, r))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"path": (&url.URL{Path: target.Virtual}).String() + "?" + shareParam + "=" + key,
	})
}

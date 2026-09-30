package httpd

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"go-fs/internal/config"
	"go-fs/internal/secrets"
	"go-fs/internal/vfs"
)

// tokenPrefix is what a bearer token's account is named with, so that the
// records never confuse a token with an account of the same name.
const tokenPrefix = "token:"

// buildTokens resolves the [[tokens]] entries once, at startup and on every
// reload. A token with a base folder gets a root of its own, and its paths
// fold case as that folder does; one without is served the server's folder,
// whose fold is fold.
func buildTokens(tokens []config.Token, fold bool) ([]*account, error) {
	resolved := make([]*account, 0, len(tokens))
	for _, token := range tokens {
		entry := &account{
			name:  tokenPrefix + token.Name,
			perms: token.Permissions(),
			hash:  strings.ToLower(token.Hash),
		}
		if at, ok := token.ExpiresAt(); ok {
			entry.expires = at
		}
		folds := fold
		if token.Basefolder != "" {
			root, err := vfs.New(token.Basefolder)
			if err != nil {
				return nil, fmt.Errorf("tokens %q basefolder: %w", token.Name, err)
			}
			entry.root = root
			folds = root.CaseInsensitive()
		}
		for k, pattern := range token.Paths {
			compiled, err := compilePattern(pattern, folds)
			if err != nil {
				return nil, fmt.Errorf("tokens %q paths[%d]: %w", token.Name, k, err)
			}
			entry.paths = append(entry.paths, compiled)
		}
		resolved = append(resolved, entry)
	}
	return resolved, nil
}

// checkBearer resolves a bearer token to its account. Every configured token
// is compared, whether or not an earlier one matched, so the time a refusal
// takes does not depend on which tokens exist. A token that has expired is
// refused like one that does not, and recorded as such; only an unknown token
// counts towards the lock, since an expired one was a real credential once.
func (s *Server) checkBearer(set *settings, r *http.Request, presented string) *account {
	hash := config.HashToken(strings.TrimSpace(presented))
	var found *account
	for _, token := range set.tokens {
		if secrets.Match(hash, token.hash) && found == nil {
			found = token
		}
	}
	if found == nil {
		s.log.Info("http login refused", "method", "bearer", "address", clientAddress(set, r))
		s.recordFailure(set, r)
		return nil
	}
	if !found.expires.IsZero() && !time.Now().Before(found.expires) {
		s.log.Info("http bearer token expired", "user", found.name,
			"expired", found.expires.Format(time.RFC3339), "address", clientAddress(set, r))
		return nil
	}
	return found
}

// refuseBearer answers a request whose bearer token was refused, as RFC 6750
// section 3.1 asks: 401 with a challenge that says the token is the problem.
func (s *Server) refuseBearer(set *settings, w http.ResponseWriter, r *http.Request) {
	if delay := set.cfg.LoginFailureDelay; delay > 0 {
		time.Sleep(time.Duration(delay) * time.Second)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer realm=%q, error="invalid_token"`, set.cfg.Realm))
	http.Error(w, "Invalid token", http.StatusUnauthorized)
}

// rootFor is the folder a request by user is served from: a token's own base
// folder, or the server's.
func (s *Server) rootFor(user *account) *vfs.Root {
	if user != nil && user.root != nil {
		return user.root
	}
	return s.root
}

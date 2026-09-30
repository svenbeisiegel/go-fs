package httpd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Container clients do not decide by themselves whether to send credentials:
// docker, containerd and podman ask /v2/ first and send credentials only when
// that answer challenged them for some. A registry that is public for pulling
// therefore cannot simply answer /v2/ and wait for a push to ask for a
// password, since the client would never send one; nor can it challenge for
// Basic, since docker then refuses to pull without a login.
//
// So the registry speaks the token protocol every public registry speaks:
// /v2/ challenges with a Bearer realm, the client fetches a token there, with
// its Basic credentials when it has some and without when it has none, and
// sends the token from then on. An anonymous token pulls where pulling is
// public; a token of an account that sets registry does everything. Basic is
// still accepted on every request, for curl and for scripts.
//
// A token is a JWT signed with the key of the session tokens, for another
// audience, so neither can stand in for the other. Like a session token it
// names the account and nothing else, and what the account may do is looked up
// on every request.
const (
	registryTokenAudience = "go-fs-registry"
	// registryService is what the challenge and the token call the registry.
	registryService = "go-fs"
	// registryTokenLifetime is how long a token is accepted. Clients fetch a
	// new one when theirs runs out, so it is short, as elsewhere.
	registryTokenLifetime = 5 * time.Minute
	// registryTokenPath is where tokens are fetched. A repository name cannot
	// start with an underscore, so it is no repository's path.
	registryTokenPath = "/v2/_token"
)

// registryParser reads registry tokens, with every guard the session parser
// has.
var registryParser = jwt.NewParser(
	jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	jwt.WithIssuer(tokenIssuer),
	jwt.WithAudience(registryTokenAudience),
	jwt.WithExpirationRequired(),
	jwt.WithIssuedAt(),
	jwt.WithLeeway(tokenLeeway),
	jwt.WithStrictDecoding(),
)

// mintRegistry signs a registry token for an account, or an anonymous one for
// nil.
func (s *signer) mintRegistry(user *account, lifetime time.Duration) (string, time.Time, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expires := now.Add(lifetime)
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{registryTokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
			ID:        base64.RawURLEncoding.EncodeToString(id),
		},
	}
	if user != nil {
		claims.Subject = user.name
		claims.Credentials = s.fingerprint(user)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.key)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// readRegistry verifies a registry token. An empty subject is an anonymous
// token.
func (s *signer) readRegistry(raw string) (*sessionClaims, error) {
	claims := &sessionClaims{}
	_, err := registryParser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Method.Alg())
		}
		return s.key, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// registryBearer resolves a registry token to its account: nil and true for
// an anonymous token, nil and false for one that is not accepted, including
// one whose account has gone or has changed its password since.
func (s *Server) registryBearer(set *settings, raw string) (*account, bool) {
	claims, err := s.tokens.readRegistry(raw)
	if err != nil {
		return nil, false
	}
	if claims.Subject == "" {
		return nil, true
	}
	user := accountNamed(set.registryAccounts, claims.Subject)
	if user == nil || !s.tokens.issuedFor(claims, user) {
		return nil, false
	}
	return user, true
}

// registryScope is the access a request needs, in the form of the token
// protocol, which the client asks the token endpoint for.
func registryScope(route registryRoute, method string) string {
	switch {
	case route.kind == routeCatalog:
		return "registry:catalog:*"
	case route.name == "":
		return ""
	case registryRead(method) && !isUpload(route):
		return "repository:" + route.name + ":pull"
	default:
		return "repository:" + route.name + ":pull,push"
	}
}

// registryChallenge sends a client to the token endpoint. invalid says the
// token it sent was not accepted, and failed that the request carried a wrong
// password, which is slowed down.
func (s *Server) registryChallenge(set *settings, w http.ResponseWriter, r *http.Request, route registryRoute, invalid, failed bool) {
	if delay := set.cfg.LoginFailureDelay; delay > 0 && failed {
		time.Sleep(time.Duration(delay) * time.Second)
	}
	scheme := "http"
	if secureRequest(set, r) {
		scheme = "https"
	}
	challenge := fmt.Sprintf(`Bearer realm=%q,service=%q`, scheme+"://"+r.Host+registryTokenPath, registryService)
	if scope := registryScope(route, r.Method); scope != "" {
		challenge += fmt.Sprintf(`,scope=%q`, scope)
	}
	if invalid {
		challenge += `,error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	writeRegistryError(w, r, regErr(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required"))
}

// handleRegistryToken hands out registry tokens: one for the account whose
// Basic credentials the request carries, which is how docker login checks a
// password, or an anonymous one where pulling is public. The scope asked for
// is not needed: what a token may do is decided on every request, from the
// account it names.
func (s *Server) handleRegistryToken(set *settings, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var user *account
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Basic ") {
		if remaining, locked := s.lockedOut(set, r); locked {
			s.log.Info("http login refused, the address is locked out", "method", "registry",
				"address", clientAddress(set, r), "remaining", remaining.Round(time.Second))
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter(remaining)))
			writeRegistryError(w, r, regErr(http.StatusTooManyRequests, "TOOMANYREQUESTS",
				"too many failed logins from your address"))
			return
		}
		name, password, ok := parseBasic(header)
		if ok {
			user = matchAccount(set.registryAccounts, name, password)
		}
		switch {
		case user != nil:
			s.logins.clear(clientAddress(set, r))
		case ok && s.otherAccount(set, name, password):
			// the right password of an account without registry: it may pull
			// where anyone may, and nothing more
			if !set.cfg.RegistryAnonymousRead {
				s.log.Info("registry refused an account that does not set registry", "user", name,
					"method", r.Method, "path", r.URL.Path, "address", clientAddress(set, r))
				writeRegistryError(w, r, regErr(http.StatusForbidden, "DENIED",
					"requested access to the resource is denied"))
				return
			}
		default:
			s.log.Info("http login refused", "user", name, "method", "registry",
				"address", clientAddress(set, r))
			s.recordFailure(set, r)
			s.basicChallenge(set, w, r, true)
			return
		}
	} else if !set.cfg.RegistryAnonymousRead {
		s.basicChallenge(set, w, r, false)
		return
	}
	token, expires, err := s.tokens.mintRegistry(user, registryTokenLifetime)
	if err != nil {
		s.log.Error("registry cannot sign a token", "error", err)
		writeRegistryError(w, r, errRegistryInternal)
		return
	}
	s.log.Debug("registry token issued", "user", nameOf(user), "scope", r.URL.Query().Get("scope"),
		"address", clientAddress(set, r))
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"access_token": token,
		"expires_in":   int(time.Until(expires).Seconds()),
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// basicChallenge asks the token endpoint's caller for Basic credentials.
func (s *Server) basicChallenge(set *settings, w http.ResponseWriter, r *http.Request, failed bool) {
	if delay := set.cfg.LoginFailureDelay; delay > 0 && failed {
		time.Sleep(time.Duration(delay) * time.Second)
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", set.cfg.Realm))
	writeRegistryError(w, r, regErr(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required"))
}

// otherAccount reports the right password of an account that does not set
// registry, which is not a failed login.
func (s *Server) otherAccount(set *settings, name, password string) bool {
	return matchAccount(set.accounts, name, password) != nil ||
		matchAccount(set.s3accounts, name, password) != nil
}

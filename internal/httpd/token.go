package httpd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"go-fs/internal/config"
)

// A browser that has used the login form carries a signed token rather than
// repeating its credentials, so that the browser's own password box never has
// to be raised and there is something to log out of. The token is a JWT
// (RFC 7519) signed with HMAC-SHA256 (RFC 7515), which is what a symmetric key
// and a single server call for.
//
// What the token says is deliberately thin: it names the account and nothing
// else. The account list is reloadable, so the rights are looked up from the
// live snapshot on every request, exactly as the opaque session it replaces
// did — a token can never reach further than the account behind it right now.
const (
	// sessionCookie is where a browser carries the token.
	sessionCookie = "goFsSessionToken"
	// legacyCookie is the name the opaque session used. It is cleared on login
	// and on logout, so a browser upgraded into this version stops carrying a
	// value nothing will ever read again.
	legacyCookie = "session"

	tokenIssuer   = "go-fs"
	tokenAudience = "go-fs-http"
	// tokenLeeway absorbs the clock difference between the host that signed a
	// token and the one reading it, which matters once a secret is shared.
	tokenLeeway = 30 * time.Second
)

// sessionClaims is what a token carries. Everything but Credentials is a
// registered claim, so a token from this server reads as a token anywhere.
type sessionClaims struct {
	jwt.RegisteredClaims
	// AuthTime is when the account logged in with the login form, the
	// auth_time of OpenID Connect. A renewed token carries it over unchanged,
	// which is what lets a renewal be capped by http.httpSessionMaxLifetime.
	// A token minted before the claim existed has none; its IssuedAt stands
	// in, since such a token was never renewed.
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	// Credentials fingerprints the account this token was issued for, so that
	// changing its password signs out the browsers already holding one.
	Credentials string `json:"cred"`
}

// signer mints and reads the session tokens.
type signer struct {
	key    []byte
	parser *jwt.Parser
}

// newSigner prepares the signer from the configured secret.
//
// The secret is generated and written into the configuration file at the
// first start (config.EnsureSecrets), so it is only missing here when that
// file could not be written. Then, as with the TLS certificate and the SFTP
// host key, one is generated for this run, which keeps the server usable at
// the cost of a key that changes on every restart: every browser is logged
// out, and two hosts serving the same folder cannot share a login. The
// warning says so.
func newSigner(configured string, logger *slog.Logger) (*signer, error) {
	var key []byte
	if configured != "" {
		decoded, err := config.DecodeSessionSecret(configured)
		if err != nil {
			return nil, fmt.Errorf("http.httpSessionTokenSecret: %w", err)
		}
		key = decoded
	} else {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		logger.Warn("no http.httpSessionTokenSecret configured, generated a temporary " +
			"signing key; it changes on every restart, so every browser is logged out " +
			"by one and two hosts cannot share a login")
	}

	return &signer{
		key: key,
		// every guard the parser has, because this is the whole of the
		// security: pinning the algorithm is what refuses a token that says
		// alg "none" or names an asymmetric algorithm to have the public key
		// taken for an HMAC secret
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithIssuer(tokenIssuer),
			jwt.WithAudience(tokenAudience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(tokenLeeway),
			jwt.WithStrictDecoding(),
		),
	}, nil
}

// sessionWindow is how long a token lasts: idle is how long it is good for
// from the request that minted it, and max how long after the login no token
// of that login is good any more.
type sessionWindow struct {
	idle, max time.Duration
}

// sessionWindowOf reads the window from the section. A cap shorter than the
// idle window is raised to it: a file from before the cap existed may set a
// lifetime longer than the default cap, and meant it.
func sessionWindowOf(cfg config.HTTP) sessionWindow {
	window := sessionWindow{
		idle: time.Duration(cfg.SessionTokenLifetime) * time.Second,
		max:  time.Duration(cfg.SessionMaxLifetime) * time.Second,
	}
	window.max = max(window.max, window.idle)
	return window
}

// mint signs a token for an account that logged in at loggedIn, good for the
// idle part of window from now but never beyond its max from loggedIn. A
// window that has already passed is what a test asks for; nothing else
// produces one.
func (s *signer) mint(user *account, loggedIn time.Time, window sessionWindow) (string, time.Time, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expires := now.Add(window.idle)
	if limit := loggedIn.Add(window.max); limit.Before(expires) {
		expires = limit
	}

	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			Subject:   user.name,
			Audience:  jwt.ClaimStrings{tokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
			ID:        base64.RawURLEncoding.EncodeToString(id),
		},
		AuthTime:    jwt.NewNumericDate(loggedIn),
		Credentials: s.fingerprint(user),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.key)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// read verifies a token and returns what it claims. It says nothing about
// whether the account still exists or still holds the password it was issued
// for; that is the caller's question, because only the caller has the current
// account list.
func (s *signer) read(raw string) (*sessionClaims, error) {
	claims := &sessionClaims{}
	_, err := s.parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		// WithValidMethods has already refused anything else; this is the
		// second lock on the one mistake that breaks every JWT verifier
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Method.Alg())
		}
		return s.key, nil
	})
	if err != nil {
		return nil, err
	}
	if claims.Subject == "" {
		return nil, errors.New("the token names no account")
	}
	return claims, nil
}

// loggedIn is when the login a token belongs to happened.
func (c *sessionClaims) loggedIn() time.Time {
	if c.AuthTime != nil {
		return c.AuthTime.Time
	}
	if c.IssuedAt != nil {
		return c.IssuedAt.Time
	}
	// read refuses a token without an expiry, and every token this server
	// mints has both; a hand-made one without either is treated as ancient
	return time.Time{}
}

// outlived reports whether the login a token belongs to is older than the
// window allows, whatever its own expiry says: a token minted while the cap
// was longer is held to the one configured now.
func (c *sessionClaims) outlived(window sessionWindow, now time.Time) bool {
	return now.After(c.loggedIn().Add(window.max).Add(tokenLeeway))
}

// renewable reports whether a browser presenting the token should be handed a
// fresh one: once less than half of the idle window is left, and only while a
// fresh one would reach further than this one does. Waiting for the second
// half is what keeps a busy browser from being sent a cookie with every
// request.
func (c *sessionClaims) renewable(window sessionWindow, now time.Time) bool {
	if c.ExpiresAt == nil {
		return false
	}
	expires := c.ExpiresAt.Time
	if expires.Sub(now) >= window.idle/2 {
		return false
	}
	return expires.Before(c.loggedIn().Add(window.max))
}

// issuedFor reports whether a token was issued for the credentials an account
// holds right now, so that changing a password signs out the browsers that
// were logged in under the old one.
func (s *signer) issuedFor(claims *sessionClaims, user *account) bool {
	return hmac.Equal([]byte(claims.Credentials), []byte(s.fingerprint(user)))
}

// fingerprint stands for an account's credentials without carrying them.
//
// It is an HMAC under the signing key rather than a plain hash for a reason
// worth stating: a JWT payload is base64, not encryption, so whoever holds a
// token can read every claim in it. A bare sha256 of the password sitting
// there would be an offline guessing target; an HMAC under a key the holder
// does not have is not.
func (s *signer) fingerprint(user *account) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(user.name))
	// the separator is what stops "ab"+"c" and "a"+"bc" fingerprinting alike
	mac.Write([]byte{0})
	mac.Write([]byte(user.password))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

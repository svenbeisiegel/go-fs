package httpd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-fs/internal/config"
)

// The S3 API authenticates with AWS Signature Version 4: a client never sends
// its secret key, it signs a canonical form of the request with a key derived
// from it. The secret key of an account here is its password, so verifying a
// signature needs the password in the clear, as Digest does.

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	// amzDateFormat is how x-amz-date and X-Amz-Date carry a time.
	amzDateFormat = "20060102T150405Z"
	// s3MaxSkew is how far the time a request was signed at may be from this
	// server's clock, which is what AWS allows too: it bounds how long a
	// captured request can be replayed.
	s3MaxSkew = 15 * time.Minute
	// s3MaxPresign is the longest a presigned URL may be valid for.
	s3MaxPresign = 7 * 24 * time.Hour

	// the payload hashes a request may declare instead of the hash itself
	payloadUnsigned                 = "UNSIGNED-PAYLOAD"
	payloadStreaming                = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	payloadStreamingTrailer         = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	payloadStreamingUnsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

// emptySHA256 is the hash of no bytes, which a chunk signature names as the
// hash of its headers.
var emptySHA256 = hex.EncodeToString(sha256.New().Sum(nil))

// noAccountSecret is what a signature is checked against when its access key
// names no account, so that an access key that does not exist takes as long to
// refuse as a secret key that is wrong.
const noAccountSecret = "go-fs: no such account"

// isS3Request reports whether a request is signed for S3, in its header or,
// for a presigned URL, in its query.
func isS3Request(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("Authorization"), sigV4Algorithm+" ") {
		return true
	}
	return strings.Contains(r.URL.RawQuery, "X-Amz-Algorithm=") &&
		r.URL.Query().Get("X-Amz-Algorithm") == sigV4Algorithm
}

// s3Signature is a request whose signature has been verified: the account it
// is from, and what a streaming body needs to verify each of its chunks.
type s3Signature struct {
	user *account
	// payload is the x-amz-content-sha256 the request declared: the hash of
	// the body, or one of the payload* markers.
	payload string
	// key, date, scope and seed are what the signature of the first chunk of
	// a streaming body is chained to.
	key   []byte
	date  string
	scope string
	seed  string
}

// sigV4Params is what a signature says about itself, from the Authorization
// header or from the query of a presigned URL.
type sigV4Params struct {
	accessKey string
	// day is the date of the credential scope, region and service the rest
	// of it
	day, region, service string
	signedHeaders        string
	signature            string
	amzDate              string
	presigned            bool
	expires              time.Duration
}

func (p sigV4Params) scope() string {
	return p.day + "/" + p.region + "/" + p.service + "/aws4_request"
}

// parseSigV4Header reads an Authorization header of the form
//
//	AWS4-HMAC-SHA256 Credential=<key>/<day>/<region>/s3/aws4_request,
//	SignedHeaders=host;x-amz-date, Signature=<hex>
func parseSigV4Header(header string) (sigV4Params, bool) {
	rest, ok := strings.CutPrefix(header, sigV4Algorithm+" ")
	if !ok {
		return sigV4Params{}, false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return sigV4Params{}, false
		}
		fields[name] = value
	}
	var p sigV4Params
	if !p.setCredential(fields["Credential"]) {
		return sigV4Params{}, false
	}
	p.signedHeaders = fields["SignedHeaders"]
	p.signature = fields["Signature"]
	return p, p.signedHeaders != "" && p.signature != ""
}

// parseSigV4Query reads the X-Amz-* parameters of a presigned URL.
func parseSigV4Query(query url.Values) (sigV4Params, bool) {
	p := sigV4Params{presigned: true}
	if query.Get("X-Amz-Algorithm") != sigV4Algorithm || !p.setCredential(query.Get("X-Amz-Credential")) {
		return sigV4Params{}, false
	}
	p.amzDate = query.Get("X-Amz-Date")
	p.signedHeaders = query.Get("X-Amz-SignedHeaders")
	p.signature = query.Get("X-Amz-Signature")
	seconds, err := strconv.Atoi(query.Get("X-Amz-Expires"))
	if err != nil || seconds < 1 {
		return sigV4Params{}, false
	}
	p.expires = time.Duration(seconds) * time.Second
	return p, p.signedHeaders != "" && p.signature != ""
}

// setCredential reads "<key>/<day>/<region>/<service>/aws4_request". An
// access key cannot hold a slash, which the configuration makes sure of.
func (p *sigV4Params) setCredential(credential string) bool {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" || parts[0] == "" {
		return false
	}
	p.accessKey, p.day, p.region, p.service = parts[0], parts[1], parts[2], parts[3]
	return true
}

// verifyS3 checks the signature of a request against the S3 accounts as they
// are configured right now.
func (s *Server) verifyS3(set *settings, r *http.Request, now time.Time) (*s3Signature, *s3Error) {
	var p sigV4Params
	var ok bool
	if header := r.Header.Get("Authorization"); header != "" {
		if p, ok = parseSigV4Header(header); !ok {
			return nil, s3Err(http.StatusBadRequest, "AuthorizationHeaderMalformed",
				"The authorization header is malformed.")
		}
		p.amzDate = r.Header.Get("X-Amz-Date")
	} else if p, ok = parseSigV4Query(r.URL.Query()); !ok {
		return nil, s3Err(http.StatusBadRequest, "AuthorizationQueryParametersError",
			"The X-Amz-* parameters of the presigned URL are malformed.")
	}

	signedAt, err := time.Parse(amzDateFormat, p.amzDate)
	if err != nil {
		return nil, s3Err(http.StatusForbidden, "AccessDenied",
			"AWS authentication requires a valid x-amz-date.")
	}
	// the region is checked before anything that depends on the secret key:
	// the answer tells a client that guessed the region wrong which one to
	// sign for, and the SDKs retry with it by themselves
	if p.region != config.S3Region {
		failure := s3Err(http.StatusBadRequest, "AuthorizationHeaderMalformed",
			"The authorization header is malformed; the region '"+p.region+
				"' is wrong; expecting '"+config.S3Region+"'.")
		failure.region = config.S3Region
		return nil, failure
	}
	if p.service != "s3" || p.day != p.amzDate[:8] {
		return nil, s3Err(http.StatusBadRequest, "AuthorizationHeaderMalformed",
			"The credential scope has to name the day the request was signed on and the service s3.")
	}
	if p.presigned {
		if p.expires > s3MaxPresign {
			return nil, s3Err(http.StatusBadRequest, "AuthorizationQueryParametersError",
				"X-Amz-Expires must be less than a week (in seconds); that is, the given "+
					"X-Amz-Expires must be less than 604800 seconds.")
		}
		if now.Before(signedAt.Add(-s3MaxSkew)) {
			return nil, s3Err(http.StatusForbidden, "AccessDenied", "Request is not valid yet.")
		}
		if now.After(signedAt.Add(p.expires)) {
			return nil, s3Err(http.StatusForbidden, "AccessDenied", "Request has expired.")
		}
	} else if skew := now.Sub(signedAt); skew > s3MaxSkew || skew < -s3MaxSkew {
		return nil, s3Err(http.StatusForbidden, "RequestTimeTooSkewed",
			"The difference between the request time and the server's time is too large.")
	}

	names := strings.Split(p.signedHeaders, ";")
	if !containsString(names, "host") {
		return nil, s3Err(http.StatusBadRequest, "AuthorizationHeaderMalformed",
			"The signed headers have to include host.")
	}

	payload := r.Header.Get("X-Amz-Content-Sha256")
	switch {
	case p.presigned && payload == "":
		payload = payloadUnsigned
	case payload == "":
		return nil, s3Err(http.StatusBadRequest, "InvalidRequest",
			"Missing required header for this request: x-amz-content-sha256.")
	case !validPayloadHash(payload):
		return nil, s3Err(http.StatusBadRequest, "InvalidArgument",
			"x-amz-content-sha256 must be UNSIGNED-PAYLOAD, a STREAMING-* value or a valid sha256 value.")
	}

	user := accountNamed(set.s3accounts, p.accessKey)
	secret := noAccountSecret
	if user != nil {
		secret = user.password
	}
	key := signingKey(secret, p.day, p.region)
	query := canonicalQuery(r.URL.RawQuery, p.presigned)
	headers := canonicalHeaders(r, names)
	matched := false
	for _, uri := range canonicalURIs(r) {
		canonical := strings.Join([]string{r.Method, uri, query, headers, p.signedHeaders, payload}, "\n")
		expected := signString(key, stringToSign(p.amzDate, p.scope(), canonical))
		if hmac.Equal([]byte(expected), []byte(strings.ToLower(p.signature))) {
			matched = true
			break
		}
	}
	if user == nil || !matched {
		reason := "the signature does not match"
		if user == nil {
			reason = "the access key is not an s3 account"
		}
		s.log.Info("s3 login refused", "user", p.accessKey, "reason", reason,
			"address", clientAddress(set, r))
		failure := s3Err(http.StatusForbidden, "SignatureDoesNotMatch",
			"The request signature we calculated does not match the signature you provided. "+
				"Check your key and signing method.")
		failure.failedLogin = true
		return nil, failure
	}
	return &s3Signature{user: user, payload: payload, key: key,
		date: p.amzDate, scope: p.scope(), seed: strings.ToLower(p.signature)}, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// validPayloadHash reports an x-amz-content-sha256 this server can read the
// body by.
func validPayloadHash(value string) bool {
	switch value {
	case payloadUnsigned, payloadStreaming, payloadStreamingTrailer, payloadStreamingUnsignedTrailer:
		return true
	}
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// signingKey derives the key a signature is made with from the secret key, for
// one day, one region and the service s3.
func signingKey(secret, day, region string) []byte {
	key := hmacSHA256([]byte("AWS4"+secret), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, "s3")
	return hmacSHA256(key, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func signString(key []byte, value string) string {
	return hex.EncodeToString(hmacSHA256(key, value))
}

func stringToSign(amzDate, scope, canonical string) string {
	return sigV4Algorithm + "\n" + amzDate + "\n" + scope + "\n" + hexSHA256(canonical)
}

func hexSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// canonicalURIs are the forms of the path a signature may have been made over.
// The first is the path encoded the way SigV4 says to, which is what the SDKs
// sign. A client that put a different encoding of the same path on the wire
// may have signed that instead, so what it sent is tried as well.
func canonicalURIs(r *http.Request) []string {
	strict := s3Escape(r.URL.Path, true)
	if strict == "" {
		strict = "/"
	}
	raw := r.RequestURI
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if !strings.HasPrefix(raw, "/") {
		// the absolute form a client may send to a proxy
		raw = r.URL.EscapedPath()
	}
	if raw == "" || raw == strict {
		return []string{strict}
	}
	return []string{strict, raw}
}

// canonicalQuery sorts the parameters of a query and encodes each of them the
// way SigV4 says to. The signature of a presigned URL is left out of what it
// signs.
func canonicalQuery(raw string, presigned bool) string {
	type pair struct{ name, value string }
	var pairs []pair
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		name, value = queryUnescape(name), queryUnescape(value)
		if presigned && name == "X-Amz-Signature" {
			continue
		}
		pairs = append(pairs, pair{s3Escape(name, false), s3Escape(value, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].name != pairs[j].name {
			return pairs[i].name < pairs[j].name
		}
		return pairs[i].value < pairs[j].value
	})
	encoded := make([]string, 0, len(pairs))
	for _, p := range pairs {
		encoded = append(encoded, p.name+"="+p.value)
	}
	return strings.Join(encoded, "&")
}

func queryUnescape(value string) string {
	if decoded, err := url.QueryUnescape(value); err == nil {
		return decoded
	}
	return value
}

// canonicalHeaders renders the signed headers, one "name:value" line each. The
// headers net/http takes out of the map are read from where it puts them.
func canonicalHeaders(r *http.Request, names []string) string {
	var b strings.Builder
	for _, name := range names {
		var values []string
		switch name {
		case "host":
			values = []string{r.Host}
		case "transfer-encoding":
			values = r.TransferEncoding
		case "content-length":
			values = r.Header.Values("Content-Length")
			if len(values) == 0 && r.ContentLength >= 0 {
				values = []string{strconv.FormatInt(r.ContentLength, 10)}
			}
		default:
			values = r.Header.Values(name)
		}
		trimmed := make([]string, 0, len(values))
		for _, value := range values {
			trimmed = append(trimmed, strings.Join(strings.Fields(value), " "))
		}
		b.WriteString(name)
		b.WriteString(":")
		b.WriteString(strings.Join(trimmed, ","))
		b.WriteString("\n")
	}
	return b.String()
}

// s3Escape encodes every byte but the unreserved characters of RFC 3986, which
// is the encoding SigV4 signs and the one S3 uses for a key in a listing. With
// keepSlash a slash stays as it is, as it does in a path.
func s3Escape(value string, keepSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~', c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

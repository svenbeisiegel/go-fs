package httpd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// The registry page can copy an image from another registry into this one,
// and a tag of this one to another registry. What talks to the other registry
// is the client here: the part of the distribution API a pull and a push
// need, and the token flow docker's registries log in with.

// A reference is written the way docker takes it: a first component with a
// dot or a colon in it, or localhost, is the registry, and anything else is on
// Docker Hub, where a name of one component is an official image under
// library/.
const (
	dockerHub    = "docker.io"
	dockerHubAPI = "registry-1.docker.io"
)

// remoteRef is an image of another registry.
type remoteRef struct {
	// scheme is https unless the reference started with http://.
	scheme string
	// host is the registry as it was written, api where its API is.
	host, api  string
	repository string
	// tag and digest are what the reference names; one of them at least.
	tag    string
	digest digest.Digest
}

// String is the reference written in full.
func (r remoteRef) String() string {
	name := r.host + "/" + r.repository
	if r.tag != "" {
		name += ":" + r.tag
	}
	if r.digest != "" {
		name += "@" + r.digest.String()
	}
	return name
}

// ref is what the manifest is fetched by: the digest where there is one, as
// it cannot change under the pull.
func (r remoteRef) ref() string {
	if r.digest != "" {
		return r.digest.String()
	}
	return r.tag
}

// cutScheme takes an http:// or https:// off the front of what was typed.
func cutScheme(value string) (scheme, rest string) {
	if rest, ok := strings.CutPrefix(value, "http://"); ok {
		return "http", rest
	}
	if rest, ok := strings.CutPrefix(value, "https://"); ok {
		return "https", rest
	}
	return "https", value
}

// isRegistryHost reports whether the first component of a name is a
// registry rather than a namespace of Docker Hub.
func isRegistryHost(component string) bool {
	return strings.ContainsAny(component, ".:") || component == "localhost"
}

// splitHost cuts the registry off a name, Docker Hub where the name does not
// start with one, and gives the host the API is at.
func splitHost(name string) (host, api, rest string) {
	host, rest, found := strings.Cut(name, "/")
	if !found || !isRegistryHost(host) {
		host, rest = dockerHub, name
	}
	host = strings.ToLower(host)
	api = host
	if host == dockerHub || host == "index.docker.io" {
		host, api = dockerHub, dockerHubAPI
	}
	return host, api, rest
}

// hubName is a repository of Docker Hub with its official images under
// library/, as docker names them.
func hubName(host, repository string) string {
	if host == dockerHub && repository != "" && !strings.Contains(repository, "/") {
		return "library/" + repository
	}
	return repository
}

// parseRemoteReference reads an image reference as docker does. A reference
// without a tag or a digest is for latest.
func parseRemoteReference(value string) (remoteRef, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return remoteRef{}, errors.New("name the image")
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return remoteRef{}, fmt.Errorf("%q is not an image reference", value)
	}
	ref := remoteRef{}
	scheme, rest := cutScheme(value)
	ref.scheme = scheme
	if before, after, found := strings.Cut(rest, "@"); found {
		d, ok := parseBlobDigest(after)
		if !ok {
			return remoteRef{}, fmt.Errorf("%q is not a digest", after)
		}
		ref.digest, rest = d, before
	}
	// the tag is after the last colon that comes after the last slash: a
	// colon before it is the port of the registry
	if at := strings.LastIndex(rest, ":"); at > strings.LastIndex(rest, "/") {
		ref.tag, rest = rest[at+1:], rest[:at]
		if !tagPattern.MatchString(ref.tag) {
			return remoteRef{}, fmt.Errorf("%q is not a tag", ref.tag)
		}
	}
	ref.host, ref.api, ref.repository = splitHost(rest)
	ref.repository = hubName(ref.host, ref.repository)
	if !validRepository(ref.repository) {
		return remoteRef{}, fmt.Errorf("%q is not a repository name: lowercase letters, digits and separators only",
			ref.repository)
	}
	if ref.tag == "" && ref.digest == "" {
		ref.tag = "latest"
	}
	return ref, nil
}

// remoteTransport is what every client shares. Nothing bounds how long a
// request may take, since a layer can be gigabytes; what is bounded is how
// long each step of it may wait, and the idle reader watches the rest.
var remoteTransport http.RoundTripper = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	TLSHandshakeTimeout:   30 * time.Second,
	ResponseHeaderTimeout: 2 * time.Minute,
	ExpectContinueTimeout: time.Second,
	MaxIdleConns:          16,
	IdleConnTimeout:       90 * time.Second,
}

// insecureRemoteTransport is remoteTransport for a transfer that was told not
// to validate the connection: it takes whatever certificate it is shown, as
// a self-signed or an internal one. It is a transport of its own, so that a
// connection it opened is never reused by a transfer that does validate.
var insecureRemoteTransport = withoutVerification(remoteTransport)

func withoutVerification(base http.RoundTripper) http.RoundTripper {
	transport := base.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return transport
}

// remoteTransportFor is the transport of a transfer, by whether it validates
// the connection.
func remoteTransportFor(skipVerify bool) http.RoundTripper {
	if skipVerify {
		return insecureRemoteTransport
	}
	return remoteTransport
}

// withCertificateHint says, of a certificate that was not trusted, how to
// accept it all the same.
func withCertificateHint(err error) error {
	var untrusted *tls.CertificateVerificationError
	if errors.As(err, &untrusted) {
		return fmt.Errorf("%w; untick Validate Connection to accept this certificate", err)
	}
	return err
}

// remoteIdleTimeout is how long a blob may go without a byte arriving or
// leaving before the transfer is given up.
var remoteIdleTimeout = 2 * time.Minute

// manifestAccept is every manifest type the registry stores.
var manifestAccept = strings.Join([]string{v1.MediaTypeImageIndex, v1.MediaTypeImageManifest,
	mediaTypeDockerList, mediaTypeDockerManifest}, ", ")

// remoteClient talks to one repository of another registry.
type remoteClient struct {
	http       *http.Client
	base       string
	host       string
	repository string
	// actions are what the token is asked for: pull, or pull,push.
	actions            string
	username, password string
	// authorization is the header every request carries once the registry
	// has said what it wants.
	authorization string
}

// remoteLogin is how a transfer reaches the other registry: the username and
// password it was given, and whether it validates the connection.
type remoteLogin struct {
	username, password string
	skipVerify         bool
}

func newRemoteClient(ref remoteRef, login remoteLogin, actions string) *remoteClient {
	return &remoteClient{
		http:       &http.Client{Transport: remoteTransportFor(login.skipVerify), CheckRedirect: keepCredentialsHome},
		base:       ref.scheme + "://" + ref.api,
		host:       ref.host,
		repository: ref.repository,
		actions:    actions,
		username:   login.username,
		password:   login.password,
	}
}

// do sends a request to the other registry.
func (c *remoteClient) do(req *http.Request) (*http.Response, error) {
	res, err := c.http.Do(req)
	return res, withCertificateHint(err)
}

// keepCredentialsHome drops the Authorization header on a redirect to any
// other host or port. net/http only drops it for another host name, and a
// bucket on the same host behind another port is someone else all the same.
func keepCredentialsHome(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
		req.Header.Del("Authorization")
	}
	return nil
}

func (c *remoteClient) basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password))
}

// authenticate asks /v2/ what the registry wants, and gets it: a token for
// the repository, or the Basic credentials on every request. It is done before
// anything is sent, since a body that is streamed cannot be sent again.
func (c *remoteClient) authenticate(ctx context.Context) error {
	res, err := c.send(ctx, http.MethodGet, c.base+"/v2/", nil, nil, false)
	if err != nil {
		return err
	}
	drain(res)
	switch res.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return c.answer(ctx, res.Header.Get("WWW-Authenticate"))
	default:
		return fmt.Errorf("%s answered %d at /v2/; is it a container registry?", c.host, res.StatusCode)
	}
}

// answer meets a challenge of the registry.
func (c *remoteClient) answer(ctx context.Context, challenge string) error {
	scheme, params := parseChallenge(challenge)
	switch strings.ToLower(scheme) {
	case "basic":
		if c.username == "" {
			return fmt.Errorf("%s needs a username and password", c.host)
		}
		c.authorization = c.basic()
		return nil
	case "bearer":
		return c.fetchToken(ctx, params)
	default:
		return fmt.Errorf("%s asks for a login this server does not know: %q", c.host, challenge)
	}
}

// fetchToken gets a token for the repository from where the challenge says,
// with the credentials if there are any, anonymously if not.
func (c *remoteClient) fetchToken(ctx context.Context, params map[string]string) error {
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" || (realm.Scheme != "https" && realm.Scheme != "http") {
		return fmt.Errorf("%s sends to a token service that is not a URL: %q", c.host, params["realm"])
	}
	query := realm.Query()
	if service := params["service"]; service != "" {
		query.Set("service", service)
	}
	query.Set("scope", "repository:"+c.repository+":"+c.actions)
	realm.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	if c.username != "" {
		req.Header.Set("Authorization", c.basic())
	}
	res, err := c.do(req)
	if err != nil {
		return fmt.Errorf("the token service of %s: %w", c.host, err)
	}
	defer drain(res)
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		if c.username == "" {
			return fmt.Errorf("%s needs a username and password", c.host)
		}
		return fmt.Errorf("%s refused the username and password", c.host)
	case res.StatusCode != http.StatusOK:
		return fmt.Errorf("the token service of %s: %w", c.host, remoteFailure(res))
	}
	var answer struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&answer); err != nil {
		return fmt.Errorf("the token service of %s answered no token: %w", c.host, err)
	}
	token := answer.Token
	if token == "" {
		token = answer.AccessToken
	}
	if token == "" {
		return fmt.Errorf("the token service of %s answered no token", c.host)
	}
	c.authorization = "Bearer " + token
	return nil
}

// parseChallenge reads a WWW-Authenticate header: its scheme and the
// parameters after it, whose quoted values may hold commas.
func parseChallenge(header string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
	params := map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		key, after, found := strings.Cut(rest, "=")
		if !found {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		var value string
		if strings.HasPrefix(after, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(after) && after[i] != '"'; i++ {
				if after[i] == '\\' && i+1 < len(after) {
					i++
				}
				b.WriteByte(after[i])
			}
			value, rest = b.String(), after[min(i+1, len(after)):]
		} else {
			value, rest, _ = strings.Cut(after, ",")
			value = strings.TrimSpace(value)
			rest = "," + rest
		}
		params[key] = value
		rest = strings.TrimLeft(rest, ", ")
	}
	return scheme, params
}

// send makes one request with the authorization there is. A request that
// may be repeated, one without a body or with one held in memory, meets a
// challenge it is answered with once and goes again: a token runs out, and
// some registries only challenge on the repository.
func (c *remoteClient) send(ctx context.Context, method, target string, header http.Header, body []byte, retry bool) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			return nil, err
		}
		for key, values := range header {
			req.Header[key] = values
		}
		if c.authorization != "" {
			req.Header.Set("Authorization", c.authorization)
		}
		res, err := c.do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.host, err)
		}
		challenge := res.Header.Get("WWW-Authenticate")
		if res.StatusCode != http.StatusUnauthorized || !retry || attempt > 0 || challenge == "" {
			return res, nil
		}
		drain(res)
		if err := c.answer(ctx, challenge); err != nil {
			return nil, err
		}
	}
}

// repoURL is a path of the repository's API.
func (c *remoteClient) repoURL(rest string) string {
	return c.base + "/v2/" + c.repository + "/" + rest
}

// remoteManifest is a manifest as the other registry has it.
type remoteManifest struct {
	body      []byte
	mediaType string
	digest    digest.Digest
}

// getManifest fetches a manifest by tag or digest. One fetched by digest is
// checked against it, and so is one whose answer names its digest.
func (c *remoteClient) getManifest(ctx context.Context, ref string) (remoteManifest, error) {
	res, err := c.send(ctx, http.MethodGet, c.repoURL("manifests/"+ref),
		http.Header{"Accept": {manifestAccept}}, nil, true)
	if err != nil {
		return remoteManifest{}, err
	}
	defer drain(res)
	if res.StatusCode != http.StatusOK {
		return remoteManifest{}, c.failure(res, c.repository+":"+ref)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxManifestSize+1))
	if err != nil {
		return remoteManifest{}, fmt.Errorf("%s: the manifest could not be read: %w", c.host, err)
	}
	if len(body) > maxManifestSize {
		return remoteManifest{}, fmt.Errorf("%s: the manifest of %s is larger than 4 MiB", c.host, ref)
	}
	found := remoteManifest{body: body, digest: digest.SHA256.FromBytes(body)}
	if mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err == nil {
		found.mediaType = mediaType
	}
	want, byDigest := parseBlobDigest(ref)
	if !byDigest {
		want, byDigest = parseBlobDigest(res.Header.Get("Docker-Content-Digest"))
	}
	if byDigest {
		if actual := want.Algorithm().FromBytes(body); actual != want {
			return remoteManifest{}, fmt.Errorf("%s: the manifest of %s is not what its digest %s says",
				c.host, ref, want)
		}
		found.digest = want
	}
	return found, nil
}

// getBlob opens a blob. The registry may send the client elsewhere for it,
// to a bucket or a CDN, which is followed without the Authorization header.
func (c *remoteClient) getBlob(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	res, err := c.send(ctx, http.MethodGet, c.repoURL("blobs/"+d.String()), nil, nil, true)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		defer drain(res)
		return nil, c.failure(res, d.String())
	}
	return res.Body, nil
}

// blobExists reports whether the repository already has a blob, which a push
// then leaves out.
func (c *remoteClient) blobExists(ctx context.Context, d digest.Digest) (bool, error) {
	res, err := c.send(ctx, http.MethodHead, c.repoURL("blobs/"+d.String()), nil, nil, true)
	if err != nil {
		return false, err
	}
	drain(res)
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, c.failure(res, d.String())
	}
}

// manifestExists reports whether the repository has a manifest under a tag
// or a digest.
func (c *remoteClient) manifestExists(ctx context.Context, ref string) (bool, error) {
	res, err := c.send(ctx, http.MethodHead, c.repoURL("manifests/"+ref),
		http.Header{"Accept": {manifestAccept}}, nil, true)
	if err != nil {
		return false, err
	}
	drain(res)
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, c.failure(res, c.repository+":"+ref)
	}
}

// canPush proves that the login may push to the repository by opening an
// upload, which it then drops. Nothing less proves it: a token service hands
// out a token for less than was asked rather than refuse.
func (c *remoteClient) canPush(ctx context.Context) error {
	res, err := c.send(ctx, http.MethodPost, c.repoURL("blobs/uploads/"), nil, nil, true)
	if err != nil {
		return err
	}
	drain(res)
	if res.StatusCode != http.StatusAccepted {
		return c.failure(res, c.repository)
	}
	if location, err := uploadLocation(res); err == nil {
		// an upload left open runs out on its own, so a failure here is no loss
		if res, err := c.send(ctx, http.MethodDelete, location.String(), nil, nil, false); err == nil {
			drain(res)
		}
	}
	return nil
}

// pushBlob uploads a blob the way docker does: an upload is opened, the whole
// blob is streamed into it in one PATCH, and a PUT with the digest closes it.
func (c *remoteClient) pushBlob(ctx context.Context, d digest.Digest, size int64, body io.Reader) error {
	res, err := c.send(ctx, http.MethodPost, c.repoURL("blobs/uploads/"), nil, nil, true)
	if err != nil {
		return err
	}
	drain(res)
	if res.StatusCode != http.StatusAccepted {
		return c.failure(res, d.String())
	}
	location, err := uploadLocation(res)
	if err != nil {
		return err
	}

	if size == 0 {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, location.String(), body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.authorization != "" {
		req.Header.Set("Authorization", c.authorization)
	}
	res, err = c.do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", c.host, err)
	}
	drain(res)
	if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusNoContent {
		return c.failure(res, d.String())
	}
	if next, err := uploadLocation(res); err == nil {
		location = next
	}

	query := location.Query()
	query.Set("digest", d.String())
	location.RawQuery = query.Encode()
	res, err = c.send(ctx, http.MethodPut, location.String(),
		http.Header{"Content-Type": {"application/octet-stream"}}, nil, false)
	if err != nil {
		return err
	}
	drain(res)
	if res.StatusCode != http.StatusCreated {
		return c.failure(res, d.String())
	}
	return nil
}

// uploadLocation is where an upload goes on: the Location of the answer,
// relative to the request it answers.
func uploadLocation(res *http.Response) (*url.URL, error) {
	value := res.Header.Get("Location")
	if value == "" {
		return nil, errors.New("the registry opened an upload without saying where it is")
	}
	location, err := res.Request.URL.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("the registry named an upload that is not a URL: %q", value)
	}
	return location, nil
}

// putManifest stores a manifest under a tag or its digest.
func (c *remoteClient) putManifest(ctx context.Context, ref, mediaType string, body []byte) error {
	res, err := c.send(ctx, http.MethodPut, c.repoURL("manifests/"+ref),
		http.Header{"Content-Type": {mediaType}}, body, true)
	if err != nil {
		return err
	}
	drain(res)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return c.failure(res, c.repository+":"+ref)
	}
	return nil
}

// failure says what went wrong with a request about what, in the words of
// the registry where it has any.
func (c *remoteClient) failure(res *http.Response, what string) error {
	switch res.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		if c.username == "" {
			return fmt.Errorf("%s refused access to %s: it does not exist, or it needs a username and password (%w)",
				c.host, what, remoteFailure(res))
		}
		return fmt.Errorf("%s refused access to %s (%w)", c.host, what, remoteFailure(res))
	case http.StatusNotFound:
		return fmt.Errorf("%s has no %s (%w)", c.host, what, remoteFailure(res))
	}
	return fmt.Errorf("%s: %s: %w", c.host, what, remoteFailure(res))
}

// remoteFailure reads the errors of an answer as the specification writes
// them, or whatever else the body says.
func remoteFailure(res *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	var answer struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &answer) == nil && len(answer.Errors) > 0 {
		var parts []string
		for _, entry := range answer.Errors {
			part := entry.Code
			if entry.Message != "" {
				part += ": " + entry.Message
			}
			parts = append(parts, part)
		}
		return fmt.Errorf("%d %s", res.StatusCode, strings.Join(parts, "; "))
	}
	text := strings.TrimSpace(string(data))
	if len(text) > 200 || strings.HasPrefix(text, "<") {
		text = ""
	}
	if text == "" {
		text = http.StatusText(res.StatusCode)
	}
	return fmt.Errorf("%d %s", res.StatusCode, text)
}

// drain reads what is left of a body and closes it, so the connection can be
// used again.
func drain(res *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	_ = res.Body.Close()
}

package httpd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestParseRemoteReference(t *testing.T) {
	sum := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		in                           string
		scheme, host, api, repo, tag string
		digest                       string
	}{
		{"nginx", "https", "docker.io", "registry-1.docker.io", "library/nginx", "latest", ""},
		{"nginx:1.27", "https", "docker.io", "registry-1.docker.io", "library/nginx", "1.27", ""},
		{"bitnami/redis:7", "https", "docker.io", "registry-1.docker.io", "bitnami/redis", "7", ""},
		{"docker.io/library/alpine", "https", "docker.io", "registry-1.docker.io", "library/alpine", "latest", ""},
		{"index.docker.io/alpine:3", "https", "docker.io", "registry-1.docker.io", "library/alpine", "3", ""},
		{"ghcr.io/org/app:v1", "https", "ghcr.io", "ghcr.io", "org/app", "v1", ""},
		{"localhost:5000/app@" + sum, "https", "localhost:5000", "localhost:5000", "app", "", sum},
		{"localhost/app:1@" + sum, "https", "localhost", "localhost", "app", "1", sum},
		{"http://127.0.0.1:5000/team/app:2", "http", "127.0.0.1:5000", "127.0.0.1:5000", "team/app", "2", ""},
		{"  Registry.Example.com/a/b/c  ", "https", "registry.example.com", "registry.example.com", "a/b/c", "latest", ""},
	}
	for _, c := range cases {
		ref, err := parseRemoteReference(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if ref.scheme != c.scheme || ref.host != c.host || ref.api != c.api || ref.repository != c.repo ||
			ref.tag != c.tag || ref.digest.String() != c.digest {
			t.Errorf("%q = %+v", c.in, ref)
		}
	}
	for _, bad := range []string{"", "Nginx", "nginx:bad tag", "a b", "app@sha256:short", "ghcr.io/", "app:-x"} {
		if _, err := parseRemoteReference(bad); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, params := parseChallenge(`Bearer realm="https://auth.example/token",service="registry.example",scope="repository:a/b:pull,push"`)
	if scheme != "Bearer" || params["realm"] != "https://auth.example/token" ||
		params["service"] != "registry.example" || params["scope"] != "repository:a/b:pull,push" {
		t.Errorf("%s %v", scheme, params)
	}
	scheme, params = parseChallenge(`Basic realm=go-fs`)
	if scheme != "Basic" || params["realm"] != "go-fs" {
		t.Errorf("%s %v", scheme, params)
	}
}

func TestPlatformFilter(t *testing.T) {
	filter, err := parsePlatforms("linux/arm, linux/amd64 linux/arm64/v8")
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]bool{"linux/arm/v7": true, "linux/amd64": true, "linux/arm64": true,
		"linux/arm/v6": false, "windows/amd64:10.0.17763": false} {
		if filter.matches(key) != want {
			t.Errorf("matches(%q) = %v", key, !want)
		}
	}
	windows, _ := parsePlatforms("windows/amd64")
	if !windows.matches("windows/amd64:10.0.17763") {
		t.Error("a platform without an OS version does not match every version")
	}
	if _, err := parsePlatforms("linux"); err == nil {
		t.Error("a platform without an architecture was taken")
	}
}

// --- through the page --------------------------------------------------------

// transferRequest sends a request of the page's script: JSON, from the same
// site, with a session.
func transferRequest(t *testing.T, server *testServer, method, path string, session *http.Cookie, body any, headers ...string) (*http.Response, []byte) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, server.url(path), reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if session != nil {
		req.AddCookie(session)
	}
	res := do(t, req)
	var data bytes.Buffer
	_, _ = data.ReadFrom(res.Body)
	return res, data.Bytes()
}

// startTransfer starts a pull or a push and waits for it to end.
func startTransfer(t *testing.T, server *testServer, path string, session *http.Cookie, body any) registryJobJSON {
	t.Helper()
	res, data := transferRequest(t, server, http.MethodPost, path, session, body)
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("POST %s answered %d: %s", path, res.StatusCode, data)
	}
	var job registryJobJSON
	if err := json.Unmarshal(data, &job); err != nil {
		t.Fatal(err)
	}
	return waitForJob(t, server, job.ID, session)
}

func waitForJob(t *testing.T, server *testServer, id string, session *http.Cookie) registryJobJSON {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		res, data := transferRequest(t, server, http.MethodGet, "/?go-fs=registry-job&id="+id, session, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("the job answered %d: %s", res.StatusCode, data)
		}
		var job registryJobJSON
		if err := json.Unmarshal(data, &job); err != nil {
			t.Fatal(err)
		}
		if job.State != jobRunning {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("the job is still running: %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// tagDigest is what a tag of a server points to.
func tagDigest(t *testing.T, server *testServer, repo, tag string) digest.Digest {
	t.Helper()
	tags, err := server.settings().registry.readTags(repo)
	if err != nil {
		t.Fatal(err)
	}
	return tags[tag]
}

func TestRegistryPushesATagAndPullsItBack(t *testing.T) {
	source := newRegistryServer(t, nil)
	amd := source.pushImage(t, "team/app", "1.0", "linux/amd64", "a")
	arm := source.pushImage(t, "team/app", "1.0", "linux/arm64", "b")
	index := tagDigest(t, source, "team/app", "1.0")
	remote := newRegistryServer(t, func(cfg *httpConfig) { cfg.RegistryAnonymousRead = false })

	ci := login(t, source, "/", pusher, pusherPassword)
	job := startTransfer(t, source, "/?go-fs=registry-push&repository=team/app&tag=1.0", ci,
		map[string]string{"reference": remote.url("/mirror/team/app:1.0"), "username": pusher, "password": pusherPassword})
	if job.State != jobDone {
		t.Fatalf("the push ended %s: %s", job.State, job.Message)
	}
	if job.BlobsTotal != 4 || job.BlobsDone != 4 || job.BytesDone != job.BytesTotal {
		t.Errorf("progress of the push: %+v", job)
	}
	if got := tagDigest(t, remote, "mirror/team/app", "1.0"); got != index {
		t.Fatalf("the remote tag names %s, want %s", got, index)
	}
	if source.logs.find("registry image pushed") == nil {
		t.Error("the push was not recorded")
	}
	source.logs.mu.Lock()
	for _, record := range source.logs.records {
		if strings.Contains(fmt.Sprint(record), pusherPassword) {
			t.Errorf("a record holds the password: %v", record)
		}
	}
	source.logs.mu.Unlock()

	// pushing again sends nothing the remote has
	job = startTransfer(t, source, "/?go-fs=registry-push&repository=team/app&tag=1.0", ci,
		map[string]string{"reference": remote.url("/mirror/team/app:1.0"), "username": pusher, "password": pusherPassword})
	if job.State != jobDone {
		t.Fatalf("the second push ended %s: %s", job.State, job.Message)
	}

	// the remote wants a login, which a pull without one is told
	fresh := newRegistryServer(t, nil)
	ci = login(t, fresh, "/", pusher, pusherPassword)
	job = startTransfer(t, fresh, "/?go-fs=registry-pull", ci,
		map[string]string{"reference": remote.url("/mirror/team/app:1.0")})
	if job.State != jobFailed || !strings.Contains(job.Message, "username and password") {
		t.Errorf("a pull without the login ended %s: %s", job.State, job.Message)
	}
	job = startTransfer(t, fresh, "/?go-fs=registry-pull", ci,
		map[string]string{"reference": remote.url("/mirror/team/app:1.0"), "username": pusher, "password": "wrong"})
	if job.State != jobFailed || !strings.Contains(job.Message, "refused") {
		t.Errorf("a pull with a wrong password ended %s: %s", job.State, job.Message)
	}

	// one platform of it: an index of its own, and only that platform's blobs
	job = startTransfer(t, fresh, "/?go-fs=registry-pull", ci, map[string]string{
		"reference": remote.url("/mirror/team/app:1.0"), "platforms": "linux/arm64",
		"username": pusher, "password": pusherPassword})
	if job.State != jobDone {
		t.Fatalf("the pull ended %s: %s", job.State, job.Message)
	}
	got := tagDigest(t, fresh, "mirror/team/app", "1.0")
	if got == "" || got == index {
		t.Fatalf("the filtered pull is tagged %q", got)
	}
	_, doc := fresh.pullManifest(t, "mirror/team/app", "1.0")
	if len(doc.Manifests) != 1 || doc.Manifests[0].Digest != arm.digest {
		t.Errorf("the filtered index: %+v", doc.Manifests)
	}
	store := fresh.settings().registry
	if _, err := store.blobInfo(arm.layer); err != nil {
		t.Errorf("the arm64 layer is missing: %v", err)
	}
	if _, err := store.blobInfo(amd.layer); err == nil {
		t.Error("the amd64 layer was pulled as well")
	}

	// all of it: the very index, under the same tag
	job = startTransfer(t, fresh, "/?go-fs=registry-pull", ci, map[string]string{
		"reference": remote.url("/mirror/team/app:1.0"), "username": pusher, "password": pusherPassword})
	if job.State != jobDone {
		t.Fatalf("the pull ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, fresh, "mirror/team/app", "1.0"); got != index {
		t.Errorf("the pull is tagged %s, want %s", got, index)
	}
	res, _ := fresh.reg(t, http.MethodGet, "/v2/mirror/team/app/blobs/"+amd.layer.String(), nil)
	if res.StatusCode != http.StatusOK {
		t.Errorf("the pulled layer is served with %d", res.StatusCode)
	}

	// a platform the index does not have
	job = startTransfer(t, fresh, "/?go-fs=registry-pull", ci, map[string]string{
		"reference": remote.url("/mirror/team/app:1.0"), "platforms": "linux/s390x",
		"username": pusher, "password": pusherPassword})
	if job.State != jobFailed || !strings.Contains(job.Message, "linux/amd64, linux/arm64") {
		t.Errorf("a pull for a missing platform ended %s: %s", job.State, job.Message)
	}
}

func TestRegistryPullsASingleImageForItsPlatformOnly(t *testing.T) {
	remote := newRegistryServer(t, nil)
	remote.pushImage(t, "tool", "latest", "linux/arm/v7", "c")
	local := newRegistryServer(t, nil)
	ci := login(t, local, "/", pusher, pusherPassword)

	job := startTransfer(t, local, "/?go-fs=registry-pull", ci,
		map[string]string{"reference": remote.url("/tool"), "platforms": "linux/amd64"})
	if job.State != jobFailed || !strings.Contains(job.Message, "only for linux/arm/v7") {
		t.Errorf("the pull ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, local, "tool", "latest"); got != "" {
		t.Errorf("a refused pull tagged %s", got)
	}
	job = startTransfer(t, local, "/?go-fs=registry-pull", ci,
		map[string]string{"reference": remote.url("/tool"), "platforms": "linux/arm"})
	if job.State != jobDone || job.Message != "Pulled tool:latest for linux/arm/v7." {
		t.Errorf("the pull ended %s: %s", job.State, job.Message)
	}
}

// A registry that wants Basic on every request and sends the client to
// another host for its blobs, the way a registry in front of a bucket does.
func TestRegistryPullsWithBasicAndFollowsBlobsElsewhere(t *testing.T) {
	config := []byte(`{"os":"linux","architecture":"amd64","rootfs":{"type":"layers"}}`)
	layer := []byte("the layer")
	configDigest, layerDigest := digest.FromBytes(config), digest.FromBytes(layer)
	manifest, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageManifest,
		Config: &v1.Descriptor{MediaType: v1.MediaTypeImageConfig, Digest: configDigest, Size: int64(len(config))},
		Layers: []v1.Descriptor{{MediaType: v1.MediaTypeImageLayerGzip, Digest: layerDigest, Size: int64(len(layer))}}})

	leaked := false
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
		switch r.URL.Path {
		case "/" + configDigest.Encoded():
			_, _ = w.Write(config)
		case "/" + layerDigest.Encoded():
			_, _ = w.Write(layer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer bucket.Close()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("me:pw"))
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/v2/":
		case r.URL.Path == "/v2/some/app/manifests/v1":
			w.Header().Set("Content-Type", v1.MediaTypeImageManifest)
			_, _ = w.Write(manifest)
		case strings.HasPrefix(r.URL.Path, "/v2/some/app/blobs/"):
			d := digest.Digest(strings.TrimPrefix(r.URL.Path, "/v2/some/app/blobs/"))
			http.Redirect(w, r, bucket.URL+"/"+d.Encoded(), http.StatusTemporaryRedirect)
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()

	local := newRegistryServer(t, nil)
	ci := login(t, local, "/", pusher, pusherPassword)
	reference := registry.URL + "/some/app:v1"
	job := startTransfer(t, local, "/?go-fs=registry-pull", ci, map[string]string{"reference": reference})
	if job.State != jobFailed || !strings.Contains(job.Message, "username and password") {
		t.Errorf("the pull without a login ended %s: %s", job.State, job.Message)
	}
	job = startTransfer(t, local, "/?go-fs=registry-pull", ci,
		map[string]string{"reference": reference, "username": "me", "password": "pw"})
	if job.State != jobDone {
		t.Fatalf("the pull ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, local, "some/app", "v1"); got != digest.FromBytes(manifest) {
		t.Errorf("the tag names %s", got)
	}
	if leaked {
		t.Error("the credentials went along to the other host")
	}
}

func TestRegistryTransfersNeedARegistrySession(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = nil
		cfg.Users = append(cfg.Users, registryUser("other", "pw"))
	})
	server.pushImage(t, "tool", "latest", "linux/amd64", "a")
	pull := map[string]string{"reference": "localhost:1/tool"}

	if res, data := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-pull", nil, pull); res.StatusCode != http.StatusForbidden {
		t.Errorf("an anonymous pull answered %d: %s", res.StatusCode, data)
	}
	john := login(t, server, "/", "john", "doe")
	if res, _ := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-pull", john, pull); res.StatusCode != http.StatusForbidden {
		t.Errorf("a pull by an account without registry answered %d", res.StatusCode)
	}
	ci := login(t, server, "/", pusher, pusherPassword)
	res, _ := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-pull", ci, pull, "Origin", "https://evil.example")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-site pull answered %d", res.StatusCode)
	}
	res, data := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-pull", ci, map[string]string{"reference": "Bad Name"})
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("a bad reference answered %d: %s", res.StatusCode, data)
	}
	res, _ = transferRequest(t, server, http.MethodPost, "/?go-fs=registry-push&repository=tool&tag=nope", ci,
		map[string]string{"reference": "localhost:1/tool:latest"})
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("pushing a missing tag answered %d", res.StatusCode)
	}
	if res, _ := transferRequest(t, server, http.MethodGet, "/?go-fs=registry-pull", ci, nil); res.StatusCode != http.StatusMethodNotAllowed ||
		res.Header.Get("Allow") != "POST" {
		t.Errorf("GET of the pull endpoint answered %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}

	// a job is its owner's alone
	job := startTransfer(t, server, "/?go-fs=registry-push&repository=tool&tag=latest", ci,
		map[string]string{"reference": "http://127.0.0.1:1/tool:latest"})
	if job.State != jobFailed {
		t.Errorf("a push to nowhere ended %s", job.State)
	}
	other := login(t, server, "/", "other", "pw")
	if res, _ := transferRequest(t, server, http.MethodGet, "/?go-fs=registry-job&id="+job.ID, other, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("another account read the job: %d", res.StatusCode)
	}

	// the page offers the transfers to that session only
	_, anonymous := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", nil)
	_, signedIn := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", ci)
	for _, marker := range []string{`id="pull-image"`, `data-do="push"`, `id="remote-pull"`} {
		if strings.Contains(anonymous, marker) {
			t.Errorf("the anonymous page has %s", marker)
		}
		if !strings.Contains(signedIn, marker) {
			t.Errorf("the page of a registry session lacks %s", marker)
		}
	}
}

func TestRegistryJobCanBeStopped(t *testing.T) {
	// a registry that never answers the manifest
	hold := make(chan struct{})
	stuck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			return
		}
		select {
		case <-hold:
		case <-r.Context().Done():
		}
	}))
	defer stuck.Close()
	defer close(hold)

	server := newRegistryServer(t, nil)
	ci := login(t, server, "/", pusher, pusherPassword)
	res, data := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-pull", ci,
		map[string]string{"reference": stuck.URL + "/app:1"})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("the pull answered %d: %s", res.StatusCode, data)
	}
	var job registryJobJSON
	_ = json.Unmarshal(data, &job)
	res, _ = transferRequest(t, server, http.MethodDelete, "/?go-fs=registry-job&id="+job.ID, ci, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("stopping answered %d", res.StatusCode)
	}
	if ended := waitForJob(t, server, job.ID, ci); ended.State != jobCancelled {
		t.Errorf("the stopped job ended %s: %s", ended.State, ended.Message)
	}
}

// checkTransfer makes the check of a pull or a push.
func checkTransfer(t *testing.T, server *testServer, path string, session *http.Cookie, body any, into any) int {
	t.Helper()
	res, data := transferRequest(t, server, http.MethodPost, path, session, body)
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatalf("%s answered %s: %v", path, data, err)
		}
	} else if into, ok := into.(*string); ok {
		*into = string(data)
	}
	return res.StatusCode
}

func choiceKeys(choices []registryPlatformChoice) string {
	var keys []string
	for _, choice := range choices {
		keys = append(keys, choice.Platform)
	}
	return strings.Join(keys, " ")
}

func TestRegistryChecksAPull(t *testing.T) {
	remote := newRegistryServer(t, func(cfg *httpConfig) { cfg.RegistryAnonymousRead = false })
	remote.pushImage(t, "team/app", "1.0", "linux/arm64", "b")
	remote.pushImage(t, "team/app", "1.0", "linux/amd64", "a")
	remote.pushImage(t, "tool", "latest", "linux/arm/v7", "c")
	index := tagDigest(t, remote, "team/app", "1.0")
	local := newRegistryServer(t, nil)
	ci := login(t, local, "/", pusher, pusherPassword)
	reference := remote.url("/team/app:1.0")

	var found registryPullCheckJSON
	status := checkTransfer(t, local, "/?go-fs=registry-pull-check", ci,
		map[string]string{"reference": reference, "username": pusher, "password": pusherPassword}, &found)
	if status != http.StatusOK {
		t.Fatalf("the check answered %d", status)
	}
	if got := choiceKeys(found.Platforms); got != "linux/amd64 linux/arm64" {
		t.Errorf("the check found %s", got)
	}
	if found.Digest != index.String() || found.Local != "team/app:1.0" {
		t.Errorf("the check found %+v, want the digest %s", found, index)
	}

	// a single image says its platform through its configuration
	var single registryPullCheckJSON
	status = checkTransfer(t, local, "/?go-fs=registry-pull-check", ci, map[string]string{
		"reference": remote.url("/tool"), "username": pusher, "password": pusherPassword}, &single)
	if status != http.StatusOK || choiceKeys(single.Platforms) != "linux/arm/v7" {
		t.Errorf("the check of a single image answered %d: %+v", status, single)
	}

	var message string
	status = checkTransfer(t, local, "/?go-fs=registry-pull-check", ci,
		map[string]string{"reference": reference, "username": pusher, "password": "wrong"}, &message)
	if status != http.StatusBadGateway || !strings.Contains(message, "refused") {
		t.Errorf("a wrong password answered %d: %s", status, message)
	}
	status = checkTransfer(t, local, "/?go-fs=registry-pull-check", ci,
		map[string]string{"reference": remote.url("/team/app@" + index.String())}, &message)
	if status != http.StatusBadRequest {
		t.Errorf("a reference without a tag answered %d: %s", status, message)
	}
	status = checkTransfer(t, local, "/?go-fs=registry-pull-check", nil,
		map[string]string{"reference": reference}, &message)
	if status != http.StatusForbidden {
		t.Errorf("a check without a session answered %d", status)
	}

	// the pull fetches what was checked
	job := startTransfer(t, local, "/?go-fs=registry-pull", ci, map[string]string{"reference": reference,
		"digest": found.Digest, "username": pusher, "password": pusherPassword})
	if job.State != jobDone {
		t.Fatalf("the pull ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, local, "team/app", "1.0"); got != index {
		t.Errorf("the pull is tagged %s, want %s", got, index)
	}
}

func TestRegistryChecksAPush(t *testing.T) {
	source := newRegistryServer(t, nil)
	source.pushImage(t, "team/app", "1.0", "linux/arm64", "b")
	source.pushImage(t, "team/app", "1.0", "linux/amd64", "a")
	remote := newRegistryServer(t, func(cfg *httpConfig) { cfg.RegistryAnonymousRead = false })
	ci := login(t, source, "/", pusher, pusherPassword)
	path := "/?go-fs=registry-push-check&repository=team/app&tag=1.0"
	body := map[string]string{"reference": remote.url("/mirror/app:2.0"), "username": pusher, "password": pusherPassword}

	var found registryPushCheckJSON
	if status := checkTransfer(t, source, path, ci, body, &found); status != http.StatusOK {
		t.Fatalf("the check answered %d", status)
	}
	if found.Exists || choiceKeys(found.Platforms) != "linux/amd64 linux/arm64" ||
		!strings.HasSuffix(found.Reference, "/mirror/app:2.0") {
		t.Errorf("the check found %+v", found)
	}
	// the check left no upload behind it
	if entries, _ := os.ReadDir(remote.settings().registry.uploadsPath()); len(entries) > 0 {
		t.Errorf("the check left %d uploads open", len(entries))
	}

	// pushed under another name and tag, which the check then finds there
	job := startTransfer(t, source, "/?go-fs=registry-push&repository=team/app&tag=1.0", ci, body)
	if job.State != jobDone {
		t.Fatalf("the push ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, remote, "mirror/app", "2.0"); got != tagDigest(t, source, "team/app", "1.0") {
		t.Errorf("the remote tag names %s", got)
	}
	found = registryPushCheckJSON{}
	if status := checkTransfer(t, source, path, ci, body, &found); status != http.StatusOK || !found.Exists {
		t.Errorf("the check after the push answered %d: %+v", status, found)
	}

	var message string
	for _, login := range []map[string]string{{"username": pusher, "password": "wrong"}, {}} {
		login["reference"] = body["reference"]
		if status := checkTransfer(t, source, path, ci, login, &message); status != http.StatusBadGateway {
			t.Errorf("the check with %v answered %d: %s", login, status, message)
		}
	}
	digested := map[string]string{"reference": remote.url("/mirror/app@sha256:" + strings.Repeat("a", 64))}
	if status := checkTransfer(t, source, path, ci, digested, &message); status != http.StatusBadRequest {
		t.Errorf("a reference with a digest answered %d: %s", status, message)
	}
}

func TestRegistryPushesSomePlatforms(t *testing.T) {
	source := newRegistryServer(t, nil)
	amd := source.pushImage(t, "team/app", "1.0", "linux/amd64", "a")
	arm := source.pushImage(t, "team/app", "1.0", "linux/arm64", "b")
	index := tagDigest(t, source, "team/app", "1.0")
	remote := newRegistryServer(t, nil)
	ci := login(t, source, "/", pusher, pusherPassword)
	push := "/?go-fs=registry-push&repository=team/app&tag=1.0"

	job := startTransfer(t, source, push, ci, map[string]string{"reference": remote.url("/app:arm"),
		"platforms": "linux/arm64", "username": pusher, "password": pusherPassword})
	if job.State != jobDone || !strings.HasSuffix(job.Message, "for linux/arm64.") {
		t.Fatalf("the push ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, remote, "app", "arm"); got == "" || got == index {
		t.Errorf("the filtered push is tagged %q", got)
	}
	_, doc := remote.pullManifest(t, "app", "arm")
	if len(doc.Manifests) != 1 || doc.Manifests[0].Digest != arm.digest {
		t.Errorf("the pushed index: %+v", doc.Manifests)
	}
	store := remote.settings().registry
	if _, err := store.blobInfo(amd.layer); err == nil {
		t.Error("the amd64 layer was pushed as well")
	}

	job = startTransfer(t, source, push, ci, map[string]string{"reference": remote.url("/app:all"),
		"username": pusher, "password": pusherPassword})
	if job.State != jobDone {
		t.Fatalf("the push ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, remote, "app", "all"); got != index {
		t.Errorf("the whole push is tagged %s, want %s", got, index)
	}

	job = startTransfer(t, source, push, ci, map[string]string{"reference": remote.url("/app:none"),
		"platforms": "linux/s390x", "username": pusher, "password": pusherPassword})
	if job.State != jobFailed || !strings.Contains(job.Message, "linux/amd64, linux/arm64") {
		t.Errorf("a push for a missing platform ended %s: %s", job.State, job.Message)
	}
}

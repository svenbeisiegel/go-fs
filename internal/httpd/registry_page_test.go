package httpd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// pageRequest asks for a path the way the page's browser does: as a browser,
// from the same site, with the session if there is one.
func pageRequest(t *testing.T, server *testServer, method, path string, session *http.Cookie, headers ...string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, server.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if session != nil {
		req.AddCookie(session)
	}
	res := do(t, req)
	return res, bodyOf(t, res)
}

// pushMultiArch pushes one tag for two platforms, which the registry merges
// into an index, and returns the digest the tag points to.
func pushMultiArch(t *testing.T, server *testServer, repo, tag string) digest.Digest {
	t.Helper()
	server.pushImage(t, repo, tag, "linux/amd64", "a")
	server.pushImage(t, repo, tag, "linux/arm64", "b")
	res, _ := server.pullManifest(t, repo, tag)
	return digest.Digest(res.Header.Get("Docker-Content-Digest"))
}

func TestTheListingOffersTheRegistry(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	body := bodyOf(t, browserGet(t, server, "/"))
	index := strings.Index(body, "go-fs=registry")
	if index < 0 {
		t.Fatal("the listing has no Registry button")
	}
	tag := body[strings.LastIndex(body[:index], "<"):index]
	if strings.Contains(tag, "needs-js") {
		t.Errorf("the Registry button is hidden until the script runs: %s", tag)
	}

	plain := newServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	if strings.Contains(bodyOf(t, browserGet(t, plain, "/")), "go-fs=registry") {
		t.Error("the listing offers a registry that is off")
	}
	if res := browserGet(t, plain, "/?go-fs=registry"); res.StatusCode != http.StatusNotFound {
		t.Errorf("the registry page of a server without one answered %d", res.StatusCode)
	}
}

func TestRegistryListShowsEveryTagWithItsPlatforms(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	pushMultiArch(t, server, "team/app", "1.0")
	server.pushImage(t, "tool", "latest", "linux/arm/v7", "c")

	res, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	for _, want := range []string{
		`data-repository="team/app" data-tag="1.0"`,
		`>team/<wbr>app<wbr>:1.0<`,
		`<span class="badge" title="linux/amd64">amd64</span>`,
		`<span class="badge" title="linux/arm64">arm64</span>`,
		`>tool<wbr>:latest<`,
		`<span class="badge" title="linux/arm/v7">arm/v7</span>`,
		`<summary class="plain"><svg class="ic"><use href="#i-box"/></svg>Registry<`,
		`<a href="/"><svg class="ic"><use href="#i-folder"/></svg>Files</a>`,
		`aria-label="Options for team/app:1.0"`,
		`data-pull="docker pull 127.0.0.1:`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
	// the page the menu is on is not one of its items
	if strings.Contains(body, `</svg>Registry</a>`) {
		t.Error("the registry page links to itself")
	}
	if got := strings.Count(body, "data-tag="); got != 2 {
		t.Errorf("%d tag rows, want 2", got)
	}
	// anonymous, and so read-only
	if strings.Contains(body, `data-do="delete"`) {
		t.Error("an anonymous visitor is offered to delete tags")
	}
	nonce := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(nonce, "script-src 'nonce-") {
		t.Errorf("policy = %q", nonce)
	}
}

func TestRegistryListShowsAFewPlatforms(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	for i, platform := range []string{"linux/386", "linux/ppc64le", "linux/arm64", "linux/s390x", "linux/amd64"} {
		server.pushImage(t, "app", "1.0", platform, string(rune('a'+i)))
	}

	res, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	want := `<span class="badges">` +
		`<span class="badge" title="linux/amd64">amd64</span>` +
		`<span class="badge" title="linux/arm64">arm64</span>` +
		`<span class="badge more" title="linux/386, linux/ppc64le, linux/s390x">…more</span></span>`
	if !strings.Contains(body, want) {
		t.Errorf("the page lacks %s", want)
	}

	res, page := pageRequest(t, server, http.MethodGet, "/?go-fs=registry-image&repository=app&tag=1.0", nil,
		"Accept", "application/json")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, page)
	}
	var image registryImageJSON
	if err := json.Unmarshal([]byte(page), &image); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, platform := range image.Platforms {
		order = append(order, platform.Platform)
	}
	if got := strings.Join(order, " "); got != "linux/amd64 linux/arm64 linux/386 linux/ppc64le linux/s390x" {
		t.Errorf("the details list the platforms as %s", got)
	}
}

func TestRegistryLeavesOutTheAttestations(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	img := server.buildImage(t, "app", "linux/amd64", "a", false)
	res, body := server.pushManifest(t, "app", img.digest.String(), img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusCreated)
	attestation := server.buildImage(t, "app", "unknown/unknown", "att", false)
	res, body = server.pushManifest(t, "app", attestation.digest.String(), attestation.mediaType, attestation.manifest)
	expectStatus(t, res, body, http.StatusCreated)
	index, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{
			{MediaType: img.mediaType, Digest: img.digest, Size: int64(len(img.manifest)),
				Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
			{MediaType: attestation.mediaType, Digest: attestation.digest, Size: int64(len(attestation.manifest)),
				Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"},
				Annotations: map[string]string{annotationReferenceType: "attestation-manifest",
					annotationReferenceDigest: img.digest.String()}},
		}})
	res, body = server.pushManifest(t, "app", "1.0", v1.MediaTypeImageIndex, index)
	expectStatus(t, res, body, http.StatusCreated)

	_, page := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", nil)
	if !strings.Contains(page, ">amd64<") {
		t.Error("the image's platform is not shown")
	}
	if strings.Contains(page, "unknown") {
		t.Error("the attestation is shown as a platform")
	}
}

func TestRegistryFolderView(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	pushMultiArch(t, server, "team/app", "1.0")
	server.pushImage(t, "team/app", "2.0", "linux/amd64", "c")
	server.pushImage(t, "tool", "latest", "linux/amd64", "d")

	_, top := pageRequest(t, server, http.MethodGet, "/?go-fs=registry&view=tree", nil)
	for _, want := range []string{
		`href="/?go-fs=registry&amp;path=team&amp;view=tree">team<`,
		`>1 repository<`,
		`href="/?go-fs=registry&amp;path=tool&amp;view=tree">tool<`,
		`>1 tag<`,
		`aria-current="page"><svg class="ic"><use href="#i-folder"/></svg>Folders`,
	} {
		if !strings.Contains(top, want) {
			t.Errorf("the top of the folder view lacks %s", want)
		}
	}
	if strings.Contains(top, "data-tag=") {
		t.Error("the top of the folder view lists tags")
	}

	_, team := pageRequest(t, server, http.MethodGet, "/?go-fs=registry&view=tree&path=team", nil)
	if !strings.Contains(team, `path=team%2Fapp&amp;view=tree">app<`) || !strings.Contains(team, ">2 tags<") {
		t.Errorf("the namespace does not show its repository: %s", team)
	}

	_, app := pageRequest(t, server, http.MethodGet, "/?go-fs=registry&view=tree&path=team/app", nil)
	for _, want := range []string{`data-tag="1.0"`, `data-tag="2.0"`, `>1.0<`, `>arm64<`,
		`<span class="here">app</span>`} {
		if !strings.Contains(app, want) {
			t.Errorf("the repository lacks %s", want)
		}
	}
	if strings.Contains(app, `>team/<wbr>app<wbr>:1.0<`) {
		t.Error("the folder view names a tag in full inside its repository")
	}

	res, _ := pageRequest(t, server, http.MethodGet, "/?go-fs=registry&view=tree&path=nothing", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("a path that is not in the registry answered %d", res.StatusCode)
	}
}

func TestRegistrySortsByPushTime(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	server.pushImage(t, "a", "1", "linux/amd64", "a")
	ageRegistry(t, server)
	server.pushImage(t, "b", "1", "linux/amd64", "b")

	_, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry&sort=date&dir=desc", nil)
	if strings.Index(body, ">b<wbr>:1<") > strings.Index(body, ">a<wbr>:1<") {
		t.Error("the tag pushed last is not first")
	}
	_, body = pageRequest(t, server, http.MethodGet, "/?go-fs=registry", nil)
	if strings.Index(body, ">a<wbr>:1<") > strings.Index(body, ">b<wbr>:1<") {
		t.Error("the default order is not by name")
	}
}

func TestRegistryPageTakesARegistrySessionWithoutAnonymousRead(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) {
		cfg.PathsRequireAuth = []string{"^/private/.*"}
		cfg.RegistryAnonymousRead = false
	})
	server.pushImage(t, "app", "1.0", "linux/amd64", "a")
	server.write(t, "private/secret.txt", "files")

	// a browser is sent to the login, which comes back here
	res, _ := pageRequest(t, server, http.MethodGet, "/?go-fs=registry&view=tree", nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("an anonymous visitor got %d, want the login", res.StatusCode)
	}
	location, _ := url.Parse(res.Header.Get("Location"))
	if location.Query().Get(sessionParam) != actionLogin || !returnsToRegistry(location) {
		t.Fatalf("sent to %s", location)
	}
	res, body := pageRequest(t, server, http.MethodGet, location.String(), nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "Container registry") {
		t.Errorf("the login page: %d", res.StatusCode)
	}

	// the registry-only account logs in, and is back on the page it asked for
	form := url.Values{"username": {pusher}, "password": {pusherPassword}}
	req, _ := http.NewRequest(http.MethodPost, server.url(location.String()), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res = do(t, req)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login answered %d", res.StatusCode)
	}
	back, _ := url.Parse(res.Header.Get("Location"))
	if back.Query().Get(sessionParam) != actionRegistry || back.Query().Get("view") != "tree" ||
		back.Query().Has(returnParam) {
		t.Errorf("after the login the browser is sent to %s", back)
	}
	session := cookieNamed(res, sessionCookie)
	if session == nil {
		t.Fatal("no session")
	}
	res, body = pageRequest(t, server, http.MethodGet, back.String(), session)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "Log out ci<") ||
		!strings.Contains(body, `data-do="delete"`) {
		t.Errorf("the session of the registry account: %d", res.StatusCode)
	}
	// its logout comes back here too
	if !strings.Contains(body, "go-fs-then=registry") {
		t.Error("the logout does not return to the registry")
	}

	// that session is still nobody to the files, and not dropped by them
	res, _ = pageRequest(t, server, http.MethodGet, "/private/secret.txt", session)
	if res.StatusCode == http.StatusOK {
		t.Error("a registry-only session read a protected file")
	}
	if cookie := cookieNamed(res, sessionCookie); res.Header.Get("Set-Cookie") != "" && cookie == nil {
		t.Error("the files signed the registry account out")
	}
	if _, listing := pageRequest(t, server, http.MethodGet, "/", session); !strings.Contains(listing, "Log out ci<") {
		t.Error("the listing does not say the registry account is signed in")
	}

	// an http account without registry is asked to log in as someone else
	john := login(t, server, "/", "john", "doe")
	res, body = pageRequest(t, server, http.MethodGet, "/?go-fs=registry", john)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "cannot use the registry") {
		t.Errorf("john got %d: %s", res.StatusCode, body)
	}
	if _, listing := pageRequest(t, server, http.MethodGet, "/", john); strings.Contains(listing, "go-fs=registry") {
		t.Error("john is offered a registry he may not see")
	}

	// the details are refused plainly to a fetch without a session
	res, _ = get(t, server, "/?go-fs=registry-image&repository=app&tag=1.0")
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("an anonymous fetch of the details got %d", res.StatusCode)
	}
}

func TestRegistryImageDetails(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	index := pushMultiArch(t, server, "team/app", "1.0")
	res, body := server.reg(t, http.MethodPut, "/v2/team/app/manifests/stable",
		manifestOf(t, server, "team/app", index), asPusher, withHeader("Content-Type", v1.MediaTypeImageIndex))
	expectStatus(t, res, body, http.StatusCreated)

	res, page := pageRequest(t, server, http.MethodGet, "/?go-fs=registry-image&repository=team/app&tag=1.0", nil,
		"Accept", "application/json")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, page)
	}
	var image registryImageJSON
	if err := json.Unmarshal([]byte(page), &image); err != nil {
		t.Fatal(err)
	}
	if image.Digest != index.String() || image.MediaType != v1.MediaTypeImageIndex {
		t.Errorf("image = %+v", image)
	}
	if image.Pushed == "" || image.Size <= 0 || !strings.HasSuffix(image.Pull, "/team/app:1.0") {
		t.Errorf("image = %+v", image)
	}
	if len(image.Tags) != 1 || image.Tags[0] != "stable" {
		t.Errorf("also tagged %v, want stable", image.Tags)
	}
	if len(image.Platforms) != 2 {
		t.Fatalf("platforms = %+v", image.Platforms)
	}
	var total int64
	for _, platform := range image.Platforms {
		if platform.Config == "" || len(platform.Layers) != 1 || platform.Size <= 0 {
			t.Errorf("platform = %+v", platform)
		}
		total += platform.Size
	}
	if image.Size != total {
		t.Errorf("size %d, want the sum of the platforms %d", image.Size, total)
	}

	res, _ = pageRequest(t, server, http.MethodGet, "/?go-fs=registry-image&repository=team/app&tag=nope", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("a tag that is not there answered %d", res.StatusCode)
	}
}

// manifestOf reads a manifest back out of the store.
func manifestOf(t *testing.T, server *testServer, repo string, d digest.Digest) []byte {
	t.Helper()
	res, body := server.reg(t, http.MethodGet, "/v2/"+repo+"/manifests/"+d.String(), nil)
	expectStatus(t, res, body, http.StatusOK)
	return body
}

func TestRegistryPageDeletesATag(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	index := pushMultiArch(t, server, "team/app", "1.0")
	server.pushImage(t, "team/app", "2.0", "linux/amd64", "c")
	path := "/?go-fs=registry&repository=team/app&tag=1.0"

	if res, _ := pageRequest(t, server, http.MethodDelete, path, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("an anonymous delete answered %d", res.StatusCode)
	}
	john := login(t, server, "/", "john", "doe")
	if res, _ := pageRequest(t, server, http.MethodDelete, path, john); res.StatusCode != http.StatusForbidden {
		t.Errorf("a delete by an account without registry answered %d", res.StatusCode)
	}
	ci := login(t, server, "/", pusher, pusherPassword)
	res, _ := pageRequest(t, server, http.MethodDelete, path, ci, "Origin", "https://evil.example")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-site delete answered %d", res.StatusCode)
	}
	res, body := pageRequest(t, server, http.MethodDelete, path, ci, "Origin", server.url(""))
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("the delete answered %d: %s", res.StatusCode, body)
	}

	res, data := server.reg(t, http.MethodGet, "/v2/team/app/tags/list", nil)
	expectStatus(t, res, data, http.StatusOK)
	if strings.Contains(string(data), `"1.0"`) || !strings.Contains(string(data), `"2.0"`) {
		t.Errorf("tags after the delete: %s", data)
	}
	// the index the registry merged for the tag goes with it
	if _, err := server.settings().registry.readRevision("team/app", index); !errors.Is(err, errRegistryNotFound) {
		t.Errorf("the merged index is still held: %v", err)
	}
	if res, _ := pageRequest(t, server, http.MethodDelete, path, ci); res.StatusCode != http.StatusNotFound {
		t.Errorf("deleting the tag again answered %d", res.StatusCode)
	}
}

func TestRegistryPageCleansUpNow(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	img := server.pushImage(t, "app", "latest", "linux/amd64", "1")
	content := []byte("pushed an hour ago, never referenced")
	orphan := server.pushBlob(t, "app", content)
	store := server.settings().registry
	old := time.Now().Add(-time.Hour)
	for _, path := range []string{store.blobPath(orphan), store.layerPath("app", orphan)} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	fresh := server.pushBlob(t, "app", []byte("pushed a moment ago"))
	path := "/?go-fs=registry-cleanup"

	if _, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", nil); strings.Contains(body, `id="clean-up"`) {
		t.Error("an anonymous visitor is offered the cleanup")
	}
	if res, _ := pageRequest(t, server, http.MethodPost, path, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("an anonymous cleanup answered %d", res.StatusCode)
	}
	john := login(t, server, "/", "john", "doe")
	if res, _ := pageRequest(t, server, http.MethodPost, path, john); res.StatusCode != http.StatusForbidden {
		t.Errorf("a cleanup by an account without registry answered %d", res.StatusCode)
	}
	ci := login(t, server, "/", pusher, pusherPassword)
	if _, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", ci); !strings.Contains(body, `id="clean-up"`) {
		t.Error("the registry account is not offered the cleanup")
	}
	res, _ := pageRequest(t, server, http.MethodPost, path, ci, "Origin", "https://evil.example")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-site cleanup answered %d", res.StatusCode)
	}
	if !server.blobStored(orphan) {
		t.Fatal("the orphan went before the cleanup was run")
	}

	res, body := pageRequest(t, server, http.MethodPost, path, ci, "Origin", server.url(""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the cleanup answered %d: %s", res.StatusCode, body)
	}
	var done registryCleanupJSON
	if err := json.Unmarshal([]byte(body), &done); err != nil {
		t.Fatal(err)
	}
	if done.Blobs != 1 || done.Bytes != int64(len(content)) {
		t.Errorf("the cleanup reported %+v", done)
	}
	if server.blobStored(orphan) {
		t.Error("the unreferenced blob was kept")
	}
	for name, d := range map[string]digest.Digest{"manifest": img.digest, "config": img.config,
		"layer": img.layer, "fresh blob": fresh} {
		if !server.blobStored(d) {
			t.Errorf("the %s was collected", name)
		}
	}
	server.pullManifest(t, "app", "latest")
	if server.logs.find("registry cleanup started from the page") == nil {
		t.Error("the cleanup was not recorded")
	}

	// run again, there is nothing left
	_, body = pageRequest(t, server, http.MethodPost, path, ci, "Origin", server.url(""))
	if err := json.Unmarshal([]byte(body), &done); err != nil || done.Blobs != 0 {
		t.Errorf("a second cleanup reported %s", body)
	}
}

func TestRegistryScriptCanBeInlined(t *testing.T) {
	if strings.Contains(strings.ToLower(string(registryScript)), "</script") {
		t.Error("registry.js closes the script element it is inlined into")
	}
}

func TestCleanURLReturnsToTheRegistry(t *testing.T) {
	u, _ := url.Parse("/team/?go-fs=registry&view=tree&path=team")
	login, _ := url.Parse(loginURL(u))
	if login.Query().Get(sessionParam) != actionLogin || !returnsToRegistry(login) {
		t.Fatalf("login URL %s", login)
	}
	if got := cleanURL(login); got != "/team/?go-fs=registry&path=team&view=tree" {
		t.Errorf("cleanURL = %s", got)
	}
	plain, _ := url.Parse("/team/?go-fs=login&sort=name")
	if got := cleanURL(plain); got != "/team/?sort=name" {
		t.Errorf("cleanURL = %s", got)
	}
}

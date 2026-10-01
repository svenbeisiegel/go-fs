package httpd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// importServer is a registry with an account that may read every file as
// well as push, beside the one that may only push.
func importServer(t *testing.T, tune func(*httpConfig)) *testServer {
	t.Helper()
	return newRegistryServer(t, func(cfg *httpConfig) {
		both := fullUser("both", "pw")
		both.Registry = true
		cfg.Users = append(cfg.Users, both)
		if tune != nil {
			tune(cfg)
		}
	})
}

// appArchive is an OCI layout with one image, named docker.io/library/app:1.
func appArchive(t *testing.T) ([]byte, ociImage) {
	t.Helper()
	img := newOCIImage(t, "linux/amd64", "app")
	data := tarOf(t, layoutEntries([]v1.Descriptor{
		named(img.desc, annotationContainerdName, "docker.io/library/app:1")}, img.blobs)...)
	return data, img
}

// sendChunk puts a chunk of an upload the way the page's script does.
func sendChunk(t *testing.T, server *testServer, session *http.Cookie, id string, data []byte, start, total int64, contentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, server.url("/?go-fs=registry-import-upload&id="+id), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, start+int64(len(data))-1, total))
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(session)
	res := do(t, req)
	_ = res.Body.Close()
	return res
}

// uploadArchive uploads an archive in chunks of chunk bytes and returns the
// upload's id.
func uploadArchive(t *testing.T, server *testServer, session *http.Cookie, name string, data []byte, chunk int) string {
	t.Helper()
	res, body := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-import-upload", session,
		map[string]any{"name": name, "size": len(data)})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("starting the upload answered %d: %s", res.StatusCode, body)
	}
	var upload importUploadJSON
	if err := json.Unmarshal(body, &upload); err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(data); start += chunk {
		end := min(start+chunk, len(data))
		want := http.StatusOK
		if end == len(data) {
			want = http.StatusCreated
		}
		if res := sendChunk(t, server, session, upload.ID, data[start:end], int64(start), int64(len(data)),
			"application/octet-stream"); res.StatusCode != want {
			t.Fatalf("the chunk at %d answered %d, want %d", start, res.StatusCode, want)
		}
	}
	return upload.ID
}

// startImport starts reading an archive and waits until the import is ready.
func startImport(t *testing.T, server *testServer, path string, session *http.Cookie, body any) registryJobJSON {
	t.Helper()
	job := startTransfer(t, server, path, session, body)
	if job.State != jobReady {
		t.Fatalf("the import is %s: %s", job.State, job.Message)
	}
	return job
}

// waitForImportEnd waits for an import to end, past waiting for an answer.
func waitForImportEnd(t *testing.T, server *testServer, id string, session *http.Cookie) registryJobJSON {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		job := waitForJob(t, server, id, session)
		if job.State != jobReady {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("the import is still waiting: %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// confirmImport answers an import.
func confirmImport(t *testing.T, server *testServer, session *http.Cookie, id string, images ...map[string]any) (*http.Response, []byte) {
	t.Helper()
	return transferRequest(t, server, http.MethodPost, "/?go-fs=registry-import-confirm&id="+id, session,
		map[string]any{"images": images})
}

// importLeftovers are the folders imports left under _uploads.
func importLeftovers(t *testing.T, server *testServer) []string {
	t.Helper()
	entries, _ := os.ReadDir(server.settings().registry.uploadsPath())
	var left []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "import-") {
			left = append(left, entry.Name())
		}
	}
	return left
}

func TestRegistryImportsAnUploadedArchive(t *testing.T) {
	server := importServer(t, func(cfg *httpConfig) { cfg.MaxChunkSize = 1000 })
	data, img := appArchive(t)
	ci := login(t, server, "/", pusher, pusherPassword)

	// a chunk that does not continue the upload is told where to start
	res, body := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-import-upload", ci,
		map[string]any{"name": "app.tar", "size": len(data)})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("starting the upload answered %d: %s", res.StatusCode, body)
	}
	var upload importUploadJSON
	_ = json.Unmarshal(body, &upload)
	if upload.ChunkSize != 1000 {
		t.Errorf("chunk size %d", upload.ChunkSize)
	}
	if res := sendChunk(t, server, ci, upload.ID, data[1000:2000], 1000, int64(len(data)), "application/octet-stream"); res.StatusCode != http.StatusRequestedRangeNotSatisfiable ||
		res.Header.Get("Content-Range") != "bytes */0" {
		t.Errorf("an early chunk answered %d %q", res.StatusCode, res.Header.Get("Content-Range"))
	}
	if res := sendChunk(t, server, ci, upload.ID, data[:2000], 0, int64(len(data)), ""); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("a chunk over the size answered %d", res.StatusCode)
	}
	if res := sendChunk(t, server, ci, upload.ID, data[:1000], 0, int64(len(data)), "text/plain"); res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("a chunk of text answered %d", res.StatusCode)
	}
	// curl -T sends no Content-Type at all
	for start := 0; start < len(data); start += 1000 {
		end := min(start+1000, len(data))
		res := sendChunk(t, server, ci, upload.ID, data[start:end], int64(start), int64(len(data)), "")
		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
			t.Fatalf("the chunk at %d answered %d", start, res.StatusCode)
		}
	}
	// someone else's upload is not there to them
	both := login(t, server, "/", "both", "pw")
	if res, _ := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-import", both,
		map[string]string{"upload": upload.ID}); res.StatusCode != http.StatusNotFound {
		t.Errorf("another account's upload answered %d", res.StatusCode)
	}

	job := startImport(t, server, "/?go-fs=registry-import", ci, map[string]string{"upload": upload.ID})
	if len(job.Images) != 1 || job.Phase != importReading {
		t.Fatalf("the import offers %+v in phase %s", job.Images, job.Phase)
	}
	offered := job.Images[0]
	if offered.Digest != img.desc.Digest.String() || len(offered.Targets) != 1 ||
		offered.Targets[0].Target != "library/app:1" || offered.Targets[0].Exists {
		t.Errorf("the image is offered as %+v", offered)
	}
	if res, body := confirmImport(t, server, both, job.ID, map[string]any{"index": 0, "targets": []string{"x:1"}}); res.StatusCode != http.StatusNotFound {
		t.Errorf("another account's import answered %d: %s", res.StatusCode, body)
	}
	res, body = confirmImport(t, server, ci, job.ID, map[string]any{"index": 0, "targets": []string{"team/renamed:v1"}})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("confirming answered %d: %s", res.StatusCode, body)
	}
	job = waitForJob(t, server, job.ID, ci)
	if job.State != jobDone || !strings.Contains(job.Message, "team/renamed:v1 (linux/amd64)") {
		t.Fatalf("the import ended %s: %s", job.State, job.Message)
	}

	if got := tagDigest(t, server, "team/renamed", "v1"); got != img.desc.Digest {
		t.Errorf("the tag points to %s", got)
	}
	res, manifest := server.reg(t, http.MethodGet, "/v2/team/renamed/manifests/v1", nil, asPusher)
	expectStatus(t, res, manifest, http.StatusOK)
	if !bytes.Equal(manifest, img.manifest) {
		t.Error("the manifest is not the archive's")
	}
	var doc manifestDoc
	_ = json.Unmarshal(manifest, &doc)
	for _, blob := range append([]v1.Descriptor{*doc.Config}, doc.Layers...) {
		res, content := server.reg(t, http.MethodGet, "/v2/team/renamed/blobs/"+blob.Digest.String(), nil, asPusher)
		expectStatus(t, res, content, http.StatusOK)
		if !bytes.Equal(content, img.blobs[blobName(blob.Digest)]) {
			t.Errorf("the blob %s is not the archive's", blob.Digest)
		}
	}
	if left := importLeftovers(t, server); len(left) > 0 {
		t.Errorf("the import left %v", left)
	}
}

func TestRegistryImportsAFileOfTheFolder(t *testing.T) {
	server := importServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = []string{"^/private/.*"} })
	data, img := appArchive(t)
	server.write(t, "images/app.tar", string(data))
	server.write(t, "private/secret.tar", string(data))
	ci := login(t, server, "/", pusher, pusherPassword)
	both := login(t, server, "/", "both", "pw")
	john := login(t, server, "/", "john", "doe")

	for _, c := range []struct {
		who     string
		session *http.Cookie
		path    string
		file    string
		want    int
		headers []string
	}{
		{"no registry", john, "/images/?go-fs=registry-import", "app.tar", http.StatusForbidden, nil},
		{"cross-site", ci, "/images/?go-fs=registry-import", "app.tar", http.StatusForbidden,
			[]string{"Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site"}},
		{"a file it may not read", ci, "/private/?go-fs=registry-import", "secret.tar", http.StatusForbidden, nil},
		{"outside the folder", ci, "/images/?go-fs=registry-import", "../private/secret.tar", http.StatusBadRequest, nil},
		{"not there", ci, "/images/?go-fs=registry-import", "gone.tar", http.StatusNotFound, nil},
	} {
		res, body := transferRequest(t, server, http.MethodPost, c.path, c.session, map[string]string{"file": c.file},
			c.headers...)
		if res.StatusCode != c.want {
			t.Errorf("%s answered %d, want %d: %s", c.who, res.StatusCode, c.want, body)
		}
	}

	job := startImport(t, server, "/private/?go-fs=registry-import", both, map[string]string{"file": "secret.tar"})
	if res, body := confirmImport(t, server, both, job.ID, map[string]any{"index": 0, "targets": []string{"app:secret"}}); res.StatusCode != http.StatusAccepted {
		t.Fatalf("confirming answered %d: %s", res.StatusCode, body)
	}
	if job = waitForJob(t, server, job.ID, both); job.State != jobDone {
		t.Fatalf("the import ended %s: %s", job.State, job.Message)
	}
	if got := tagDigest(t, server, "app", "secret"); got != img.desc.Digest {
		t.Errorf("the tag points to %s", got)
	}
	// the file of the folder stays
	if server.read(t, "private/secret.tar") != string(data) {
		t.Error("the imported file changed")
	}

	job = startImport(t, server, "/images/?go-fs=registry-import", ci, map[string]string{"file": "app.tar"})
	if len(job.Images) != 1 {
		t.Errorf("the import offers %+v", job.Images)
	}
}

func TestRegistryImportChecksTheChoice(t *testing.T) {
	server := importServer(t, nil)
	data, _ := appArchive(t)
	server.write(t, "app.tar", string(data))
	ci := login(t, server, "/", pusher, pusherPassword)
	server.pushImage(t, "library/app", "1", "linux/amd64", "older")
	job := startImport(t, server, "/?go-fs=registry-import", ci, map[string]string{"file": "app.tar"})
	if !job.Images[0].Targets[0].Exists {
		t.Error("a tag the registry has is not said to be there")
	}

	for name, images := range map[string][]map[string]any{
		"nothing":          {},
		"no tag":           {{"index": 0, "targets": []string{"app"}}},
		"bad repository":   {{"index": 0, "targets": []string{"Bad Name:1"}}},
		"bad tag":          {{"index": 0, "targets": []string{"app:-x"}}},
		"no such image":    {{"index": 3, "targets": []string{"app:1"}}},
		"twice":            {{"index": 0, "targets": []string{"app:1", "app:1"}}},
		"another platform": {{"index": 0, "targets": []string{"app:1"}, "platforms": "linux/s390x"}},
		"not a platform":   {{"index": 0, "targets": []string{"app:1"}, "platforms": "linux"}},
	} {
		if res, body := confirmImport(t, server, ci, job.ID, images...); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s answered %d: %s", name, res.StatusCode, body)
		}
	}
	res, body := confirmImport(t, server, ci, job.ID, map[string]any{"index": 0, "targets": []string{"library/app:1"},
		"platforms": "linux/amd64"})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("confirming answered %d: %s", res.StatusCode, body)
	}
	if res, _ := confirmImport(t, server, ci, job.ID, map[string]any{"index": 0, "targets": []string{"app:2"}}); res.StatusCode != http.StatusConflict {
		t.Errorf("a second answer answered %d", res.StatusCode)
	}
	if job = waitForJob(t, server, job.ID, ci); job.State != jobDone {
		t.Fatalf("the import ended %s: %s", job.State, job.Message)
	}
	if res, _ := confirmImport(t, server, ci, job.ID, map[string]any{"index": 0, "targets": []string{"app:2"}}); res.StatusCode != http.StatusConflict {
		t.Errorf("an answer to a finished import answered %d", res.StatusCode)
	}
}

// An index can be imported for some of its platforms, which makes an index
// of its own, as a pull does.
func TestRegistryImportsSomePlatformsOfAnIndex(t *testing.T) {
	server := importServer(t, nil)
	amd, arm := newOCIImage(t, "linux/amd64", "amd"), newOCIImage(t, "linux/arm64", "arm")
	index, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{amd.desc, arm.desc}})
	indexDesc := describe(v1.MediaTypeImageIndex, index)
	server.write(t, "multi.tar.gz", string(gzipped(t, tarOf(t, layoutEntries(
		[]v1.Descriptor{named(indexDesc, v1.AnnotationRefName, "2.0")},
		amd.blobs, arm.blobs, map[string][]byte{blobName(indexDesc.Digest): index})...))))
	ci := login(t, server, "/", pusher, pusherPassword)

	job := startImport(t, server, "/?go-fs=registry-import", ci, map[string]string{"file": "multi.tar.gz"})
	offered := job.Images[0]
	if !offered.IsIndex || len(offered.Platforms) != 2 || offered.Targets[0].Target != "multi:2.0" {
		t.Fatalf("the index is offered as %+v", offered)
	}
	res, body := confirmImport(t, server, ci, job.ID, map[string]any{"index": 0, "targets": []string{"multi:2.0"},
		"platforms": "linux/arm64"})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("confirming answered %d: %s", res.StatusCode, body)
	}
	if job = waitForJob(t, server, job.ID, ci); job.State != jobDone {
		t.Fatalf("the import ended %s: %s", job.State, job.Message)
	}
	got := tagDigest(t, server, "multi", "2.0")
	if got == indexDesc.Digest {
		t.Error("the index was stored whole")
	}
	_, doc := server.pullManifest(t, "multi", "2.0")
	if len(doc.Manifests) != 1 || doc.Manifests[0].Digest != arm.desc.Digest {
		t.Errorf("the index holds %+v", doc.Manifests)
	}
	if server.blobStored(amd.desc.Digest) {
		t.Error("the platform left out was stored")
	}
}

func TestRegistryImportsADockerSave(t *testing.T) {
	server := importServer(t, nil)
	data, layerA, _ := dockerSave24(t)
	server.write(t, "images.tar", string(data))
	ci := login(t, server, "/", pusher, pusherPassword)

	job := startImport(t, server, "/?go-fs=registry-import", ci, map[string]string{"file": "images.tar"})
	if len(job.Images) != 2 {
		t.Fatalf("the import offers %+v", job.Images)
	}
	res, body := confirmImport(t, server, ci, job.ID,
		map[string]any{"index": 0, "targets": []string{"library/alpine:latest"}},
		map[string]any{"index": 1, "targets": []string{"foo:1", "team/foo:2"}})
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("confirming answered %d: %s", res.StatusCode, body)
	}
	if job = waitForJob(t, server, job.ID, ci); job.State != jobDone {
		t.Fatalf("the import ended %s: %s", job.State, job.Message)
	}
	res, doc := server.pullManifest(t, "library/alpine", "latest")
	if got := res.Header.Get("Content-Type"); got != mediaTypeDockerManifest {
		t.Errorf("the manifest is served as %s", got)
	}
	layer := doc.Layers[0]
	res, content := server.reg(t, http.MethodGet, "/v2/library/alpine/blobs/"+layer.Digest.String(), nil, asPusher)
	expectStatus(t, res, content, http.StatusOK)
	if !bytes.Equal(content, layerA) {
		t.Error("the layer is not the archive's")
	}
	if tagDigest(t, server, "foo", "1") == "" || tagDigest(t, server, "foo", "1") != tagDigest(t, server, "team/foo", "2") {
		t.Error("the second image is not under both its tags")
	}
}

func TestRegistryImportCanBeStoppedWhileReady(t *testing.T) {
	server := importServer(t, nil)
	data, img := appArchive(t)
	server.write(t, "app.tar", string(data))
	ci := login(t, server, "/", pusher, pusherPassword)
	job := startImport(t, server, "/?go-fs=registry-import", ci, map[string]string{"file": "app.tar"})
	if left := importLeftovers(t, server); len(left) != 1 {
		t.Errorf("a ready import stages in %v", left)
	}

	// a cleanup meanwhile takes nothing the import has staged
	server.cleanRegistryNow(server.settings().registry)
	if left := importLeftovers(t, server); len(left) != 1 {
		t.Errorf("the cleanup took what the import staged: %v", left)
	}

	res, body := transferRequest(t, server, http.MethodDelete, "/?go-fs=registry-job&id="+job.ID, ci, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("stopping answered %d: %s", res.StatusCode, body)
	}
	if job = waitForImportEnd(t, server, job.ID, ci); job.State != jobCancelled {
		t.Errorf("the import ended %s", job.State)
	}
	if left := importLeftovers(t, server); len(left) > 0 {
		t.Errorf("a stopped import left %v", left)
	}
	if server.blobStored(img.desc.Digest) {
		t.Error("a stopped import stored its manifest")
	}
}

// What an import stores is referenced at once, so a cleanup right after it
// keeps all of it, however old the files of the archive look.
func TestRegistryImportSurvivesTheCleanup(t *testing.T) {
	server := importServer(t, nil)
	data, img := appArchive(t)
	server.write(t, "app.tar", string(data))
	ci := login(t, server, "/", pusher, pusherPassword)
	job := startImport(t, server, "/?go-fs=registry-import", ci, map[string]string{"file": "app.tar"})
	if res, body := confirmImport(t, server, ci, job.ID, map[string]any{"index": 0, "targets": []string{"app:1"}}); res.StatusCode != http.StatusAccepted {
		t.Fatalf("confirming answered %d: %s", res.StatusCode, body)
	}
	waitForJob(t, server, job.ID, ci)
	ageRegistry(t, server)
	server.cleanRegistryNow(server.settings().registry)
	for name := range img.blobs {
		if !server.blobStored(digest.Digest("sha256:" + strings.TrimPrefix(name, "blobs/sha256/"))) {
			t.Errorf("the cleanup took %s", name)
		}
	}
}

func TestRegistryImportUploadLimits(t *testing.T) {
	server := importServer(t, func(cfg *httpConfig) {
		cfg.MaxUploadSize = 100
	})
	ci := login(t, server, "/", pusher, pusherPassword)
	if res, body := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-import-upload", ci,
		map[string]any{"name": "big.tar", "size": 1000}); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("an archive over the limit answered %d: %s", res.StatusCode, body)
	}
	for name, body := range map[string]map[string]any{
		"empty":   {"name": "x.tar", "size": 0},
		"no name": {"name": "", "size": 10},
	} {
		if res, data := transferRequest(t, server, http.MethodPost, "/?go-fs=registry-import-upload", ci, body); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s answered %d: %s", name, res.StatusCode, data)
		}
	}

	// without a chunk size the archive comes in one piece
	whole := importServer(t, func(cfg *httpConfig) { cfg.MaxChunkSize = 0 })
	data, _ := appArchive(t)
	ci = login(t, whole, "/", pusher, pusherPassword)
	id := uploadArchive(t, whole, ci, "app.tar", data, len(data))
	res, body := transferRequest(t, whole, http.MethodDelete, "/?go-fs=registry-import-upload&id="+id, ci, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("dropping the upload answered %d: %s", res.StatusCode, body)
	}
	if left := importLeftovers(t, whole); len(left) > 0 {
		t.Errorf("a dropped upload left %v", left)
	}
}

func TestRegistryImportOfWhatIsNoImage(t *testing.T) {
	server := importServer(t, nil)
	server.write(t, "rootfs.tar", string(tarOf(t, file("etc/passwd", []byte("root")))))
	ci := login(t, server, "/", pusher, pusherPassword)
	job := startTransfer(t, server, "/?go-fs=registry-import", ci, map[string]string{"file": "rootfs.tar"})
	if job.State != jobFailed || !strings.Contains(job.Message, "docker export") {
		t.Errorf("the import ended %s: %s", job.State, job.Message)
	}
	if left := importLeftovers(t, server); len(left) > 0 {
		t.Errorf("a failed import left %v", left)
	}
}

func TestRegistryPageOffersTheImport(t *testing.T) {
	server := importServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	if _, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", nil); strings.Contains(body, `id="import-image"`) {
		t.Error("an anonymous visitor is offered the import")
	}
	ci := login(t, server, "/", pusher, pusherPassword)
	if _, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry", ci); !strings.Contains(body, `id="import-image"`) {
		t.Error("the registry account is not offered the import")
	}
	for query, want := range map[string]string{
		"import=app.tar.gz":    `data-file="app.tar.gz"`,
		"import=..%2Fapp.tar":  `data-file=""`,
		"import=notes.txt":     `data-file=""`,
		"import=sub%5Capp.tar": `data-file=""`,
	} {
		if _, body := pageRequest(t, server, http.MethodGet, "/?go-fs=registry&"+query, ci); !strings.Contains(body, want) {
			t.Errorf("%s does not give %s", query, want)
		}
	}
}

func TestTheListingOffersTheImportToTheRegistry(t *testing.T) {
	server := importServer(t, func(cfg *httpConfig) { cfg.PathsRequireAuth = nil })
	server.write(t, "app.tar", "not really")
	john := login(t, server, "/", "john", "doe")
	if _, body := pageRequest(t, server, http.MethodGet, "/", john); strings.Contains(body, `data-do="import"`) {
		t.Error("an account without the registry is offered the import")
	}
	both := login(t, server, "/", "both", "pw")
	if _, body := pageRequest(t, server, http.MethodGet, "/", both); !strings.Contains(body, `data-do="import"`) {
		t.Error("an account of the registry is not offered the import")
	}
}

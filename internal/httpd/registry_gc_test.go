package httpd

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
)

// ageRegistry makes everything in the registry folder look two days old, as
// if nothing had been pushed since.
func ageRegistry(t *testing.T, server *testServer) {
	t.Helper()
	old := time.Now().Add(-48 * time.Hour)
	err := filepath.WalkDir(server.registryBase(), func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, old, old)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (s *testServer) blobStored(d digest.Digest) bool {
	_, err := os.Stat(s.settings().registry.blobPath(d))
	return err == nil
}

func TestRegistryGarbageCollectionKeepsWhatIsReferenced(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.pushImage(t, "app", "latest", "linux/amd64", "1")
	orphan := server.pushBlob(t, "app", []byte("pushed, never referenced"))
	ageRegistry(t, server)
	fresh := server.pushBlob(t, "app", []byte("pushed a moment ago"))

	server.sweepRegistry()

	for name, d := range map[string]digest.Digest{"manifest": img.digest, "config": img.config,
		"layer": img.layer, "fresh blob": fresh} {
		if !server.blobStored(d) {
			t.Errorf("the %s was collected", name)
		}
	}
	if server.blobStored(orphan) {
		t.Error("the unreferenced blob was kept")
	}
	res, body := server.reg(t, http.MethodGet, "/v2/app/blobs/"+orphan.String(), nil)
	expectStatus(t, res, body, http.StatusNotFound)
	server.pullManifest(t, "app", "latest")
	if server.logs.find("registry cleanup removed an unreferenced blob") == nil {
		t.Error("the removal was not recorded")
	}
}

func TestRegistryGarbageCollectionRemovesADeletedImage(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.pushImage(t, "app", "latest", "linux/amd64", "1")
	kept := server.pushImage(t, "other", "latest", "linux/arm64", "2")
	// the layer is linked into another repository too, where no manifest
	// refers to it
	res, body := server.reg(t, http.MethodPost,
		"/v2/other/blobs/uploads/?mount="+img.layer.String()+"&from=app", nil, asPusher)
	expectStatus(t, res, body, http.StatusCreated)
	res, body = server.reg(t, http.MethodDelete, "/v2/app/manifests/"+img.digest.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	ageRegistry(t, server)

	server.sweepRegistry()

	if server.blobStored(img.digest) || server.blobStored(img.config) || server.blobStored(img.layer) {
		t.Error("the deleted image's manifest, config or layer was kept")
	}
	if !server.blobStored(kept.digest) || !server.blobStored(kept.config) || !server.blobStored(kept.layer) {
		t.Error("the other repository's image was collected")
	}
	if _, err := os.Stat(server.settings().registry.layerPath("other", img.layer)); err == nil {
		t.Error("the stale link was kept")
	}
}

func TestRegistryGarbageCollectionFollowsIndexes(t *testing.T) {
	server := newRegistryServer(t, nil)
	amd64 := server.pushImage(t, "app", "1.0", "linux/amd64", "1")
	arm64 := server.pushImage(t, "app", "1.0", "linux/arm64", "1")
	// the arm64 image is only reachable through the merged index now
	res, body := server.reg(t, http.MethodDelete, "/v2/app/manifests/"+arm64.digest.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	ageRegistry(t, server)

	server.sweepRegistry()

	for _, d := range []digest.Digest{amd64.digest, amd64.layer, arm64.digest, arm64.config, arm64.layer} {
		if !server.blobStored(d) {
			t.Errorf("%s, referenced through the index, was collected", d)
		}
	}
}

func TestRegistrySweepsAbandonedUploads(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	abandoned := res.Header.Get("Location")
	res, body = server.reg(t, http.MethodPatch, abandoned, []byte("half"), asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	ageRegistry(t, server)
	res, body = server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	active := res.Header.Get("Location")

	server.sweepRegistry()

	res, body = server.reg(t, http.MethodGet, abandoned, nil, asPusher)
	expectStatus(t, res, body, http.StatusNotFound)
	res, body = server.reg(t, http.MethodGet, active, nil, asPusher)
	expectStatus(t, res, body, http.StatusNoContent)
	id := active[strings.LastIndex(active, "/")+1:]
	if _, err := os.Stat(filepath.Join(server.registryBase(), registryUploadsFolder, id)); err != nil {
		t.Errorf("the active upload is gone: %v", err)
	}
}

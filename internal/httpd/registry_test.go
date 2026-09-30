package httpd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"go-fs/internal/config"
)

func TestRegistryAnswersItsBase(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodGet, "/v2/", nil, asPusher)
	expectStatus(t, res, body, http.StatusOK)
	if got := res.Header.Get("Docker-Distribution-API-Version"); got != "registry/2.0" {
		t.Errorf("Docker-Distribution-API-Version = %q", got)
	}
	if strings.TrimSpace(string(body)) != "{}" {
		t.Errorf("body = %q", body)
	}
}

func TestRegistryIsOffWithoutAFolder(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "v2/readme.txt", "a file")
	res, body := server.reg(t, http.MethodGet, "/v2/readme.txt", nil)
	expectStatus(t, res, body, http.StatusOK)
	if string(body) != "a file" || res.Header.Get("Docker-Distribution-API-Version") != "" {
		t.Errorf("/v2 was not served as a folder: %q", body)
	}
}

func TestRegistryMonolithicUpload(t *testing.T) {
	server := newRegistryServer(t, nil)
	content := []byte("hello registry")
	d := digest.FromBytes(content)
	res, body := server.reg(t, http.MethodPost, "/v2/team/app/blobs/uploads/?digest="+d.String(), content, asPusher)
	expectStatus(t, res, body, http.StatusCreated)
	if got := res.Header.Get("Docker-Content-Digest"); got != d.String() {
		t.Errorf("Docker-Content-Digest = %q", got)
	}
	if got := res.Header.Get("Location"); got != "/v2/team/app/blobs/"+d.String() {
		t.Errorf("Location = %q", got)
	}

	res, body = server.reg(t, http.MethodGet, "/v2/team/app/blobs/"+d.String(), nil)
	expectStatus(t, res, body, http.StatusOK)
	if !bytes.Equal(body, content) {
		t.Errorf("blob = %q", body)
	}
	res, body = server.reg(t, http.MethodHead, "/v2/team/app/blobs/"+d.String(), nil)
	expectStatus(t, res, body, http.StatusOK)
	if res.ContentLength != int64(len(content)) || len(body) != 0 {
		t.Errorf("HEAD: length %d, body %q", res.ContentLength, body)
	}
	stored := filepath.Join(server.registryBase(), "blobs", "sha256", d.Encoded()[:2], d.Encoded())
	if data, err := os.ReadFile(stored); err != nil || !bytes.Equal(data, content) {
		t.Errorf("blob on disk: %q, %v", data, err)
	}
}

func TestRegistryChunkedUpload(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	location := res.Header.Get("Location")
	if !strings.HasPrefix(location, "/v2/app/blobs/uploads/") || res.Header.Get("Docker-Upload-UUID") == "" {
		t.Fatalf("Location = %q", location)
	}

	res, body = server.reg(t, http.MethodPatch, location, []byte("01234"), asPusher,
		withHeader("Content-Range", "0-4"))
	expectStatus(t, res, body, http.StatusAccepted)
	if got := res.Header.Get("Range"); got != "0-4" {
		t.Errorf("Range = %q", got)
	}

	// a chunk that does not continue the upload is refused, and the client
	// is told where it stands
	res, body = server.reg(t, http.MethodPatch, location, []byte("234"), asPusher,
		withHeader("Content-Range", "2-4"))
	expectStatus(t, res, body, http.StatusRequestedRangeNotSatisfiable)
	if got := res.Header.Get("Range"); got != "0-4" {
		t.Errorf("Range after a refused chunk = %q", got)
	}

	res, body = server.reg(t, http.MethodPatch, location, []byte("56789"), asPusher,
		withHeader("Content-Range", "5-9"))
	expectStatus(t, res, body, http.StatusAccepted)

	res, body = server.reg(t, http.MethodGet, location, nil, asPusher)
	expectStatus(t, res, body, http.StatusNoContent)
	if got := res.Header.Get("Range"); got != "0-9" {
		t.Errorf("status Range = %q", got)
	}

	d := digest.FromString("0123456789")
	res, body = server.reg(t, http.MethodPut, location+"?digest="+d.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusCreated)
	res, body = server.reg(t, http.MethodGet, "/v2/app/blobs/"+d.String(), nil)
	expectStatus(t, res, body, http.StatusOK)
	if string(body) != "0123456789" {
		t.Errorf("blob = %q", body)
	}
	// the upload is gone once it is a blob
	res, body = server.reg(t, http.MethodGet, location, nil, asPusher)
	expectStatus(t, res, body, http.StatusNotFound)
}

func TestRegistryStreamedUploadWithTheLastChunkInThePut(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	location := res.Header.Get("Location")

	// docker streams a layer as one PATCH with no Content-Range
	res, body = server.reg(t, http.MethodPatch, location, []byte("streamed "), asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	d := digest.FromString("streamed and finished")
	res, body = server.reg(t, http.MethodPut, location+"?digest="+d.String(), []byte("and finished"), asPusher)
	expectStatus(t, res, body, http.StatusCreated)
	_, body = server.reg(t, http.MethodGet, "/v2/app/blobs/"+d.String(), nil)
	if string(body) != "streamed and finished" {
		t.Errorf("blob = %q", body)
	}
}

func TestRegistrySHA512Upload(t *testing.T) {
	server := newRegistryServer(t, nil)
	content := []byte("a blob named by sha512")
	d := digest.SHA512.FromBytes(content)
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/?digest="+d.String(), content, asPusher)
	expectStatus(t, res, body, http.StatusCreated)
	_, body = server.reg(t, http.MethodGet, "/v2/app/blobs/"+d.String(), nil)
	if !bytes.Equal(body, content) {
		t.Errorf("blob = %q", body)
	}
}

func TestRegistryRefusesADigestThatDoesNotMatch(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	location := res.Header.Get("Location")
	wrong := digest.FromString("something else")
	res, body = server.reg(t, http.MethodPut, location+"?digest="+wrong.String(), []byte("content"), asPusher)
	expectStatus(t, res, body, http.StatusBadRequest)
	if code := errorCodeOf(t, body); code != "DIGEST_INVALID" {
		t.Errorf("code = %s", code)
	}
	res, body = server.reg(t, http.MethodGet, "/v2/app/blobs/"+wrong.String(), nil)
	expectStatus(t, res, body, http.StatusNotFound)
	res, body = server.reg(t, http.MethodGet, location, nil, asPusher)
	expectStatus(t, res, body, http.StatusNotFound)
}

func TestRegistryUploadBelongsToItsRepositoryAndAccount(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, registryUser("other", "pw"))
	})
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	location := res.Header.Get("Location")
	id := strings.TrimPrefix(location, "/v2/app/blobs/uploads/")

	res, body = server.reg(t, http.MethodPatch, "/v2/elsewhere/blobs/uploads/"+id, []byte("x"), asPusher)
	expectStatus(t, res, body, http.StatusNotFound)
	if code := errorCodeOf(t, body); code != "BLOB_UPLOAD_UNKNOWN" {
		t.Errorf("code = %s", code)
	}
	res, body = server.reg(t, http.MethodPatch, location, []byte("x"), as("other", "pw"))
	expectStatus(t, res, body, http.StatusNotFound)
	res, body = server.reg(t, http.MethodPatch, "/v2/app/blobs/uploads/../../x", []byte("x"), asPusher)
	if res.StatusCode < 400 {
		t.Errorf("a path that climbs out was accepted: %d %s", res.StatusCode, body)
	}
}

func TestRegistryHonoursMaxUploadSize(t *testing.T) {
	server := newRegistryServer(t, func(cfg *httpConfig) { cfg.MaxUploadSize = 10 })
	content := []byte("eleven byte")
	d := digest.FromBytes(content)
	res, body := server.reg(t, http.MethodPost, "/v2/app/blobs/uploads/?digest="+d.String(), content, asPusher)
	expectStatus(t, res, body, http.StatusRequestEntityTooLarge)
	if code := errorCodeOf(t, body); code != "SIZE_INVALID" {
		t.Errorf("code = %s", code)
	}
	// a blob of the limit itself is fine, and chunks may add up to it
	server.pushBlob(t, "app", []byte("ten bytes!"))
}

func TestRegistryMountsABlobFromAnotherRepository(t *testing.T) {
	server := newRegistryServer(t, nil)
	d := server.pushBlob(t, "base", []byte("shared layer"))
	res, body := server.reg(t, http.MethodPost, "/v2/derived/blobs/uploads/?mount="+d.String()+"&from=base", nil, asPusher)
	expectStatus(t, res, body, http.StatusCreated)
	if got := res.Header.Get("Docker-Content-Digest"); got != d.String() {
		t.Errorf("Docker-Content-Digest = %q", got)
	}
	_, body = server.reg(t, http.MethodGet, "/v2/derived/blobs/"+d.String(), nil)
	if string(body) != "shared layer" {
		t.Errorf("mounted blob = %q", body)
	}
	// a blob the source does not have starts an ordinary upload
	missing := digest.FromString("not there")
	res, body = server.reg(t, http.MethodPost, "/v2/derived/blobs/uploads/?mount="+missing.String()+"&from=base", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
}

func TestRegistryServesBlobsOnlyToTheirRepository(t *testing.T) {
	server := newRegistryServer(t, nil)
	d := server.pushBlob(t, "one", []byte("private to one"))
	res, body := server.reg(t, http.MethodGet, "/v2/two/blobs/"+d.String(), nil)
	expectStatus(t, res, body, http.StatusNotFound)
	if code := errorCodeOf(t, body); code != "BLOB_UNKNOWN" {
		t.Errorf("code = %s", code)
	}
}

func TestRegistryServesBlobRanges(t *testing.T) {
	server := newRegistryServer(t, nil)
	d := server.pushBlob(t, "app", []byte("0123456789"))
	res, body := server.reg(t, http.MethodGet, "/v2/app/blobs/"+d.String(), nil, withHeader("Range", "bytes=2-4"))
	expectStatus(t, res, body, http.StatusPartialContent)
	if string(body) != "234" {
		t.Errorf("range = %q", body)
	}
}

func TestRegistryDeletesABlob(t *testing.T) {
	server := newRegistryServer(t, nil)
	d := server.pushBlob(t, "app", []byte("to delete"))
	res, body := server.reg(t, http.MethodDelete, "/v2/app/blobs/"+d.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	res, body = server.reg(t, http.MethodGet, "/v2/app/blobs/"+d.String(), nil)
	expectStatus(t, res, body, http.StatusNotFound)
	res, body = server.reg(t, http.MethodDelete, "/v2/app/blobs/"+d.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusNotFound)
}

func TestRegistryPushesAndPullsAManifest(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.buildImage(t, "team/app", "linux/amd64", "1", false)
	res, body := server.pushManifest(t, "team/app", "v1.0", img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusCreated)
	if got := res.Header.Get("Docker-Content-Digest"); got != img.digest.String() {
		t.Errorf("Docker-Content-Digest = %q, want %s", got, img.digest)
	}
	if got := res.Header.Get("Location"); got != "/v2/team/app/manifests/"+img.digest.String() {
		t.Errorf("Location = %q", got)
	}

	for _, ref := range []string{"v1.0", img.digest.String()} {
		res, body = server.reg(t, http.MethodGet, "/v2/team/app/manifests/"+ref, nil)
		expectStatus(t, res, body, http.StatusOK)
		if !bytes.Equal(body, img.manifest) {
			t.Errorf("%s: manifest differs: %s", ref, body)
		}
		if got := res.Header.Get("Content-Type"); got != v1.MediaTypeImageManifest {
			t.Errorf("%s: Content-Type = %q", ref, got)
		}
		if got := res.Header.Get("Docker-Content-Digest"); got != img.digest.String() {
			t.Errorf("%s: Docker-Content-Digest = %q", ref, got)
		}
	}
	res, body = server.reg(t, http.MethodHead, "/v2/team/app/manifests/v1.0", nil)
	expectStatus(t, res, body, http.StatusOK)
	if res.ContentLength != int64(len(img.manifest)) {
		t.Errorf("HEAD Content-Length = %d", res.ContentLength)
	}
	res, body = server.reg(t, http.MethodGet, "/v2/team/app/manifests/v2.0", nil)
	expectStatus(t, res, body, http.StatusNotFound)
	if code := errorCodeOf(t, body); code != "MANIFEST_UNKNOWN" {
		t.Errorf("code = %s", code)
	}
}

func TestRegistryPushesADockerManifest(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.buildImage(t, "app", "linux/amd64", "1", true)
	res, body := server.pushManifest(t, "app", "latest", img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusCreated)
	res, _ = server.pullManifest(t, "app", "latest")
	if got := res.Header.Get("Content-Type"); got != mediaTypeDockerManifest {
		t.Errorf("Content-Type = %q", got)
	}
}

func TestRegistryRefusesAManifestWithMissingBlobs(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.buildImage(t, "app", "linux/amd64", "1", false)
	res, body := server.reg(t, http.MethodDelete, "/v2/app/blobs/"+img.layer.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	res, body = server.pushManifest(t, "app", "latest", img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusBadRequest)
	if code := errorCodeOf(t, body); code != "MANIFEST_BLOB_UNKNOWN" {
		t.Errorf("code = %s", code)
	}
}

func TestRegistryRefusesAManifestThatIsNotWhatItSays(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.buildImage(t, "app", "linux/amd64", "1", false)
	wrong := digest.FromString("another manifest")
	res, body := server.pushManifest(t, "app", wrong.String(), img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusBadRequest)
	if code := errorCodeOf(t, body); code != "DIGEST_INVALID" {
		t.Errorf("by digest: code = %s", code)
	}
	res, body = server.pushManifest(t, "app", "latest", v1.MediaTypeImageIndex, img.manifest)
	expectStatus(t, res, body, http.StatusBadRequest)
	if code := errorCodeOf(t, body); code != "MANIFEST_INVALID" {
		t.Errorf("media type: code = %s", code)
	}
	res, body = server.pushManifest(t, "app", "latest", img.mediaType, []byte("not json"))
	expectStatus(t, res, body, http.StatusBadRequest)
	res, body = server.pushManifest(t, "app", "bad:tag!", img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusBadRequest)
}

// TestRegistryRefusesDigestsThatAreNot checks the digests inside a manifest:
// they become the paths of the store, so one that is not a digest must never
// be looked up.
func TestRegistryRefusesDigestsThatAreNot(t *testing.T) {
	server := newRegistryServer(t, nil)
	config := server.pushBlob(t, "app", []byte(`{"os":"linux","architecture":"amd64"}`))
	for _, bad := range []digest.Digest{"sha256:../../../../etc/passwd", "sha256:a", "md5:d41d8cd98f00b204e9800998ecf8427e"} {
		manifests := map[string]manifestDoc{
			"layer": {SchemaVersion: 2, MediaType: v1.MediaTypeImageManifest,
				Config: &v1.Descriptor{MediaType: v1.MediaTypeImageConfig, Digest: config, Size: 1},
				Layers: []v1.Descriptor{{MediaType: v1.MediaTypeImageLayerGzip, Digest: bad, Size: 1}}},
			"config": {SchemaVersion: 2, MediaType: v1.MediaTypeImageManifest,
				Config: &v1.Descriptor{MediaType: v1.MediaTypeImageConfig, Digest: bad, Size: 1}},
			"index": {SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex,
				Manifests: []v1.Descriptor{{MediaType: v1.MediaTypeImageManifest, Digest: bad, Size: 1}}},
		}
		for name, doc := range manifests {
			body, _ := json.Marshal(doc)
			res, answer := server.pushManifest(t, "app", "latest", doc.MediaType, body)
			if res.StatusCode != http.StatusBadRequest || errorCodeOf(t, answer) != "MANIFEST_INVALID" {
				t.Errorf("%s %s: %d %s", name, bad, res.StatusCode, answer)
			}
		}
	}
}

func TestRegistryListsTagsAndRepositoriesAPageAtATime(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.buildImage(t, "app", "linux/amd64", "1", false)
	for _, tag := range []string{"b", "a", "c", "B"} {
		res, body := server.pushManifest(t, "app", tag, img.mediaType, img.manifest)
		expectStatus(t, res, body, http.StatusCreated)
	}
	server.pushImage(t, "team/tools", "latest", "linux/amd64", "2")

	var tags struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	res, body := server.reg(t, http.MethodGet, "/v2/app/tags/list", nil)
	expectStatus(t, res, body, http.StatusOK)
	_ = json.Unmarshal(body, &tags)
	if tags.Name != "app" || strings.Join(tags.Tags, ",") != "B,a,b,c" {
		t.Errorf("tags = %+v", tags)
	}

	res, body = server.reg(t, http.MethodGet, "/v2/app/tags/list?n=2", nil)
	expectStatus(t, res, body, http.StatusOK)
	_ = json.Unmarshal(body, &tags)
	if strings.Join(tags.Tags, ",") != "B,a" {
		t.Errorf("first page = %v", tags.Tags)
	}
	if got := res.Header.Get("Link"); got != `</v2/app/tags/list?last=a&n=2>; rel="next"` {
		t.Errorf("Link = %q", got)
	}
	res, body = server.reg(t, http.MethodGet, "/v2/app/tags/list?n=2&last=a", nil)
	expectStatus(t, res, body, http.StatusOK)
	_ = json.Unmarshal(body, &tags)
	if strings.Join(tags.Tags, ",") != "b,c" || res.Header.Get("Link") != "" {
		t.Errorf("last page = %v, Link %q", tags.Tags, res.Header.Get("Link"))
	}

	res, body = server.reg(t, http.MethodGet, "/v2/nothing/tags/list", nil)
	expectStatus(t, res, body, http.StatusNotFound)
	if code := errorCodeOf(t, body); code != "NAME_UNKNOWN" {
		t.Errorf("code = %s", code)
	}

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	res, body = server.reg(t, http.MethodGet, "/v2/_catalog", nil)
	expectStatus(t, res, body, http.StatusOK)
	_ = json.Unmarshal(body, &catalog)
	if strings.Join(catalog.Repositories, ",") != "app,team/tools" {
		t.Errorf("catalog = %v", catalog.Repositories)
	}
	res, body = server.reg(t, http.MethodGet, "/v2/_catalog?n=1", nil)
	expectStatus(t, res, body, http.StatusOK)
	_ = json.Unmarshal(body, &catalog)
	if strings.Join(catalog.Repositories, ",") != "app" || res.Header.Get("Link") == "" {
		t.Errorf("catalog page = %v, Link %q", catalog.Repositories, res.Header.Get("Link"))
	}
}

func TestRegistryDeletesTagsAndManifests(t *testing.T) {
	server := newRegistryServer(t, nil)
	img := server.pushImage(t, "app", "one", "linux/amd64", "1")
	res, body := server.pushManifest(t, "app", "two", img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusCreated)

	res, body = server.reg(t, http.MethodDelete, "/v2/app/manifests/one", nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	res, body = server.reg(t, http.MethodGet, "/v2/app/manifests/one", nil)
	expectStatus(t, res, body, http.StatusNotFound)
	server.pullManifest(t, "app", img.digest.String())

	res, body = server.reg(t, http.MethodDelete, "/v2/app/manifests/"+img.digest.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	for _, ref := range []string{"two", img.digest.String()} {
		res, body = server.reg(t, http.MethodGet, "/v2/app/manifests/"+ref, nil)
		expectStatus(t, res, body, http.StatusNotFound)
	}
	res, body = server.reg(t, http.MethodDelete, "/v2/app/manifests/"+img.digest.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusNotFound)
}

func TestRegistryListsReferrers(t *testing.T) {
	server := newRegistryServer(t, nil)
	subject := server.pushImage(t, "app", "latest", "linux/amd64", "1")

	empty := []byte("{}")
	emptyDigest := server.pushBlob(t, "app", empty)
	signature := []byte("signature")
	signatureDigest := server.pushBlob(t, "app", signature)
	artifact, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     v1.MediaTypeImageManifest,
		ArtifactType:  "application/vnd.example.signature",
		Config:        &v1.Descriptor{MediaType: v1.MediaTypeEmptyJSON, Digest: emptyDigest, Size: 2},
		Layers:        []v1.Descriptor{{MediaType: "application/octet-stream", Digest: signatureDigest, Size: int64(len(signature))}},
		Subject:       &v1.Descriptor{MediaType: subject.mediaType, Digest: subject.digest, Size: int64(len(subject.manifest))},
		Annotations:   map[string]string{"org.example.signer": "ci"},
	})
	artifactDigest := digest.FromBytes(artifact)
	res, body := server.pushManifest(t, "app", artifactDigest.String(), v1.MediaTypeImageManifest, artifact)
	expectStatus(t, res, body, http.StatusCreated)
	if got := res.Header.Get("OCI-Subject"); got != subject.digest.String() {
		t.Errorf("OCI-Subject = %q", got)
	}

	var index v1.Index
	res, body = server.reg(t, http.MethodGet, "/v2/app/referrers/"+subject.digest.String(), nil)
	expectStatus(t, res, body, http.StatusOK)
	if got := res.Header.Get("Content-Type"); got != v1.MediaTypeImageIndex {
		t.Errorf("Content-Type = %q", got)
	}
	_ = json.Unmarshal(body, &index)
	if len(index.Manifests) != 1 || index.Manifests[0].Digest != artifactDigest ||
		index.Manifests[0].ArtifactType != "application/vnd.example.signature" ||
		index.Manifests[0].Annotations["org.example.signer"] != "ci" {
		t.Fatalf("referrers = %s", body)
	}

	res, body = server.reg(t, http.MethodGet, "/v2/app/referrers/"+subject.digest.String()+"?artifactType=application/other", nil)
	expectStatus(t, res, body, http.StatusOK)
	_ = json.Unmarshal(body, &index)
	if len(index.Manifests) != 0 || res.Header.Get("OCI-Filters-Applied") != "artifactType" {
		t.Errorf("filtered referrers = %s, header %q", body, res.Header.Get("OCI-Filters-Applied"))
	}
	if !strings.Contains(string(body), `"manifests":[]`) {
		t.Errorf("an empty list has to be a list: %s", body)
	}

	res, body = server.reg(t, http.MethodDelete, "/v2/app/manifests/"+artifactDigest.String(), nil, asPusher)
	expectStatus(t, res, body, http.StatusAccepted)
	_, body = server.reg(t, http.MethodGet, "/v2/app/referrers/"+subject.digest.String(), nil)
	_ = json.Unmarshal(body, &index)
	if len(index.Manifests) != 0 {
		t.Errorf("a deleted referrer is still listed: %s", body)
	}
}

func TestRegistryRefusesWhatIsNotItsAPI(t *testing.T) {
	server := newRegistryServer(t, nil)
	cases := []struct {
		method, path string
		status       int
		code         string
	}{
		{http.MethodGet, "/v2/Upper/tags/list", http.StatusBadRequest, "NAME_INVALID"},
		{http.MethodGet, "/v2/a/../b/tags/list", http.StatusBadRequest, "NAME_INVALID"},
		{http.MethodGet, "/v2/_hidden/tags/list", http.StatusBadRequest, "NAME_INVALID"},
		{http.MethodGet, "/v2/app/something", http.StatusNotFound, "NOT_FOUND"},
		{http.MethodPost, "/v2/app/tags/list", http.StatusMethodNotAllowed, "UNSUPPORTED"},
		{http.MethodGet, "/v2/app/blobs/sha256:short", http.StatusBadRequest, "DIGEST_INVALID"},
		{http.MethodGet, "/v2/app/blobs/md5:d41d8cd98f00b204e9800998ecf8427e", http.StatusBadRequest, "DIGEST_INVALID"},
	}
	for _, c := range cases {
		res, body := server.reg(t, c.method, c.path, nil, asPusher)
		if res.StatusCode != c.status || errorCodeOf(t, body) != c.code {
			t.Errorf("%s %s: %d %s, want %d %s", c.method, c.path, res.StatusCode, body, c.status, c.code)
		}
	}
}

func TestRegistryReloadSwitchesAnonymousRead(t *testing.T) {
	server := newRegistryServer(t, nil)
	res, body := server.reg(t, http.MethodGet, "/v2/_catalog", nil)
	expectStatus(t, res, body, http.StatusOK)

	set := server.settings()
	cfg := set.cfg
	cfg.RegistryAnonymousRead = false
	users := []config.User{fullUser("john", "doe"), registryUser(pusher, pusherPassword)}
	if err := server.Reload(cfg, set.https, users, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	res, body = server.reg(t, http.MethodGet, "/v2/_catalog", nil)
	expectStatus(t, res, body, http.StatusUnauthorized)
	res, body = server.reg(t, http.MethodGet, "/v2/_catalog", nil, asPusher)
	expectStatus(t, res, body, http.StatusOK)

	// switching the registry off gives /v2 back to the served folder
	cfg.RegistryBaseFolder = ""
	if err := server.Reload(cfg, set.https, users, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	res, _ = server.reg(t, http.MethodGet, "/v2/_catalog", nil, asPusher)
	if res.Header.Get("Docker-Distribution-API-Version") != "" {
		t.Errorf("the registry still answers after it was switched off")
	}
}

func TestRegistryWarnsAboutTheFolderItHides(t *testing.T) {
	server := newRegistryServer(t, nil)
	server.mkdir(t, "v2")
	set := server.settings()
	users := []config.User{fullUser("john", "doe"), registryUser(pusher, pusherPassword)}
	if err := server.Reload(set.cfg, set.https, users, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if server.logs.findLike("the container registry answers /v2") == nil {
		t.Error("no warning about the hidden v2 folder")
	}
}

func TestParseChunkRange(t *testing.T) {
	cases := []struct {
		in         string
		start, end int64
		ok         bool
	}{
		{"0-4", 0, 4, true},
		{"bytes 5-9/10", 5, 9, true},
		{"bytes=5-9", 5, 9, true},
		{"5-", 0, 0, false},
		{"9-5", 0, 0, false},
		{"-1-4", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		start, end, ok := parseChunkRange(c.in)
		if ok != c.ok || ok && (start != c.start || end != c.end) {
			t.Errorf("parseChunkRange(%q) = %d, %d, %v", c.in, start, end, ok)
		}
	}
}

func FuzzParseRegistryPath(f *testing.F) {
	for _, seed := range []string{"/v2/", "/v2/_catalog", "/v2/a/b/manifests/latest",
		"/v2/a/blobs/uploads/", "/v2/a/blobs/uploads/0123", "/v2/a/../x/tags/list",
		"/v2/a/referrers/sha256:00", "/v2/a//b/blobs/x"} {
		f.Add(seed)
	}
	store := &registryStore{base: filepath.Join(string(filepath.Separator), "registry")}
	repositories := filepath.Join(store.base, "repositories") + string(filepath.Separator)
	f.Fuzz(func(t *testing.T, path string) {
		route, failure := parseRegistryPath(path)
		if failure != nil || route.name == "" {
			return
		}
		if !validRepository(route.name) {
			t.Fatalf("%q: accepted the name %q", path, route.name)
		}
		// whatever the name, its folder is inside the repositories
		if repo := store.repoPath(route.name); !strings.HasPrefix(repo, repositories) ||
			strings.Contains(repo, "..") {
			t.Fatalf("%q: the repository %q is kept at %q", path, route.name, repo)
		}
	})
}

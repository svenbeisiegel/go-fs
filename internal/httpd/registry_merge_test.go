package httpd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// platformsOf lists what each entry of an index is for, as platformKey writes
// it, mapped to the entry's digest.
func platformsOf(doc manifestDoc) map[string]digest.Digest {
	found := map[string]digest.Digest{}
	for _, entry := range doc.Manifests {
		found[platformKey(entry.Platform)] = entry.Digest
	}
	return found
}

func TestRegistryMergesPlatformsPushedToOneTag(t *testing.T) {
	server := newRegistryServer(t, nil)
	amd64 := server.pushImage(t, "app", "1.0", "linux/amd64", "1")
	arm64 := server.buildImage(t, "app", "linux/arm64", "1", false)
	res, body := server.pushManifest(t, "app", "1.0", arm64.mediaType, arm64.manifest)
	expectStatus(t, res, body, http.StatusCreated)
	// the push is answered with what was pushed, which is what docker checks
	if got := res.Header.Get("Docker-Content-Digest"); got != arm64.digest.String() {
		t.Errorf("Docker-Content-Digest = %q, want %s", got, arm64.digest)
	}

	res, index := server.pullManifest(t, "app", "1.0")
	if got := res.Header.Get("Content-Type"); got != v1.MediaTypeImageIndex {
		t.Errorf("Content-Type = %q", got)
	}
	platforms := platformsOf(index)
	if len(platforms) != 2 || platforms["linux/amd64"] != amd64.digest || platforms["linux/arm64"] != arm64.digest {
		t.Fatalf("index = %+v", platforms)
	}
	// each platform is still there by its own digest
	server.pullManifest(t, "app", amd64.digest.String())
	server.pullManifest(t, "app", arm64.digest.String())
	if server.logs.find("registry merged platform") == nil {
		t.Error("the merge was not recorded")
	}
}

func TestRegistryReplacesOnlyThePlatformPushedAgain(t *testing.T) {
	server := newRegistryServer(t, nil)
	server.pushImage(t, "app", "1.0", "linux/amd64", "1")
	arm64 := server.pushImage(t, "app", "1.0", "linux/arm64", "1")
	server.pushImage(t, "app", "1.0", "linux/arm/v7", "1")
	res, _ := server.pullManifest(t, "app", "1.0")
	oldIndex := res.Header.Get("Docker-Content-Digest")

	rebuilt := server.pushImage(t, "app", "1.0", "linux/amd64", "2")
	res, index := server.pullManifest(t, "app", "1.0")
	platforms := platformsOf(index)
	if len(platforms) != 3 || platforms["linux/amd64"] != rebuilt.digest || platforms["linux/arm64"] != arm64.digest {
		t.Fatalf("index = %+v", platforms)
	}
	// the index the registry built before is forgotten, since no tag points
	// to it and nobody pushed it
	res2, body := server.reg(t, http.MethodGet, "/v2/app/manifests/"+oldIndex, nil)
	expectStatus(t, res2, body, http.StatusNotFound)
	if res.Header.Get("Docker-Content-Digest") == oldIndex {
		t.Error("the tag still points to the old index")
	}
}

func TestRegistryReplacesASinglePlatformPushedAgain(t *testing.T) {
	server := newRegistryServer(t, nil)
	server.pushImage(t, "app", "1.0", "linux/amd64", "1")
	second := server.pushImage(t, "app", "1.0", "linux/amd64", "2")
	res, doc := server.pullManifest(t, "app", "1.0")
	if res.Header.Get("Docker-Content-Digest") != second.digest.String() || doc.Manifests != nil {
		t.Errorf("the tag is %s, want the second image", res.Header.Get("Docker-Content-Digest"))
	}
}

func TestRegistryTreatsArm64V8AsArm64(t *testing.T) {
	server := newRegistryServer(t, nil)
	server.pushImage(t, "app", "1.0", "linux/arm64", "1")
	second := server.pushImage(t, "app", "1.0", "linux/arm64/v8", "2")
	res, _ := server.pullManifest(t, "app", "1.0")
	if res.Header.Get("Docker-Content-Digest") != second.digest.String() {
		t.Error("arm64/v8 was merged next to arm64 instead of replacing it")
	}
}

func TestRegistryLetsAPushedIndexReplaceTheTag(t *testing.T) {
	server := newRegistryServer(t, nil)
	server.pushImage(t, "app", "1.0", "linux/amd64", "1")
	server.pushImage(t, "app", "1.0", "linux/arm64", "1")

	s390x := server.pushImage(t, "app", "s390x", "linux/s390x", "1")
	index, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{{MediaType: s390x.mediaType, Digest: s390x.digest,
			Size: int64(len(s390x.manifest)), Platform: &v1.Platform{OS: "linux", Architecture: "s390x"}}}})
	res, body := server.pushManifest(t, "app", "1.0", v1.MediaTypeImageIndex, index)
	expectStatus(t, res, body, http.StatusCreated)
	res, doc := server.pullManifest(t, "app", "1.0")
	if res.Header.Get("Docker-Content-Digest") != digest.FromBytes(index).String() || len(doc.Manifests) != 1 {
		t.Errorf("the pushed index did not replace the tag: %+v", platformsOf(doc))
	}
}

func TestRegistryDoesNotMergeAnArtifact(t *testing.T) {
	server := newRegistryServer(t, nil)
	server.pushImage(t, "app", "1.0", "linux/amd64", "1")
	config := server.pushBlob(t, "app", []byte(`{"anything":"else"}`))
	artifact, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageManifest,
		Config: &v1.Descriptor{MediaType: "application/vnd.example.config", Digest: config, Size: 19}})
	res, body := server.pushManifest(t, "app", "1.0", v1.MediaTypeImageManifest, artifact)
	expectStatus(t, res, body, http.StatusCreated)
	res, _ = server.pullManifest(t, "app", "1.0")
	if res.Header.Get("Docker-Content-Digest") != digest.FromBytes(artifact).String() {
		t.Error("an artifact was merged as if it were an image")
	}
}

func TestRegistryMergesDockerImagesIntoAManifestList(t *testing.T) {
	server := newRegistryServer(t, nil)
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		img := server.buildImage(t, "app", platform, "1", true)
		res, body := server.pushManifest(t, "app", "1.0", img.mediaType, img.manifest)
		expectStatus(t, res, body, http.StatusCreated)
	}
	res, doc := server.pullManifest(t, "app", "1.0")
	if got := res.Header.Get("Content-Type"); got != mediaTypeDockerList || doc.MediaType != mediaTypeDockerList {
		t.Errorf("Content-Type = %q, mediaType %q", got, doc.MediaType)
	}
	// an OCI image joining them makes it an OCI index
	server.pushImage(t, "app", "1.0", "linux/s390x", "1")
	res, doc = server.pullManifest(t, "app", "1.0")
	if got := res.Header.Get("Content-Type"); got != v1.MediaTypeImageIndex || len(doc.Manifests) != 3 {
		t.Errorf("Content-Type = %q with %d entries", got, len(doc.Manifests))
	}
}

func TestRegistryDropsTheAttestationOfAReplacedImage(t *testing.T) {
	server := newRegistryServer(t, nil)
	amd64 := server.pushImage(t, "app", amd64Tag, "linux/amd64", "1")
	arm64 := server.pushImage(t, "app", "arm64", "linux/arm64", "1")
	attestationFor := func(img image) v1.Descriptor {
		statement := server.pushBlob(t, "app", []byte("attestation of "+img.digest.String()))
		config := server.pushBlob(t, "app", []byte("{}"))
		manifest, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageManifest,
			Config: &v1.Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: config, Size: 2},
			Layers: []v1.Descriptor{{MediaType: "application/vnd.in-toto+json", Digest: statement, Size: 1}}})
		d := digest.FromBytes(manifest)
		res, body := server.pushManifest(t, "app", d.String(), v1.MediaTypeImageManifest, manifest)
		expectStatus(t, res, body, http.StatusCreated)
		return v1.Descriptor{MediaType: v1.MediaTypeImageManifest, Digest: d, Size: int64(len(manifest)),
			Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{annotationReferenceType: "attestation-manifest",
				annotationReferenceDigest: img.digest.String()}}
	}
	entry := func(img image, platform string) v1.Descriptor {
		os, arch, _ := strings.Cut(platform, "/")
		return v1.Descriptor{MediaType: img.mediaType, Digest: img.digest, Size: int64(len(img.manifest)),
			Platform: &v1.Platform{OS: os, Architecture: arch}}
	}
	amd64Attestation := attestationFor(amd64)
	arm64Attestation := attestationFor(arm64)
	index, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{entry(amd64, "linux/amd64"), entry(arm64, "linux/arm64"),
			amd64Attestation, arm64Attestation}})
	res, body := server.pushManifest(t, "app", "1.0", v1.MediaTypeImageIndex, index)
	expectStatus(t, res, body, http.StatusCreated)

	rebuilt := server.pushImage(t, "app", "1.0", "linux/amd64", "2")
	_, doc := server.pullManifest(t, "app", "1.0")
	var digests []digest.Digest
	for _, entry := range doc.Manifests {
		digests = append(digests, entry.Digest)
	}
	if len(digests) != 3 || !slices.Contains(digests, rebuilt.digest) || !slices.Contains(digests, arm64.digest) ||
		!slices.Contains(digests, arm64Attestation.Digest) || slices.Contains(digests, amd64Attestation.Digest) {
		t.Errorf("entries = %v", digests)
	}
}

// amd64Tag is a tag of its own for the amd64 image in the attestation test,
// so that pushing it merges nothing.
const amd64Tag = "amd64"

// TestRegistryMergesPlatformsPushedAtOnce pushes several platforms to one
// tag at the same moment, as a CI matrix does: none of them may be lost.
func TestRegistryMergesPlatformsPushedAtOnce(t *testing.T) {
	server := newRegistryServer(t, nil)
	platforms := []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/s390x", "linux/ppc64le", "linux/riscv64"}
	images := make([]image, len(platforms))
	for i, platform := range platforms {
		images[i] = server.buildImage(t, "app", platform, "1", false)
	}
	statuses := make(chan int, len(images))
	for _, img := range images {
		go func() {
			req, _ := http.NewRequest(http.MethodPut, server.url("/v2/app/manifests/1.0"), bytes.NewReader(img.manifest))
			req.Header.Set("Content-Type", img.mediaType)
			asPusher(req)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			_ = res.Body.Close()
			statuses <- res.StatusCode
		}()
	}
	for range images {
		if status := <-statuses; status != http.StatusCreated {
			t.Errorf("a push was answered %d", status)
		}
	}
	_, index := server.pullManifest(t, "app", "1.0")
	if got := platformsOf(index); len(got) != len(platforms) {
		t.Errorf("the index holds %d platforms, want %d: %v", len(got), len(platforms), got)
	}
}

func TestPlatformKey(t *testing.T) {
	cases := []struct {
		platform v1.Platform
		want     string
	}{
		{v1.Platform{OS: "linux", Architecture: "amd64"}, "linux/amd64"},
		{v1.Platform{OS: "linux", Architecture: "x86_64"}, "linux/amd64"},
		{v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, "linux/arm64"},
		{v1.Platform{OS: "linux", Architecture: "aarch64"}, "linux/arm64"},
		{v1.Platform{OS: "linux", Architecture: "arm"}, "linux/arm/v7"},
		{v1.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}, "linux/arm/v6"},
		{v1.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348.2340"}, "windows/amd64:10.0.20348.2340"},
	}
	for _, c := range cases {
		if got := platformKey(&c.platform); got != c.want {
			t.Errorf("platformKey(%+v) = %q, want %q", c.platform, got, c.want)
		}
	}
}

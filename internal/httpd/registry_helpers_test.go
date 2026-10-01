package httpd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"go-fs/internal/config"
)

// The account the registry tests push with: one that sets registry and
// nothing else. "john"/"doe" from newServer is an http account without it.
const (
	pusher         = "ci"
	pusherPassword = "secret"
)

func registryUser(name, password string) config.User {
	return config.User{Username: name, Password: password, Registry: true}
}

// newRegistryServer starts a server with the registry on, in a folder of its
// own, and the pushing account beside john.
func newRegistryServer(t *testing.T, tune func(*httpConfig)) *testServer {
	t.Helper()
	folder := t.TempDir()
	return newServer(t, func(cfg *httpConfig) {
		cfg.RegistryBaseFolder = folder
		cfg.Users = append(cfg.Users, registryUser(pusher, pusherPassword))
		if tune != nil {
			tune(cfg)
		}
	})
}

// registryBase is the folder the registry of a test server keeps its store in.
func (s *testServer) registryBase() string {
	return s.settings().registry.base
}

// reqOption changes a registry request before it is sent.
type reqOption func(*http.Request)

// as sends the request with Basic credentials.
func as(name, password string) reqOption {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(name+":"+password)))
	}
}

// asPusher is as for the account that sets registry.
var asPusher = as(pusher, pusherPassword)

func withHeader(key, value string) reqOption {
	return func(r *http.Request) { r.Header.Set(key, value) }
}

// reg sends a request to the registry and reads the whole answer.
func (s *testServer) reg(t *testing.T, method, path string, body []byte, options ...reqOption) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, s.url(path), reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, option := range options {
		option(req)
	}
	res := do(t, req)
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, data
}

// expectStatus fails a test whose response has another status, showing the
// body, which says why.
func expectStatus(t *testing.T, res *http.Response, body []byte, want int) {
	t.Helper()
	if res.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d: %s", res.Request.Method, res.Request.URL.Path,
			res.StatusCode, want, body)
	}
}

// errorCodeOf reads the first code of a registry error.
func errorCodeOf(t *testing.T, body []byte) string {
	t.Helper()
	var answer struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || len(answer.Errors) == 0 {
		t.Fatalf("not a registry error: %s", body)
	}
	return answer.Errors[0].Code
}

// pushBlob uploads a blob in one request and returns its digest.
func (s *testServer) pushBlob(t *testing.T, repo string, content []byte) digest.Digest {
	t.Helper()
	d := digest.FromBytes(content)
	res, body := s.reg(t, http.MethodPost, "/v2/"+repo+"/blobs/uploads/?digest="+d.String(), content, asPusher)
	expectStatus(t, res, body, http.StatusCreated)
	return d
}

// pushManifest puts a manifest under a tag or a digest.
func (s *testServer) pushManifest(t *testing.T, repo, ref, mediaType string, manifest []byte) (*http.Response, []byte) {
	t.Helper()
	return s.reg(t, http.MethodPut, "/v2/"+repo+"/manifests/"+ref, manifest, asPusher,
		withHeader("Content-Type", mediaType))
}

// image is a manifest of a test image together with what it is.
type image struct {
	manifest  []byte
	mediaType string
	digest    digest.Digest
	config    digest.Digest
	layer     digest.Digest
}

// buildImage uploads the configuration and the one layer of an image for a
// platform and returns its manifest, not yet pushed. salt tells two images
// for one platform apart.
func (s *testServer) buildImage(t *testing.T, repo, platform, salt string, docker bool) image {
	t.Helper()
	parts := strings.Split(platform, "/")
	config := map[string]any{"os": parts[0], "architecture": parts[1],
		"rootfs": map[string]any{"type": "layers"}}
	if len(parts) > 2 {
		config["variant"] = parts[2]
	}
	configBytes, _ := json.Marshal(config)
	configDigest := s.pushBlob(t, repo, configBytes)
	layer := fmt.Appendf(nil, "layer of %s %s", platform, salt)
	layerDigest := s.pushBlob(t, repo, layer)

	mediaType, configType, layerType := v1.MediaTypeImageManifest, v1.MediaTypeImageConfig, v1.MediaTypeImageLayerGzip
	if docker {
		mediaType, configType = mediaTypeDockerManifest, mediaTypeDockerConfig
		layerType = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	}
	manifest, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     mediaType,
		Config:        &v1.Descriptor{MediaType: configType, Digest: configDigest, Size: int64(len(configBytes))},
		Layers:        []v1.Descriptor{{MediaType: layerType, Digest: layerDigest, Size: int64(len(layer))}},
	})
	return image{manifest: manifest, mediaType: mediaType, digest: digest.FromBytes(manifest),
		config: configDigest, layer: layerDigest}
}

// pushImage builds an image and pushes it under ref.
func (s *testServer) pushImage(t *testing.T, repo, ref, platform, salt string) image {
	t.Helper()
	img := s.buildImage(t, repo, platform, salt, false)
	res, body := s.pushManifest(t, repo, ref, img.mediaType, img.manifest)
	expectStatus(t, res, body, http.StatusCreated)
	return img
}

// pullManifest fetches a manifest and decodes it.
func (s *testServer) pullManifest(t *testing.T, repo, ref string) (*http.Response, manifestDoc) {
	t.Helper()
	res, body := s.reg(t, http.MethodGet, "/v2/"+repo+"/manifests/"+ref, nil)
	expectStatus(t, res, body, http.StatusOK)
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("manifest: %v: %s", err, body)
	}
	return res, doc
}

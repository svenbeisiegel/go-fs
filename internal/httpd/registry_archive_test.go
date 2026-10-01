package httpd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ulikunitz/xz"
)

// --- building archives ------------------------------------------------------

// tarEntry is one entry of a test archive.
type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
	link     string
}

func file(name string, body []byte) tarEntry {
	return tarEntry{name: name, body: body, typeflag: tar.TypeReg}
}

func symlink(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeSymlink, link: target}
}

func hardlink(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeLink, link: target}
}

func folder(name string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeDir}
}

func tarOf(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Linkname: entry.link, Mode: 0o644,
			Size: int64(len(entry.body))}
		if entry.typeflag == tar.TypeDir {
			header.Mode = 0o755
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// layerTar is a layer: a tar holding one file.
func layerTar(t *testing.T, salt string) []byte {
	return tarOf(t, file("app/"+salt, []byte("content of "+salt)))
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	_, _ = writer.Write(data)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func zstded(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(data)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func xzed(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer, err := xz.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(data)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// configOf is the configuration of an image for a platform, with the
// digests of its uncompressed layers.
func configOf(platform string, diffIDs ...digest.Digest) []byte {
	parts := strings.Split(platform, "/")
	config := map[string]any{"os": parts[0], "architecture": parts[1],
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}}
	data, _ := json.Marshal(config)
	return data
}

func describe(mediaType string, data []byte) v1.Descriptor {
	return v1.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
}

func blobName(d digest.Digest) string {
	return "blobs/sha256/" + d.Encoded()
}

// ociImage is an image of an OCI layout: its manifest, and the blobs it
// refers to, the manifest among them.
type ociImage struct {
	manifest []byte
	desc     v1.Descriptor
	blobs    map[string][]byte
}

func newOCIImage(t *testing.T, platform, salt string) ociImage {
	t.Helper()
	layer := gzipped(t, layerTar(t, salt))
	config := configOf(platform, digest.FromBytes(layerTar(t, salt)))
	manifest, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageManifest,
		Config: ptr(describe(v1.MediaTypeImageConfig, config)),
		Layers: []v1.Descriptor{describe(v1.MediaTypeImageLayerGzip, layer)}})
	desc := describe(v1.MediaTypeImageManifest, manifest)
	parts := strings.Split(platform, "/")
	desc.Platform = &v1.Platform{OS: parts[0], Architecture: parts[1]}
	return ociImage{manifest: manifest, desc: desc, blobs: map[string][]byte{
		blobName(digest.FromBytes(layer)):    layer,
		blobName(digest.FromBytes(config)):   config,
		blobName(digest.FromBytes(manifest)): manifest,
	}}
}

func ptr[T any](v T) *T { return &v }

// layoutEntries are the files of an OCI layout whose index.json names
// entries, with the blobs given.
func layoutEntries(entries []v1.Descriptor, blobs ...map[string][]byte) []tarEntry {
	index, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex, Manifests: entries})
	out := []tarEntry{
		file("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)),
		file("index.json", index),
	}
	seen := map[string]bool{}
	for _, set := range blobs {
		for name, data := range set {
			if !seen[name] {
				seen[name] = true
				out = append(out, file(name, data))
			}
		}
	}
	return out
}

func named(desc v1.Descriptor, annotations ...string) v1.Descriptor {
	desc.Annotations = map[string]string{}
	for i := 0; i+1 < len(annotations); i += 2 {
		desc.Annotations[annotations[i]] = annotations[i+1]
	}
	return desc
}

// readArchive reads an archive the way an import does.
func readArchive(t *testing.T, data []byte, name string) (*imageArchive, string, error) {
	t.Helper()
	dir := t.TempDir()
	archive, err := readImageArchive(context.Background(), bytes.NewReader(data), dir, name, 0)
	return archive, dir, err
}

func mustReadArchive(t *testing.T, data []byte, name string) *imageArchive {
	t.Helper()
	archive, _, err := readArchive(t, data, name)
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}
	return archive
}

func expectRefusal(t *testing.T, data []byte, want string) {
	t.Helper()
	_, dir, err := readArchive(t, data, "image.tar")
	if err == nil {
		t.Fatalf("the archive was read; want an error saying %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q, want one saying %q", err, want)
	}
	if entries, _ := os.ReadDir(dir); len(entries) > 0 {
		t.Errorf("a refused archive left %d files staged", len(entries))
	}
}

// --- docker save ------------------------------------------------------------

// dockerSave24 is what docker save writes before 25: a folder per layer, the
// configurations beside them, and manifest.json. The second image shares the
// first one's layer through a link, as docker writes a layer it has once.
func dockerSave24(t *testing.T) ([]byte, []byte, []byte) {
	layerA, layerB := layerTar(t, "a"), layerTar(t, "b")
	config1 := configOf("linux/amd64", digest.FromBytes(layerA))
	config2 := configOf("linux/arm64", digest.FromBytes(layerA), digest.FromBytes(layerB))
	c1, c2 := digest.FromBytes(config1).Encoded(), digest.FromBytes(config2).Encoded()
	manifest, _ := json.Marshal([]dockerEntry{
		{Config: c1 + ".json", RepoTags: []string{"alpine:latest"}, Layers: []string{"v1a/layer.tar"}},
		{Config: c2 + ".json", RepoTags: []string{"localhost/foo:1", "registry.example.com:5000/team/foo:2"},
			Layers: []string{"v1c/layer.tar", "v1b/layer.tar"}},
	})
	data := tarOf(t,
		folder("v1a/"), file("v1a/VERSION", []byte("1.0")), file("v1a/json", []byte("{}")),
		file("v1a/layer.tar", layerA),
		folder("v1b/"), file("v1b/layer.tar", layerB),
		folder("v1c/"), symlink("v1c/layer.tar", "../v1a/layer.tar"),
		file(c1+".json", config1), file(c2+".json", config2),
		file("repositories", []byte(`{"alpine":{"latest":"v1a"}}`)),
		file("manifest.json", manifest))
	return data, layerA, layerB
}

func TestImportArchiveDockerSave(t *testing.T) {
	data, layerA, layerB := dockerSave24(t)
	archive := mustReadArchive(t, data, "images.tar")
	if archive.format != archiveDocker || len(archive.images) != 2 {
		t.Fatalf("format %s with %d images", archive.format, len(archive.images))
	}
	first, second := archive.images[0], archive.images[1]
	if first.top.mediaType != mediaTypeDockerManifest {
		t.Errorf("the manifest is %s", first.top.mediaType)
	}
	if layer := first.top.doc.Layers[0]; layer.MediaType != mediaTypeDockerLayer || layer.Digest != digest.FromBytes(layerA) {
		t.Errorf("the layer is %+v", layer)
	}
	if got := strings.Join(first.targets, " "); got != "library/alpine:latest" {
		t.Errorf("the first image goes to %s", got)
	}
	if got := strings.Join(second.targets, " "); got != "foo:1 team/foo:2" {
		t.Errorf("the second image goes to %s", got)
	}
	if got := strings.Join(second.platforms, " "); got != "linux/arm64" {
		t.Errorf("the second image is for %s", got)
	}
	if len(second.blobs) != 3 || second.blobs[2].Digest != digest.FromBytes(layerB) {
		t.Errorf("the second image refers to %+v", second.blobs)
	}
	if first.note == "" {
		t.Error("a built manifest is not noted")
	}
	if len(archive.checks) != 0 {
		t.Errorf("uncompressed layers are checked again: %d", len(archive.checks))
	}
	// the shared layer is staged once
	if archive.blobs[digest.FromBytes(layerA)] == nil {
		t.Error("the shared layer is not staged")
	}
}

// crane writes the configuration under its digest and gzipped layers.
func TestImportArchiveCraneTarball(t *testing.T) {
	layer := layerTar(t, "crane")
	compressed := gzipped(t, layer)
	config := configOf("linux/amd64", digest.FromBytes(layer))
	configName := digest.FromBytes(config).String()
	layerName := digest.FromBytes(compressed).Encoded() + ".tar.gz"
	manifest, _ := json.Marshal([]dockerEntry{{Config: configName, RepoTags: []string{"ghcr.io/org/app:v1"},
		Layers: []string{layerName}}})
	archive := mustReadArchive(t, tarOf(t, file(configName, config), file(layerName, compressed),
		file("manifest.json", manifest)), "app.tar")
	image := archive.images[0]
	if got := image.top.doc.Layers[0]; got.MediaType != mediaTypeDockerLayerGzip || got.Digest != digest.FromBytes(compressed) {
		t.Errorf("the layer is %+v", got)
	}
	if got := strings.Join(image.targets, " "); got != "org/app:v1" {
		t.Errorf("the image goes to %s", got)
	}
	if err := archive.verifyLayers(context.Background(), nil); err != nil {
		t.Errorf("verifying: %v", err)
	}

	// a configuration that says otherwise of the layer is found out
	wrong := configOf("linux/amd64", digest.FromString("something else"))
	manifest, _ = json.Marshal([]dockerEntry{{Config: "config.json", Layers: []string{layerName}}})
	archive = mustReadArchive(t, tarOf(t, file("config.json", wrong), file(layerName, compressed),
		file("manifest.json", manifest)), "app.tar")
	if err := archive.verifyLayers(context.Background(), nil); err == nil ||
		!strings.Contains(err.Error(), "not what its configuration says") {
		t.Errorf("a wrong layer verified: %v", err)
	}
}

// A zstd layer needs a manifest of OCI's, which has a media type for it.
func TestImportArchiveZstdLayer(t *testing.T) {
	layer := layerTar(t, "zstd")
	compressed := zstded(t, layer)
	config := configOf("linux/amd64", digest.FromBytes(layer))
	manifest, _ := json.Marshal([]dockerEntry{{Config: "c.json", Layers: []string{"l.tar.zst"}}})
	archive := mustReadArchive(t, tarOf(t, file("c.json", config), file("l.tar.zst", compressed),
		file("manifest.json", manifest)), "x.tar")
	image := archive.images[0]
	if image.top.mediaType != v1.MediaTypeImageManifest || image.top.doc.Config.MediaType != v1.MediaTypeImageConfig ||
		image.top.doc.Layers[0].MediaType != v1.MediaTypeImageLayerZstd {
		t.Errorf("the manifest is %s", image.top.body)
	}
	if err := archive.verifyLayers(context.Background(), nil); err != nil {
		t.Errorf("verifying: %v", err)
	}
	if len(image.targets) != 0 || len(image.names) != 0 {
		t.Errorf("an image without a name is named %v → %v", image.names, image.targets)
	}
}

// A layer that is a link out of the archive is not there.
func TestImportArchiveLinkOutside(t *testing.T) {
	layer := layerTar(t, "out")
	config := configOf("linux/amd64", digest.FromBytes(layer))
	manifest, _ := json.Marshal([]dockerEntry{{Config: "c.json", Layers: []string{"x/layer.tar"}}})
	expectRefusal(t, tarOf(t, file("c.json", config), symlink("x/layer.tar", "../../layer.tar"),
		file("manifest.json", manifest)), "links outside the archive")
}

// podman save -m keeps a layer once, as <diffid>.tar, and links to it.
func TestImportArchivePodmanMultiImage(t *testing.T) {
	layer := layerTar(t, "p")
	diffID := digest.FromBytes(layer)
	configA, configB := configOf("linux/amd64", diffID), configOf("linux/s390x", diffID)
	manifest, _ := json.Marshal([]dockerEntry{
		{Config: "a.json", RepoTags: []string{"localhost/a:1"}, Layers: []string{"x/layer.tar"}},
		{Config: "b.json", RepoTags: []string{"docker.io/library/b:2"}, Layers: []string{"y/layer.tar"}},
	})
	archive := mustReadArchive(t, tarOf(t,
		file(diffID.Encoded()+".tar", layer),
		symlink("x/layer.tar", "../"+diffID.Encoded()+".tar"),
		hardlink("y/layer.tar", diffID.Encoded()+".tar"),
		file("a.json", configA), file("b.json", configB), file("manifest.json", manifest)), "p.tar")
	var targets []string
	for _, image := range archive.images {
		targets = append(targets, image.targets...)
	}
	if got := strings.Join(targets, " "); got != "a:1 library/b:2" {
		t.Errorf("the images go to %s", got)
	}
}

// docker 25 lists every layer as a source, which only matters for one
// fetched from elsewhere.
func TestImportArchiveForeignLayerSource(t *testing.T) {
	layer := layerTar(t, "win")
	diffID := digest.FromBytes(layer)
	foreign := v1.Descriptor{MediaType: "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
		Digest: digest.FromString("compressed elsewhere"), Size: 1234, URLs: []string{"https://example.com/layer"}}
	plain := configOf("windows/amd64", diffID)
	manifest, _ := json.Marshal([]dockerEntry{{Config: "c.json", Layers: []string{"blobs/sha256/" + diffID.Encoded()},
		LayerSources: map[digest.Digest]v1.Descriptor{diffID: foreign}}})
	archive := mustReadArchive(t, tarOf(t, file("c.json", plain), file("blobs/sha256/"+diffID.Encoded(), layer),
		file("manifest.json", manifest)), "w.tar")
	image := archive.images[0]
	if got := image.top.doc.Layers[0]; got.Digest != foreign.Digest || len(got.URLs) != 1 {
		t.Errorf("the foreign layer is %+v", got)
	}
	if len(image.blobs) != 1 {
		t.Errorf("a foreign layer is to be stored: %+v", image.blobs)
	}
}

// --- OCI layouts ------------------------------------------------------------

// docker save 25 writes a layout and manifest.json both, and names an image
// once for each tag.
func TestImportArchiveDockerSave25(t *testing.T) {
	img := newOCIImage(t, "linux/amd64", "25")
	legacy, _ := json.Marshal([]dockerEntry{{Config: "nonsense", Layers: []string{"nonsense"}}})
	entries := layoutEntries([]v1.Descriptor{
		named(img.desc, annotationContainerdName, "docker.io/library/app:1", v1.AnnotationRefName, "1"),
		named(img.desc, annotationContainerdName, "docker.io/library/app:2", v1.AnnotationRefName, "2"),
	}, img.blobs)
	entries = append(entries, file("manifest.json", legacy))
	archive := mustReadArchive(t, tarOf(t, entries...), "app.tar")
	if archive.format != archiveOCI || len(archive.images) != 1 {
		t.Fatalf("format %s with %d images", archive.format, len(archive.images))
	}
	image := archive.images[0]
	if image.top.digest != img.desc.Digest {
		t.Errorf("the digest changed to %s", image.top.digest)
	}
	if got := strings.Join(image.targets, " "); got != "library/app:1 library/app:2" {
		t.Errorf("the image goes to %s", got)
	}
	if got := strings.Join(image.platforms, " "); got != "linux/amd64" {
		t.Errorf("the image is for %s", got)
	}
	if image.note != "" {
		t.Errorf("an image kept as it was is noted: %s", image.note)
	}
}

// skopeo names an image of an oci-archive by its tag alone, so the archive's
// name is the repository.
func TestImportArchiveTagOnly(t *testing.T) {
	img := newOCIImage(t, "linux/amd64", "skopeo")
	archive := mustReadArchive(t, tarOf(t, layoutEntries([]v1.Descriptor{
		named(img.desc, v1.AnnotationRefName, "v3")}, img.blobs)...), "My Service.oci.tar.gz")
	if got := strings.Join(archive.images[0].targets, " "); got != "my-service.oci:v3" {
		t.Errorf("the image goes to %s", got)
	}
}

// containerd exports the index an image was pulled with whole, with only
// the platforms it was asked for.
func TestImportArchiveSparseIndex(t *testing.T) {
	amd, arm := newOCIImage(t, "linux/amd64", "amd"), newOCIImage(t, "linux/arm64", "arm")
	attestation := func(of ociImage, salt string) ociImage {
		att := newOCIImage(t, "unknown/unknown", salt)
		att.desc = named(att.desc, annotationReferenceType, "attestation-manifest",
			annotationReferenceDigest, of.desc.Digest.String())
		return att
	}
	amdAtt, armAtt := attestation(amd, "amd-att"), attestation(arm, "arm-att")
	index, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{amd.desc, arm.desc, amdAtt.desc, armAtt.desc}})
	indexDesc := describe(v1.MediaTypeImageIndex, index)
	entries := layoutEntries([]v1.Descriptor{named(indexDesc, annotationContainerdName, "docker.io/library/multi:1")},
		amd.blobs, amdAtt.blobs, map[string][]byte{blobName(indexDesc.Digest): index})
	archive := mustReadArchive(t, tarOf(t, entries...), "multi.tar")
	image := archive.images[0]
	if image.top.digest == indexDesc.Digest {
		t.Error("an index with platforms missing was kept as it was")
	}
	if got := strings.Join(image.platforms, " "); got != "linux/amd64" {
		t.Errorf("the index is for %s", got)
	}
	if len(image.children) != 2 || len(image.top.doc.Manifests) != 2 {
		t.Errorf("the index keeps %d entries and %d children", len(image.top.doc.Manifests), len(image.children))
	}
	if image.note == "" {
		t.Error("a cut index is not noted")
	}

	// whole, it stays as it is
	entries = layoutEntries([]v1.Descriptor{indexDesc}, amd.blobs, arm.blobs, amdAtt.blobs, armAtt.blobs,
		map[string][]byte{blobName(indexDesc.Digest): index})
	archive = mustReadArchive(t, tarOf(t, entries...), "multi.tar")
	if got := archive.images[0]; got.top.digest != indexDesc.Digest || len(got.children) != 4 {
		t.Errorf("a whole index became %s with %d children", got.top.digest, len(got.children))
	}
}

// --- what wraps the archive -------------------------------------------------

func TestImportArchiveCompression(t *testing.T) {
	img := newOCIImage(t, "linux/amd64", "c")
	plain := tarOf(t, layoutEntries([]v1.Descriptor{img.desc}, img.blobs)...)
	for name, data := range map[string][]byte{
		"gzip":         gzipped(t, plain),
		"zstd":         zstded(t, plain),
		"xz":           xzed(t, plain),
		"zstd in gzip": gzipped(t, zstded(t, plain)),
	} {
		t.Run(name, func(t *testing.T) {
			if archive := mustReadArchive(t, data, "c.tar"); archive.images[0].top.digest != img.desc.Digest {
				t.Errorf("read %s", archive.images[0].top.digest)
			}
		})
	}
	expectRefusal(t, gzipped(t, gzipped(t, gzipped(t, plain))), "compressed more than twice")

	// the standard library writes no bzip2, so this is one made by bzip2 -9
	stream, _ := hex.DecodeString("425a6839314159265359555a44f70000021980400010001264c0102000220069ea" +
		"100305d3b62183c5dc914e14241556913dc0")
	if kind := compressionOf(stream); kind != compressionBzip2 {
		t.Fatalf("bzip2 is taken for %q", kind)
	}
	reader, done, err := decompress(compressionBzip2, bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if got, _ := io.ReadAll(reader); string(got) != "hello bzip2" {
		t.Errorf("bzip2 read %q", got)
	}
}

// tar -c of a folder puts everything in it, and on macOS adds a ._ file of
// attributes beside each name, the folder's own among them.
func TestImportArchiveInFolder(t *testing.T) {
	img := newOCIImage(t, "linux/amd64", "f")
	var entries []tarEntry
	entries = append(entries, file("._image", []byte("attributes")), folder("image/"), file("image/.DS_Store", nil))
	for _, entry := range layoutEntries([]v1.Descriptor{img.desc}, img.blobs) {
		name := entry.name
		entry.name = "image/" + name
		entries = append(entries, file("image/._"+path.Base(name), []byte("attributes")), entry)
	}
	if archive := mustReadArchive(t, tarOf(t, entries...), "f.tar"); len(archive.images) != 1 {
		t.Errorf("%d images", len(archive.images))
	}
}

// --- what is refused --------------------------------------------------------

func TestImportArchiveRefusals(t *testing.T) {
	img := newOCIImage(t, "linux/amd64", "r")
	layout := func(entries []v1.Descriptor, blobs ...map[string][]byte) []byte {
		return tarOf(t, layoutEntries(entries, blobs...)...)
	}
	damaged := map[string][]byte{}
	for name, data := range img.blobs {
		damaged[name] = data
	}
	for name := range damaged {
		if strings.Contains(name, img.desc.Digest.Encoded()) {
			continue
		}
		damaged[name] = []byte("not what it was")
		break
	}
	inner := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	nested, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{describe(v1.MediaTypeImageIndex, inner)}})
	nestedDesc := describe(v1.MediaTypeImageIndex, nested)

	many := make([]tarEntry, maxArchiveEntries+1)
	for i := range many {
		many[i] = file(fmt.Sprintf("f%d", i), nil)
	}

	for _, c := range []struct {
		name string
		data []byte
		want string
	}{
		{"file system", tarOf(t, file("etc/passwd", []byte("root:x:0:0")), file("bin/ls", nil)), "docker export"},
		{"file system in a folder", tarOf(t, file("rootfs/usr/bin/env", nil)), "docker export"},
		{"device", tarOf(t, tarEntry{name: "dev/null", typeflag: tar.TypeChar}), "docker export"},
		{"too many files", tarOf(t, many...), "more than 10000 files"},
		{"docker before 1.10", tarOf(t, file("repositories", []byte(`{}`)), file("abc/json", []byte(`{}`)),
			file("abc/layer.tar", nil)), "older than 1.10"},
		{"dir: copy", tarOf(t, file("manifest.json", []byte(`{"schemaVersion":2}`)), file("version", []byte("1.1"))),
			"dir: copy"},
		{"nothing", tarOf(t, file("readme.txt", []byte("hi"))), "no image in the archive"},
		{"sif", append([]byte("#!/usr/bin/env run-singularity\n\x00"), make([]byte, 600)...), "SIF"},
		{"squashfs", append([]byte("hsqs"), make([]byte, 600)...), "squashfs"},
		{"zip", append([]byte("PK\x03\x04"), make([]byte, 600)...), "zip"},
		{"junk", bytes.Repeat([]byte("junk"), 300), "not a tar archive"},
		{"leaving", tarOf(t, file("../x", nil)), "leaves it"},
		{"absolute", tarOf(t, file("/etc/x", nil)), "leaves it"},
		{"file system with absolute links", tarOf(t, symlink("bin/arch", "/bin/busybox"),
			symlink("bin/sh", "/bin/busybox")), "docker export"},
		{"no index.json", tarOf(t, file("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))), "no index.json"},
		{"damaged blob", layout([]v1.Descriptor{img.desc}, damaged), "the archive is damaged"},
		{"missing manifest", layout([]v1.Descriptor{img.desc}), "is not in the archive"},
		{"nested index", layout([]v1.Descriptor{nestedDesc},
			map[string][]byte{blobName(nestedDesc.Digest): nested, blobName(digest.FromBytes(inner)): inner}),
			"an index inside an index"},
	} {
		t.Run(c.name, func(t *testing.T) { expectRefusal(t, c.data, c.want) })
	}
}

func TestImportArchiveEntryLimit(t *testing.T) {
	img := newOCIImage(t, "linux/amd64", "big")
	_, err := readImageArchive(context.Background(),
		bytes.NewReader(tarOf(t, layoutEntries([]v1.Descriptor{img.desc}, img.blobs)...)), t.TempDir(), "x.tar", 64)
	if err == nil || !strings.Contains(err.Error(), "maxUploadSize") {
		t.Errorf("a file over the limit: %v", err)
	}
}

func TestImportArchiveStopped(t *testing.T) {
	img := newOCIImage(t, "linux/amd64", "stop")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := readImageArchive(ctx, bytes.NewReader(tarOf(t, layoutEntries([]v1.Descriptor{img.desc}, img.blobs)...)),
		t.TempDir(), "x.tar", 0)
	if err == nil {
		t.Error("a stopped import read on")
	}
}

func TestArchiveRepository(t *testing.T) {
	for file, want := range map[string]string{
		"alpine.tar":             "alpine",
		"my-app_v1.tar.gz":       "my-app_v1",
		"Alpine Image.tar.zst":   "alpine-image",
		"k3s-airgap.amd64.tzst":  "k3s-airgap.amd64",
		"/some/folder/redis.tgz": "redis",
		"___.tar":                "",
	} {
		if got := archiveRepository(file); got != want {
			t.Errorf("%s suggests %q, want %q", file, got, want)
		}
	}
	if !isArchiveName("x.tar.zst") || isArchiveName("x.zip") || isArchiveName(".tar") {
		t.Error("isArchiveName")
	}
}

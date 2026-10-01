package httpd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ulikunitz/xz"
)

// An image archive is what docker save, podman save, skopeo copy, ctr images
// export, nerdctl save, crane pull and their kind write: a tar, often
// compressed, in one of two shapes.
//
//	OCI image layout   oci-layout, index.json, blobs/<alg>/<hex>
//	docker save        manifest.json, an array of {Config, RepoTags, Layers}
//
// The first is what docker save writes since 25, what containerd writes, and
// what an oci-archive is. Its manifests are stored as they are, so an image
// keeps its digest. The second is what docker save wrote before, what podman
// writes as a docker-archive and what crane pull writes by default. It has
// no manifest, only the image's configuration and its layers, so the
// registry builds one, and the image gets a digest of its own. Where an
// archive has both, as docker save 25 writes it, the layout is the one read.
//
// The entries of a tar come in whatever order its writer chose, and the
// manifest.json of docker save comes last, so what an archive holds is known
// only once all of it has been read. It is read once: every file is staged
// in a folder of its own under _uploads while it is hashed, on the same
// filesystem as the blobs, so that storing a layer later is a rename.

// The kinds of compression an archive may come in.
const (
	compressionGzip  = "gzip"
	compressionZstd  = "zstd"
	compressionXz    = "xz"
	compressionBzip2 = "bzip2"
)

// The formats an archive may be in.
const (
	archiveOCI    = "oci"
	archiveDocker = "docker"
)

const (
	// maxArchiveEntries bounds the files of an archive. An image has a file
	// per layer and a few more; a tree of tens of thousands is a container's
	// file system.
	maxArchiveEntries = 10000
	// maxArchiveImages bounds the images one archive offers.
	maxArchiveImages = 256
	// maxArchivePath is the longest name an entry may have.
	maxArchivePath = 1024
	// maxArchiveLinks is how many links a name may go through.
	maxArchiveLinks = 8
	// maxCompression is how many layers of compression are taken off: a
	// gzip of a zstd is still an archive someone made, a third is not.
	maxCompression = 2
	// maxLayoutFile bounds oci-layout, which holds a version and nothing else.
	maxLayoutFile = 4 << 10
	// zstdWindow is the largest window a zstd stream may ask for, which
	// zstd --long=28 writes.
	zstdWindow = 1 << 28
)

// Media types of layers the image-spec module does not name.
const (
	mediaTypeDockerLayer     = "application/vnd.docker.image.rootfs.diff.tar"
	mediaTypeDockerLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	// annotationContainerdName is the full reference containerd names an
	// image of an index.json by.
	annotationContainerdName = "io.containerd.image.name"
)

// errArchiveMissing is a file the archive does not have.
var errArchiveMissing = errors.New("not in the archive")

// stagedFile is a file of an archive as it was staged.
type stagedFile struct {
	path   string
	size   int64
	sha256 digest.Digest
	// sha512 is there for a file under blobs/sha512, the one place a digest
	// in that algorithm is looked for.
	sha512 digest.Digest
	// magic is how the file starts, which says whether a layer is compressed.
	magic []byte
}

// archiveImage is an image an archive offers: one manifest or index, under
// the names the archive gives it.
type archiveImage struct {
	// names are the references the archive names the image by, as it writes
	// them: a full reference, or a tag alone.
	names []string
	// targets are where the registry would store the image by default, as
	// repository:tag, one for each name it could read one from.
	targets  []string
	top      pulledManifest
	children []pulledManifest
	// blobs are what the manifests refer to, the configurations and layers.
	blobs     []v1.Descriptor
	platforms []string
	// note says how the image differs from the one the archive was saved
	// from: an index cut to the platforms the archive has, or a manifest
	// built for a docker save.
	note string
}

// layerCheck is a compressed layer of a docker save, whose content has to be
// checked against what its configuration says it is once it is uncompressed.
type layerCheck struct {
	file        *stagedFile
	compression string
	diffID      digest.Digest
	label       string
}

// imageArchive is what reading an archive found.
type imageArchive struct {
	format string
	images []archiveImage

	dir string
	// name is the file the archive was read from, which names an image that
	// the archive only gives a tag.
	name   string
	files  map[string]*stagedFile
	links  map[string]string
	blobs  map[digest.Digest]*stagedFile
	prefix string
	checks []layerCheck
}

// blob finds a staged file by its digest.
func (a *imageArchive) blob(d digest.Digest) (*stagedFile, bool) {
	file, ok := a.blobs[d]
	return file, ok
}

// verifySize is how many bytes verifyLayers reads.
func (a *imageArchive) verifySize() int64 {
	var size int64
	for _, check := range a.checks {
		size += check.file.size
	}
	return size
}

// readImageArchive reads an archive into dir and finds the images in it.
// name is the file it came from. An archive that is not one, or is damaged,
// is an error that says why, and leaves dir empty.
func readImageArchive(ctx context.Context, r io.Reader, dir, name string, maxEntrySize int64) (*imageArchive, error) {
	a := &imageArchive{dir: dir, name: name, files: map[string]*stagedFile{},
		links: map[string]string{}, blobs: map[digest.Digest]*stagedFile{}}
	err := a.read(ctx, r, maxEntrySize)
	if err == nil {
		err = a.resolve()
	}
	if err != nil {
		a.discard()
		return nil, err
	}
	return a, nil
}

// discard removes what was staged.
func (a *imageArchive) discard() {
	entries, _ := os.ReadDir(a.dir)
	for _, entry := range entries {
		_ = os.RemoveAll(filepath.Join(a.dir, entry.Name()))
	}
}

// --- reading the tar --------------------------------------------------------

// contextReader stops a read once its context is done.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// compressionOf names the compression a stream starts with, "" for none.
func compressionOf(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return compressionGzip
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return compressionZstd
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return compressionXz
	case bytes.HasPrefix(head, []byte("BZh")):
		return compressionBzip2
	}
	return ""
}

// decompress reads a stream in a compression.
func decompress(kind string, r io.Reader) (io.Reader, func(), error) {
	switch kind {
	case compressionGzip:
		reader, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, err
		}
		return reader, func() { _ = reader.Close() }, nil
	case compressionZstd:
		reader, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(zstdWindow))
		if err != nil {
			return nil, nil, err
		}
		return reader, reader.Close, nil
	case compressionXz:
		reader, err := xz.NewReader(r)
		if err != nil {
			return nil, nil, err
		}
		return reader, func() {}, nil
	case compressionBzip2:
		return bzip2.NewReader(r), func() {}, nil
	}
	return nil, nil, fmt.Errorf("%s is not a compression", kind)
}

// openArchive takes the compression off an archive and makes sure a tar is
// what is left. What else people take for an image is named, so the error
// says what to do instead.
func openArchive(r io.Reader) (io.Reader, func(), error) {
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	reader := bufio.NewReaderSize(r, 64<<10)
	for level := 0; ; level++ {
		head, _ := reader.Peek(512)
		kind := compressionOf(head)
		if kind == "" {
			break
		}
		if level == maxCompression {
			closeAll()
			return nil, nil, errors.New("the archive is compressed more than twice over")
		}
		inner, done, err := decompress(kind, reader)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("the archive cannot be read as %s: %w", kind, err)
		}
		closers = append(closers, done)
		reader = bufio.NewReaderSize(inner, 64<<10)
	}
	head, err := reader.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) {
		closeAll()
		return nil, nil, fmt.Errorf("the archive cannot be read: %w", err)
	}
	switch {
	case isTarHeader(head):
		return reader, closeAll, nil
	case bytes.HasPrefix(head, []byte("hsqs")):
		err = errors.New("this is a squashfs file system, not an image archive")
	case bytes.HasPrefix(head, []byte("#!/usr/bin/env run-singularity")) ||
		(len(head) > 41 && string(head[32:41]) == "SIF_MAGIC"):
		err = errors.New("this is a Singularity or Apptainer image (SIF), not a container image archive: " +
			"build an OCI image from it, or push it with singularity push")
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		err = errors.New("a zip file cannot be imported: save the image as a tar, " +
			"with docker save or skopeo copy to oci-archive:")
	default:
		err = errors.New("this is not a tar archive, plain or compressed with gzip, zstd, xz or bzip2")
	}
	closeAll()
	return nil, nil, err
}

// isTarHeader reports whether a block is the header of a tar entry: one with
// the magic of ustar, or of the format before it, whose checksum is right.
func isTarHeader(block []byte) bool {
	if len(block) < 512 {
		return false
	}
	if string(block[257:262]) == "ustar" {
		return true
	}
	field := strings.TrimRight(strings.TrimSpace(string(block[148:156])), "\x00 ")
	want, err := strconv.ParseInt(field, 8, 64)
	if err != nil {
		return false
	}
	var sum int64
	for i, b := range block[:512] {
		if i >= 148 && i < 156 {
			b = ' '
		}
		sum += int64(b)
	}
	return sum == want
}

// errFileSystem is a tar of a container's file system, which is what people
// take for an image most often.
var errFileSystem = errors.New("this is the file system of a container, as docker export or crane export " +
	"writes it, not an image: save the image with docker save, or make one of it with docker import")

// fileSystemMarks are the files a container's file system has and an image
// archive never does.
var fileSystemMarks = regexp.MustCompile(`^(etc/passwd|etc/os-release|bin/sh|usr/bin/.+|usr/lib/.+)$`)

// isFileSystemFile reports a name that only a container's file system has,
// at its root or one folder down.
func isFileSystemFile(name string) bool {
	if fileSystemMarks.MatchString(name) {
		return true
	}
	_, rest, found := strings.Cut(name, "/")
	return found && fileSystemMarks.MatchString(rest)
}

// isFinderFile reports what macOS adds to a tar it makes of a folder: the
// ._ file beside each name, which holds its extended attributes, and the
// .DS_Store of a folder Finder opened. Neither is part of what was packed.
func isFinderFile(name string) bool {
	base := path.Base(name)
	return strings.HasPrefix(base, "._") || base == ".DS_Store"
}

// cleanEntryName is the name of an entry as a path inside the archive, or an
// error for one that would leave it. The root itself is "".
func cleanEntryName(name string) (string, error) {
	if len(name) > maxArchivePath || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("the archive names %q, which is not a name a file can have", name)
	}
	trimmed := strings.TrimPrefix(name, "./")
	if strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("the archive names %q, which leaves it", name)
	}
	clean := path.Clean(trimmed)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("the archive names %q, which leaves it", name)
	}
	if clean == "." {
		return "", nil
	}
	return clean, nil
}

// read stages every file of the archive.
func (a *imageArchive) read(ctx context.Context, r io.Reader, maxEntrySize int64) error {
	stream, done, err := openArchive(contextReader{ctx: ctx, r: r})
	if err != nil {
		return err
	}
	defer done()
	reader := tar.NewReader(stream)
	names := map[string]bool{}
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("the archive cannot be read: %w", err)
		}
		name, err := cleanEntryName(header.Name)
		if err != nil {
			return err
		}
		if name == "" || isFinderFile(name) {
			continue
		}
		names[name] = true
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeXGlobalHeader:
			continue
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return errFileSystem
		}
		if isFileSystemFile(name) {
			return errFileSystem
		}
		if entries++; entries > maxArchiveEntries {
			return fmt.Errorf("the archive has more than %d files, which no image has; %w",
				maxArchiveEntries, errFileSystem)
		}
		switch header.Typeflag {
		case tar.TypeReg:
			if maxEntrySize > 0 && header.Size > maxEntrySize {
				return fmt.Errorf("%s has %d bytes, more than http.maxUploadSize allows", name, header.Size)
			}
			file, err := a.stage(reader, name, entries)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				return err
			}
			delete(a.links, name)
			a.files[name] = file
		case tar.TypeSymlink, tar.TypeLink:
			// a link that leaves the archive is kept as one that leads
			// nowhere: an image never needs one, and a file system, which
			// has them, is told apart by its names
			target := ""
			if header.Typeflag == tar.TypeLink {
				target, _ = cleanEntryName(header.Linkname)
			} else if !strings.HasPrefix(header.Linkname, "/") {
				target = path.Join(path.Dir(name), header.Linkname)
				if target == ".." || strings.HasPrefix(target, "../") {
					target = ""
				}
			}
			delete(a.files, name)
			a.links[name] = target
		default:
			return fmt.Errorf("%s is an entry of a kind an image archive does not have", name)
		}
	}
	a.prefix = commonPrefix(names)
	return nil
}

// stage copies one file of the archive into the staging folder, hashing it
// on the way.
func (a *imageArchive) stage(r io.Reader, name string, n int) (*stagedFile, error) {
	staged := filepath.Join(a.dir, strconv.Itoa(n))
	out, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	sum := sha256.New()
	writers := []io.Writer{out, sum}
	var sum512 hash.Hash
	if strings.Contains("/"+name, "/blobs/sha512/") {
		sum512 = sha512.New()
		writers = append(writers, sum512)
	}
	head := &headWriter{}
	writers = append(writers, head)
	// not synced: most of what an archive holds is either in the store
	// already or not chosen, and what is stored is synced as it is
	size, err := io.Copy(io.MultiWriter(writers...), r)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(staged)
		return nil, fmt.Errorf("%s cannot be read from the archive: %w", name, err)
	}
	file := &stagedFile{path: staged, size: size, sha256: digest.NewDigest(digest.SHA256, sum), magic: head.b}
	if sum512 != nil {
		file.sha512 = digest.NewDigest(digest.SHA512, sum512)
	}
	// a file the archive has twice, under two names, is kept once
	if had, ok := a.blobs[file.sha256]; ok && had.size == size {
		_ = os.Remove(staged)
		if file.sha512 != "" && had.sha512 == "" {
			had.sha512 = file.sha512
			a.blobs[had.sha512] = had
		}
		return had, nil
	}
	a.blobs[file.sha256] = file
	if file.sha512 != "" {
		a.blobs[file.sha512] = file
	}
	return file, nil
}

// headWriter keeps the first bytes written to it.
type headWriter struct {
	b []byte
}

func (h *headWriter) Write(p []byte) (int, error) {
	if room := 6 - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// commonPrefix is the folder every entry of an archive is in, with its
// slash, when there is one: what tar -c of a folder writes, rather than of
// what is in it. An archive with an image at its root has none.
func commonPrefix(names map[string]bool) string {
	if names["oci-layout"] || names["index.json"] || names["manifest.json"] {
		return ""
	}
	first := ""
	for name := range names {
		top, _, _ := strings.Cut(name, "/")
		if first == "" {
			first = top
		}
		if top != first {
			return ""
		}
	}
	if first == "" || names[first] && len(names) == 1 {
		return ""
	}
	return first + "/"
}

// file finds a file of the archive by its name, through the links on the way.
func (a *imageArchive) file(name string) (*stagedFile, error) {
	clean, err := cleanEntryName(name)
	if err != nil || clean == "" {
		return nil, fmt.Errorf("%q is not a file of the archive", name)
	}
	current := a.prefix + clean
	for range maxArchiveLinks + 1 {
		if file, ok := a.files[current]; ok {
			return file, nil
		}
		target, ok := a.links[current]
		if !ok {
			return nil, fmt.Errorf("%s is %w", name, errArchiveMissing)
		}
		if target == "" {
			return nil, fmt.Errorf("%s links outside the archive", name)
		}
		current = target
	}
	return nil, fmt.Errorf("%s goes through more than %d links", name, maxArchiveLinks)
}

// has reports whether the archive has a file of a name, through links.
func (a *imageArchive) has(name string) bool {
	_, err := a.file(name)
	return err == nil
}

// readSmall reads a staged file that is a document, not a layer.
func readSmall(file *stagedFile, name string, limit int64) ([]byte, error) {
	if file.size > limit {
		return nil, fmt.Errorf("%s has %d bytes, more than %d", name, file.size, limit)
	}
	data, err := os.ReadFile(file.path)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", name, err)
	}
	return data, nil
}

// --- what the archive holds -------------------------------------------------

// resolve finds the images of an archive that was read.
func (a *imageArchive) resolve() error {
	if a.has("oci-layout") {
		a.format = archiveOCI
		return a.resolveLayout()
	}
	if file, err := a.file("manifest.json"); err == nil {
		data, err := readSmall(file, "manifest.json", maxManifestSize)
		if err != nil {
			return err
		}
		data = bytes.TrimSpace(data)
		if bytes.HasPrefix(data, []byte("[")) {
			a.format = archiveDocker
			return a.resolveDocker(data)
		}
		if a.has("version") {
			return errors.New("this is a dir: copy of skopeo or podman (docker-dir), which cannot be imported: " +
				"copy the image to oci-archive: or docker-archive: instead")
		}
		return errors.New("the manifest.json of the archive is not the one docker save writes")
	}
	if a.has("repositories") {
		return errors.New("this archive was saved by a Docker older than 1.10 and has no manifest.json: " +
			"load it into a current docker and save it again")
	}
	return errors.New("no image in the archive: it has neither the oci-layout and index.json of an OCI layout " +
		"nor the manifest.json of docker save")
}

// layoutBlob finds a blob of an OCI layout by its descriptor. A blob that is
// there under its name but is not what its name says is damage, which is an
// error; one that is not there at all is errArchiveMissing.
func (a *imageArchive) layoutBlob(descriptor v1.Descriptor) (*stagedFile, error) {
	d := descriptor.Digest
	if _, ok := parseBlobDigest(d.String()); !ok {
		return nil, fmt.Errorf("%s is not a digest the registry takes", d)
	}
	name := "blobs/" + d.Algorithm().String() + "/" + d.Encoded()
	file, err := a.file(name)
	switch {
	case errors.Is(err, errArchiveMissing):
		return nil, fmt.Errorf("the blob %s is %w", d, errArchiveMissing)
	case err != nil:
		return nil, err
	}
	if (d.Algorithm() == digest.SHA256 && file.sha256 != d) || (d.Algorithm() == digest.SHA512 && file.sha512 != d) {
		return nil, fmt.Errorf("%s is not what its name says: the archive is damaged", name)
	}
	if descriptor.Size != file.size {
		return nil, fmt.Errorf("%s has %d bytes where its descriptor says %d: the archive is damaged",
			name, file.size, descriptor.Size)
	}
	return file, nil
}

// layoutManifest reads a manifest of an OCI layout.
func (a *imageArchive) layoutManifest(descriptor v1.Descriptor) (pulledManifest, error) {
	file, err := a.layoutBlob(descriptor)
	if err != nil {
		return pulledManifest{}, err
	}
	body, err := readSmall(file, descriptor.Digest.String(), maxManifestSize)
	if err != nil {
		return pulledManifest{}, err
	}
	return decodeManifest(remoteManifest{body: body, mediaType: descriptor.MediaType, digest: descriptor.Digest})
}

// hasImage reports whether the archive holds all of an image: the blobs it
// refers to, each what its descriptor says. A blob that is missing is false;
// one that is damaged is an error.
func (a *imageArchive) hasImage(doc manifestDoc) (bool, error) {
	for _, blob := range imageBlobs(doc) {
		if _, err := a.layoutBlob(blob); err != nil {
			if errors.Is(err, errArchiveMissing) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

// resolveLayout finds the images of an OCI layout: what its index.json names.
func (a *imageArchive) resolveLayout() error {
	file, err := a.file("oci-layout")
	if err != nil {
		return err
	}
	data, err := readSmall(file, "oci-layout", maxLayoutFile)
	if err != nil {
		return err
	}
	var layout v1.ImageLayout
	if json.Unmarshal(data, &layout) != nil || layout.Version == "" {
		return errors.New("the oci-layout of the archive cannot be read")
	}
	file, err = a.file("index.json")
	if errors.Is(err, errArchiveMissing) {
		return errors.New("the OCI layout has no index.json")
	}
	if err != nil {
		return err
	}
	body, err := readSmall(file, "index.json", maxManifestSize)
	if err != nil {
		return err
	}
	index, err := decodeManifest(remoteManifest{body: body, mediaType: v1.MediaTypeImageIndex,
		digest: digest.SHA256.FromBytes(body)})
	if err != nil {
		return fmt.Errorf("the index.json of the archive: %w", err)
	}
	if !isIndexType(index.mediaType) {
		return errors.New("the index.json of the archive is not an index")
	}

	// docker save names an image once for each of its tags, so an image is
	// the digest, and the names are all of those it has
	var order []digest.Digest
	found := map[digest.Digest]*archiveImage{}
	descriptors := map[digest.Digest]v1.Descriptor{}
	for _, entry := range index.doc.Manifests {
		image, ok := found[entry.Digest]
		if !ok {
			if len(order) == maxArchiveImages {
				return fmt.Errorf("the archive holds more than %d images", maxArchiveImages)
			}
			image = &archiveImage{}
			found[entry.Digest] = image
			descriptors[entry.Digest] = entry
			order = append(order, entry.Digest)
		}
		if ref := layoutName(entry.Annotations); ref != "" && !slices.Contains(image.names, ref) {
			image.names = append(image.names, ref)
		}
	}
	if len(order) == 0 {
		return errors.New("the index.json of the archive names no image")
	}
	for _, d := range order {
		image := found[d]
		if err := a.layoutImage(image, descriptors[d]); err != nil {
			return err
		}
		image.targets = a.targetsOf(image.names)
		a.images = append(a.images, *image)
	}
	return nil
}

// layoutName is the reference an entry of an index.json names its image by:
// containerd's full one, or the OCI one, which can be a tag alone.
func layoutName(annotations map[string]string) string {
	if name := strings.TrimSpace(annotations[annotationContainerdName]); name != "" {
		return name
	}
	return strings.TrimSpace(annotations[v1.AnnotationRefName])
}

// layoutImage reads one image of an OCI layout. An index is cut to the
// platforms the archive has all of: containerd writes the index an image
// was pulled with whole, with only the platforms that were exported.
func (a *imageArchive) layoutImage(image *archiveImage, descriptor v1.Descriptor) error {
	top, err := a.layoutManifest(descriptor)
	if err != nil {
		return err
	}
	if !isIndexType(top.mediaType) {
		complete, err := a.hasImage(top.doc)
		if err != nil {
			return err
		}
		if !complete {
			return fmt.Errorf("the archive does not have all of the image %s", top.digest)
		}
		image.top, image.blobs = top, imageBlobs(top.doc)
		if platform, ok := a.platformOf(top); ok {
			image.platforms = []string{platform}
		}
		return nil
	}

	present := map[digest.Digest]pulledManifest{}
	for _, entry := range top.doc.Manifests {
		child, err := a.layoutManifest(entry)
		if errors.Is(err, errArchiveMissing) {
			continue
		}
		if err != nil {
			return err
		}
		if !isImageType(child.mediaType) {
			return fmt.Errorf("the index names %s, which is not an image: an index inside an index is not supported",
				entry.Digest)
		}
		complete, err := a.hasImage(child.doc)
		if err != nil {
			return err
		}
		if complete {
			present[entry.Digest] = child
		}
	}
	var kept []v1.Descriptor
	images := 0
	for _, entry := range top.doc.Manifests {
		if _, ok := present[entry.Digest]; !ok {
			continue
		}
		if isAttestation(entry) {
			if _, ok := present[digest.Digest(entry.Annotations[annotationReferenceDigest])]; !ok {
				continue
			}
		} else {
			images++
		}
		kept = append(kept, entry)
	}
	if images == 0 {
		return fmt.Errorf("the archive holds none of the images its index %s names", top.digest)
	}
	if len(kept) < len(top.doc.Manifests) {
		body, d, rebuilt, err := subsetIndex(top.mediaType, top.doc, kept)
		if err != nil {
			return err
		}
		top = pulledManifest{body: body, mediaType: top.mediaType, digest: d, doc: rebuilt}
		image.note = "Only the platforms the archive holds are kept, in an index of their own."
	}
	image.top = top
	for _, entry := range kept {
		child := present[entry.Digest]
		image.children = append(image.children, child)
		image.blobs = addBlobs(image.blobs, imageBlobs(child.doc)...)
	}
	image.platforms = indexPlatforms(top.doc)
	return nil
}

// platformOf reads the platform of a single image from its configuration.
func (a *imageArchive) platformOf(image pulledManifest) (string, bool) {
	if !hasImageConfig(image.mediaType, image.doc) {
		return "", false
	}
	file, ok := a.blob(image.doc.Config.Digest)
	if !ok {
		return "", false
	}
	data, err := readSmall(file, "the configuration", maxConfigSize)
	if err != nil {
		return "", false
	}
	config, ok := decodeImageConfig(data)
	if !ok {
		return "", false
	}
	return platformKey(&config.platform), true
}

// dockerEntry is one image of the manifest.json of docker save.
type dockerEntry struct {
	Config       string                          `json:"Config"`
	RepoTags     []string                        `json:"RepoTags"`
	Layers       []string                        `json:"Layers"`
	LayerSources map[digest.Digest]v1.Descriptor `json:"LayerSources"`
}

// resolveDocker builds a manifest for each image of a docker save.
func (a *imageArchive) resolveDocker(data []byte) error {
	var entries []dockerEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("the manifest.json of the archive cannot be read: %w", err)
	}
	if len(entries) == 0 {
		return errors.New("the manifest.json of the archive names no image")
	}
	if len(entries) > maxArchiveImages {
		return fmt.Errorf("the archive holds more than %d images", maxArchiveImages)
	}
	for i, entry := range entries {
		image, err := a.dockerImage(entry, i)
		if err != nil {
			return err
		}
		a.images = append(a.images, image)
	}
	return nil
}

// dockerImage builds the manifest of one image of a docker save. Its
// layers are stored as the archive has them: uncompressed, as docker save
// writes them, which is what the configuration's diff_ids are the digests
// of; or compressed, as containerd and crane write them. A manifest whose
// layers are all tar or gzip is Docker's; one with a zstd layer is OCI's,
// since Docker's format has no zstd.
func (a *imageArchive) dockerImage(entry dockerEntry, i int) (archiveImage, error) {
	label := fmt.Sprintf("image %d of manifest.json", i+1)
	if len(entry.RepoTags) > 0 {
		label = entry.RepoTags[0]
	}
	configFile, err := a.file(entry.Config)
	if err != nil {
		return archiveImage{}, fmt.Errorf("the configuration of %s: %w", label, err)
	}
	data, err := readSmall(configFile, "the configuration of "+label, maxConfigSize)
	if err != nil {
		return archiveImage{}, err
	}
	var config struct {
		RootFS struct {
			DiffIDs []digest.Digest `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return archiveImage{}, fmt.Errorf("the configuration of %s cannot be read: %w", label, err)
	}
	if len(config.RootFS.DiffIDs) != len(entry.Layers) {
		return archiveImage{}, fmt.Errorf("%s has %d layers where its configuration says %d",
			label, len(entry.Layers), len(config.RootFS.DiffIDs))
	}

	type layer struct {
		descriptor  v1.Descriptor
		compression string
		foreign     bool
	}
	layers := make([]layer, len(entry.Layers))
	oci := false
	for n, name := range entry.Layers {
		diffID := config.RootFS.DiffIDs[n]
		// docker 25 lists every layer as a source; only one fetched from
		// elsewhere is taken from there
		if source, ok := entry.LayerSources[diffID]; ok && isForeign(source) {
			layers[n] = layer{descriptor: source, foreign: true}
			continue
		}
		file, err := a.file(name)
		if err != nil {
			return archiveImage{}, fmt.Errorf("layer %d of %s: %w", n+1, label, err)
		}
		kind := compressionOf(file.magic)
		switch kind {
		case "":
			if file.sha256 != diffID {
				return archiveImage{}, fmt.Errorf("layer %d of %s is not what its configuration says", n+1, label)
			}
		case compressionGzip, compressionZstd:
			a.checks = append(a.checks, layerCheck{file: file, compression: kind, diffID: diffID,
				label: fmt.Sprintf("layer %d of %s", n+1, label)})
			oci = oci || kind == compressionZstd
		default:
			return archiveImage{}, fmt.Errorf("layer %d of %s is compressed with %s, which a layer cannot be",
				n+1, label, kind)
		}
		layers[n] = layer{descriptor: v1.Descriptor{Digest: file.sha256, Size: file.size}, compression: kind}
	}

	manifest := manifestDoc{SchemaVersion: 2, MediaType: mediaTypeDockerManifest,
		Config: &v1.Descriptor{MediaType: mediaTypeDockerConfig, Digest: configFile.sha256, Size: configFile.size}}
	if oci {
		manifest.MediaType = v1.MediaTypeImageManifest
		manifest.Config.MediaType = v1.MediaTypeImageConfig
	}
	for _, l := range layers {
		descriptor := l.descriptor
		if !l.foreign {
			descriptor.MediaType = layerMediaType(l.compression, oci)
		}
		manifest.Layers = append(manifest.Layers, descriptor)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return archiveImage{}, err
	}
	top, err := decodeManifest(remoteManifest{body: body, mediaType: manifest.MediaType,
		digest: digest.SHA256.FromBytes(body)})
	if err != nil {
		return archiveImage{}, err
	}
	image := archiveImage{top: top, blobs: imageBlobs(top.doc),
		note: "docker save keeps no manifest, so the registry builds one, with a digest of its own."}
	if parsed, ok := decodeImageConfig(data); ok {
		image.platforms = []string{platformKey(&parsed.platform)}
	}
	for _, tag := range entry.RepoTags {
		if tag = strings.TrimSpace(tag); tag != "" && !slices.Contains(image.names, tag) {
			image.names = append(image.names, tag)
		}
	}
	image.targets = a.targetsOf(image.names)
	return image, nil
}

// layerMediaType is what a layer of a built manifest is served as.
func layerMediaType(compression string, oci bool) string {
	switch {
	case oci && compression == compressionZstd:
		return v1.MediaTypeImageLayerZstd
	case oci && compression == compressionGzip:
		return v1.MediaTypeImageLayerGzip
	case oci:
		return v1.MediaTypeImageLayer
	case compression == compressionGzip:
		return mediaTypeDockerLayerGzip
	default:
		return mediaTypeDockerLayer
	}
}

// verifyLayers checks the compressed layers of a docker save against the
// digests their configurations give their content. count is told the bytes
// read.
func (a *imageArchive) verifyLayers(ctx context.Context, count func(int64)) error {
	checked := map[*stagedFile]digest.Digest{}
	for _, check := range a.checks {
		if had, ok := checked[check.file]; ok {
			if had != check.diffID {
				return fmt.Errorf("%s is not what its configuration says", check.label)
			}
			continue
		}
		file, err := os.Open(check.file.path)
		if err != nil {
			return err
		}
		reader, done, err := decompress(check.compression, &countingReader{r: contextReader{ctx: ctx, r: file},
			count: count})
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("%s cannot be read as %s: %w", check.label, check.compression, err)
		}
		sum := sha256.New()
		_, err = io.Copy(sum, reader)
		done()
		_ = file.Close()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("%s cannot be read as %s: %w", check.label, check.compression, err)
		}
		if digest.NewDigest(digest.SHA256, sum) != check.diffID {
			return fmt.Errorf("%s is not what its configuration says", check.label)
		}
		checked[check.file] = check.diffID
	}
	return nil
}

// countingReader tells count how much passed through it.
type countingReader struct {
	r     io.Reader
	count func(int64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.count != nil {
		c.count(int64(n))
	}
	return n, err
}

// --- where the images go ----------------------------------------------------

// archiveExtensions are what the name of an archive ends in.
var archiveExtensions = []string{".tar.gz", ".tar.zst", ".tar.xz", ".tar.bz2", ".tgz", ".tzst", ".txz",
	".tbz2", ".tbz", ".tar"}

// isArchiveName reports a file name an image archive is likely to have.
func isArchiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, extension := range archiveExtensions {
		if strings.HasSuffix(lower, extension) && len(lower) > len(extension) {
			return true
		}
	}
	return false
}

var notRepositoryCharacters = regexp.MustCompile(`[^a-z0-9._-]+`)

// archiveRepository is the repository the name of an archive file suggests,
// for an image the archive gives only a tag: alpine.tar is alpine. It is ""
// when the name makes none.
func archiveRepository(file string) string {
	name := strings.ToLower(path.Base(filepath.ToSlash(file)))
	for _, extension := range archiveExtensions {
		if trimmed, ok := strings.CutSuffix(name, extension); ok {
			name = trimmed
			break
		}
	}
	name = notRepositoryCharacters.ReplaceAllString(name, "-")
	name = strings.Trim(name, "._-")
	if !validRepository(name) {
		return ""
	}
	return name
}

// targetsOf are where the names of an image would store it by default:
// the repository and tag of each full reference, as a pull names what it
// fetches, and the archive's own name with a tag that comes alone.
func (a *imageArchive) targetsOf(names []string) []string {
	var targets []string
	for _, name := range names {
		target := ""
		if strings.ContainsAny(name, "/:@") {
			if ref, err := parseRemoteReference(name); err == nil && ref.tag != "" {
				target = ref.repository + ":" + ref.tag
			}
		} else if tagPattern.MatchString(name) {
			if repository := archiveRepository(a.name); repository != "" {
				target = repository + ":" + name
			}
		}
		if target != "" && !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
	}
	return targets
}

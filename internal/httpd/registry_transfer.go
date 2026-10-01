package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Copying an image between this registry and another. A pull fetches the
// manifests first, then the blobs they name, each checked against its digest
// before it goes into the store, and only then stores the manifests and
// points the tag at them, so the tag never names an image that is not all
// there. A push sends the blobs the other registry does not have yet, then the
// manifests, the tag last. Either way the manifests travel as they are, so an
// image keeps its digest, except for an index a pull leaves platforms out of,
// which the registry builds anew.

// platformFilter is the platforms a pull keeps, as platformKey writes them;
// empty keeps them all.
type platformFilter []string

// parsePlatforms reads a list such as "linux/amd64, linux/arm64".
func parsePlatforms(value string) (platformFilter, error) {
	var filter platformFilter
	for _, entry := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		parts := strings.Split(entry, "/")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("%q is not a platform; write it as os/architecture, such as linux/amd64", entry)
		}
		platform := v1.Platform{OS: parts[0], Architecture: parts[1]}
		if len(parts) == 3 {
			platform.Variant = parts[2]
		}
		if key := platformKey(&platform); !slices.Contains(filter, key) {
			filter = append(filter, key)
		}
	}
	return filter, nil
}

// matches reports whether a filter keeps a platform. A platform asked for
// without an OS version is any version of it, which is how a Windows image is
// asked for.
func (f platformFilter) matches(key string) bool {
	if len(f) == 0 {
		return true
	}
	plain, _, _ := strings.Cut(key, ":")
	return slices.Contains(f, key) || slices.Contains(f, plain)
}

// isForeign reports a layer that is fetched from elsewhere than the registry,
// which the non-distributable media types and a list of URLs say: it is
// neither expected in the store nor copied.
func isForeign(layer v1.Descriptor) bool {
	return len(layer.URLs) > 0 || strings.Contains(layer.MediaType, "nondistributable") ||
		strings.Contains(layer.MediaType, "foreign")
}

// imageBlobs are the blobs of an image the registry holds: its configuration,
// unless the manifest carries it, and the layers that are not foreign.
func imageBlobs(doc manifestDoc) []v1.Descriptor {
	var blobs []v1.Descriptor
	if doc.Config != nil && len(doc.Config.Data) == 0 {
		blobs = append(blobs, *doc.Config)
	}
	for _, layer := range doc.Layers {
		if !isForeign(layer) {
			blobs = append(blobs, layer)
		}
	}
	return blobs
}

// addBlobs adds blobs to a list, each once.
func addBlobs(list []v1.Descriptor, blobs ...v1.Descriptor) []v1.Descriptor {
	for _, blob := range blobs {
		if !slices.ContainsFunc(list, func(had v1.Descriptor) bool { return had.Digest == blob.Digest }) {
			list = append(list, blob)
		}
	}
	return list
}

func blobsSize(blobs []v1.Descriptor) int64 {
	var size int64
	for _, blob := range blobs {
		size += blob.Size
	}
	return size
}

// --- pulling ---------------------------------------------------------------

// pulledManifest is a manifest a pull stores.
type pulledManifest struct {
	body      []byte
	mediaType string
	digest    digest.Digest
	doc       manifestDoc
}

// decodeManifest reads a fetched manifest and checks it as a push of it
// would be checked.
func decodeManifest(found remoteManifest) (pulledManifest, error) {
	var doc manifestDoc
	if err := json.Unmarshal(found.body, &doc); err != nil {
		return pulledManifest{}, fmt.Errorf("the manifest %s cannot be read: %w", found.digest, err)
	}
	mediaType, failure := manifestMediaType(found.mediaType, doc)
	if failure == nil {
		failure = checkDescriptors(doc)
	}
	if failure != nil {
		message := failure.message
		if detail, ok := failure.detail.(string); ok {
			message += ": " + detail
		}
		return pulledManifest{}, fmt.Errorf("the manifest %s cannot be stored: %s", found.digest, message)
	}
	return pulledManifest{body: found.body, mediaType: mediaType, digest: found.digest, doc: doc}, nil
}

// pullImage copies an image of another registry into the store, under the
// repository and tag of its reference.
func (s *Server) pullImage(ctx context.Context, set *settings, job *registryJob, ref remoteRef, filter platformFilter, username, password string, user *account) (string, error) {
	store := set.registry
	name, tag := ref.repository, ref.tag
	client := newRemoteClient(ref, username, password, "pull")
	if err := client.authenticate(ctx); err != nil {
		return "", err
	}
	found, err := client.getManifest(ctx, ref.ref())
	if err != nil {
		return "", err
	}
	top, err := decodeManifest(found)
	if err != nil {
		return "", err
	}

	var children []pulledManifest
	var blobs []v1.Descriptor
	var platforms []string
	if isIndexType(top.mediaType) {
		kept, err := keptEntries(top.doc, filter)
		if err != nil {
			return "", err
		}
		for _, entry := range kept {
			fetched, err := client.getManifest(ctx, entry.Digest.String())
			if err != nil {
				return "", err
			}
			child, err := decodeManifest(fetched)
			if err != nil {
				return "", err
			}
			if !isImageType(child.mediaType) {
				return "", fmt.Errorf("the index names %s, which is not an image: an index inside an index is not supported",
					entry.Digest)
			}
			children = append(children, child)
			blobs = addBlobs(blobs, imageBlobs(child.doc)...)
			if entry.Platform != nil && !isAttestation(entry) {
				platforms = append(platforms, platformKey(entry.Platform))
			}
		}
		if len(kept) < len(top.doc.Manifests) {
			body, d, rebuilt, err := subsetIndex(top.mediaType, top.doc, kept)
			if err != nil {
				return "", err
			}
			top = pulledManifest{body: body, mediaType: top.mediaType, digest: d, doc: rebuilt}
		}
	} else {
		blobs = imageBlobs(top.doc)
	}
	job.plan(len(blobs), blobsSize(blobs))

	for i, blob := range blobs {
		if err := s.fetchBlob(ctx, set, client, job, name, blob); err != nil {
			return "", err
		}
		// a single image is checked against the filter once its configuration,
		// which comes first, is there, before any layer is fetched for nothing
		if i == 0 && !isIndexType(top.mediaType) {
			config, ok := store.imageConfig(top.mediaType, top.doc)
			key := ""
			if ok {
				key = platformKey(&config.platform)
				platforms = []string{key}
			}
			if len(filter) > 0 && !filter.matches(key) {
				if key == "" {
					return "", fmt.Errorf("%s is not an image for a platform, so it cannot be pulled for %s",
						ref, strings.Join(filter, ", "))
				}
				return "", fmt.Errorf("%s is only for %s, not for %s", ref, key, strings.Join(filter, ", "))
			}
		}
	}

	if err := s.storePulled(store, name, tag, top, children, user); err != nil {
		return "", err
	}
	s.log.Info("registry image pulled", "repository", name, "tag", tag, "source", ref.String(),
		"digest", top.digest.String(), "platforms", strings.Join(platforms, ","),
		"blobs", len(blobs), "bytes", job.bytesTotal.Load(), "user", nameOf(user),
		"took", time.Since(job.started).Round(time.Millisecond))
	message := "Pulled " + name + ":" + tag
	if len(platforms) > 0 {
		message += " for " + strings.Join(platforms, ", ")
	}
	return message + ".", nil
}

// keptEntries are the entries of an index a filter keeps: the images for the
// platforms it names, and the attestations of those images.
func keptEntries(index manifestDoc, filter platformFilter) ([]v1.Descriptor, error) {
	if len(filter) == 0 {
		return index.Manifests, nil
	}
	images := map[digest.Digest]bool{}
	var offered []string
	for _, entry := range index.Manifests {
		if entry.Platform == nil || isAttestation(entry) {
			continue
		}
		key := platformKey(entry.Platform)
		if !slices.Contains(offered, key) {
			offered = append(offered, key)
		}
		if filter.matches(key) {
			images[entry.Digest] = true
		}
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("the image has no %s; it has %s", strings.Join(filter, ", "),
			strings.Join(offered, ", "))
	}
	var kept []v1.Descriptor
	for _, entry := range index.Manifests {
		if images[entry.Digest] ||
			(isAttestation(entry) && images[digest.Digest(entry.Annotations[annotationReferenceDigest])]) {
			kept = append(kept, entry)
		}
	}
	return kept, nil
}

// subsetIndex is what is left of an index once only some of its entries are
// kept: a new index, with a digest of its own.
func subsetIndex(mediaType string, index manifestDoc, kept []v1.Descriptor) ([]byte, digest.Digest, manifestDoc, error) {
	rebuilt := manifestDoc{SchemaVersion: 2, MediaType: mediaType, ArtifactType: index.ArtifactType,
		Manifests: kept, Annotations: index.Annotations}
	body, err := json.Marshal(rebuilt)
	if err != nil {
		return nil, "", manifestDoc{}, err
	}
	return body, digest.SHA256.FromBytes(body), rebuilt, nil
}

// indexPlatforms are the platforms of the images an index names, each once,
// without the attestations beside them.
func indexPlatforms(index manifestDoc) []string {
	var keys []string
	for _, entry := range index.Manifests {
		if entry.Platform == nil || isAttestation(entry) || entry.Platform.OS == "unknown" {
			continue
		}
		if key := platformKey(entry.Platform); !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	return orderKeys(keys)
}

// remoteImage is what checking an image of another registry finds.
type remoteImage struct {
	digest    digest.Digest
	platforms []string
}

// inspectRemote checks that an image of another registry can be pulled with
// the login given, and finds the platforms it is for. Of a single image only
// its configuration is fetched, which says its platform.
func (s *Server) inspectRemote(ctx context.Context, ref remoteRef, username, password string) (remoteImage, error) {
	client := newRemoteClient(ref, username, password, "pull")
	if err := client.authenticate(ctx); err != nil {
		return remoteImage{}, err
	}
	found, err := client.getManifest(ctx, ref.ref())
	if err != nil {
		return remoteImage{}, err
	}
	top, err := decodeManifest(found)
	if err != nil {
		return remoteImage{}, err
	}
	image := remoteImage{digest: top.digest}
	if isIndexType(top.mediaType) {
		image.platforms = indexPlatforms(top.doc)
		return image, nil
	}
	if !hasImageConfig(top.mediaType, top.doc) {
		return image, nil
	}
	config := top.doc.Config
	if config.Size > maxConfigSize {
		return remoteImage{}, fmt.Errorf("the configuration of %s is too large", ref)
	}
	body, err := client.getBlob(ctx, config.Digest)
	if err != nil {
		return remoteImage{}, err
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(io.LimitReader(body, maxConfigSize+1))
	if err != nil {
		return remoteImage{}, fmt.Errorf("the configuration of %s from %s: %w", ref, client.host, err)
	}
	if config.Digest.Algorithm().FromBytes(data) != config.Digest {
		return remoteImage{}, fmt.Errorf("the configuration of %s from %s is not what its digest says", ref, client.host)
	}
	if parsed, ok := decodeImageConfig(data); ok {
		image.platforms = []string{platformKey(&parsed.platform)}
	}
	return image, nil
}

// fetchBlob brings a blob into the store and links it to the repository. A
// blob the store already has, from any repository, is only linked.
func (s *Server) fetchBlob(ctx context.Context, set *settings, client *remoteClient, job *registryJob, name string, blob v1.Descriptor) error {
	store := set.registry
	link := func() error {
		s.registryMu.RLock()
		defer s.registryMu.RUnlock()
		return store.linkBlob(name, blob.Digest)
	}
	if _, err := store.blobInfo(blob.Digest); err == nil {
		job.skipped(blob.Size)
		return link()
	}
	if limit := set.cfg.MaxUploadSize; limit > 0 && blob.Size > limit {
		return fmt.Errorf("the blob %s has %d bytes, more than http.maxUploadSize allows", blob.Digest, blob.Size)
	}

	blobCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	body, err := client.getBlob(blobCtx, blob.Digest)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()

	if err := os.MkdirAll(store.uploadsPath(), 0o755); err != nil {
		return err
	}
	staged, err := os.CreateTemp(store.uploadsPath(), "pull-*")
	if err != nil {
		return err
	}
	path := staged.Name()
	committed := false
	defer func() {
		if !committed {
			_ = staged.Close()
			_ = os.Remove(path)
		}
	}()

	sum := blob.Digest.Algorithm().Hash()
	reader := watch(io.LimitReader(body, blob.Size+1), job, cancel)
	written, err := io.Copy(io.MultiWriter(staged, sum), reader)
	reader.done()
	if err != nil {
		if errors.Is(context.Cause(blobCtx), errStalled) {
			return fmt.Errorf("the blob %s from %s: %w", blob.Digest, client.host, errStalled)
		}
		return fmt.Errorf("the blob %s from %s: %w", blob.Digest, client.host, err)
	}
	if written != blob.Size {
		return fmt.Errorf("the blob %s from %s has %d bytes where the manifest says %d",
			blob.Digest, client.host, written, blob.Size)
	}
	if actual := digest.NewDigest(blob.Digest.Algorithm(), sum); actual != blob.Digest {
		return fmt.Errorf("the blob %s from %s is not what its digest says", blob.Digest, client.host)
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return err
	}
	s.registryMu.RLock()
	err = store.commitBlob(path, blob.Digest)
	if err == nil {
		committed = true
		err = store.linkBlob(name, blob.Digest)
	}
	s.registryMu.RUnlock()
	if err != nil {
		return err
	}
	job.blobsDone.Add(1)
	return nil
}

// storePulled stores the manifests of a pull, the ones an index names before
// the index, and points the tag at the last. The tag is replaced, not merged
// into: what was pulled is what the tag is to hold.
func (s *Server) storePulled(store *registryStore, name, tag string, top pulledManifest, children []pulledManifest, user *account) error {
	s.registryMu.RLock()
	defer s.registryMu.RUnlock()
	lock := registryLock(&s.registryRepositoryLocks, name)
	lock.Lock()
	defer lock.Unlock()
	for _, manifest := range append(children, top) {
		if _, err := store.putBlob(manifest.body, manifest.digest.Algorithm()); err != nil {
			return err
		}
		if err := store.writeRevision(name, manifest.digest,
			revision{MediaType: manifest.mediaType, Size: int64(len(manifest.body))}); err != nil {
			return err
		}
		if manifest.doc.Subject != nil {
			if err := store.addReferrer(name, manifest.doc.Subject.Digest, manifest.digest); err != nil {
				return err
			}
		}
	}
	tags, err := store.readTags(name)
	if err != nil {
		return err
	}
	previous, had := tags[tag]
	tags[tag] = top.digest
	if err := store.writeTags(name, tags); err != nil {
		return err
	}
	if had && previous != top.digest {
		s.dropMergedOrphan(store, name, previous, tags)
	}
	s.log.Debug("registry tag set by a pull", "repository", name, "tag", tag,
		"digest", top.digest.String(), "user", nameOf(user))
	return nil
}

// --- pushing ---------------------------------------------------------------

// localManifest is a manifest of the store a push sends.
type localManifest struct {
	body      []byte
	mediaType string
	digest    digest.Digest
}

// readLocal reads a manifest of a repository as it is stored.
func readLocal(store *registryStore, name string, d digest.Digest) (localManifest, manifestDoc, error) {
	rev, err := store.readRevision(name, d)
	if err != nil {
		return localManifest{}, manifestDoc{}, fmt.Errorf("the manifest %s is not in %s: %w", d, name, err)
	}
	body, err := store.readBlob(d, maxManifestSize)
	if err != nil {
		return localManifest{}, manifestDoc{}, fmt.Errorf("the manifest %s cannot be read: %w", d, err)
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return localManifest{}, manifestDoc{}, fmt.Errorf("the manifest %s cannot be read: %w", d, err)
	}
	return localManifest{body: body, mediaType: rev.MediaType, digest: d}, doc, nil
}

// pushImage copies a tag of the store to another registry.
// A filter leaves out the platforms it does not name, which an index loses
// as a pull's does: what is pushed is an index of its own.
func (s *Server) pushImage(ctx context.Context, set *settings, job *registryJob, name, tag string, d digest.Digest, target remoteRef, filter platformFilter, username, password string, user *account) (string, error) {
	store := set.registry
	top, doc, err := readLocal(store, name, d)
	if err != nil {
		return "", err
	}
	var children []localManifest
	var blobs []v1.Descriptor
	var platforms []string
	if isIndexType(top.mediaType) {
		kept, err := keptEntries(doc, filter)
		if err != nil {
			return "", err
		}
		for _, entry := range kept {
			child, childDoc, err := readLocal(store, name, entry.Digest)
			if err != nil {
				return "", err
			}
			children = append(children, child)
			blobs = addBlobs(blobs, imageBlobs(childDoc)...)
			if entry.Platform != nil && !isAttestation(entry) {
				platforms = append(platforms, platformKey(entry.Platform))
			}
		}
		if len(kept) < len(doc.Manifests) {
			body, rebuilt, _, err := subsetIndex(top.mediaType, doc, kept)
			if err != nil {
				return "", err
			}
			top = localManifest{body: body, mediaType: top.mediaType, digest: rebuilt}
		}
	} else {
		key := ""
		if config, ok := store.imageConfig(top.mediaType, doc); ok {
			key = platformKey(&config.platform)
		}
		if len(filter) > 0 && !filter.matches(key) {
			if key == "" {
				return "", fmt.Errorf("%s:%s is not an image for a platform, so it cannot be pushed for %s",
					name, tag, strings.Join(filter, ", "))
			}
			return "", fmt.Errorf("%s:%s is only for %s, not for %s", name, tag, key, strings.Join(filter, ", "))
		}
		blobs = imageBlobs(doc)
	}
	// the sizes are the store's, which is what is sent
	for i := range blobs {
		info, err := store.blobInfo(blobs[i].Digest)
		if err != nil {
			return "", fmt.Errorf("the blob %s is not in the registry: %w", blobs[i].Digest, err)
		}
		blobs[i].Size = info.Size()
	}
	job.plan(len(blobs), blobsSize(blobs))

	client := newRemoteClient(target, username, password, "pull,push")
	if err := client.authenticate(ctx); err != nil {
		return "", err
	}
	sent := 0
	for _, blob := range blobs {
		there, err := client.blobExists(ctx, blob.Digest)
		if err != nil {
			return "", err
		}
		if there {
			job.skipped(blob.Size)
			continue
		}
		if err := s.sendBlob(ctx, store, client, job, blob); err != nil {
			return "", err
		}
		sent++
	}
	for _, child := range children {
		if err := client.putManifest(ctx, child.digest.String(), child.mediaType, child.body); err != nil {
			return "", err
		}
	}
	if err := client.putManifest(ctx, target.tag, top.mediaType, top.body); err != nil {
		return "", err
	}
	s.log.Info("registry image pushed", "repository", name, "tag", tag, "target", target.String(),
		"digest", top.digest.String(), "platforms", strings.Join(platforms, ","), "blobs", len(blobs),
		"sent", sent, "bytes", job.bytesTotal.Load(), "user", nameOf(user),
		"took", time.Since(job.started).Round(time.Millisecond))
	message := "Pushed " + name + ":" + tag + " to " + target.String()
	if len(filter) > 0 && len(platforms) > 0 {
		message += " for " + strings.Join(platforms, ", ")
	}
	return message + ".", nil
}

// sendBlob uploads a blob of the store.
func (s *Server) sendBlob(ctx context.Context, store *registryStore, client *remoteClient, job *registryJob, blob v1.Descriptor) error {
	file, err := os.Open(store.blobPath(blob.Digest))
	if err != nil {
		return fmt.Errorf("the blob %s cannot be read: %w", blob.Digest, err)
	}
	defer func() { _ = file.Close() }()
	blobCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	reader := watch(file, job, cancel)
	err = client.pushBlob(blobCtx, blob.Digest, blob.Size, reader)
	reader.done()
	if err != nil {
		if errors.Is(context.Cause(blobCtx), errStalled) {
			return fmt.Errorf("the blob %s to %s: %w", blob.Digest, client.host, errStalled)
		}
		return err
	}
	job.blobsDone.Add(1)
	return nil
}

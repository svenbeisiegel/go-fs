package httpd

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// The Docker media types, which the image-spec module does not name. Docker
// still pushes these by default, so they are served alongside the OCI ones.
const (
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeDockerConfig   = "application/vnd.docker.container.image.v1+json"
)

// maxManifestSize is the largest manifest accepted, the limit the
// specification suggests registries at least allow.
const maxManifestSize = 4 << 20

// maxConfigSize is the largest image configuration read to find the platform
// of an image. A configuration carries the image's history, which is small
// next to this for any image anyone builds.
const maxConfigSize = 16 << 20

// The annotations with which buildx ties an attestation to its image in an
// index.
const (
	annotationReferenceType   = "vnd.docker.reference.type"
	annotationReferenceDigest = "vnd.docker.reference.digest"
)

// manifestDoc is the part of a manifest or an index the registry reads. It
// covers the OCI and the Docker formats alike: they share their fields.
type manifestDoc struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        *v1.Descriptor    `json:"config,omitempty"`
	Layers        []v1.Descriptor   `json:"layers,omitempty"`
	Manifests     []v1.Descriptor   `json:"manifests,omitempty"`
	Subject       *v1.Descriptor    `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

func isIndexType(mediaType string) bool {
	return mediaType == v1.MediaTypeImageIndex || mediaType == mediaTypeDockerList
}

func isImageType(mediaType string) bool {
	return mediaType == v1.MediaTypeImageManifest || mediaType == mediaTypeDockerManifest
}

// manifestMediaType decides what a pushed manifest is: what its Content-Type
// says, which has to agree with its own mediaType field where it has one, or
// else what that field or its shape says.
func manifestMediaType(contentType string, doc manifestDoc) (string, *registryError) {
	if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
		contentType = parsed
	}
	mediaType := contentType
	if !isIndexType(mediaType) && !isImageType(mediaType) {
		mediaType = doc.MediaType
	}
	if mediaType == "" {
		switch {
		case doc.Manifests != nil:
			mediaType = v1.MediaTypeImageIndex
		case doc.Config != nil:
			mediaType = v1.MediaTypeImageManifest
		}
	}
	switch {
	case !isIndexType(mediaType) && !isImageType(mediaType):
		return "", errManifestInvalid.with("unsupported manifest media type " + mediaType)
	case doc.MediaType != "" && doc.MediaType != mediaType:
		return "", errManifestInvalid.with("the mediaType of the manifest is not its Content-Type")
	case doc.SchemaVersion != 2:
		return "", errManifestInvalid.with("schemaVersion has to be 2")
	case isImageType(mediaType) && doc.Config == nil:
		return "", errManifestInvalid.with("an image manifest needs a config")
	}
	return mediaType, nil
}

// resolveManifest finds the digest a reference names: the digest itself, or
// what the tag points to.
func (q *registryRequest) resolveManifest(ref string) (digest.Digest, *registryError) {
	if strings.Contains(ref, ":") {
		d, ok := parseBlobDigest(ref)
		if !ok {
			return "", errDigestInvalid.with(ref)
		}
		return d, nil
	}
	if !tagPattern.MatchString(ref) {
		return "", errTagInvalid.with(ref)
	}
	tags, err := q.store.readTags(q.route.name)
	if err != nil {
		q.s.log.Error("registry cannot read the tags", "repository", q.route.name, "error", err)
		return "", errRegistryInternal
	}
	d, ok := tags[ref]
	if !ok {
		return "", errManifestUnknown.with(ref)
	}
	return d, nil
}

// getManifest serves a manifest as what it was pushed as.
func (q *registryRequest) getManifest() {
	d, failure := q.resolveManifest(q.route.ref)
	if failure != nil {
		q.fail(failure)
		return
	}
	rev, err := q.store.readRevision(q.route.name, d)
	if errors.Is(err, errRegistryNotFound) {
		q.fail(errManifestUnknown.with(q.route.ref))
		return
	}
	if err != nil {
		q.internal("cannot read a manifest", err)
		return
	}
	file, err := os.Open(q.store.blobPath(d))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			q.fail(errManifestUnknown.with(q.route.ref))
			return
		}
		q.internal("cannot open a manifest", err)
		return
	}
	defer func() { _ = file.Close() }()
	header := q.w.Header()
	header.Set("Content-Type", rev.MediaType)
	header.Set("Docker-Content-Digest", d.String())
	header.Set("ETag", `"`+d.String()+`"`)
	http.ServeContent(q.w, q.r, "", time.Time{}, file)
}

// putManifest stores a manifest, after checking that everything it refers to
// is there, and points its tag at it.
func (q *registryRequest) putManifest() {
	name, ref := q.route.name, q.route.ref
	body, err := io.ReadAll(io.LimitReader(q.r.Body, maxManifestSize+1))
	if err != nil {
		q.fail(errManifestInvalid.with("the manifest could not be read"))
		return
	}
	if len(body) > maxManifestSize {
		q.fail(errSizeInvalid.with("a manifest cannot be larger than 4 MiB"))
		return
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		q.fail(errManifestInvalid.with(err.Error()))
		return
	}
	mediaType, failure := manifestMediaType(q.r.Header.Get("Content-Type"), doc)
	if failure != nil {
		q.fail(failure)
		return
	}

	d := digest.SHA256.FromBytes(body)
	tag := ""
	if strings.Contains(ref, ":") {
		want, ok := parseBlobDigest(ref)
		if !ok {
			q.fail(errDigestInvalid.with(ref))
			return
		}
		d = want.Algorithm().FromBytes(body)
		if d != want {
			q.fail(errDigestInvalid.with(ref))
			return
		}
	} else {
		if !tagPattern.MatchString(ref) {
			q.fail(errTagInvalid.with(ref))
			return
		}
		tag = ref
	}
	if failure := checkDescriptors(doc); failure != nil {
		q.fail(failure)
		return
	}

	q.s.registryMu.RLock()
	defer q.s.registryMu.RUnlock()
	lock := q.repoLock()
	lock.Lock()
	defer lock.Unlock()

	if failure := q.checkReferences(mediaType, doc); failure != nil {
		q.fail(failure)
		return
	}
	if _, err := q.store.putBlob(body, d.Algorithm()); err != nil {
		q.internal("cannot store a manifest", err)
		return
	}
	if err := q.store.writeRevision(name, d, revision{MediaType: mediaType, Size: int64(len(body))}); err != nil {
		q.internal("cannot record a manifest", err)
		return
	}
	if doc.Subject != nil {
		if err := q.store.addReferrer(name, doc.Subject.Digest, d); err != nil {
			q.internal("cannot record a referrer", err)
			return
		}
		q.w.Header().Set("OCI-Subject", doc.Subject.Digest.String())
	}
	if tag != "" {
		if err := q.tagManifest(tag, d, mediaType, int64(len(body)), doc); err != nil {
			q.internal("cannot tag a manifest", err)
			return
		}
	}
	q.s.log.Info("registry manifest pushed", "repository", name, "reference", ref,
		"digest", d.String(), "mediaType", mediaType, "user", nameOf(q.user),
		"address", clientAddress(q.set, q.r))
	header := q.w.Header()
	header.Set("Location", "/v2/"+name+"/manifests/"+d.String())
	header.Set("Docker-Content-Digest", d.String())
	header.Set("Content-Length", "0")
	q.w.WriteHeader(http.StatusCreated)
}

// checkDescriptors makes sure every digest a manifest names is one: they are
// what the store's paths are built from, so a digest that is not one could
// name a path outside it.
func checkDescriptors(doc manifestDoc) *registryError {
	var descriptors []v1.Descriptor
	if doc.Config != nil {
		descriptors = append(descriptors, *doc.Config)
	}
	if doc.Subject != nil {
		descriptors = append(descriptors, *doc.Subject)
	}
	descriptors = append(descriptors, doc.Layers...)
	descriptors = append(descriptors, doc.Manifests...)
	for _, descriptor := range descriptors {
		if _, ok := parseBlobDigest(descriptor.Digest.String()); !ok {
			return errManifestInvalid.with("invalid digest " + descriptor.Digest.String())
		}
	}
	return nil
}

// checkReferences makes sure a manifest refers to nothing the repository does
// not hold: the configuration and layers of an image, the manifests of an
// index. A layer that is fetched from elsewhere, which the non-distributable
// media types and a list of URLs say, is not expected here, and neither is a
// configuration carried in the manifest itself.
func (q *registryRequest) checkReferences(mediaType string, doc manifestDoc) *registryError {
	if isIndexType(mediaType) {
		for _, entry := range doc.Manifests {
			if _, err := q.store.readRevision(q.route.name, entry.Digest); err != nil {
				return errManifestUnknown.with(entry.Digest.String())
			}
		}
		return nil
	}
	if doc.Config != nil && len(doc.Config.Data) == 0 {
		if _, err := q.store.repoBlob(q.route.name, doc.Config.Digest); err != nil {
			return errManifestBlob.with(doc.Config.Digest.String())
		}
	}
	for _, layer := range doc.Layers {
		if len(layer.URLs) > 0 || strings.Contains(layer.MediaType, "nondistributable") ||
			strings.Contains(layer.MediaType, "foreign") {
			continue
		}
		if _, err := q.store.repoBlob(q.route.name, layer.Digest); err != nil {
			return errManifestBlob.with(layer.Digest.String())
		}
	}
	return nil
}

// deleteManifest removes a tag, or a manifest with every tag that points to
// it. The blobs are left to the garbage collection.
func (q *registryRequest) deleteManifest() {
	name, ref := q.route.name, q.route.ref
	lock := q.repoLock()
	lock.Lock()
	defer lock.Unlock()
	tags, err := q.store.readTags(name)
	if err != nil {
		q.internal("cannot read the tags", err)
		return
	}

	if !strings.Contains(ref, ":") {
		if !tagPattern.MatchString(ref) {
			q.fail(errTagInvalid.with(ref))
			return
		}
		err := q.s.untag(q.store, name, ref, tags, q.user, clientAddress(q.set, q.r))
		switch {
		case errors.Is(err, errRegistryNotFound):
			q.fail(errManifestUnknown.with(ref))
		case err != nil:
			q.internal("cannot delete a tag", err)
		default:
			q.w.WriteHeader(http.StatusAccepted)
		}
		return
	}

	d, ok := parseBlobDigest(ref)
	if !ok {
		q.fail(errDigestInvalid.with(ref))
		return
	}
	if _, err := q.store.readRevision(name, d); err != nil {
		q.fail(errManifestUnknown.with(ref))
		return
	}
	if data, err := q.store.readBlob(d, maxManifestSize); err == nil {
		var doc manifestDoc
		if json.Unmarshal(data, &doc) == nil && doc.Subject != nil {
			q.store.removeReferrer(name, doc.Subject.Digest, d)
		}
	}
	if err := q.store.removeRevision(name, d); err != nil && !errors.Is(err, errRegistryNotFound) {
		q.internal("cannot delete a manifest", err)
		return
	}
	untagged := false
	for tag, target := range tags {
		if target == d {
			delete(tags, tag)
			untagged = true
		}
	}
	if untagged {
		if err := q.store.writeTags(name, tags); err != nil {
			q.internal("cannot delete the tags of a manifest", err)
			return
		}
	}
	q.s.log.Info("registry manifest deleted", "repository", name, "digest", d.String(),
		"user", nameOf(q.user), "address", clientAddress(q.set, q.r))
	q.w.WriteHeader(http.StatusAccepted)
}

// untag removes a tag from a repository whose tags the caller has read, and
// with it the index the registry merged for it, once nothing else points
// there. The blobs are left to the garbage collection. The caller holds the
// repository's lock.
func (s *Server) untag(store *registryStore, name, tag string, tags map[string]digest.Digest, user *account, address string) error {
	target, ok := tags[tag]
	if !ok {
		return errRegistryNotFound
	}
	delete(tags, tag)
	if err := store.writeTags(name, tags); err != nil {
		return err
	}
	s.dropMergedOrphan(store, name, target, tags)
	s.log.Info("registry tag deleted", "repository", name, "tag", tag, "digest", target.String(),
		"user", nameOf(user), "address", address)
	return nil
}

// referrersOf lists the manifests whose subject is the given digest, as an
// index, optionally only those of one artifact type.
func (q *registryRequest) referrersOf() {
	subject, ok := parseBlobDigest(q.route.ref)
	if !ok {
		q.fail(errDigestInvalid.with(q.route.ref))
		return
	}
	found, err := q.store.referrers(q.route.name, subject)
	if err != nil {
		q.internal("cannot list the referrers", err)
		return
	}
	filter := q.r.URL.Query().Get("artifactType")
	descriptors := []v1.Descriptor{}
	for _, d := range found {
		rev, err := q.store.readRevision(q.route.name, d)
		if err != nil {
			continue
		}
		data, err := q.store.readBlob(d, maxManifestSize)
		if err != nil {
			continue
		}
		var doc manifestDoc
		if json.Unmarshal(data, &doc) != nil {
			continue
		}
		artifactType := doc.ArtifactType
		if artifactType == "" && doc.Config != nil {
			artifactType = doc.Config.MediaType
		}
		if filter != "" && artifactType != filter {
			continue
		}
		descriptors = append(descriptors, v1.Descriptor{MediaType: rev.MediaType, Digest: d,
			Size: rev.Size, ArtifactType: artifactType, Annotations: doc.Annotations})
	}
	if filter != "" {
		q.w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	index := v1.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: v1.MediaTypeImageIndex,
		Manifests: descriptors}
	q.w.Header().Set("Content-Type", v1.MediaTypeImageIndex)
	q.w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(q.w).Encode(index)
}

// tagManifest points a tag at a pushed manifest, merging platforms: an image
// for one platform pushed to a tag that holds another platform does not
// replace it but joins it in an index the registry builds, so that images
// built and pushed on separate machines, one per architecture, end up under
// one tag as buildx would have pushed them together.
//
// An index that is pushed replaces the tag as it is: the client has said what
// the tag should hold. So does an image with no platform, an artifact, and an
// image for the platform the tag already holds. When the tag holds an index,
// the entry for the pushed image's platform is replaced or added, and the
// attestations of an image that is replaced go with it. The caller holds the
// repository's lock.
func (q *registryRequest) tagManifest(tag string, d digest.Digest, mediaType string, size int64, doc manifestDoc) error {
	name := q.route.name
	tags, err := q.store.readTags(name)
	if err != nil {
		return err
	}
	current, had := tags[tag]
	point := func(target digest.Digest) error {
		tags[tag] = target
		if err := q.store.writeTags(name, tags); err != nil {
			return err
		}
		if had && current != target {
			q.dropMergedOrphan(current, tags)
		}
		return nil
	}
	if !had || current == d || isIndexType(mediaType) {
		return point(d)
	}
	platform, ok := q.platformOf(mediaType, doc)
	if !ok {
		return point(d)
	}
	currentRev, err := q.store.readRevision(name, current)
	if err != nil {
		return point(d)
	}
	data, err := q.store.readBlob(current, maxManifestSize)
	if err != nil {
		return point(d)
	}
	var currentDoc manifestDoc
	if json.Unmarshal(data, &currentDoc) != nil {
		return point(d)
	}

	pushed := v1.Descriptor{MediaType: mediaType, Digest: d, Size: size, Platform: &platform}
	var entries []v1.Descriptor
	var annotations map[string]string
	switch {
	case isImageType(currentRev.MediaType):
		currentPlatform, ok := q.platformOf(currentRev.MediaType, currentDoc)
		if !ok || samePlatform(currentPlatform, platform) {
			return point(d)
		}
		entries = []v1.Descriptor{{MediaType: currentRev.MediaType, Digest: current,
			Size: currentRev.Size, Platform: &currentPlatform}, pushed}
	case isIndexType(currentRev.MediaType):
		replaced := map[digest.Digest]bool{}
		for _, entry := range currentDoc.Manifests {
			if entry.Digest == d {
				// the index already holds this very image
				return nil
			}
			if entry.Platform != nil && !isAttestation(entry) && samePlatform(*entry.Platform, platform) {
				replaced[entry.Digest] = true
				continue
			}
			entries = append(entries, entry)
		}
		entries = slices.DeleteFunc(entries, func(entry v1.Descriptor) bool {
			return isAttestation(entry) && replaced[digest.Digest(entry.Annotations[annotationReferenceDigest])]
		})
		entries = append(entries, pushed)
		annotations = currentDoc.Annotations
	default:
		return point(d)
	}

	indexType := mediaTypeDockerList
	for _, entry := range entries {
		if entry.MediaType != mediaTypeDockerManifest {
			indexType = v1.MediaTypeImageIndex
		}
	}
	slices.SortStableFunc(entries, func(a, b v1.Descriptor) int {
		return strings.Compare(platformKey(a.Platform), platformKey(b.Platform))
	})
	index, err := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: indexType,
		Manifests: entries, Annotations: annotations})
	if err != nil {
		return err
	}
	indexDigest, err := q.store.putBlob(index, digest.SHA256)
	if err != nil {
		return err
	}
	if err := q.store.writeRevision(name, indexDigest,
		revision{MediaType: indexType, Size: int64(len(index)), Merged: true}); err != nil {
		return err
	}
	q.s.log.Info("registry merged platform", "repository", name, "tag", tag,
		"platform", platformKey(&platform), "index", indexDigest.String(), "entries", len(entries),
		"user", nameOf(q.user))
	return point(indexDigest)
}

// dropMergedOrphan forgets an index the registry built itself once no tag
// points to it any more: nobody pushed it, so nobody can be pulling it by its
// digest, and the garbage collection can then take it. The caller holds the
// repository's lock.
func (q *registryRequest) dropMergedOrphan(d digest.Digest, tags map[string]digest.Digest) {
	q.s.dropMergedOrphan(q.store, q.route.name, d, tags)
}

func (s *Server) dropMergedOrphan(store *registryStore, name string, d digest.Digest, tags map[string]digest.Digest) {
	for _, target := range tags {
		if target == d {
			return
		}
	}
	rev, err := store.readRevision(name, d)
	if err != nil || !rev.Merged {
		return
	}
	if err := store.removeRevision(name, d); err == nil {
		s.log.Debug("registry dropped a merged index no tag points to", "repository", name,
			"digest", d.String())
	}
}

// platformOf reads the platform of an image from its configuration. An
// artifact, whose configuration is not an image's, has none.
func (q *registryRequest) platformOf(mediaType string, doc manifestDoc) (v1.Platform, bool) {
	config, ok := q.store.imageConfig(mediaType, doc)
	return config.platform, ok
}

// imageConfiguration is what the registry reads from the configuration of an
// image: its platform, and when it was built.
type imageConfiguration struct {
	platform v1.Platform
	// created is the time the configuration gives, zero where it gives none
	// or one that does not parse. Reproducible builds set it to the epoch.
	created time.Time
}

// imageConfig reads the configuration of an image. An artifact, whose
// configuration is not an image's, has none.
func (st *registryStore) imageConfig(mediaType string, doc manifestDoc) (imageConfiguration, bool) {
	if !isImageType(mediaType) || doc.Config == nil {
		return imageConfiguration{}, false
	}
	if doc.Config.MediaType != v1.MediaTypeImageConfig && doc.Config.MediaType != mediaTypeDockerConfig {
		return imageConfiguration{}, false
	}
	data, err := st.readBlob(doc.Config.Digest, maxConfigSize)
	if err != nil {
		return imageConfiguration{}, false
	}
	var config struct {
		OS           string   `json:"os"`
		Architecture string   `json:"architecture"`
		Variant      string   `json:"variant"`
		OSVersion    string   `json:"os.version"`
		OSFeatures   []string `json:"os.features"`
		Created      string   `json:"created"`
	}
	if json.Unmarshal(data, &config) != nil || config.OS == "" || config.Architecture == "" {
		return imageConfiguration{}, false
	}
	found := imageConfiguration{platform: v1.Platform{OS: config.OS, Architecture: config.Architecture,
		Variant: config.Variant, OSVersion: config.OSVersion, OSFeatures: config.OSFeatures}}
	if created, err := time.Parse(time.RFC3339Nano, config.Created); err == nil {
		found.created = created
	}
	return found, true
}

// isAttestation reports an index entry that is not an image but the
// attestation buildx attaches to one.
func isAttestation(entry v1.Descriptor) bool {
	return entry.Annotations[annotationReferenceType] == "attestation-manifest"
}

func samePlatform(a, b v1.Platform) bool {
	return platformKey(&a) == platformKey(&b)
}

// platformKey is a platform written the way docker writes it, os/arch/variant,
// with the spellings that mean the same thing made the same: arm64 is v8
// whether it says so or not, and arm is v7 unless it says otherwise.
func platformKey(platform *v1.Platform) string {
	if platform == nil {
		return ""
	}
	os := strings.ToLower(platform.OS)
	arch := strings.ToLower(platform.Architecture)
	variant := strings.ToLower(platform.Variant)
	switch arch {
	case "x86_64", "x86-64":
		arch = "amd64"
	case "aarch64":
		arch = "arm64"
	case "armhf":
		arch, variant = "arm", "v7"
	case "armel":
		arch, variant = "arm", "v6"
	}
	switch {
	case arch == "arm64" && variant == "v8":
		variant = ""
	case arch == "arm" && variant == "":
		variant = "v7"
	}
	key := os + "/" + arch
	if variant != "" {
		key += "/" + variant
	}
	if platform.OSVersion != "" {
		key += ":" + platform.OSVersion
	}
	return key
}

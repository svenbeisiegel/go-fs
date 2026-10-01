package httpd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"go-fs/internal/vfs"
)

// Importing an image archive into the registry. The archive is a file of a
// served folder, or one the registry page uploads in chunks, the way the
// listing uploads a large file. Either way the import is a job, in three
// steps. It reads the archive once, staging what is in it (see
// registry_archive.go), and offers the page the images it found. The page
// says which of them to store, under what repository and tag, and for which
// platforms. The job then stores those, the blobs and the manifests together
// under one hold of the registry's lock, so the garbage collection never sees
// a blob of the import before the manifest that refers to it.
//
// Importing takes what pushing takes, a session of an account of the
// registry. A file of a served folder also takes the right to read it, as a
// download of it would: an account that may not download a file is not to
// learn what is in it this way either.

const (
	// actionRegistryImportUpload is an archive being uploaded: POST starts
	// one, each PUT adds a chunk, DELETE drops it.
	actionRegistryImportUpload = "registry-import-upload"
	// actionRegistryImport starts reading an uploaded archive, or a file of
	// the folder.
	actionRegistryImport = "registry-import"
	// actionRegistryImportConfirm says what of an archive to store.
	actionRegistryImportConfirm = "registry-import-confirm"
)

// The steps of an import, which its job's phase names.
const (
	importReading   = "reading"
	importVerifying = "verifying"
	importStoring   = "storing"
)

// importWait is how long an import that has read its archive waits for the
// page to say what to store of it. What it staged takes the space of the
// archive meanwhile.
const importWait = 30 * time.Minute

// maxImportConfirm bounds the answer of the page, which names a target for
// each image of an archive that can hold a few hundred.
const maxImportConfirm = 64 << 10

// importUploadPrefix starts the folder of an archive being uploaded, beside
// the registry's own uploads, whose names are bare hex.
const importUploadPrefix = "import-upload-"

// importStagingPrefix starts the folder an import stages its archive in.
const importStagingPrefix = "import-"

// importArchiveFile is the uploaded archive in its folder.
const importArchiveFile = "archive"

var errImportUnanswered = errors.New("nobody chose what to import within 30 minutes, so the archive was let go")

// importUploadRecord is the record of an archive being uploaded.
type importUploadRecord struct {
	Owner   string    `json:"owner"`
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Started time.Time `json:"started"`
}

// importImageJSON is an image an import found, as the page shows it.
type importImageJSON struct {
	Index int `json:"index"`
	// Names are the references the archive gives the image.
	Names     []string                 `json:"names"`
	Targets   []importTargetJSON       `json:"targets"`
	Digest    string                   `json:"digest"`
	IsIndex   bool                     `json:"isIndex"`
	Platforms []registryPlatformChoice `json:"platforms"`
	Note      string                   `json:"note,omitempty"`
}

// importTargetJSON is where an image would be stored by default.
type importTargetJSON struct {
	Target string `json:"target"`
	// Exists says the registry has the tag already, which the import
	// replaces.
	Exists bool `json:"exists"`
}

// importChoice is what the page chose to store of an archive.
type importChoice struct {
	images []importChosen
}

// importChosen is one image to store, under its targets, for its platforms.
type importChosen struct {
	index   int
	targets []importTarget
	filter  platformFilter
}

// importTarget is a repository and a tag an image is stored under.
type importTarget struct {
	repository, tag string
}

func (t importTarget) String() string {
	return t.repository + ":" + t.tag
}

// parseImportTarget reads repository:tag.
func parseImportTarget(value string) (importTarget, error) {
	value = strings.TrimSpace(value)
	at := strings.LastIndex(value, ":")
	if at < 0 || at < strings.LastIndex(value, "/") {
		return importTarget{}, fmt.Errorf("%q has no tag; write it as repository:tag", value)
	}
	target := importTarget{repository: value[:at], tag: value[at+1:]}
	if !validRepository(target.repository) {
		return importTarget{}, fmt.Errorf("%q is not a repository name: lowercase letters, digits and separators only",
			target.repository)
	}
	if !tagPattern.MatchString(target.tag) {
		return importTarget{}, fmt.Errorf("%q is not a tag", target.tag)
	}
	return target, nil
}

// importSource is the archive an import reads.
type importSource struct {
	path string
	size int64
	// name is the file's name, which an image the archive gives only a tag
	// is named after.
	name string
	// upload is the folder of an uploaded archive, which goes once it is
	// read; "" for a file of a served folder, which stays.
	upload string
}

// --- uploading --------------------------------------------------------------

// importUploadBody starts an upload.
type importUploadBody struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// importUploadJSON is an upload that was started.
type importUploadJSON struct {
	ID string `json:"id"`
	// ChunkSize is the most a chunk may carry, 0 for no limit.
	ChunkSize int64 `json:"chunkSize"`
}

// importUploadFolder is where an upload is kept, for an id that is one.
func importUploadFolder(store *registryStore, id string) (string, bool) {
	if !uploadIDPattern.MatchString(id) {
		return "", false
	}
	return store.uploadPath(importUploadPrefix + id), true
}

// loadImportUpload reads the record of an upload of the account, and
// answers a request for one that is not there to it.
func (s *Server) loadImportUpload(set *settings, w http.ResponseWriter, id string, user *account) (string, importUploadRecord, bool) {
	folder, ok := importUploadFolder(set.registry, id)
	var record importUploadRecord
	if ok {
		data, err := os.ReadFile(filepath.Join(folder, uploadRecordFile))
		ok = err == nil && json.Unmarshal(data, &record) == nil && record.Owner == user.name
	}
	if !ok {
		http.Error(w, "That upload is not known.", http.StatusNotFound)
		return "", importUploadRecord{}, false
	}
	return folder, record, true
}

// registryImportUpload answers the requests of an upload.
func (s *Server) registryImportUpload(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	w.Header().Set("Cache-Control", "no-store")
	if user == nil {
		s.log.Info("http registry import refused, no session of a registry account",
			"address", clientAddress(set, r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.importUploadStart(set, w, r, user)
	case http.MethodPut:
		s.importUploadChunk(set, w, r, user)
	case http.MethodDelete:
		folder, _, ok := s.loadImportUpload(set, w, r.URL.Query().Get("id"), user)
		if !ok {
			return
		}
		if err := os.RemoveAll(folder); err != nil {
			s.log.Error("registry cannot remove an import upload", "path", folder, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// importUploadStart makes the folder of a new upload.
func (s *Server) importUploadStart(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	var body importUploadBody
	if !s.readTransferRequest(set, w, r, user, &body) {
		return
	}
	name := path.Base(strings.ReplaceAll(strings.TrimSpace(body.Name), "\\", "/"))
	if name == "" || name == "." || name == "/" || len(name) > 255 {
		http.Error(w, "Name the archive.", http.StatusBadRequest)
		return
	}
	if body.Size <= 0 {
		http.Error(w, "The archive is empty.", http.StatusBadRequest)
		return
	}
	if limit := set.cfg.MaxUploadSize; limit > 0 && body.Size > limit {
		http.Error(w, fmt.Sprintf("The archive has %d bytes, more than http.maxUploadSize allows.", body.Size),
			http.StatusRequestEntityTooLarge)
		return
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	id := hex.EncodeToString(raw)
	folder, _ := importUploadFolder(set.registry, id)
	record := importUploadRecord{Owner: user.name, Name: name, Size: body.Size, Started: time.Now().UTC()}
	data, err := json.Marshal(record)
	if err == nil {
		err = os.MkdirAll(folder, 0o700)
	}
	if err == nil {
		err = writeFileAtomic(filepath.Join(folder, uploadRecordFile), data)
	}
	if err != nil {
		_ = os.RemoveAll(folder)
		s.log.Error("registry cannot start an import upload", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	s.log.Info("registry import upload started", "name", name, "bytes", body.Size, "user", user.name,
		"address", clientAddress(set, r))
	writeJSON(w, http.StatusCreated, importUploadJSON{ID: id, ChunkSize: set.cfg.MaxChunkSize})
}

// importUploadChunk adds a chunk to an upload, as Content-Range says where
// it goes. A chunk that does not continue what is there gets 416 naming
// where it should have started, as for an upload to the listing.
func (s *Server) importUploadChunk(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	folder, record, ok := s.loadImportUpload(set, w, r.URL.Query().Get("id"), user)
	if !ok {
		return
	}
	if !rawUpload(r.Header.Get("Content-Type")) {
		http.Error(w, "A chunk is sent as application/octet-stream.", http.StatusUnsupportedMediaType)
		return
	}
	rng, ok := parseContentRange(r.Header.Get("Content-Range"))
	if !ok || rng.total != record.Size {
		http.Error(w, fmt.Sprintf("Each chunk names where it goes as Content-Range: bytes start-end/%d.", record.Size),
			http.StatusBadRequest)
		return
	}
	label := "registry import " + record.Name
	if limit := set.cfg.MaxChunkSize; limit > 0 && rng.end-rng.start+1 > limit {
		s.chunkTooLarge(set, w, label)
		return
	}
	archive := filepath.Join(folder, importArchiveFile)
	lock := s.uploadLock(archive)
	lock.Lock()
	defer lock.Unlock()
	if !s.writeRangeChunk(set, w, r, archive, rng, user, label) {
		return
	}
	if rng.end+1 < rng.total {
		w.WriteHeader(http.StatusOK)
		return
	}
	if info, err := os.Stat(archive); err != nil || info.Size() != record.Size {
		s.log.Error("registry import upload does not have the size it was started with",
			"name", record.Name, "want", record.Size, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	s.log.Info("registry import upload finished", "name", record.Name, "bytes", record.Size,
		"user", user.name, "address", clientAddress(set, r))
	w.WriteHeader(http.StatusCreated)
}

// --- starting -------------------------------------------------------------

// importStartBody names the archive an import reads: an upload, or a file of
// the folder the page is on.
type importStartBody struct {
	Upload string `json:"upload"`
	File   string `json:"file"`
}

// registryImport starts reading an archive.
func (s *Server) registryImport(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, user *account) {
	var body importStartBody
	if !s.readTransferRequest(set, w, r, user, &body) {
		return
	}
	var src importSource
	switch {
	case body.Upload != "" && body.File == "":
		folder, record, ok := s.loadImportUpload(set, w, body.Upload, user)
		if !ok {
			return
		}
		archive := filepath.Join(folder, importArchiveFile)
		if info, err := os.Stat(archive); err != nil || info.Size() != record.Size {
			http.Error(w, "The upload is not complete yet.", http.StatusConflict)
			return
		}
		src = importSource{path: archive, size: record.Size, name: record.Name, upload: folder}
	case body.File != "" && body.Upload == "":
		found, ok := s.importFile(set, w, r, target, body.File)
		if !ok {
			return
		}
		src = found
	default:
		http.Error(w, "Name either an upload or a file.", http.StatusBadRequest)
		return
	}

	address := clientAddress(set, r)
	job, err := s.startJob(jobImport, user.name, src.name+" → registry", func(ctx context.Context, job *registryJob) (string, error) {
		message, err := s.importArchive(ctx, set, job, src, user)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("registry import failed", "archive", src.name, "user", user.name,
				"address", address, "error", err)
		}
		return message, err
	})
	if err == nil {
		s.log.Info("registry import started", "archive", src.name, "bytes", src.size,
			"uploaded", src.upload != "", "user", user.name, "address", address, "job", job.id)
	}
	s.answerStarted(w, job, err)
}

// importFile finds a file of the folder the page is on that the session may
// read, and answers a request for one it may not.
func (s *Server) importFile(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, name string) (importSource, bool) {
	folder := vfs.AsFolder(target.Virtual)
	file := s.root.Resolve(folder, name)
	if strings.ContainsAny(name, "/\\") || !file.Valid || vfs.AsFolder(path.Dir(file.Virtual)) != folder {
		http.Error(w, "That is not a file of this folder.", http.StatusBadRequest)
		return importSource{}, false
	}
	cred := s.identify(set, w, r)
	if !s.permits(set, cred.user, http.MethodGet, file.Virtual, actRead) {
		s.log.Info("http registry import refused, the account may not read the file",
			"user", nameOf(cred.user), "file", file.Virtual, "address", clientAddress(set, r))
		http.Error(w, "This account may not read that file.", http.StatusForbidden)
		return importSource{}, false
	}
	info, err := os.Stat(file.Path)
	if err != nil || !info.Mode().IsRegular() {
		http.Error(w, "That file is not there.", http.StatusNotFound)
		return importSource{}, false
	}
	return importSource{path: file.Path, size: info.Size(), name: path.Base(file.Virtual)}, true
}

// --- the job ----------------------------------------------------------------

// importArchive reads an archive, waits for the page to choose what of it to
// store, and stores that.
func (s *Server) importArchive(ctx context.Context, set *settings, job *registryJob, src importSource, user *account) (string, error) {
	store := set.registry
	started := time.Now()
	dir := store.uploadPath(importStagingPrefix + job.id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if src.upload != "" {
		defer func() { _ = os.RemoveAll(src.upload) }()
	}

	file, err := os.Open(src.path)
	if err != nil {
		return "", fmt.Errorf("the archive cannot be opened: %w", err)
	}
	job.setPhase(importReading, src.size)
	count := func(n int64) { job.bytesDone.Add(n) }
	archive, err := readImageArchive(ctx, &countingReader{r: file, count: count}, dir, src.name, set.cfg.MaxUploadSize)
	_ = file.Close()
	if src.upload != "" {
		// staged, the upload is only taking room twice
		_ = os.RemoveAll(src.upload)
	}
	if err != nil {
		return "", err
	}
	if size := archive.verifySize(); size > 0 {
		job.setPhase(importVerifying, size)
		if err := archive.verifyLayers(ctx, count); err != nil {
			return "", err
		}
	}
	s.log.Info("registry import read its archive", "archive", src.name, "format", archive.format,
		"images", len(archive.images), "user", user.name, "job", job.id,
		"took", time.Since(started).Round(time.Millisecond))

	job.ready(importOffer(store, archive))
	choice, err := job.await(ctx, importWait)
	if err != nil {
		return "", err
	}
	plans, err := planImport(archive, choice)
	if err != nil {
		return "", err
	}
	var blobs []v1.Descriptor
	for _, plan := range plans {
		blobs = addBlobs(blobs, plan.blobs...)
	}
	job.setPhase(importStoring, blobsSize(blobs))
	job.blobsTotal.Store(int64(len(blobs)))

	s.registryMu.RLock()
	err = s.storeImport(store, archive, plans, blobs, job)
	s.registryMu.RUnlock()
	if err != nil {
		return "", err
	}

	var stored []string
	for _, plan := range plans {
		for _, target := range plan.targets {
			s.log.Info("registry image imported", "repository", target.repository, "tag", target.tag,
				"archive", src.name, "digest", plan.top.digest.String(), "platforms", strings.Join(plan.platforms, ","),
				"user", user.name, "took", time.Since(started).Round(time.Millisecond))
			entry := target.String()
			if len(plan.platforms) > 0 {
				entry += " (" + strings.Join(plan.platforms, ", ") + ")"
			}
			stored = append(stored, entry)
		}
	}
	return "Imported " + strings.Join(stored, ", ") + ".", nil
}

// importOffer is what the page is offered of an archive.
func importOffer(store *registryStore, archive *imageArchive) []importImageJSON {
	offer := []importImageJSON{}
	for i, image := range archive.images {
		entry := importImageJSON{Index: i, Names: image.names, Digest: image.top.digest.String(),
			IsIndex: isIndexType(image.top.mediaType), Platforms: platformChoices(image.platforms), Note: image.note,
			Targets: []importTargetJSON{}}
		if entry.Names == nil {
			entry.Names = []string{}
		}
		for _, value := range image.targets {
			target, err := parseImportTarget(value)
			if err != nil {
				continue
			}
			exists := false
			if tags, err := store.readTags(target.repository); err == nil {
				_, exists = tags[target.tag]
			}
			entry.Targets = append(entry.Targets, importTargetJSON{Target: value, Exists: exists})
		}
		offer = append(offer, entry)
	}
	return offer
}

// importPlan is one image to store, as its platforms leave it.
type importPlan struct {
	top       pulledManifest
	children  []pulledManifest
	blobs     []v1.Descriptor
	platforms []string
	targets   []importTarget
}

// planImport is what storing a choice takes.
func planImport(archive *imageArchive, choice importChoice) ([]importPlan, error) {
	var plans []importPlan
	for _, chosen := range choice.images {
		if chosen.index < 0 || chosen.index >= len(archive.images) {
			return nil, fmt.Errorf("the archive has no image %d", chosen.index)
		}
		plan, err := planImage(archive.images[chosen.index], chosen.filter)
		if err != nil {
			return nil, err
		}
		plan.targets = chosen.targets
		plans = append(plans, plan)
	}
	return plans, nil
}

// planImage is an image as a platform filter leaves it: an index cut to the
// platforms kept, as a pull cuts it.
func planImage(image archiveImage, filter platformFilter) (importPlan, error) {
	plan := importPlan{top: image.top, children: image.children, blobs: image.blobs, platforms: image.platforms}
	if len(filter) == 0 {
		return plan, nil
	}
	if !isIndexType(image.top.mediaType) {
		key := ""
		if len(image.platforms) > 0 {
			key = image.platforms[0]
		}
		if !filter.matches(key) {
			if key == "" {
				return importPlan{}, fmt.Errorf("%s is not an image for a platform, so it cannot be imported for %s",
					image.top.digest, strings.Join(filter, ", "))
			}
			return importPlan{}, fmt.Errorf("%s is only for %s, not for %s", image.top.digest, key,
				strings.Join(filter, ", "))
		}
		return plan, nil
	}
	kept, err := keptEntries(image.top.doc, filter)
	if err != nil {
		return importPlan{}, err
	}
	if len(kept) < len(image.top.doc.Manifests) {
		body, d, rebuilt, err := subsetIndex(image.top.mediaType, image.top.doc, kept)
		if err != nil {
			return importPlan{}, err
		}
		plan.top = pulledManifest{body: body, mediaType: image.top.mediaType, digest: d, doc: rebuilt}
	}
	keep := map[digest.Digest]bool{}
	for _, entry := range kept {
		keep[entry.Digest] = true
	}
	plan.children, plan.blobs = nil, nil
	for _, child := range image.children {
		if keep[child.digest] {
			plan.children = append(plan.children, child)
			plan.blobs = addBlobs(plan.blobs, imageBlobs(child.doc)...)
		}
	}
	plan.platforms = indexPlatforms(plan.top.doc)
	return plan, nil
}

// storeImport moves the blobs of an import into the store, then stores its
// manifests and points its tags at them. The caller holds the registry's
// lock, which keeps the garbage collection out until the manifests that
// refer to the blobs are there.
func (s *Server) storeImport(store *registryStore, archive *imageArchive, plans []importPlan, blobs []v1.Descriptor, job *registryJob) error {
	for _, blob := range blobs {
		file, ok := archive.blob(blob.Digest)
		if !ok {
			return fmt.Errorf("the blob %s is not in the archive", blob.Digest)
		}
		if _, err := store.blobInfo(blob.Digest); err != nil {
			if err := syncFile(file.path); err != nil {
				return err
			}
		}
		if err := store.commitBlob(file.path, blob.Digest); err != nil {
			return err
		}
		job.blobsDone.Add(1)
		job.bytesDone.Add(blob.Size)
	}
	for _, plan := range plans {
		for _, target := range plan.targets {
			if err := s.storeImportTarget(store, plan, target); err != nil {
				return err
			}
		}
	}
	return nil
}

// storeImportTarget stores an image under one of its targets.
func (s *Server) storeImportTarget(store *registryStore, plan importPlan, target importTarget) error {
	lock := registryLock(&s.registryRepositoryLocks, target.repository)
	lock.Lock()
	defer lock.Unlock()
	for _, blob := range plan.blobs {
		if err := store.linkBlob(target.repository, blob.Digest); err != nil {
			return err
		}
	}
	return s.storePulledLocked(store, target.repository, target.tag, plan.top, plan.children)
}

// --- confirming -------------------------------------------------------------

// importConfirmBody is what the page chose of an archive.
type importConfirmBody struct {
	Images []struct {
		Index     int      `json:"index"`
		Targets   []string `json:"targets"`
		Platforms string   `json:"platforms"`
	} `json:"images"`
}

// registryImportConfirm hands the page's choice to an import that waits for
// it. A choice that cannot be stored is refused here, and the import goes on
// waiting for a better one.
func (s *Server) registryImportConfirm(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	job := s.jobOf(w, r, user)
	if job == nil {
		return
	}
	if job.kind != jobImport {
		http.Error(w, "That transfer is not an import.", http.StatusNotFound)
		return
	}
	var body importConfirmBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxImportConfirm)).Decode(&body); err != nil {
		http.Error(w, "The request could not be read.", http.StatusBadRequest)
		return
	}
	view := job.view()
	if view.State != jobReady {
		http.Error(w, "The import is not waiting for a choice.", http.StatusConflict)
		return
	}
	choice, err := readImportChoice(body, view.Images)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !job.choose(choice) {
		http.Error(w, "The import was told what to store already.", http.StatusConflict)
		return
	}
	var targets []string
	for _, chosen := range choice.images {
		for _, target := range chosen.targets {
			targets = append(targets, target.String())
		}
	}
	s.log.Info("registry import confirmed", "job", job.id, "targets", strings.Join(targets, ","),
		"user", user.name, "address", clientAddress(set, r))
	writeJSON(w, http.StatusAccepted, job.view())
}

// readImportChoice checks what the page chose against what the import
// offered.
func readImportChoice(body importConfirmBody, offer []importImageJSON) (importChoice, error) {
	var choice importChoice
	seenImages := map[int]bool{}
	seenTargets := map[string]bool{}
	for _, image := range body.Images {
		if image.Index < 0 || image.Index >= len(offer) {
			return importChoice{}, fmt.Errorf("the archive has no image %d", image.Index)
		}
		if seenImages[image.Index] {
			return importChoice{}, fmt.Errorf("image %d is chosen twice", image.Index)
		}
		seenImages[image.Index] = true
		if len(image.Targets) == 0 {
			continue
		}
		chosen := importChosen{index: image.Index}
		for _, value := range image.Targets {
			target, err := parseImportTarget(value)
			if err != nil {
				return importChoice{}, err
			}
			if seenTargets[target.String()] {
				return importChoice{}, fmt.Errorf("%s is chosen for two images; a tag holds one", target)
			}
			seenTargets[target.String()] = true
			chosen.targets = append(chosen.targets, target)
		}
		filter, err := parsePlatforms(image.Platforms)
		if err != nil {
			return importChoice{}, err
		}
		if len(filter) > 0 {
			matched := false
			var offered []string
			for _, platform := range offer[image.Index].Platforms {
				offered = append(offered, platform.Platform)
				matched = matched || filter.matches(platform.Platform)
			}
			if !matched {
				return importChoice{}, fmt.Errorf("image %d has no %s; it has %s", image.Index,
					strings.Join(filter, ", "), strings.Join(offered, ", "))
			}
		}
		chosen.filter = filter
		choice.images = append(choice.images, chosen)
	}
	if len(choice.images) == 0 {
		return importChoice{}, errors.New("choose at least one image to import, with a repository and a tag")
	}
	return choice, nil
}

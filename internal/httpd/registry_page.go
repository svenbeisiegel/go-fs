package httpd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"go-fs/internal/vfs"
)

// The registry page shows what the container registry holds, the way the
// listing shows a folder. It is served under the go-fs marker like the login
// and the admin interface, so it reserves no name in the served folder, and it
// is served on whatever folder its button was pressed in, which is where its
// Files button leads back to.
//
// Who may look is what may pull: anyone while registryAnonymousRead is on,
// and otherwise a session of an account that sets registry. Deleting a tag
// takes that session whatever the setting says, since it is what pushing
// takes. A session is the only credential it reads, as for the admin
// interface: a header is what docker sends, and docker has the API. Pulling
// an image from another registry and pushing a tag to one take that session
// too: the one writes to the registry, and the other hands its images to
// wherever the account says. So does importing an image archive, which
// writes to the registry as a push does, and running the cleanup of
// unreferenced blobs now rather than with the hourly sweep, since it removes
// what a push may still be about to refer to.

const (
	actionRegistry      = "registry"
	actionRegistryImage = "registry-image"
	actionRegistryPull  = "registry-pull"
	actionRegistryPush  = "registry-push"
	actionRegistryJob   = "registry-job"
	// the cleanup of unreferenced blobs, run now
	actionRegistryCleanup = "registry-cleanup"
	// the checks the dialogs make before a pull or a push may start
	actionRegistryPullCheck = "registry-pull-check"
	actionRegistryPushCheck = "registry-push-check"
	// importing an image archive is in registry_import.go
)

// registryPageMethods are the methods each endpoint of the page answers.
var registryPageMethods = map[string]string{
	actionRegistry:          "GET, HEAD, DELETE",
	actionRegistryImage:     "GET, HEAD",
	actionRegistryPull:      "POST",
	actionRegistryPush:      "POST",
	actionRegistryJob:       "GET, HEAD, DELETE",
	actionRegistryCleanup:   "POST",
	actionRegistryPullCheck: "POST",
	actionRegistryPushCheck: "POST",

	actionRegistryImportUpload:  "POST, PUT, DELETE",
	actionRegistryImport:        "POST",
	actionRegistryImportConfirm: "POST",
}

// registryPageAction reports which registry endpoint a request is for, or ""
// for any other request.
func registryPageAction(r *http.Request) string {
	switch action := r.URL.Query().Get(sessionParam); action {
	case actionRegistry, actionRegistryImage, actionRegistryPull, actionRegistryPush, actionRegistryJob,
		actionRegistryPullCheck, actionRegistryPushCheck, actionRegistryCleanup,
		actionRegistryImportUpload, actionRegistryImport, actionRegistryImportConfirm:
		return action
	default:
		return ""
	}
}

// canLogInToRegistry reports whether the login form has an account of the
// registry to log in, beside the http ones canLogIn counts.
func canLogInToRegistry(set *settings) bool {
	return set.registry != nil && len(set.registryAccounts) > 0
}

// registryClaims resolves a session token to the account of the registry it
// was issued for, or nothing while the registry is off.
func (s *Server) registryClaims(set *settings, claims *sessionClaims) *account {
	if set.registry == nil {
		return nil
	}
	user := accountNamed(set.registryAccounts, claims.Subject)
	if user == nil || !s.tokens.issuedFor(claims, user) {
		return nil
	}
	return user
}

// registrySession is the account of the registry the browser holds a session
// of, or nothing. Like sessionMatches it clears and logs nothing: checkToken
// does that for the cookie, on the requests that depend on it.
func (s *Server) registrySession(set *settings, r *http.Request) *account {
	if set.registry == nil {
		return nil
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	claims, err := s.tokens.read(cookie.Value)
	if err != nil {
		return nil
	}
	return s.registryClaims(set, claims)
}

// offersRegistry decides whether a page carries the Registry button. It is
// left off only where pressing it could not help: the registry is off, or
// someone is signed in whom the registry refuses.
func (s *Server) offersRegistry(set *settings, cred credential, registryUser *account) bool {
	if set.registry == nil {
		return false
	}
	if set.cfg.RegistryAnonymousRead || registryUser != nil {
		return true
	}
	return !cred.token || cred.user == nil
}

// registryURL is the registry page on the folder of this request. Nothing
// else of the query comes along: the listing's order is not the registry's.
func registryURL(u *url.URL) string {
	return (&url.URL{Path: u.Path, RawQuery: sessionParam + "=" + actionRegistry}).RequestURI()
}

// handleRegistryPage guards the registry page and its endpoints and hands the
// request over.
func (s *Server) handleRegistryPage(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, action string) {
	if set.registry == nil {
		// switched off, the marker names nothing
		http.NotFound(w, r)
		return
	}
	// what is on the page depends on who is signed in, so a shared cache must
	// not hand one browser's copy to another
	w.Header().Set("Vary", "Cookie")
	user, ok := s.registryViewer(set, w, r, target, action)
	if !ok {
		return
	}
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case action == actionRegistryImage && read:
		s.registryImage(set, w, r)
	case action == actionRegistry && read:
		s.registryPage(set, w, r, user)
	case action == actionRegistry && r.Method == http.MethodDelete:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryUntag(set, w, r, user)
	case action == actionRegistryPull && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryPull(set, w, r, user)
	case action == actionRegistryPush && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryPush(set, w, r, user)
	case action == actionRegistryPullCheck && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryPullCheck(set, w, r, user)
	case action == actionRegistryPushCheck && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryPushCheck(set, w, r, user)
	case action == actionRegistryJob && read:
		s.registryJobStatus(w, r, user)
	case action == actionRegistryJob && r.Method == http.MethodDelete:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryJobCancel(w, r, user)
	case action == actionRegistryCleanup && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryCleanup(set, w, r, user)
	case action == actionRegistryImportUpload &&
		(r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete):
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryImportUpload(set, w, r, user)
	case action == actionRegistryImport && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryImport(set, w, r, target, user)
	case action == actionRegistryImportConfirm && r.Method == http.MethodPost:
		if !s.sameSite(set, w, r) {
			return
		}
		s.registryImportConfirm(set, w, r, user)
	default:
		w.Header().Set("Allow", registryPageMethods[action])
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// registryViewer decides whether a request may see the registry, and returns
// the account of the registry behind it, nil for someone who may only look.
// A request that may not is answered here.
func (s *Server) registryViewer(set *settings, w http.ResponseWriter, r *http.Request, target vfs.Target, action string) (*account, bool) {
	if user := s.registrySession(set, r); user != nil {
		return user, true
	}
	if set.cfg.RegistryAnonymousRead {
		return nil, true
	}
	w.Header().Set("Cache-Control", "no-store")
	page := action == actionRegistry && browserRequest(r) &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead)
	if !page {
		// a fetch from a page whose session ran out is told plainly, as it is
		// for the file endpoints
		s.log.Debug("http registry page refused, no session", "method", r.Method,
			"address", clientAddress(set, r))
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return nil, false
	}
	if cred := s.identify(set, w, r); cred.token && cred.user != nil {
		// signed in, but as an account the registry does not know: the login
		// page would send a session straight back here, so it is shown in
		// place, to log in as someone else
		s.log.Info("http registry page refused, the account does not set registry",
			"user", cred.user.name, "address", clientAddress(set, r))
		s.loginPage(w, r, target, "This account cannot use the registry. Log in with one that can.")
		return nil, false
	}
	http.Redirect(w, r, loginURL(r.URL), http.StatusSeeOther)
	return nil, false
}

// --- what an image is ------------------------------------------------------

// registryPlatform is one image of a tag: the only one of a plain image, or
// one entry of an index.
type registryPlatform struct {
	// key is the platform as platformKey writes it, empty for an artifact,
	// whose configuration names none.
	key       string
	digest    digest.Digest
	mediaType string
	config    digest.Digest
	// configSize is the size of the configuration blob.
	configSize int64
	created    time.Time
	// size is what pulling the image downloads: its configuration and its
	// layers, as the manifest gives their sizes.
	size   int64
	layers []v1.Descriptor
}

// imageSummary is what a manifest amounts to. It depends on nothing but the
// manifest's content, which its digest names, so it never goes stale.
type imageSummary struct {
	mediaType string
	platforms []registryPlatform
	// size is what the platforms take up in the store, where a blob two of
	// them share is kept once.
	size int64
}

// maxSummaries bounds the cache of summaries. Each is a few hundred bytes, and
// a registry with more manifests than this is read again, not held in memory.
const maxSummaries = 4096

// summaryCache keeps the summaries already worked out, so that a page does
// not read every manifest and every configuration each time it is shown.
type summaryCache struct {
	mu      sync.Mutex
	entries map[digest.Digest]imageSummary
}

func (c *summaryCache) get(d digest.Digest) (imageSummary, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	found, ok := c.entries[d]
	return found, ok
}

func (c *summaryCache) put(d digest.Digest, summary imageSummary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= maxSummaries {
		c.entries = make(map[digest.Digest]imageSummary)
	}
	c.entries[d] = summary
}

// readManifest reads and decodes a manifest of the store.
func readManifest(store *registryStore, d digest.Digest) (manifestDoc, error) {
	data, err := store.readBlob(d, maxManifestSize)
	if err != nil {
		return manifestDoc{}, err
	}
	var doc manifestDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return manifestDoc{}, fmt.Errorf("manifest %s: %w", d, err)
	}
	return doc, nil
}

// summarize works out what a manifest of a repository is. An index is its
// images, without the attestations buildx puts beside them.
func (s *Server) summarize(store *registryStore, name string, d digest.Digest) (imageSummary, error) {
	if found, ok := s.registrySummaries.get(d); ok {
		return found, nil
	}
	rev, err := store.readRevision(name, d)
	if err != nil {
		return imageSummary{}, err
	}
	doc, err := readManifest(store, d)
	if err != nil {
		return imageSummary{}, err
	}
	summary := imageSummary{mediaType: rev.MediaType}
	complete := true
	switch {
	case isIndexType(rev.MediaType):
		for _, entry := range doc.Manifests {
			if isAttestation(entry) || (entry.Platform != nil && entry.Platform.OS == "unknown") {
				continue
			}
			child, err := readManifest(store, entry.Digest)
			if err != nil {
				// what the index says is still worth showing, without a size
				complete = false
				child = manifestDoc{}
			}
			summary.platforms = append(summary.platforms,
				describeImage(store, entry.MediaType, entry.Digest, child, entry.Platform))
		}
	case isImageType(rev.MediaType):
		summary.platforms = []registryPlatform{describeImage(store, rev.MediaType, d, doc, nil)}
	}
	orderPlatforms(summary.platforms)
	seen := map[digest.Digest]bool{}
	for _, platform := range summary.platforms {
		for _, blob := range platform.blobs() {
			if !seen[blob.Digest] {
				seen[blob.Digest] = true
				summary.size += blob.Size
			}
		}
	}
	if complete {
		s.registrySummaries.put(d, summary)
	}
	return summary, nil
}

// describeImage reads what an image manifest says. declared is the platform
// an index gives the image, which is what a client picks it by, and so what
// is shown where there is one.
func describeImage(store *registryStore, mediaType string, d digest.Digest, doc manifestDoc, declared *v1.Platform) registryPlatform {
	found := registryPlatform{digest: d, mediaType: mediaType, layers: doc.Layers}
	if doc.Config != nil {
		found.config, found.configSize = doc.Config.Digest, doc.Config.Size
	}
	for _, blob := range found.blobs() {
		found.size += blob.Size
	}
	if config, ok := store.imageConfig(mediaType, doc); ok {
		found.key = platformKey(&config.platform)
		found.created = config.created
	}
	if declared != nil {
		found.key = platformKey(declared)
	}
	return found
}

// blobs are what pulling an image downloads: its configuration and its
// layers.
func (p registryPlatform) blobs() []v1.Descriptor {
	blobs := make([]v1.Descriptor, 0, len(p.layers)+1)
	if p.config != "" {
		blobs = append(blobs, v1.Descriptor{Digest: p.config, Size: p.configSize})
	}
	return append(blobs, p.layers...)
}

// leadingPlatforms are the platforms most images are run on. They come first
// wherever the platforms of a tag are shown, in this order; the rest keep the
// order of the index.
var leadingPlatforms = []string{"linux/amd64", "linux/arm64", "linux/arm/v7"}

func platformRank(key string) int {
	if i := slices.Index(leadingPlatforms, key); i >= 0 {
		return i
	}
	return len(leadingPlatforms)
}

func orderPlatforms(platforms []registryPlatform) {
	slices.SortStableFunc(platforms, func(a, b registryPlatform) int {
		return platformRank(a.key) - platformRank(b.key)
	})
}

// orderKeys orders platforms written as platformKey writes them the same way.
func orderKeys(keys []string) []string {
	slices.SortStableFunc(keys, func(a, b string) int {
		return platformRank(a) - platformRank(b)
	})
	return keys
}

// platformLabel is what the badge of a platform says. Nearly every image is
// for Linux, so the badge names only the architecture unless it is not.
func platformLabel(key string) string {
	return strings.TrimPrefix(key, "linux/")
}

// registryTag is a tag together with the image it points to.
type registryTag struct {
	repository string
	tag        string
	digest     digest.Digest
	summary    imageSummary
	pushed     time.Time
}

// registryTags reads the tags of a repository. A tag whose manifest cannot be
// read is still listed, without what it is, so that it can be deleted.
func (s *Server) registryTags(store *registryStore, name string) ([]registryTag, error) {
	tags, err := store.readTags(name)
	if err != nil {
		return nil, err
	}
	found := make([]registryTag, 0, len(tags))
	for tag, d := range tags {
		entry := registryTag{repository: name, tag: tag, digest: d}
		if summary, err := s.summarize(store, name, d); err == nil {
			entry.summary = summary
		} else {
			s.log.Warn("registry page cannot read a manifest", "repository", name, "tag", tag,
				"digest", d.String(), "error", err)
		}
		if pushed, err := store.revisionTime(name, d); err == nil {
			entry.pushed = pushed
		}
		found = append(found, entry)
	}
	return found, nil
}

// --- the page --------------------------------------------------------------

// registryView is what the query string asked the page to show.
type registryView struct {
	tree bool
	// path is the namespace or repository the folder view is at, "" for the
	// top. The list view has none.
	path  string
	order sortOrder
}

func parseRegistryView(query url.Values) registryView {
	view := registryView{tree: query.Get("view") == "tree", order: parseSort(query)}
	if view.tree {
		view.path = strings.Trim(query.Get("path"), "/")
	}
	if view.order.key == sortType {
		// the registry has no Type column
		view.order = sortOrder{}
	}
	return view
}

// link is the page with this view, on the folder base.
func (v registryView) link(base string) string {
	query := url.Values{sessionParam: {actionRegistry}}
	if v.tree {
		query.Set("view", "tree")
		if v.path != "" {
			query.Set("path", v.path)
		}
	}
	if v.order.key != "" {
		query.Set("sort", v.order.key)
		query.Set("dir", v.order.direction())
	}
	return base + "?" + query.Encode()
}

type registryBadge struct {
	Label string
	Title string
	// More stands in for the platforms a row has no room for.
	More bool
}

// maxBadges is how many badges a row shows. A tag with more platforms shows
// one fewer and a badge that names the rest in its title.
const maxBadges = 3

type registryRow struct {
	// Name is what the filter looks at.
	Name  string
	Label string
	// Parts are the label cut where a narrow screen may wrap it: after each
	// slash and before the tag.
	Parts    []string
	IsFolder bool
	// Link and Note are a folder's: where it leads, and what is in it.
	Link string
	Note string
	// The rest is a tag's.
	Repository string
	Tag        string
	Pull       string
	Platforms  []registryBadge
	Pushed     string
	Unix       int64
	Size       string
	Bytes      int64
}

type registryData struct {
	Title  string
	Crumbs []crumb
	Parent string
	Tree   bool
	// List and Folders are the two views.
	List    string
	Folders string
	// Base is the path the script sends its requests to.
	Base    string
	Columns []column
	Entries []registryRow
	Empty   string
	// Write says the account may delete tags, pull images from another
	// registry and push tags to one.
	Write bool
	// Import is the archive of the folder the Import dialog opens with,
	// which the listing's Import into registry asks for.
	Import  string
	Session sessionView
	Nonce   string
	Style   template.CSS
	Script  template.JS
}

var registryTemplate = template.Must(template.ParseFS(assets, "assets/registry.html", "assets/partials.html"))

var registryScript = template.JS(mustRead("assets/registry.js"))

// registryPage renders the list or the folder view.
func (s *Server) registryPage(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	store := set.registry
	view := parseRegistryView(r.URL.Query())
	base := (&url.URL{Path: r.URL.Path}).EscapedPath()
	names, err := store.repositories()
	if err != nil {
		s.log.Error("registry page cannot list the repositories", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	var folders []registryRow
	var shown []string
	if view.tree {
		children, isRepository, exists := treeAt(names, view.path)
		if !exists {
			http.NotFound(w, r)
			return
		}
		for _, child := range children {
			folders = append(folders, s.folderRow(store, names, child, view, base))
		}
		if isRepository {
			shown = []string{view.path}
		}
	} else {
		shown = names
	}
	var tags []registryTag
	for _, name := range shown {
		found, err := s.registryTags(store, name)
		if err != nil {
			s.log.Error("registry page cannot read the tags", "repository", name, "error", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		tags = append(tags, found...)
	}
	sortRegistryTags(tags, view.order)

	rows := folders
	for _, entry := range tags {
		rows = append(rows, tagRow(entry, view.tree, r.Host))
	}

	nonce, err := pageNonce()
	if err != nil {
		s.log.Error("http cannot render the registry page", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	who := s.sessionViewFor(set, r, s.identify(set, w, r))
	who.Page, who.Files, who.Registry = "Registry", base, ""
	listView, treeView := view, view
	listView.tree, listView.path = false, ""
	treeView.tree, treeView.path = true, ""
	data := registryData{
		Title:   "Registry",
		Crumbs:  registryCrumbs(view, base),
		Tree:    view.tree,
		List:    listView.link(base),
		Folders: treeView.link(base),
		Base:    base,
		Columns: registryColumns(view, base),
		Entries: rows,
		Write:   user != nil,
		Import:  importParam(r, user),
		Session: who,
		Nonce:   nonce,
		Style:   listingStyle,
		Script:  registryScript,
	}
	if view.tree && view.path != "" {
		data.Title = view.path + " · Registry"
		parent := view
		parent.path, _, _ = cutLast(view.path)
		data.Parent = parent.link(base)
	}
	if len(rows) == 0 {
		data.Empty = "Nothing has been pushed to the registry yet."
		if view.tree && view.path != "" {
			data.Empty = "This repository has no tags."
		}
	}

	var page bytes.Buffer
	if err := registryTemplate.Execute(&page, data); err != nil {
		s.log.Error("http cannot render the registry page", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Security-Policy", contentPolicy(nonce))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(page.Bytes())
	}
}

// importParam is the archive the page is asked to open the Import dialog
// with: a name in the folder, never a path, and only for whoever may import.
func importParam(r *http.Request, user *account) string {
	name := r.URL.Query().Get("import")
	if user == nil || name == "" || strings.ContainsAny(name, "/\\") || !isArchiveName(name) {
		return ""
	}
	return name
}

// treeAt reads the folder view at a path out of the repository names: the
// namespaces and repositories right below it, in order, and whether it is a
// repository itself. A path that is neither of these does not exist.
func treeAt(names []string, at string) (children []string, isRepository, exists bool) {
	prefix := ""
	if at != "" {
		prefix = at + "/"
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == at {
			isRepository = true
			continue
		}
		rest, ok := strings.CutPrefix(name, prefix)
		if !ok {
			continue
		}
		segment, _, _ := strings.Cut(rest, "/")
		if child := prefix + segment; !seen[child] {
			seen[child] = true
			children = append(children, child)
		}
	}
	slices.Sort(children)
	return children, isRepository, at == "" || isRepository || len(children) > 0
}

// folderRow is a namespace or a repository in the folder view.
func (s *Server) folderRow(store *registryStore, names []string, child string, view registryView, base string) registryRow {
	_, label, _ := cutLast(child)
	next := view
	next.path = child
	row := registryRow{Name: label, Label: label, IsFolder: true, Link: next.link(base), Size: "—", Pushed: "—"}
	var notes []string
	if slices.Contains(names, child) {
		if tags, err := store.readTags(child); err == nil {
			notes = append(notes, plural(len(tags), "tag", "tags"))
		}
	}
	below := 0
	for _, name := range names {
		if strings.HasPrefix(name, child+"/") {
			below++
		}
	}
	if below > 0 {
		notes = append(notes, plural(below, "repository", "repositories"))
	}
	row.Note = strings.Join(notes, " · ")
	return row
}

// tagRow is a tag. The list view names it in full, the folder view, which is
// already in the repository, by the tag alone.
func tagRow(entry registryTag, tree bool, host string) registryRow {
	full := entry.repository + ":" + entry.tag
	row := registryRow{
		Name:       full,
		Label:      full,
		Repository: entry.repository,
		Tag:        entry.tag,
		Pull:       "docker pull " + host + "/" + full,
		Size:       "—",
		Pushed:     "—",
	}
	if tree {
		row.Name, row.Label = entry.tag, entry.tag
	}
	row.Parts = wrapPoints(row.Label)
	if !entry.pushed.IsZero() {
		row.Pushed = entry.pushed.Format("2006-01-02 15:04")
		row.Unix = entry.pushed.Unix()
	}
	if entry.summary.size > 0 {
		row.Size = readableSize(entry.summary.size)
		row.Bytes = entry.summary.size
	}
	for _, platform := range entry.summary.platforms {
		if platform.key == "" {
			continue
		}
		row.Platforms = append(row.Platforms, registryBadge{Label: platformLabel(platform.key), Title: platform.key})
	}
	if len(row.Platforms) > maxBadges {
		var rest []string
		for _, badge := range row.Platforms[maxBadges-1:] {
			rest = append(rest, badge.Title)
		}
		row.Platforms = append(row.Platforms[:maxBadges-1:maxBadges-1],
			registryBadge{Label: "…more", Title: strings.Join(rest, ", "), More: true})
	}
	return row
}

// sortRegistryTags puts the tags in the asked-for order. The default is by
// name, which keeps the tags of a repository together. Ties break on the
// name, so that two tags pushed together keep a fixed order between reloads.
func sortRegistryTags(tags []registryTag, order sortOrder) {
	name := func(a, b registryTag) int {
		if c := strings.Compare(a.repository, b.repository); c != 0 {
			return c
		}
		return strings.Compare(a.tag, b.tag)
	}
	slices.SortStableFunc(tags, func(a, b registryTag) int {
		c := 0
		switch order.key {
		case sortName:
			c = name(a, b)
		case sortDate:
			c = a.pushed.Compare(b.pushed)
		case sortSize:
			c = compareSizes(a.summary.size, b.summary.size)
		}
		if order.desc {
			c = -c
		}
		if c != 0 {
			return c
		}
		return name(a, b)
	})
}

func compareSizes(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// registryColumns are the headers of the page. The platforms are a set of
// badges, which have no order to sort by.
func registryColumns(view registryView, base string) []column {
	defined := []column{
		{Key: sortName, Label: "Name", Class: "c-name"},
		{Label: "Platforms", Class: "c-plat"},
		{Key: sortDate, Label: "Pushed", Class: "c-mod"},
		{Key: sortSize, Label: "Size", Class: "c-size num"},
	}
	for i := range defined {
		if defined[i].Key == "" {
			continue
		}
		next := view
		next.order = nextOrder(view.order, defined[i].Key)
		defined[i].Link = next.link(base)
		if defined[i].Key != view.order.key {
			continue
		}
		defined[i].Active = true
		if view.order.desc {
			defined[i].Order, defined[i].Caret = "descending", "▼"
		} else {
			defined[i].Order, defined[i].Caret = "ascending", "▲"
		}
	}
	return defined
}

// registryCrumbs is the trail above the page: the registry, and in the folder
// view the namespaces down to where it is.
func registryCrumbs(view registryView, base string) []crumb {
	root := crumb{Name: "Registry"}
	if !view.tree || view.path == "" {
		return []crumb{root}
	}
	top := view
	top.path = ""
	root.Link, root.Sep = top.link(base), true
	crumbs := []crumb{root}
	parts := strings.Split(view.path, "/")
	for i, part := range parts {
		step := crumb{Name: part, Sep: i < len(parts)-1}
		if i < len(parts)-1 {
			at := view
			at.path = strings.Join(parts[:i+1], "/")
			step.Link = at.link(base)
		}
		crumbs = append(crumbs, step)
	}
	return crumbs
}

// cutLast splits a repository name at its last slash, into the namespace and
// the last component.
func cutLast(name string) (before, last string, found bool) {
	i := strings.LastIndex(name, "/")
	if i < 0 {
		return "", name, false
	}
	return name[:i], name[i+1:], true
}

// wrapPoints cuts a name after each slash and before the colon of its tag.
func wrapPoints(label string) []string {
	var parts []string
	for _, part := range strings.SplitAfter(label, "/") {
		if before, after, found := strings.Cut(part, ":"); found {
			parts = append(parts, before, ":"+after)
			continue
		}
		parts = append(parts, part)
	}
	return parts
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// --- the details and the delete ----------------------------------------------

type registryLayerJSON struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
}

type registryPlatformJSON struct {
	Platform  string              `json:"platform"`
	Label     string              `json:"label"`
	Digest    string              `json:"digest"`
	MediaType string              `json:"mediaType"`
	Config    string              `json:"config,omitempty"`
	Created   string              `json:"created,omitempty"`
	Size      int64               `json:"size"`
	Layers    []registryLayerJSON `json:"layers"`
}

type registryImageJSON struct {
	Repository string                 `json:"repository"`
	Tag        string                 `json:"tag"`
	Digest     string                 `json:"digest"`
	MediaType  string                 `json:"mediaType"`
	Merged     bool                   `json:"merged"`
	Pushed     string                 `json:"pushed,omitempty"`
	Size       int64                  `json:"size"`
	Pull       string                 `json:"pull"`
	Tags       []string               `json:"tags"`
	Platforms  []registryPlatformJSON `json:"platforms"`
}

// registryTagQuery reads the repository and the tag a request names, and the
// digest the tag points to. A name that is not one is a tag that is not there.
func registryTagQuery(store *registryStore, r *http.Request) (name, tag string, tags map[string]digest.Digest, ok bool, err error) {
	query := r.URL.Query()
	name, tag = query.Get("repository"), query.Get("tag")
	if !validRepository(name) || !tagPattern.MatchString(tag) {
		return name, tag, nil, false, nil
	}
	tags, err = store.readTags(name)
	if err != nil {
		return name, tag, nil, false, err
	}
	_, ok = tags[tag]
	return name, tag, tags, ok, nil
}

// registryImage answers the details of one tag, for the dialog the page
// opens.
func (s *Server) registryImage(set *settings, w http.ResponseWriter, r *http.Request) {
	store := set.registry
	name, tag, tags, ok, err := registryTagQuery(store, r)
	if err != nil {
		s.log.Error("registry page cannot read the tags", "repository", name, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "That tag is not in the registry.", http.StatusNotFound)
		return
	}
	d := tags[tag]
	summary, err := s.summarize(store, name, d)
	if err != nil {
		s.log.Error("registry page cannot read a manifest", "repository", name, "tag", tag,
			"digest", d.String(), "error", err)
		http.Error(w, "The manifest of that tag cannot be read.", http.StatusInternalServerError)
		return
	}
	answer := registryImageJSON{
		Repository: name,
		Tag:        tag,
		Digest:     d.String(),
		MediaType:  summary.mediaType,
		Size:       summary.size,
		Pull:       "docker pull " + r.Host + "/" + name + ":" + tag,
		Tags:       []string{},
		Platforms:  []registryPlatformJSON{},
	}
	if rev, err := store.readRevision(name, d); err == nil {
		answer.Merged = rev.Merged
	}
	if pushed, err := store.revisionTime(name, d); err == nil {
		answer.Pushed = pushed.UTC().Format(time.RFC3339)
	}
	for other, target := range tags {
		if target == d && other != tag {
			answer.Tags = append(answer.Tags, other)
		}
	}
	slices.Sort(answer.Tags)
	for _, platform := range summary.platforms {
		entry := registryPlatformJSON{
			Platform:  platform.key,
			Label:     platformLabel(platform.key),
			Digest:    platform.digest.String(),
			MediaType: platform.mediaType,
			Size:      platform.size,
			Layers:    []registryLayerJSON{},
		}
		if platform.config != "" {
			entry.Config = platform.config.String()
		}
		if !platform.created.IsZero() {
			entry.Created = platform.created.UTC().Format(time.RFC3339)
		}
		for _, layer := range platform.layers {
			entry.Layers = append(entry.Layers, registryLayerJSON{Digest: layer.Digest.String(),
				MediaType: layer.MediaType, Size: layer.Size})
		}
		answer.Platforms = append(answer.Platforms, entry)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, answer)
}

// registryUntag deletes a tag, as DELETE /v2/<name>/manifests/<tag> does.
func (s *Server) registryUntag(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	if user == nil {
		s.log.Info("http registry tag delete refused, no session of a registry account",
			"address", clientAddress(set, r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	store := set.registry
	query := r.URL.Query()
	name, tag := query.Get("repository"), query.Get("tag")
	if !validRepository(name) || !tagPattern.MatchString(tag) {
		http.Error(w, "That tag is not in the registry.", http.StatusNotFound)
		return
	}
	lock := registryLock(&s.registryRepositoryLocks, name)
	lock.Lock()
	defer lock.Unlock()
	tags, err := store.readTags(name)
	if err == nil {
		err = s.untag(store, name, tag, tags, user, clientAddress(set, r))
	}
	switch {
	case errors.Is(err, errRegistryNotFound):
		http.Error(w, "That tag is not in the registry.", http.StatusNotFound)
	case err != nil:
		s.log.Error("registry page cannot delete a tag", "repository", name, "tag", tag, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// registryCleanupJSON is what the cleanup run from the page removed.
type registryCleanupJSON struct {
	Blobs int   `json:"blobs"`
	Bytes int64 `json:"bytes"`
}

// registryCleanup removes the blobs nothing refers to now, keeping only those
// of the last registryCleanupGrace. It is a walk of the registry folder, over
// before a job would be worth it.
func (s *Server) registryCleanup(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	w.Header().Set("Cache-Control", "no-store")
	if user == nil {
		s.log.Info("http registry cleanup refused, no session of a registry account",
			"address", clientAddress(set, r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	s.log.Info("registry cleanup started from the page", "user", user.name,
		"address", clientAddress(set, r))
	blobs, freed := s.cleanRegistryNow(set.registry)
	writeJSON(w, http.StatusOK, registryCleanupJSON{Blobs: blobs, Bytes: freed})
}

// --- pulling from and pushing to other registries ---------------------------

// maxTransferRequest bounds the body of a pull or a push: a reference, an
// address and a login.
const maxTransferRequest = 16 << 10

// readTransferRequest decodes the body of a pull or a push, and answers a
// request that may not start one.
func (s *Server) readTransferRequest(set *settings, w http.ResponseWriter, r *http.Request, user *account, into any) bool {
	w.Header().Set("Cache-Control", "no-store")
	if user == nil {
		s.log.Info("http registry transfer refused, no session of a registry account",
			"address", clientAddress(set, r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxTransferRequest)).Decode(into); err != nil {
		http.Error(w, "The request could not be read.", http.StatusBadRequest)
		return false
	}
	return true
}

// answerStarted answers a job that was started, or why it was not.
func (s *Server) answerStarted(w http.ResponseWriter, job *registryJob, err error) {
	switch {
	case errors.Is(err, errTooManyJobs):
		w.Header().Set("Retry-After", "30")
		http.Error(w, err.Error(), http.StatusTooManyRequests)
	case err != nil:
		s.log.Error("registry cannot start a transfer", "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusAccepted, job.view())
	}
}

// transferBody is the body of a pull or a push, and of their checks.
type transferBody struct {
	// Reference is the image of the other registry, with its tag.
	Reference string `json:"reference"`
	// Digest is what the check of a pull found the reference to name, which
	// the pull then fetches, so that it is what was checked.
	Digest    string `json:"digest"`
	Platforms string `json:"platforms"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	// SkipVerify takes whatever certificate the other registry shows: the
	// dialog's Validate Connection, unticked.
	SkipVerify bool `json:"skipVerify"`
}

// login is how the request reaches the other registry, as the client takes it.
func (t transferBody) login() remoteLogin {
	return remoteLogin{username: strings.TrimSpace(t.Username), password: t.Password, skipVerify: t.SkipVerify}
}

// pullReference reads what a pull fetches: an image under a tag, since that
// is where it is stored.
func pullReference(value string) (remoteRef, error) {
	ref, err := parseRemoteReference(value)
	if err == nil && ref.tag == "" {
		err = errors.New("the image is stored under its tag, so name one along with the digest")
	}
	return ref, err
}

// pushReference reads where a push goes: an image under a tag of another
// registry.
func pushReference(value string) (remoteRef, error) {
	ref, err := parseRemoteReference(value)
	if err == nil && ref.digest != "" {
		err = errors.New("a push goes to a tag; leave the digest out")
	}
	return ref, err
}

// checkTimeout bounds a check, which takes a few small requests.
const checkTimeout = time.Minute

// registryPlatformChoice is a platform a dialog offers to copy.
type registryPlatformChoice struct {
	Platform string `json:"platform"`
	Label    string `json:"label"`
}

func platformChoices(keys []string) []registryPlatformChoice {
	choices := []registryPlatformChoice{}
	for _, key := range keys {
		choices = append(choices, registryPlatformChoice{Platform: key, Label: platformLabel(key)})
	}
	return choices
}

// registryPullCheckJSON is what the check of a pull found.
type registryPullCheckJSON struct {
	Reference string                   `json:"reference"`
	Local     string                   `json:"local"`
	Digest    string                   `json:"digest"`
	Platforms []registryPlatformChoice `json:"platforms"`
}

// registryPullCheck checks that an image of another registry can be pulled
// with the login given, and says what platforms it is for.
func (s *Server) registryPullCheck(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	var body transferBody
	if !s.readTransferRequest(set, w, r, user, &body) {
		return
	}
	ref, err := pullReference(body.Reference)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
	defer cancel()
	image, err := s.inspectRemote(ctx, ref, body.login())
	if err != nil {
		// the other registry's refusal is not this one's: a 401 would read
		// as the session having ended
		s.log.Info("registry pull check failed", "source", ref.String(), "user", user.name,
			"address", clientAddress(set, r), "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, registryPullCheckJSON{Reference: ref.String(),
		Local: ref.repository + ":" + ref.tag, Digest: image.digest.String(),
		Platforms: platformChoices(image.platforms)})
}

// registryPushCheckJSON is what the check of a push found.
type registryPushCheckJSON struct {
	Reference string `json:"reference"`
	// Exists says the other registry has the tag already, which the push
	// replaces.
	Exists    bool                     `json:"exists"`
	Platforms []registryPlatformChoice `json:"platforms"`
}

// registryPushCheck checks that a tag of this registry can be pushed to
// another with the login given, and says what platforms the tag has.
func (s *Server) registryPushCheck(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	var body transferBody
	if !s.readTransferRequest(set, w, r, user, &body) {
		return
	}
	store := set.registry
	name, tag, tags, ok, err := registryTagQuery(store, r)
	if err != nil {
		s.log.Error("registry page cannot read the tags", "repository", name, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "That tag is not in the registry.", http.StatusNotFound)
		return
	}
	ref, err := pushReference(body.Reference)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	summary, err := s.summarize(store, name, tags[tag])
	if err != nil {
		s.log.Error("registry page cannot read a manifest", "repository", name, "tag", tag, "error", err)
		http.Error(w, "The manifest of that tag cannot be read.", http.StatusInternalServerError)
		return
	}
	var keys []string
	for _, platform := range summary.platforms {
		if platform.key != "" && !slices.Contains(keys, platform.key) {
			keys = append(keys, platform.key)
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
	defer cancel()
	client := newRemoteClient(ref, body.login(), "pull,push")
	err = client.authenticate(ctx)
	if err == nil {
		err = client.canPush(ctx)
	}
	exists := false
	if err == nil {
		exists, err = client.manifestExists(ctx, ref.tag)
	}
	if err != nil {
		s.log.Info("registry push check failed", "repository", name, "tag", tag, "target", ref.String(),
			"user", user.name, "address", clientAddress(set, r), "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, registryPushCheckJSON{Reference: ref.String(), Exists: exists,
		Platforms: platformChoices(keys)})
}

// registryPull starts copying an image from another registry into this one.
func (s *Server) registryPull(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	var body transferBody
	if !s.readTransferRequest(set, w, r, user, &body) {
		return
	}
	ref, err := pullReference(body.Reference)
	if err == nil && body.Digest != "" && ref.digest == "" {
		d, ok := parseBlobDigest(body.Digest)
		if !ok {
			err = fmt.Errorf("%q is not a digest", body.Digest)
		}
		ref.digest = d
	}
	var filter platformFilter
	if err == nil {
		filter, err = parsePlatforms(body.Platforms)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	what := ref.String() + " → " + ref.repository + ":" + ref.tag
	address := clientAddress(set, r)
	job, err := s.startJob(jobPull, user.name, what, func(ctx context.Context, job *registryJob) (string, error) {
		message, err := s.pullImage(ctx, set, job, ref, filter, body.login(), user)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("registry pull failed", "source", ref.String(), "user", user.name,
				"address", address, "error", err)
		}
		return message, err
	})
	if err == nil {
		s.log.Info("registry pull started", "source", ref.String(), "platforms", strings.Join(filter, ","),
			"login", body.Username != "", "verify", !body.SkipVerify, "user", user.name, "address", address, "job", job.id)
	}
	s.answerStarted(w, job, err)
}

// registryPush starts copying a tag of this registry to another one.
func (s *Server) registryPush(set *settings, w http.ResponseWriter, r *http.Request, user *account) {
	var body transferBody
	if !s.readTransferRequest(set, w, r, user, &body) {
		return
	}
	store := set.registry
	name, tag, tags, ok, err := registryTagQuery(store, r)
	if err != nil {
		s.log.Error("registry page cannot read the tags", "repository", name, "error", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "That tag is not in the registry.", http.StatusNotFound)
		return
	}
	ref, err := pushReference(body.Reference)
	var filter platformFilter
	if err == nil {
		filter, err = parsePlatforms(body.Platforms)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d := tags[tag]
	what := name + ":" + tag + " → " + ref.String()
	address := clientAddress(set, r)
	job, err := s.startJob(jobPush, user.name, what, func(ctx context.Context, job *registryJob) (string, error) {
		message, err := s.pushImage(ctx, set, job, name, tag, d, ref, filter, body.login(), user)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("registry push failed", "repository", name, "tag", tag, "target", ref.String(),
				"user", user.name, "address", address, "error", err)
		}
		return message, err
	})
	if err == nil {
		s.log.Info("registry push started", "repository", name, "tag", tag, "target", ref.String(),
			"platforms", strings.Join(filter, ","), "login", body.Username != "", "verify", !body.SkipVerify,
			"user", user.name, "address", address, "job", job.id)
	}
	s.answerStarted(w, job, err)
}

// jobOf finds the job a request names, and answers a request for one that
// is not the caller's.
func (s *Server) jobOf(w http.ResponseWriter, r *http.Request, user *account) *registryJob {
	w.Header().Set("Cache-Control", "no-store")
	if user == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil
	}
	job := s.job(r.URL.Query().Get("id"), user.name)
	// a fetch or a send of the listing is a job too, but not one of the
	// registry's
	if job == nil || listingJob(job.kind) {
		http.Error(w, "That transfer is not known.", http.StatusNotFound)
		return nil
	}
	return job
}

// registryJobStatus says how far a transfer has got.
func (s *Server) registryJobStatus(w http.ResponseWriter, r *http.Request, user *account) {
	if job := s.jobOf(w, r, user); job != nil {
		writeJSON(w, http.StatusOK, job.view())
	}
}

// registryJobCancel stops a transfer. What it had fetched stays in the store
// for the garbage collection, or for the next pull of the same image.
func (s *Server) registryJobCancel(w http.ResponseWriter, r *http.Request, user *account) {
	job := s.jobOf(w, r, user)
	if job == nil {
		return
	}
	if job.running() {
		s.log.Info("registry transfer stopped", "job", job.id, "what", job.what, "user", user.name)
		job.cancel()
	}
	w.WriteHeader(http.StatusNoContent)
}

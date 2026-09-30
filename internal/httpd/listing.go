package httpd

import (
	"bytes"
	"embed"
	"html"
	"html/template"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// entry is one line of a directory listing.
type entry struct {
	// Name carries a trailing slash for a folder, as the Node implementation's
	// cnam does, because that is also the href the browser follows.
	Name    string
	IsFile  bool
	Kind    string
	Size    int64
	ModTime time.Time
}

// isFolder reports whether an entry is a folder. The trailing slash is what
// says so rather than IsFile, which is also false for a socket or a device
// node — those are files as far as the listing is concerned.
func (e entry) isFolder() bool {
	return strings.HasSuffix(e.Name, "/")
}

// bare is the name without the trailing slash a folder carries.
func (e entry) bare() string {
	return strings.TrimSuffix(e.Name, "/")
}

// readDirectory lists a folder: the folders first in the order the filesystem
// reports them, then the files newest first.
//
// This order is the one the legacy dls_directory_reader endpoint answers with,
// so it is left as it was; the browsable page sorts the result itself.
func readDirectory(folder string) ([]entry, error) {
	items, err := os.ReadDir(folder)
	if err != nil {
		return nil, err
	}

	var folders, files []entry
	for _, item := range items {
		info, err := item.Info()
		if err != nil {
			// a name that vanished between the read and the stat is skipped
			// rather than failing the whole listing
			continue
		}
		found := entry{
			Name:    info.Name(),
			IsFile:  info.Mode().IsRegular(),
			Kind:    typeOf(info.Name()).Kind,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}
		if info.IsDir() {
			found.Name += "/"
			folders = append(folders, found)
			continue
		}
		files = append(files, found)
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })
	return append(folders, files...), nil
}

// The columns a listing can be ordered by. An empty key is the default, which
// is not a column order at all: it groups the folders above the files.
const (
	sortName = "name"
	sortDate = "date"
	sortSize = "size"
	sortType = "type"
)

// sortOrder is what the query string asked the listing to be ordered by.
type sortOrder struct {
	key  string
	desc bool
}

// parseSort reads the order out of a query string. Anything that is not one of
// the four columns falls back to the default rather than being an error: the
// query string is part of a link a user can edit.
func parseSort(query url.Values) sortOrder {
	switch key := query.Get("sort"); key {
	case sortName, sortDate, sortSize, sortType:
		return sortOrder{key: key, desc: query.Get("dir") == "desc"}
	default:
		return sortOrder{}
	}
}

// query is the link that asks for this order.
func (o sortOrder) query() string {
	if o.key == "" {
		return "?"
	}
	if o.desc {
		return "?sort=" + o.key + "&dir=desc"
	}
	return "?sort=" + o.key + "&dir=asc"
}

func (o sortOrder) direction() string {
	if o.desc {
		return "desc"
	}
	return "asc"
}

// nextOrder is the order a click on a column asks for: ascending, then
// descending, then no order at all. The third step is the grouped default the
// listing opens in, so every column has a way to turn itself off rather than
// leaving a sort that can only be swapped for another one.
//
// The script does the same, so a click behaves identically whether or not it
// ran.
func nextOrder(current sortOrder, key string) sortOrder {
	if current.key != key {
		return sortOrder{key: key}
	}
	if !current.desc {
		return sortOrder{key: key, desc: true}
	}
	return sortOrder{}
}

// sortEntries returns the entries in the asked-for order, leaving the slice it
// was given alone. Ties break on the name so that two files of the same size
// keep a fixed order between reloads.
func sortEntries(entries []entry, order sortOrder) []entry {
	sorted := make([]entry, len(entries))
	copy(sorted, entries)

	byName := func(a, b entry) bool {
		return strings.ToLower(a.bare()) < strings.ToLower(b.bare())
	}
	if order.key == "" {
		// the order a file browser opens in: folders above files, both by name
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].isFolder() != sorted[j].isFolder() {
				return sorted[i].isFolder()
			}
			return byName(sorted[i], sorted[j])
		})
		return sorted
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		var before, after bool
		switch order.key {
		case sortDate:
			before, after = a.ModTime.Before(b.ModTime), b.ModTime.Before(a.ModTime)
		case sortSize:
			before, after = sizeOf(a) < sizeOf(b), sizeOf(b) < sizeOf(a)
		case sortType:
			before, after = kindOf(a) < kindOf(b), kindOf(b) < kindOf(a)
		default:
			before, after = byName(a, b), byName(b, a)
		}
		switch {
		case before:
			return !order.desc
		case after:
			return order.desc
		default:
			return byName(a, b)
		}
	})
	return sorted
}

// sizeOf is what a row sorts by in the size column. A folder has a size on
// disk, but it is the size of the folder itself and says nothing about what is
// in it, so it sorts as nothing.
func sizeOf(item entry) int64 {
	if item.isFolder() {
		return 0
	}
	return item.Size
}

// kindOf is the word the Type column shows.
func kindOf(item entry) string {
	if item.isFolder() {
		return "Folder"
	}
	return item.Kind
}

//go:embed assets
var assets embed.FS

// listingTemplate is parsed once: a page that cannot be built is a bug in the
// embedded template rather than something a request can cause.
var listingTemplate = template.Must(template.ParseFS(assets, "assets/listing.html"))

// loginTemplate is the page that asks for a password. It is a template of its
// own rather than a branch inside the listing, so that "the login page shows no
// folder content" holds because there is nothing there to show, rather than
// because an {{if}} is right.
var loginTemplate = template.Must(template.ParseFS(assets, "assets/login.html"))

// listingStyle and listingScript are inlined into every page. Keeping them out
// of the URL space is deliberate: every path this server answers is a path in
// the served folder, so an asset URL would shadow a real name.
var (
	listingStyle  = template.CSS(mustRead("assets/listing.css"))
	listingScript = template.JS(mustRead("assets/listing.js"))
)

func mustRead(name string) string {
	body, err := assets.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(body)
}

// rights is what the page may offer to the account looking at it.
type rights struct {
	Upload       bool
	DeleteFile   bool
	DeleteFolder bool
	Mkdir        bool
	Rename       bool
}

// Any reports whether any per-row action is offered, which is what decides
// whether the actions column is there at all.
func (r rights) Any() bool {
	return r.Rename || r.DeleteFile || r.DeleteFolder
}

type crumb struct {
	Name string
	// Link is empty for the folder being shown, which is not a link to itself.
	Link string
	Sep  bool
}

type column struct {
	Key    string
	Label  string
	Class  string
	Link   string
	Active bool
	Order  string
	Caret  string
}

type listingRow struct {
	Name     string
	Label    string
	Link     string
	IsDir    bool
	Group    string
	Bytes    int64
	Unix     int64
	Kind     string
	Size     string
	Modified string
}

// sessionView is what the page says about who is looking at it.
type sessionView struct {
	// User is the signed in account, empty when nobody is. It is filled only
	// for a request that came in with a session token: someone who
	// authenticated with a header has no session to log out of, and offering
	// the button would be a lie.
	User string
	// CanLogin says an account that may use the form exists and nobody is
	// signed in, which is what puts the Log in button on the page.
	CanLogin bool
	Login    string
	Logout   string
	// Admin is the link to the admin interface, empty for everyone but an
	// admin account signed in with a session while the interface is on.
	Admin string
}

// loginData is the login page.
type loginData struct {
	Path    string
	Action  string
	Cancel  string
	Message string
	Nonce   string
	Style   template.CSS
}

func renderLogin(data loginData) ([]byte, error) {
	var page bytes.Buffer
	if err := loginTemplate.Execute(&page, data); err != nil {
		return nil, err
	}
	return page.Bytes(), nil
}

type listingData struct {
	Path    string
	Folder  string
	Crumbs  []crumb
	Parent  string
	Columns []column
	Entries []listingRow
	Sort    string
	Dir     string
	Rights  rights
	Session sessionView
	Nonce   string
	Style   template.CSS
	Script  template.JS
	// MaxChunkSize is what the client splits a large upload into pieces of; 0
	// means chunked upload is off and a large file is sent as one request, as
	// before.
	MaxChunkSize int64
}

// listingPage renders the browsable directory page.
func listingPage(virtual string, entries []entry, order sortOrder, allowed rights, who sessionView, nonce string, maxChunkSize int64) ([]byte, error) {
	rows := make([]listingRow, 0, len(entries))
	for _, item := range sortEntries(entries, order) {
		row := listingRow{
			Name:     item.bare(),
			Label:    item.Name,
			Link:     (&url.URL{Path: item.Name}).String(),
			IsDir:    item.isFolder(),
			Group:    "0",
			Bytes:    sizeOf(item),
			Unix:     item.ModTime.Unix(),
			Kind:     kindOf(item),
			Size:     readableSize(item.Size),
			Modified: item.ModTime.Format("2006-01-02 15:04"),
		}
		if item.isFolder() {
			row.Group = "1"
			// a folder has no size worth showing, but it does have a date, and
			// without it the date column could not be sorted on
			row.Size = "—"
		}
		rows = append(rows, row)
	}

	data := listingData{
		Path:    virtual,
		Folder:  (&url.URL{Path: virtual}).String(),
		Crumbs:  crumbsOf(virtual),
		Parent:  parentOf(virtual),
		Columns: columnsOf(order),
		Session: who,
		Entries: rows,
		Sort:    order.key,
		Dir:     order.direction(),
		Rights:  allowed,
		Nonce:   nonce,
		Style:   listingStyle,
		Script:  listingScript,

		MaxChunkSize: maxChunkSize,
	}

	var page bytes.Buffer
	if err := listingTemplate.Execute(&page, data); err != nil {
		return nil, err
	}
	return page.Bytes(), nil
}

func columnsOf(order sortOrder) []column {
	defined := []column{
		{Key: sortName, Label: "Name", Class: "c-name"},
		{Key: sortDate, Label: "Modified", Class: "c-mod"},
		{Key: sortType, Label: "Type", Class: "c-kind"},
		{Key: sortSize, Label: "Size", Class: "c-size num"},
	}
	for i := range defined {
		defined[i].Link = nextOrder(order, defined[i].Key).query()
		if defined[i].Key != order.key || order.key == "" {
			continue
		}
		defined[i].Active = true
		if order.desc {
			defined[i].Order, defined[i].Caret = "descending", "▼"
		} else {
			defined[i].Order, defined[i].Caret = "ascending", "▲"
		}
	}
	return defined
}

// crumbsOf breaks the path into the links above it. The first one is the root,
// whose name is the leading slash, so the trail reads as the path itself.
func crumbsOf(virtual string) []crumb {
	root := crumb{Name: "/", Link: "/"}
	parts := strings.Split(strings.Trim(virtual, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		root.Link = ""
		return []crumb{root}
	}
	crumbs := make([]crumb, 0, len(parts)+1)
	crumbs = append(crumbs, root)
	walked := "/"
	for i, part := range parts {
		walked += part + "/"
		step := crumb{Name: part, Sep: i < len(parts)-1}
		if i < len(parts)-1 {
			step.Link = (&url.URL{Path: walked}).String()
		}
		crumbs = append(crumbs, step)
	}
	return crumbs
}

// parentOf is the link to the folder above, empty at the root.
func parentOf(virtual string) string {
	cleaned := strings.TrimSuffix(virtual, "/")
	if cleaned == "" || cleaned == "/" {
		return ""
	}
	parent := path.Dir(cleaned)
	if !strings.HasSuffix(parent, "/") {
		parent += "/"
	}
	return parent
}

// readerPage is the answer of the dls_directory_reader endpoint, a plain list
// of links rather than the browsable page. It is what a client that is not a
// browser parses, so it is left exactly as the Node implementation wrote it.
func readerPage(folder string, entries []entry) []byte {
	var page strings.Builder
	page.WriteString("listing directory: " + html.EscapeString(folder) + "\n")
	for _, item := range entries {
		kind := "dir"
		if item.IsFile {
			kind = "file"
		}
		link := (&url.URL{Path: item.Name}).String()
		page.WriteString(`<a href="` + link + `">` + html.EscapeString(item.Name) + `</a>` +
			" - filetype: " + kind + " filesize: " + itoa(item.Size) + "<br/>\n")
	}
	return []byte(page.String())
}

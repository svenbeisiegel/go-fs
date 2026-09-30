package httpd

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-fs/internal/config"
)

// s3Entry is one line of a listing: an object, or a common prefix, which is how
// S3 lists a folder when the client asked for the keys one level at a time.
type s3Entry struct {
	key      string
	prefix   bool
	size     int64
	modified time.Time
}

// syntheticETag is the ETag an object is listed and served with. S3 makes it
// the MD5 of the object, which would mean reading every file a listing names,
// so here it is derived from what changes when the file does. The "-1" is how
// S3 writes the ETag of a multipart upload, which is not an MD5 either, so a
// client does not take this for one and compare it against its own.
func syntheticETag(info fs.FileInfo) string {
	return etagOf(info.ModTime(), info.Size())
}

func etagOf(modified time.Time, size int64) string {
	var seed [16]byte
	binary.BigEndian.PutUint64(seed[:8], uint64(modified.UnixNano()))
	binary.BigEndian.PutUint64(seed[8:], uint64(size))
	sum := md5.Sum(seed[:])
	return `"` + hex.EncodeToString(sum[:]) + `-1"`
}

// s3ListObjects answers ListObjects, and ListObjectsV2 for list-type=2.
func (s *Server) s3ListObjects(q *s3Request) {
	query := q.r.URL.Query()
	if !granted(q.user.perms, actRead) {
		q.fail(errAccessDenied)
		return
	}
	v2 := query.Get("list-type") == "2"
	prefix, delimiter := query.Get("prefix"), query.Get("delimiter")
	maxKeys := 1000
	if raw := query.Get("max-keys"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			q.fail(s3Err(http.StatusBadRequest, "InvalidArgument", "max-keys has to be a number of 0 or more."))
			return
		}
		maxKeys = min(n, 1000)
	}
	after := query.Get("marker")
	token := query.Get("continuation-token")
	if v2 {
		after = query.Get("start-after")
		if token != "" {
			decoded, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				q.fail(s3Err(http.StatusBadRequest, "InvalidArgument",
					"The continuation token provided is incorrect."))
				return
			}
			after = max(after, string(decoded))
		}
	}

	entries, err := s.s3Entries(q.user, prefix, delimiter)
	if err != nil {
		s.log.Error("s3 cannot list the folder", "prefix", prefix, "error", err)
		q.fail(errInternal)
		return
	}
	start := sort.Search(len(entries), func(i int) bool { return entries[i].key > after })
	entries = entries[start:]
	truncated := len(entries) > maxKeys
	if truncated {
		entries = entries[:maxKeys]
	}

	type object struct {
		Key          string   `xml:"Key"`
		LastModified string   `xml:"LastModified"`
		ETag         string   `xml:"ETag"`
		Size         int64    `xml:"Size"`
		StorageClass string   `xml:"StorageClass"`
		Owner        *s3Owner `xml:"Owner,omitempty"`
	}
	type commonPrefix struct {
		Prefix string `xml:"Prefix"`
	}
	escape := escapeKeys(query)
	var objects []object
	var prefixes []commonPrefix
	owner := ownerOf(q.user)
	for _, entry := range entries {
		if entry.prefix {
			prefixes = append(prefixes, commonPrefix{Prefix: escape(entry.key)})
			continue
		}
		listed := object{Key: escape(entry.key), LastModified: entry.modified.UTC().Format(s3TimeFormat),
			ETag: entryETag(entry), Size: entry.size, StorageClass: "STANDARD"}
		if !v2 || query.Get("fetch-owner") == "true" {
			listed.Owner = &owner
		}
		objects = append(objects, listed)
	}
	next := ""
	if truncated && len(entries) > 0 {
		next = entries[len(entries)-1].key
	}
	encoding := ""
	if query.Get("encoding-type") == "url" {
		encoding = "url"
	}

	if v2 {
		result := struct {
			XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
			Name                  string         `xml:"Name"`
			Prefix                string         `xml:"Prefix"`
			Delimiter             string         `xml:"Delimiter,omitempty"`
			StartAfter            string         `xml:"StartAfter,omitempty"`
			ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
			NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
			KeyCount              int            `xml:"KeyCount"`
			MaxKeys               int            `xml:"MaxKeys"`
			EncodingType          string         `xml:"EncodingType,omitempty"`
			IsTruncated           bool           `xml:"IsTruncated"`
			Contents              []object       `xml:"Contents"`
			CommonPrefixes        []commonPrefix `xml:"CommonPrefixes"`
		}{
			Name: config.S3Bucket, Prefix: escape(prefix), Delimiter: escape(delimiter),
			StartAfter: escape(query.Get("start-after")), ContinuationToken: token,
			KeyCount: len(entries), MaxKeys: maxKeys, EncodingType: encoding, IsTruncated: truncated,
			Contents: objects, CommonPrefixes: prefixes,
		}
		if next != "" {
			result.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(next))
		}
		writeS3XML(q.w, http.StatusOK, result)
		return
	}
	writeS3XML(q.w, http.StatusOK, struct {
		XMLName        xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
		Name           string         `xml:"Name"`
		Prefix         string         `xml:"Prefix"`
		Marker         string         `xml:"Marker"`
		NextMarker     string         `xml:"NextMarker,omitempty"`
		Delimiter      string         `xml:"Delimiter,omitempty"`
		MaxKeys        int            `xml:"MaxKeys"`
		EncodingType   string         `xml:"EncodingType,omitempty"`
		IsTruncated    bool           `xml:"IsTruncated"`
		Contents       []object       `xml:"Contents"`
		CommonPrefixes []commonPrefix `xml:"CommonPrefixes"`
	}{
		Name: config.S3Bucket, Prefix: escape(prefix), Marker: escape(query.Get("marker")),
		NextMarker: escape(next), Delimiter: escape(delimiter), MaxKeys: maxKeys,
		EncodingType: encoding, IsTruncated: truncated, Contents: objects, CommonPrefixes: prefixes,
	})
}

// entryETag is the ETag a listing gives an entry: a folder is an object of no
// bytes, and a file has the ETag it is served with.
func entryETag(entry s3Entry) string {
	if strings.HasSuffix(entry.key, "/") {
		return emptyETag
	}
	return etagOf(entry.modified, entry.size)
}

// s3Entries lists what an account may see under a prefix, sorted by key as S3
// sorts: byte by byte.
//
// With the delimiter "/", which is how every client browses, that is one
// folder read. Without one it is every file below, and every empty folder as
// the "folder/" key it would be in S3, so that copying a listing elsewhere
// takes the empty folders along. Any other delimiter is applied to that.
func (s *Server) s3Entries(user *account, prefix, delimiter string) ([]s3Entry, error) {
	var entries []s3Entry
	var err error
	if delimiter == "/" {
		entries, err = s.s3Folder(user, prefix)
	} else {
		entries, err = s.s3Walk(user, prefix)
		if err == nil && delimiter != "" {
			entries = rollUp(entries, prefix, delimiter)
		}
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	return entries, nil
}

// s3Folder lists the folder a prefix points into: the files and folders in it
// whose names begin with the rest of the prefix, the folders as common
// prefixes.
func (s *Server) s3Folder(user *account, prefix string) ([]s3Entry, error) {
	folderKey := prefix[:strings.LastIndex(prefix, "/")+1]
	folder, ok := s.folderOf(folderKey)
	if !ok {
		return nil, nil
	}
	listed, err := os.ReadDir(folder)
	if err != nil {
		return nil, err
	}
	rest := prefix[len(folderKey):]
	var entries []s3Entry
	for _, item := range listed {
		if !strings.HasPrefix(item.Name(), rest) {
			continue
		}
		key := folderKey + item.Name()
		// resolved one by one, which is what keeps a link that points out of
		// the served folder out of the listing, as it is out of every other
		child, ok := s.resolveKey(key)
		if !ok || !user.allows(child.target.Virtual) {
			continue
		}
		info, err := os.Stat(child.target.Path)
		switch {
		case err != nil:
			continue
		case info.IsDir():
			entries = append(entries, s3Entry{key: key + "/", prefix: true})
		case info.Mode().IsRegular():
			entries = append(entries, s3Entry{key: key, size: info.Size(), modified: info.ModTime()})
		}
	}
	return entries, nil
}

// s3Walk lists every file below the folder a prefix points into whose key
// begins with the prefix, and every empty folder as its "folder/" key. A link
// to a folder is not followed, so a link that points back up cannot make the
// walk endless.
func (s *Server) s3Walk(user *account, prefix string) ([]s3Entry, error) {
	folderKey := prefix[:strings.LastIndex(prefix, "/")+1]
	folder, ok := s.folderOf(folderKey)
	if !ok {
		return nil, nil
	}
	var entries []s3Entry
	var walk func(path, key string) error
	walk = func(path, key string) error {
		listed, err := os.ReadDir(path)
		if err != nil {
			// a folder below that cannot be read is left out, as the page
			// leaves out what it cannot stat
			if key != folderKey {
				return nil
			}
			return err
		}
		if len(listed) == 0 && key != folderKey && strings.HasPrefix(key, prefix) &&
			user.allows("/"+strings.TrimSuffix(key, "/")) {
			entries = append(entries, s3Entry{key: key, modified: modTime(path)})
		}
		for _, item := range listed {
			childKey := key + item.Name()
			childPath := filepath.Join(path, item.Name())
			isLink := item.Type()&fs.ModeSymlink != 0
			if isLink || runtime.GOOS == "windows" {
				// a link has to stay inside the served folder, and a name has
				// to mean on Windows what it says; resolving it checks both
				child, ok := s.resolveKey(childKey)
				if !ok {
					continue
				}
				childPath = child.target.Path
			}
			if item.IsDir() {
				childFolder := childKey + "/"
				if !strings.HasPrefix(childFolder, prefix) && !strings.HasPrefix(prefix, childFolder) {
					continue
				}
				if err := walk(childPath, childFolder); err != nil {
					return err
				}
				continue
			}
			if !strings.HasPrefix(childKey, prefix) || !user.allows("/"+childKey) {
				continue
			}
			info, err := os.Stat(childPath)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			entries = append(entries, s3Entry{key: childKey, size: info.Size(), modified: info.ModTime()})
		}
		return nil
	}
	if err := walk(folder, folderKey); err != nil {
		return nil, err
	}
	return entries, nil
}

// folderOf is where a folder key, "" or ending with a slash, is on disk, and
// false for a key that names no folder there, which lists as nothing.
func (s *Server) folderOf(folderKey string) (string, bool) {
	path := s.root.Base()
	if folderKey != "" {
		folder, ok := s.resolveKey(folderKey)
		if !ok {
			return "", false
		}
		path = folder.target.Path
	}
	info, err := os.Stat(path)
	return path, err == nil && info.IsDir()
}

// rollUp groups the keys that hold the delimiter after the prefix into the
// common prefix they share, as S3 does for any delimiter.
func rollUp(entries []s3Entry, prefix, delimiter string) []s3Entry {
	rolled := make([]s3Entry, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		rest := entry.key[len(prefix):]
		i := strings.Index(rest, delimiter)
		if i < 0 {
			rolled = append(rolled, entry)
			continue
		}
		common := prefix + rest[:i+len(delimiter)]
		if !seen[common] {
			seen[common] = true
			rolled = append(rolled, s3Entry{key: common, prefix: true})
		}
	}
	return rolled
}

func modTime(path string) time.Time {
	if info, err := os.Stat(path); err == nil {
		return info.ModTime()
	}
	return time.Time{}
}

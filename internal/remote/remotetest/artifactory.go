package remotetest

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ArtifactoryHost is a JFrog Artifactory a test sends to and browses, as far
// as go-fs speaks to one: the repositories, the storage API, files, folders,
// and the move. Every folder of Dir is a repository. It takes one token.
type ArtifactoryHost struct {
	// URL is where its REST API is, …/artifactory.
	URL   string
	Token string
	Dir   string
	// OSS makes it one without the listing and the move, which are of Pro.
	OSS atomic.Bool
	// Requests counts the requests that came with the token.
	Requests atomic.Int32
	// Slow is how long every read of an upload waits, which holds a send up
	// for a test that stops it.
	Slow atomic.Int64
}

// NewArtifactoryHost starts an Artifactory that takes token, with the
// repositories named, and stops it when the test ends.
func NewArtifactoryHost(t testing.TB, token string, repos ...string) *ArtifactoryHost {
	t.Helper()
	host := &ArtifactoryHost{Token: token, Dir: t.TempDir()}
	for _, repo := range repos {
		if err := os.Mkdir(filepath.Join(host.Dir, repo), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(host.serve))
	t.Cleanup(server.Close)
	host.URL = server.URL + "/artifactory"
	return host
}

// Write puts a file into a repository, with the folders leading up to it.
func (h *ArtifactoryHost) Write(t testing.TB, name, content string) {
	t.Helper()
	full := filepath.Join(h.Dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Read is what a file of a repository holds, "" when it is not there.
func (h *ArtifactoryHost) Read(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.Dir, filepath.FromSlash(name)))
	if err != nil {
		return ""
	}
	return string(b)
}

func artifactoryError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]any{{"status": status, "message": message}},
	})
}

func artifactoryJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// local is where a path of the host is on disk, and whether it is in a
// repository that is there.
func (h *ArtifactoryHost) local(p string) (string, bool) {
	p = path.Clean("/" + p)
	if p == "/" {
		return h.Dir, false
	}
	repo, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	if info, err := os.Stat(filepath.Join(h.Dir, repo)); err != nil || !info.IsDir() {
		return "", false
	}
	return filepath.Join(h.Dir, filepath.FromSlash(p)), true
}

func (h *ArtifactoryHost) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+h.Token {
		artifactoryError(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	h.Requests.Add(1)
	rest, ok := strings.CutPrefix(r.URL.Path, "/artifactory")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case rest == "/api/repositories" && r.Method == http.MethodGet:
		h.repositories(w)
	case strings.HasPrefix(rest, "/api/storage/") && r.Method == http.MethodGet:
		h.storage(w, r, strings.TrimPrefix(rest, "/api/storage"))
	case strings.HasPrefix(rest, "/api/move/") && r.Method == http.MethodPost:
		h.move(w, r, strings.TrimPrefix(rest, "/api/move"))
	case strings.HasPrefix(rest, "/api/"):
		artifactoryError(w, http.StatusNotFound, "no such API")
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		h.download(w, r, rest)
	case r.Method == http.MethodPut:
		h.upload(w, r, rest)
	case r.Method == http.MethodDelete:
		h.remove(w, rest)
	default:
		artifactoryError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

func (h *ArtifactoryHost) repositories(w http.ResponseWriter) {
	entries, _ := os.ReadDir(h.Dir)
	repos := []map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() {
			repos = append(repos, map[string]string{"key": entry.Name(), "type": "LOCAL", "packageType": "Generic"})
		}
	}
	artifactoryJSON(w, http.StatusOK, repos)
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func (h *ArtifactoryHost) storage(w http.ResponseWriter, r *http.Request, p string) {
	full, ok := h.local(p)
	if !ok {
		artifactoryError(w, http.StatusNotFound, "Unable to find item")
		return
	}
	info, err := os.Stat(full)
	if err != nil {
		artifactoryError(w, http.StatusNotFound, "Unable to find item")
		return
	}
	if r.URL.Query().Has("list") {
		if h.OSS.Load() {
			artifactoryError(w, http.StatusBadRequest, "This REST API is available only in Artifactory Pro.")
			return
		}
		if !info.IsDir() {
			artifactoryError(w, http.StatusBadRequest, "Expected a folder")
			return
		}
		entries, _ := os.ReadDir(full)
		files := []map[string]any{}
		for _, entry := range entries {
			inner, err := entry.Info()
			if err != nil {
				continue
			}
			files = append(files, map[string]any{
				"uri": "/" + entry.Name(), "size": inner.Size(), "lastModified": stamp(inner.ModTime()),
				"folder": entry.IsDir(),
			})
		}
		artifactoryJSON(w, http.StatusOK, map[string]any{"uri": h.URL + "/api/storage" + p, "files": files})
		return
	}
	if info.IsDir() {
		entries, _ := os.ReadDir(full)
		children := []map[string]any{}
		for _, entry := range entries {
			children = append(children, map[string]any{"uri": "/" + entry.Name(), "folder": entry.IsDir()})
		}
		artifactoryJSON(w, http.StatusOK, map[string]any{"uri": h.URL + "/api/storage" + p, "path": p,
			"lastModified": stamp(info.ModTime()), "children": children})
		return
	}
	artifactoryJSON(w, http.StatusOK, map[string]any{"uri": h.URL + "/api/storage" + p,
		"downloadUri": h.URL + p, "path": p, "lastModified": stamp(info.ModTime()),
		"size": strconv.FormatInt(info.Size(), 10), "checksums": map[string]string{"sha1": "x"}})
}

func (h *ArtifactoryHost) download(w http.ResponseWriter, r *http.Request, p string) {
	full, ok := h.local(p)
	if !ok {
		artifactoryError(w, http.StatusNotFound, "Could not find resource")
		return
	}
	file, err := os.Open(full)
	if err != nil {
		artifactoryError(w, http.StatusNotFound, "Could not find resource")
		return
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		artifactoryError(w, http.StatusNotFound, "Could not find resource")
		return
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// slowReader waits before every read, as long as the host's Slow says.
type slowReader struct {
	r    io.Reader
	host *ArtifactoryHost
}

func (s slowReader) Read(b []byte) (int, error) {
	if wait := time.Duration(s.host.Slow.Load()); wait > 0 {
		time.Sleep(wait)
	}
	return s.r.Read(b)
}

func (h *ArtifactoryHost) upload(w http.ResponseWriter, r *http.Request, p string) {
	full, ok := h.local(p)
	if !ok {
		artifactoryError(w, http.StatusNotFound, "No repository found")
		return
	}
	if strings.HasSuffix(p, "/") {
		if err := os.MkdirAll(full, 0o755); err != nil {
			artifactoryError(w, http.StatusConflict, err.Error())
			return
		}
		artifactoryJSON(w, http.StatusCreated, map[string]string{"path": p})
		return
	}
	if info, err := os.Stat(full); err == nil && info.IsDir() {
		artifactoryError(w, http.StatusConflict, "a folder is there")
		return
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		artifactoryError(w, http.StatusConflict, err.Error())
		return
	}
	// what is taken is kept only once all of it was, as Artifactory does
	staged, err := os.CreateTemp(h.Dir, ".upload-*")
	if err != nil {
		artifactoryError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = os.Remove(staged.Name()) }()
	_, err = io.Copy(staged, slowReader{r: r.Body, host: h})
	if closeErr := staged.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		artifactoryError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.Rename(staged.Name(), full); err != nil {
		artifactoryError(w, http.StatusInternalServerError, err.Error())
		return
	}
	artifactoryJSON(w, http.StatusCreated, map[string]string{"path": p, "downloadUri": h.URL + p})
}

func (h *ArtifactoryHost) remove(w http.ResponseWriter, p string) {
	full, ok := h.local(p)
	if !ok {
		artifactoryError(w, http.StatusNotFound, "Could not locate artifact")
		return
	}
	if !strings.Contains(strings.Trim(path.Clean(p), "/"), "/") {
		artifactoryError(w, http.StatusForbidden, "a repository is not removed by a delete")
		return
	}
	if _, err := os.Lstat(full); errors.Is(err, fs.ErrNotExist) {
		artifactoryError(w, http.StatusNotFound, "Could not locate artifact")
		return
	}
	if err := os.RemoveAll(full); err != nil {
		artifactoryError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ArtifactoryHost) move(w http.ResponseWriter, r *http.Request, from string) {
	if h.OSS.Load() {
		artifactoryError(w, http.StatusBadRequest, "This REST API is available only in Artifactory Pro.")
		return
	}
	source, ok := h.local(from)
	to := r.URL.Query().Get("to")
	target, okTo := h.local(to)
	if !ok || !okTo {
		artifactoryError(w, http.StatusNotFound, "Could not find the item or the repository")
		return
	}
	if _, err := os.Stat(source); err != nil {
		artifactoryError(w, http.StatusNotFound, "Could not find the item")
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err == nil {
		err = os.Rename(source, target)
		if err != nil {
			artifactoryJSON(w, http.StatusConflict, map[string]any{
				"messages": []map[string]string{{"level": "ERROR", "message": err.Error()}},
			})
			return
		}
	}
	artifactoryJSON(w, http.StatusOK, map[string]any{
		"messages": []map[string]string{{"level": "INFO", "message": "move " + from + " to " + to + " completed successfully"}},
	})
}

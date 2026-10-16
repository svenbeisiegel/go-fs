package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-fs/internal/config"
)

func testSigningKey(t *testing.T) string {
	t.Helper()
	armored, err := os.ReadFile(filepath.Join("..", "rpm", "testdata", "foreign.asc"))
	if err != nil {
		t.Fatal(err)
	}
	return config.Encode(armored)
}

func loadRepositories(t *testing.T, path string) config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestRepositorySaveAddsMakesTheFolderAndEdits(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)
	key := testSigningKey(t)

	status, body := postServer(t, front, ActionRepositorySave, repositorySaveBody{Repository: repositoryJSON{
		Name: "go-fs", Type: "rpm", Folder: "rpm/go-fs/", SigningKey: key, Keep: 3, PollInterval: 60,
	}})
	if status != http.StatusOK {
		t.Fatalf("save: %d %s", status, body)
	}
	var answer struct {
		Record map[string]any `json:"record"`
		View   repositoryView `json:"view"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Record["folder"] != "/rpm/go-fs" || !strings.HasPrefix(answer.View.Key, "RSA 2048 OpenPGP key") {
		t.Errorf("answer = %+v", answer)
	}
	cfg := loadRepositories(t, path)
	if len(cfg.Repositories) != 1 {
		t.Fatalf("repositories = %+v", cfg.Repositories)
	}
	repo := cfg.Repositories[0]
	if repo.Folder != "/rpm/go-fs" || repo.Keep != 3 || repo.PollInterval != 0 || repo.SigningKey != key {
		t.Errorf("stored %+v", repo)
	}
	if info, err := os.Stat(config.RepositoryPath(cfg.HTTP.Basefolder, repo.Folder)); err != nil || !info.IsDir() {
		t.Fatalf("the folder was not made: %v", err)
	}

	// an edit without a key keeps the one stored
	status, body = postServer(t, front, ActionRepositorySave, repositorySaveBody{Was: "go-fs", Repository: repositoryJSON{
		Name: "go-fs", Type: "rpm", Folder: "/rpm/go-fs", Keep: 1, PollInterval: 30, URL: "https://x.example.com/rpm/go-fs/",
	}})
	if status != http.StatusOK {
		t.Fatalf("edit: %d %s", status, body)
	}
	repo = loadRepositories(t, path).Repositories[0]
	if repo.SigningKey != key || repo.Keep != 1 || repo.PollInterval != 30 || repo.URL != "https://x.example.com/rpm/go-fs" {
		t.Errorf("edited %+v", repo)
	}

	// a repository that was removed meanwhile is not edited
	if status, body := postServer(t, front, ActionRepositorySave, repositorySaveBody{Was: "gone",
		Repository: repositoryJSON{Name: "gone", Type: "rpm", Folder: "/x"}}); status != http.StatusConflict {
		t.Errorf("an edit of a repository not in the file: %d %s", status, body)
	}
}

func TestRepositorySaveRefuses(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)
	key := testSigningKey(t)
	cases := []struct {
		repo repositoryJSON
		want string
	}{
		{repositoryJSON{Type: "rpm", Folder: "/rpm", SigningKey: key}, "name the repository"},
		{repositoryJSON{Name: "x", Type: "rpm", Folder: "/rpm"}, "generate or upload the key"},
		{repositoryJSON{Name: "x", Type: "rpm", Folder: "/", SigningKey: key}, "a folder of its own"},
		{repositoryJSON{Name: "x", Type: "deb", Folder: "/rpm", SigningKey: key}, `type "deb"`},
		{repositoryJSON{Name: "x y", Type: "rpm", Folder: "/rpm", SigningKey: key}, "letters, digits"},
		{repositoryJSON{Name: "x", Type: "rpm", Folder: "/rpm", SigningKey: config.Encode([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----\n"))}, "signingKey"},
	}
	for _, c := range cases {
		status, body := postServer(t, front, ActionRepositorySave, repositorySaveBody{Repository: c.repo})
		if status != http.StatusBadRequest || !strings.Contains(body, c.want) {
			t.Errorf("%+v: %d %s, want %q", c.repo, status, body, c.want)
		}
	}
	if repos := loadRepositories(t, path).Repositories; len(repos) != 0 {
		t.Errorf("a refused repository was stored: %+v", repos)
	}
}

func TestStateCarriesRepositories(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)
	if status, body := postServer(t, front, ActionRepositorySave, repositorySaveBody{Repository: repositoryJSON{
		Name: "go-fs", Type: "rpm", Folder: "/rpm", SigningKey: testSigningKey(t),
	}}); status != http.StatusOK {
		t.Fatalf("save: %d %s", status, body)
	}
	got := get(t, front)
	if len(got.RepositoryTypes) == 0 || got.RepositoryTypes[0].ID != "rpm" {
		t.Errorf("types = %+v", got.RepositoryTypes)
	}
	if view, ok := got.Repositories["go-fs"]; !ok || !strings.HasPrefix(view.Key, "RSA 2048") {
		t.Errorf("views = %+v", got.Repositories)
	}
}

func TestGeneratePGPKey(t *testing.T) {
	if testing.Short() {
		t.Skip("generating an RSA 4096 key takes seconds")
	}
	path := testConfig(t)
	_, front := testServer(t, path)
	status, body := postServer(t, front, ActionGenerate, map[string]string{"kind": config.KindPGPKey, "name": "go-fs"})
	if status != http.StatusOK {
		t.Fatalf("generate: %d %s", status, body)
	}
	var answer struct{ Value, Summary string }
	json.Unmarshal([]byte(body), &answer)
	if _, err := config.DecodePGPKey(answer.Value); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(answer.Summary, "RSA 4096 OpenPGP key") || !strings.Contains(answer.Summary, "go-fs") {
		t.Errorf("summary = %q", answer.Summary)
	}
}

func TestRepositorySaveFDroid(t *testing.T) {
	if testing.Short() {
		t.Skip("generating an RSA 4096 key takes seconds")
	}
	path := testConfig(t)
	_, front := testServer(t, path)
	status, body := postServer(t, front, ActionGenerate, map[string]string{"kind": config.KindJARKey, "name": "android"})
	if status != http.StatusOK {
		t.Fatalf("generate: %d %s", status, body)
	}
	var generated struct{ Value, Summary string }
	json.Unmarshal([]byte(body), &generated)
	if !strings.HasPrefix(generated.Summary, "RSA 4096 key, fingerprint ") {
		t.Errorf("summary = %q", generated.Summary)
	}

	status, body = postServer(t, front, ActionRepositorySave, repositorySaveBody{Repository: repositoryJSON{
		Name: "android", Type: "fdroid", Folder: "/android/repo", SigningKey: generated.Value, Keep: 2,
		URL: "https://files.example.com/android/repo", Title: " Example apps ", Description: "Apps", Icon: "icon.png",
	}})
	if status != http.StatusOK {
		t.Fatalf("save: %d %s", status, body)
	}
	var answer struct {
		View repositoryView `json:"view"`
	}
	json.Unmarshal([]byte(body), &answer)
	if answer.View.Key != generated.Summary {
		t.Errorf("the key is described as %q, want %q", answer.View.Key, generated.Summary)
	}
	repo := loadRepositories(t, path).Repositories[0]
	if repo.Type != "fdroid" || repo.Title != "Example apps" || repo.Description != "Apps" || repo.Icon != "/icon.png" {
		t.Errorf("stored %+v", repo)
	}

	// the address has to be one the F-Droid app finds the repository at
	status, body = postServer(t, front, ActionRepositorySave, repositorySaveBody{Was: "android", Repository: repositoryJSON{
		Name: "android", Type: "fdroid", Folder: "/android/repo", URL: "https://files.example.com/android",
	}})
	if status != http.StatusBadRequest || !strings.Contains(body, "/repo") {
		t.Errorf("an address not ending in /repo: %d %s", status, body)
	}
}

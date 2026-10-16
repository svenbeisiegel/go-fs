package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"go-fs/internal/config"
	"go-fs/internal/repository"
)

// The package repositories are edited in a dialog, as the remote servers are:
// it asks for the kind, the folder, the key and how many versions to keep, and
// for an F-Droid repository what the app shows of it, and
// the repository is written into the file at once, with nothing else of the
// page, once the file it would make is one go-fs starts with. The folder is
// made when it is not there yet.

// KindRepository is the Create of the [[repositories]] table, which tells the
// page to add and edit its records with the dialog.
const KindRepository = "repository"

// repositoryJSON is a repository as the dialog edits it.
type repositoryJSON struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Folder string `json:"folder"`
	// SigningKey is the value an upload or a generate handed the page, ""
	// to keep the key stored.
	SigningKey   string `json:"signingKey"`
	Keep         int    `json:"keep"`
	PollInterval int    `json:"pollInterval"`
	URL          string `json:"url"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Icon         string `json:"icon"`
}

// repositorySaveBody stores a repository.
type repositorySaveBody struct {
	// Was is the name the repository had in the file when the page read
	// it, "" for a repository that is new.
	Was        string         `json:"was"`
	Repository repositoryJSON `json:"repository"`
}

// repositoryView is what the page shows of a stored repository besides its
// keys: what its key is, and how it is doing.
type repositoryView struct {
	Key    string             `json:"key"`
	Status *repository.Status `json:"status,omitempty"`
}

// repositoryViews describes the repositories of cfg, by name.
func repositoryViews(cfg config.Config) map[string]repositoryView {
	statuses := repository.Statuses()
	views := make(map[string]repositoryView, len(cfg.Repositories))
	for _, repo := range cfg.Repositories {
		view := repositoryView{Key: config.Describe(config.SigningKeyKind(repo.Type), repo.SigningKey)}
		if status, ok := statuses[repo.Name]; ok {
			view.Status = &status
		}
		views[repo.Name] = view
	}
	return views
}

// handleRepositorySave writes a repository into the file: in place of the
// one it was, or after the others.
func (h *Handler) handleRepositorySave(w http.ResponseWriter, r *http.Request) {
	if !h.posted(w, r) {
		return
	}
	var body repositorySaveBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPost)).Decode(&body); err != nil {
		http.Error(w, "the body is not a repository: "+err.Error(), http.StatusBadRequest)
		return
	}
	h.saving.Lock()
	defer h.saving.Unlock()

	cfg, err := h.read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	index := -1
	if body.Was != "" {
		for i, repo := range cfg.Repositories {
			if repo.Name == body.Was {
				index = i
				break
			}
		}
		if index < 0 {
			http.Error(w, fmt.Sprintf("the file no longer holds the repository %q; reload the page", body.Was),
				http.StatusConflict)
			return
		}
	}

	posted := body.Repository
	repo := config.Repository{
		Name:         strings.TrimSpace(posted.Name),
		Type:         strings.TrimSpace(posted.Type),
		SigningKey:   strings.TrimSpace(posted.SigningKey),
		Keep:         posted.Keep,
		PollInterval: posted.PollInterval,
		Title:        strings.TrimSpace(posted.Title),
		Description:  strings.TrimSpace(posted.Description),
	}
	if repo.Name == "" {
		http.Error(w, "name the repository", http.StatusBadRequest)
		return
	}
	// the key stays the one stored unless another was made or uploaded
	if repo.SigningKey == "" && index >= 0 {
		repo.SigningKey = cfg.Repositories[index].SigningKey
	}
	if repo.SigningKey == "" {
		http.Error(w, "generate or upload the key the repository signs with", http.StatusBadRequest)
		return
	}
	if repo.Folder, err = config.RepositoryFolder(posted.Folder); err != nil {
		http.Error(w, "folder: "+err.Error(), http.StatusBadRequest)
		return
	}
	if repo.URL, err = config.RepositoryURL(posted.URL); err != nil {
		http.Error(w, "address: "+err.Error(), http.StatusBadRequest)
		return
	}
	if icon := strings.TrimSpace(posted.Icon); icon != "" {
		if repo.Icon, err = config.RepositoryFolder(icon); err != nil {
			http.Error(w, "icon: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if repo.PollInterval == config.DefaultPollInterval {
		// the default is left out of the file, as an unset key
		repo.PollInterval = 0
	}
	if index >= 0 {
		cfg.Repositories[index] = repo
	} else {
		cfg.Repositories = append(cfg.Repositories, repo)
		index = len(cfg.Repositories) - 1
	}

	// the folder is made where it is not there yet, which is what adding a
	// repository to a folder that is to hold one means
	resolved := cfg.Resolved()
	made := false
	if resolved.HTTP.Basefolder != "" {
		folder := config.RepositoryPath(resolved.HTTP.Basefolder, repo.Folder)
		if _, err := os.Stat(folder); errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(folder, 0o755); err != nil {
				http.Error(w, "the folder cannot be made: "+err.Error(), http.StatusConflict)
				return
			}
			made = true
		}
	}
	if err := resolved.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	backup, err := h.write(cfg)
	if err != nil {
		h.log.Error("the admin interface cannot write the configuration",
			"path", h.path, "error", err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	h.log.Info("the admin interface stored a repository", "repository", repo.Name, "type", repo.Type,
		"folder", repo.Folder, "madeFolder", made, "path", h.path, "backup", backup, "address", addressOf(r))

	records, _ := h.schema.Values(cfg)["repositories"].([]any)
	var record any
	if index < len(records) {
		record = records[index]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"record": record,
		"view":   repositoryViews(cfg)[repo.Name],
		"path":   h.path,
		"backup": backup,
		"reload": cfg.General.ReloadConfig,
	})
}

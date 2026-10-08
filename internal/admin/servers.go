package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go-fs/internal/remote"
)

// The remote servers the file listing sends to are not typed into the form
// like the rest of the file. The page edits one in a dialog: it asks for the
// key the host shows, the admin accepts it, and the server logs in with the
// login and that key before it stores the entry. Only a login that works is
// written, and it is written at once, with nothing else of the file changed,
// so that what the dialog said worked is what the file holds.

// KindServer is the Create of the [[servers]] table, which tells the page to
// add and edit its records with the dialog.
const KindServer = "server"

// serverTimeout bounds asking a host for its key, and logging in to it.
const serverTimeout = time.Minute

// serverJSON is a server as the dialog edits it.
type serverJSON struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s serverJSON) login() remote.Login {
	return remote.Login{Type: strings.TrimSpace(s.Type), Host: s.Host, Port: s.Port,
		Username: s.Username, Password: s.Password}
}

// serverHostKeyBody asks for the key of the host of a server.
type serverHostKeyBody struct {
	Server serverJSON `json:"server"`
}

// serverSaveBody stores a server.
type serverSaveBody struct {
	// Was is the name the server had in the file when the page read it, ""
	// for a server that is new.
	Was    string     `json:"was"`
	Server serverJSON `json:"server"`
	// HostKey is the fingerprint of the key the admin accepted.
	HostKey string `json:"hostKey"`
}

// decodeServer reads the body of one of the server endpoints.
func (h *Handler) decodeServer(w http.ResponseWriter, r *http.Request, into any) bool {
	if !h.posted(w, r) {
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPost)).Decode(into); err != nil {
		http.Error(w, "the body is not a server: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// handleServerHostKey answers the key the host of a server shows, without
// offering it a login.
func (h *Handler) handleServerHostKey(w http.ResponseWriter, r *http.Request) {
	var body serverHostKeyBody
	if !h.decodeServer(w, r, &body) {
		return
	}
	login, err := body.Server.login().Checked(true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg, err := h.read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), serverTimeout)
	defer cancel()
	keyType, fingerprint, err := remote.HostKey(ctx, login, cfg.General.SSH)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"host": login.Shown(), "keyType": keyType, "fingerprint": fingerprint,
	})
}

// handleServerSave logs in to a server and, once that worked, writes it into
// the file: in place of the one it was, or after the others.
func (h *Handler) handleServerSave(w http.ResponseWriter, r *http.Request) {
	var body serverSaveBody
	if !h.decodeServer(w, r, &body) {
		return
	}
	// the file is read, changed and written as one, so that two saves do not
	// each write a file without the other's server
	h.saving.Lock()
	defer h.saving.Unlock()

	cfg, err := h.read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	index := -1
	if body.Was != "" {
		for i, server := range cfg.Servers {
			if server.Name == body.Was {
				index = i
				break
			}
		}
		if index < 0 {
			http.Error(w, fmt.Sprintf("the file no longer holds the server %q; reload the page", body.Was),
				http.StatusConflict)
			return
		}
	}
	name := strings.TrimSpace(body.Server.Name)
	if name == "" {
		http.Error(w, "name the server", http.StatusBadRequest)
		return
	}
	login := body.Server.login()
	// an edit that leaves the password empty keeps the one stored
	if index >= 0 && login.Password == "" {
		login.Password = cfg.Servers[index].Password
	}
	login.HostKey = body.HostKey
	login, err = login.Checked(false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	server := login.ConfigServer(name)
	if index >= 0 {
		cfg.Servers[index] = server
	} else {
		cfg.Servers = append(cfg.Servers, server)
		index = len(cfg.Servers) - 1
	}
	// what the file would be is checked before anyone is logged in to, so
	// that a name that is taken is said at once
	if err := cfg.Resolved().Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), serverTimeout)
	defer cancel()
	if err := remote.Test(ctx, login, cfg.General.SSH); err != nil {
		h.log.Info("the admin interface did not store a server, its login failed",
			"server", name, "host", login.Shown(), "error", err, "address", addressOf(r))
		status := http.StatusBadGateway
		if errors.Is(err, context.Canceled) {
			status = http.StatusRequestTimeout
		}
		http.Error(w, err.Error(), status)
		return
	}

	backup, err := h.write(cfg)
	if err != nil {
		h.log.Error("the admin interface cannot write the configuration",
			"path", h.path, "error", err)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	h.log.Info("the admin interface stored a server", "server", name, "type", login.Type,
		"host", login.Shown(), "username", login.Username, "path", h.path, "backup", backup,
		"address", addressOf(r))

	records, _ := h.schema.Values(cfg)["servers"].([]any)
	var record any
	if index < len(records) {
		record = records[index]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"record": record,
		"path":   h.path,
		"backup": backup,
		"reload": cfg.General.ReloadConfig,
	})
}

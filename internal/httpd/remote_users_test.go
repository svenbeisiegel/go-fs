package httpd

import (
	"net/http"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/remote/remotetest"
)

// A server that does not name an account is not there for it: not in the
// menu, not in the Send File dialog, and not to be browsed, fetched from or
// sent to, whatever the account itself may.
func TestRemoteServerRefusesAnAccountItDoesNotName(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Servers[0].AllowedUsers = []string{"someone-else"}
	})
	server.write(t, "report.txt", "the report")

	body := listingOf(t, server, session)
	if strings.Contains(body, "go-fs=remote") {
		t.Error("the menu offers a server that does not admit the account")
	}
	if strings.Contains(body, `<option value="Backup">`) {
		t.Error("the Send File dialog offers a server that does not admit the account")
	}

	for what, res := range map[string]*http.Response{
		"page":     remoteDo(t, server, http.MethodGet, remoteAt(host, ""), session, nil, map[string]string{"Accept": "text/html"}),
		"download": remoteDo(t, server, http.MethodGet, remoteAt(host, "a.txt"), session, nil, nil),
		"upload":   remoteDo(t, server, http.MethodPut, remoteAt(host, "new.txt"), session, strings.NewReader("x"), octetStream),
		"mkdir":    remoteDo(t, server, methodMkcol, remoteAt(host, "made"), session, nil, nil),
		"delete":   remoteDo(t, server, http.MethodDelete, remoteAt(host, "a.txt"), session, nil, nil),
	} {
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("the %s answered %d", what, res.StatusCode)
		}
	}
	res, data := transferRequest(t, server, http.MethodPost, remoteFetchOf(remoteAt(host, "a.txt")), session,
		remoteFetchBody{Folder: "/"})
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("the fetch answered %d: %s", res.StatusCode, data)
	}
	res, data = transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session,
		sendBody{Server: "Backup"})
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), `no server named "Backup"`) {
		t.Errorf("browsing to send answered %d: %s", res.StatusCode, data)
	}
	if remoteFile(host, "a.txt") != "a" || remoteFile(host, "new.txt") != "" {
		t.Error("the server was changed")
	}
}

// A server that names nobody is for admins alone, and an admin may use every
// server, named or not.
func TestRemoteServerAdmitsAnAdminAlways(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	server := newServer(t, func(cfg *httpConfig) {
		admin := fullUser("root", "pw")
		admin.IsAdmin = true
		cfg.Users = append(cfg.Users, admin)
		backup := storedServer(host, "Backup")
		backup.AllowedUsers = nil
		cfg.Servers = []config.Server{backup}
	})
	server.write(t, "report.txt", "the report")

	john := login(t, server, "/", "john", "doe")
	if strings.Contains(listingOf(t, server, john), "go-fs=remote") {
		t.Error("a server that names nobody is offered to an account that is no admin")
	}
	if res := remoteDo(t, server, http.MethodGet, remoteAt(host, "a.txt"), john, nil, nil); res.StatusCode != http.StatusNotFound {
		t.Errorf("the download by an account that is no admin answered %d", res.StatusCode)
	}

	root := login(t, server, "/", "root", "pw")
	body := listingOf(t, server, root)
	if !strings.Contains(body, "go-fs=remote") || !strings.Contains(body, `<option value="Backup">`) {
		t.Error("an admin is not offered the server")
	}
	if res := remoteDo(t, server, http.MethodGet, remoteAt(host, "a.txt"), root, nil, nil); res.StatusCode != http.StatusOK {
		t.Errorf("the download by an admin answered %d", res.StatusCode)
	}
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", root,
		sendBody{Server: "Backup"})
	if res.StatusCode != http.StatusOK {
		t.Errorf("browsing to send as an admin answered %d: %s", res.StatusCode, data)
	}
}

package httpd

import (
	"net/http"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/remote/remotetest"
)

// asStored is the server as the admin interface stores it, with none of its
// rights set, so that each is its default.
func asStored(server config.Server) config.Server {
	server.AllowDownload, server.AllowUpload, server.AllowCreate = nil, nil, nil
	server.AllowDelete, server.AllowRename = nil, nil
	return server
}

// A server allows downloading by default, and nothing that changes it, even
// to an account that may do everything.
func TestRemoteServerAllowsOnlyDownloadsByDefault(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	host.Write(t, "docs/b.txt", "b")
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Servers[0] = asStored(cfg.Servers[0])
	})
	server.write(t, "report.txt", "the report")

	body := bodyOf(t, remoteDo(t, server, http.MethodGet, remoteAt(host, ""), session, nil, nil))
	if !strings.Contains(body, `data-do="download"`) || !strings.Contains(body, `data-do="remote-fetch"`) {
		t.Error("the page does not offer Download and Fetch")
	}
	for _, unwanted := range []string{`data-do="rename"`, `data-do="delete"`, `id="upload"`, `id="new-folder"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the page has %s", unwanted)
		}
	}
	if res := remoteDo(t, server, http.MethodGet, remoteAt(host, "a.txt"), session, nil, nil); res.StatusCode != http.StatusOK {
		t.Errorf("the download answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodGet, remoteAt(host, "docs")+"&archive=1", session, nil, nil); res.StatusCode != http.StatusOK {
		t.Errorf("the archive answered %d", res.StatusCode)
	}

	refused := map[string]*http.Response{
		"upload": remoteDo(t, server, http.MethodPut, remoteAt(host, "new.txt"), session, strings.NewReader("x"), octetStream),
		"chunk": remoteDo(t, server, http.MethodPut, remoteAt(host, "new.txt"), session, strings.NewReader("x"),
			map[string]string{"Content-Type": "application/octet-stream", "Content-Range": "bytes 0-0/1"}),
		"mkdir": remoteDo(t, server, methodMkcol, remoteAt(host, "made"), session, nil, nil),
		"rename": remoteDo(t, server, methodMove, remoteAt(host, "a.txt"), session, nil,
			map[string]string{"Destination": server.url(remoteAt(host, "c.txt"))}),
		"delete": remoteDo(t, server, http.MethodDelete, remoteAt(host, "a.txt"), session, nil, nil),
	}
	for what, res := range refused {
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("the %s answered %d", what, res.StatusCode)
		}
	}
	if remoteFile(host, "a.txt") != "a" || remoteFile(host, "new.txt") != "" || remoteFile(host, "c.txt") != "" {
		t.Error("the server was changed")
	}

	// nor is the server one to send to
	if strings.Contains(listingOf(t, server, session), `<option value="Backup">`) {
		t.Error("the Send File dialog offers a server that does not allow uploads")
	}
	res, data := transferRequest(t, server, http.MethodPost, "/report.txt?go-fs=send-browse", session,
		sendBody{Server: "Backup"})
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), "does not allow to upload") {
		t.Errorf("browsing to send answered %d: %s", res.StatusCode, data)
	}
}

// Each right of a server allows what it names, and nothing beside.
func TestRemoteServerRightsAllowWhatTheyName(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	host.Write(t, "b.txt", "b")
	yes := true
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		stored := asStored(cfg.Servers[0])
		stored.AllowUpload, stored.AllowCreate, stored.AllowDelete, stored.AllowRename = &yes, &yes, &yes, &yes
		cfg.Servers[0] = stored
	})

	if res := remoteDo(t, server, http.MethodPut, remoteAt(host, "new.txt"), session, strings.NewReader("x"), octetStream); res.StatusCode != http.StatusOK {
		t.Errorf("the upload answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, methodMkcol, remoteAt(host, "made"), session, nil, nil); res.StatusCode != http.StatusCreated {
		t.Errorf("MKCOL answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, methodMove, remoteAt(host, "a.txt"), session, nil,
		map[string]string{"Destination": server.url(remoteAt(host, "c.txt"))}); res.StatusCode != http.StatusCreated {
		t.Errorf("the rename answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodDelete, remoteAt(host, "b.txt"), session, nil, nil); res.StatusCode != http.StatusNoContent {
		t.Errorf("the delete answered %d", res.StatusCode)
	}
	if !strings.Contains(listingOf(t, server, session), `<option value="Backup">`) {
		t.Error("the Send File dialog does not offer a server that allows uploads")
	}
}

// A server that does not allow downloads is still listed, but none of its
// files leaves it.
func TestRemoteServerWithoutDownloads(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	host.Write(t, "a.txt", "a")
	host.Write(t, "docs/b.txt", "b")
	no := false
	server, session := remoteServer(t, host, func(cfg *httpConfig) {
		cfg.Servers[0].AllowDownload = &no
	})
	server.mkdir(t, "inbox")

	res := remoteDo(t, server, http.MethodGet, remoteAt(host, ""), session, nil, nil)
	body := bodyOf(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "a.txt") {
		t.Fatalf("the page answered %d", res.StatusCode)
	}
	for _, unwanted := range []string{`data-do="download"`, `data-do="remote-fetch"`,
		`href="` + strings.ReplaceAll(remoteAt(host, "a.txt"), "&", "&amp;") + `"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the page has %s", unwanted)
		}
	}
	if !strings.Contains(body, `href="`+strings.ReplaceAll(remoteAt(host, "docs"), "&", "&amp;")+`"`) {
		t.Error("the page does not link the folder")
	}

	if res := remoteDo(t, server, http.MethodGet, remoteAt(host, "a.txt"), session, nil, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("the download answered %d", res.StatusCode)
	}
	if res := remoteDo(t, server, http.MethodGet, remoteAt(host, "docs")+"&archive=1", session, nil, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("the archive answered %d", res.StatusCode)
	}
	res, data := transferRequest(t, server, http.MethodPost, remoteFetchOf(remoteAt(host, "a.txt")), session,
		remoteFetchBody{Folder: "/inbox"})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("the fetch answered %d: %s", res.StatusCode, data)
	}
}

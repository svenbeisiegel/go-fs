package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/remote/remotetest"
)

// postServer posts to one of the server endpoints, and reports the status and
// the body.
func postServer(t *testing.T, front *httptest.Server, action string, body any) (int, string) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, front.URL+"/?go-fs="+action, strings.NewReader(string(encoded)))
	request.Header.Set("Content-Type", "application/json")
	answer, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Body.Close()
	returned, _ := io.ReadAll(answer.Body)
	return answer.StatusCode, strings.TrimSpace(string(returned))
}

// serverOn is the server the dialog would post for a host.
func serverOn(host *remotetest.SFTPHost, name, password string) serverJSON {
	return serverJSON{Name: name, Type: config.ServerTypeSFTP, Host: host.Host, Port: host.Port,
		Username: "alice", Password: password}
}

func loadServers(t *testing.T, path string) []config.Server {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Servers
}

func TestServerHostKeyIsShownWithoutALogin(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	_, front := testServer(t, testConfig(t))

	status, body := postServer(t, front, ActionServerHostKey, serverHostKeyBody{Server: serverOn(host, "backup", "")})
	if status != http.StatusOK {
		t.Fatalf("the host key answered %d: %s", status, body)
	}
	var view map[string]string
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatal(err)
	}
	if view["fingerprint"] != host.Fingerprint || view["keyType"] == "" {
		t.Errorf("the key is %v, want %s", view, host.Fingerprint)
	}
	if n := host.Logins.Load(); n != 0 {
		t.Errorf("%d logins were offered for the key alone", n)
	}

	status, body = postServer(t, front, ActionServerHostKey, serverHostKeyBody{Server: serverJSON{Host: "sftp://x"}})
	if status != http.StatusBadRequest {
		t.Errorf("a URL for a host answered %d: %s", status, body)
	}
}

func TestServerIsStoredOnceTheLoginWorks(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	path := testConfig(t)
	_, front := testServer(t, path)

	// a wrong password is not stored, and the file is left as it was
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	status, body := postServer(t, front, ActionServerSave,
		serverSaveBody{Server: serverOn(host, "backup", "wrong"), HostKey: host.Fingerprint})
	if status != http.StatusBadGateway || !strings.Contains(body, "refused the login") {
		t.Errorf("a wrong password answered %d: %s", status, body)
	}
	// and nor is a host that shows another key, which is not logged in to
	logins := host.Logins.Load()
	status, body = postServer(t, front, ActionServerSave,
		serverSaveBody{Server: serverOn(host, "backup", "secret"), HostKey: "SHA256:somebodyElse"})
	if status != http.StatusBadGateway || host.Logins.Load() != logins {
		t.Errorf("another key answered %d: %s", status, body)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Errorf("a login that failed changed the file:\n%s", after)
	}

	status, body = postServer(t, front, ActionServerSave,
		serverSaveBody{Server: serverOn(host, "backup", "secret"), HostKey: host.Fingerprint})
	if status != http.StatusOK {
		t.Fatalf("the save answered %d: %s", status, body)
	}
	var answer struct {
		Record map[string]any `json:"record"`
		Backup string         `json:"backup"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Record["name"] != "backup" || answer.Record["hostKeyFingerprint"] != host.Fingerprint ||
		answer.Record["password"] != "secret" {
		t.Errorf("the record answered is %v", answer.Record)
	}
	servers := loadServers(t, path)
	want := config.Server{Name: "backup", Type: config.ServerTypeSFTP, Host: host.Host, Port: host.Port,
		Username: "alice", Password: "secret", HostKeyFingerprint: host.Fingerprint}
	if len(servers) != 1 || servers[0] != want {
		t.Fatalf("the file holds %+v, want %+v", servers, want)
	}
	// nothing else of the file changed
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FTP.Port != 2121 || len(cfg.Users) != 1 {
		t.Errorf("the rest of the file changed: %+v", cfg)
	}

	// a second server cannot take the name, whatever its case, nor can one
	// be called what the dialog calls the login typed in
	for _, name := range []string{"BACKUP", "manual"} {
		status, body = postServer(t, front, ActionServerSave,
			serverSaveBody{Server: serverOn(host, name, "secret"), HostKey: host.Fingerprint})
		if status != http.StatusBadRequest {
			t.Errorf("a server named %q answered %d: %s", name, status, body)
		}
	}
	if len(loadServers(t, path)) != 1 {
		t.Error("a refused server was stored")
	}
}

func TestServerIsEditedInPlace(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	path := testConfig(t)
	_, front := testServer(t, path)
	for _, name := range []string{"first", "second"} {
		if status, body := postServer(t, front, ActionServerSave,
			serverSaveBody{Server: serverOn(host, name, "secret"), HostKey: host.Fingerprint}); status != http.StatusOK {
			t.Fatalf("storing %s answered %d: %s", name, status, body)
		}
	}

	// renamed, with the password left empty, which keeps the one stored
	status, body := postServer(t, front, ActionServerSave,
		serverSaveBody{Was: "first", Server: serverOn(host, "renamed", ""), HostKey: host.Fingerprint})
	if status != http.StatusOK {
		t.Fatalf("the edit answered %d: %s", status, body)
	}
	servers := loadServers(t, path)
	if len(servers) != 2 || servers[0].Name != "renamed" || servers[0].Password != "secret" || servers[1].Name != "second" {
		t.Errorf("the file holds %+v", servers)
	}

	// an edit of a server the file no longer holds is not taken for a new one
	status, body = postServer(t, front, ActionServerSave,
		serverSaveBody{Was: "first", Server: serverOn(host, "first", "secret"), HostKey: host.Fingerprint})
	if status != http.StatusConflict {
		t.Errorf("an edit of a server that is gone answered %d: %s", status, body)
	}
	if len(loadServers(t, path)) != 2 {
		t.Error("the edit of a server that is gone stored one")
	}
}

// The dialog edits the login of a server, and what the server allows stays as
// the file has it.
func TestServerEditKeepsTheRights(t *testing.T) {
	host := remotetest.NewSFTPHost(t, "alice", "secret")
	path := testConfig(t)
	_, front := testServer(t, path)
	if status, body := postServer(t, front, ActionServerSave,
		serverSaveBody{Server: serverOn(host, "backup", "secret"), HostKey: host.Fingerprint}); status != http.StatusOK {
		t.Fatalf("storing answered %d: %s", status, body)
	}
	if servers := loadServers(t, path); servers[0].AllowDownload != nil || servers[0].AllowUpload != nil {
		t.Errorf("a new server is stored with rights: %+v", servers[0])
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	cfg.Servers[0].AllowDownload, cfg.Servers[0].AllowUpload, cfg.Servers[0].AllowRename = &no, &yes, &yes
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	if status, body := postServer(t, front, ActionServerSave,
		serverSaveBody{Was: "backup", Server: serverOn(host, "backup", ""), HostKey: host.Fingerprint}); status != http.StatusOK {
		t.Fatalf("the edit answered %d: %s", status, body)
	}
	rights := loadServers(t, path)[0].Rights()
	if want := (config.ServerRights{Upload: true, Rename: true}); rights != want {
		t.Errorf("the edited server allows %+v, want %+v", rights, want)
	}
}

func TestStateOffersTheProtocols(t *testing.T) {
	_, front := testServer(t, testConfig(t))
	body := get(t, front)
	if len(body.Protocols) != 3 || body.Protocols[0].ID != config.ServerTypeSFTP ||
		body.Protocols[1].ID != config.ServerTypeArtifactory || !body.Protocols[1].Token ||
		body.Protocols[2].ID != config.ServerTypeSMB || body.Protocols[2].HostKey || body.Protocols[2].DefaultPort != 445 {
		t.Errorf("the state offers %+v", body.Protocols)
	}
}

func TestArtifactoryIsStoredOnceTheTokenWorks(t *testing.T) {
	host := remotetest.NewArtifactoryHost(t, "secret", "libs")
	path := testConfig(t)
	_, front := testServer(t, path)
	server := serverJSON{Name: "artifacts", Type: config.ServerTypeArtifactory, URL: host.URL + "/", Token: "wrong"}

	status, body := postServer(t, front, ActionServerSave, serverSaveBody{Server: server})
	if status != http.StatusBadGateway || !strings.Contains(body, "refused the token") {
		t.Errorf("a wrong token answered %d: %s", status, body)
	}
	if len(loadServers(t, path)) != 0 {
		t.Error("a server with a wrong token was stored")
	}

	server.Token = "secret"
	status, body = postServer(t, front, ActionServerSave, serverSaveBody{Server: server})
	if status != http.StatusOK {
		t.Fatalf("the right token answered %d: %s", status, body)
	}
	stored := loadServers(t, path)
	want := config.Server{Name: "artifacts", Type: config.ServerTypeArtifactory, URL: host.URL, Token: "secret"}
	if len(stored) != 1 || stored[0] != want {
		t.Fatalf("the file holds %+v, want %+v", stored, want)
	}

	// an edit that leaves the token empty keeps the one stored
	server.Name, server.Token = "renamed", ""
	status, body = postServer(t, front, ActionServerSave, serverSaveBody{Was: "artifacts", Server: server})
	if status != http.StatusOK {
		t.Fatalf("an edit without a token answered %d: %s", status, body)
	}
	if stored := loadServers(t, path); len(stored) != 1 || stored[0].Name != "renamed" || stored[0].Token != "secret" {
		t.Errorf("after the edit the file holds %+v", stored)
	}

	status, body = postServer(t, front, ActionServerHostKey, serverHostKeyBody{Server: server})
	if status != http.StatusBadRequest {
		t.Errorf("the key of an Artifactory answered %d: %s", status, body)
	}
}

package httpd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-fs/internal/config"
)

func TestMkcolCreatesTheFolder(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/kept.txt", "x")

	if res := mkcol(t, server, "/private/new/", "john", "doe"); res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	info, err := os.Stat(filepath.Join(server.base, "private", "new"))
	if err != nil || !info.IsDir() {
		t.Fatalf("the folder was not created: %v", err)
	}
	if record := server.logs.find("http mkdir"); record == nil {
		t.Error("a mkdir has to be reported")
	} else if record["folder"] != "/private/new" {
		t.Errorf("mkdir record = %v", record)
	}
}

// The name has to be free, and it has to be reachable: MKCOL creates one
// folder rather than the whole line of them.
func TestMkcolRefusesWhatItCannotCreate(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/taken/kept.txt", "x")
	server.write(t, "private/file.txt", "x")

	cases := map[string]struct {
		path string
		want int
	}{
		"a folder that is there": {"/private/taken/", http.StatusMethodNotAllowed},
		"a file that is there":   {"/private/file.txt", http.StatusMethodNotAllowed},
		"the served folder":      {"/", http.StatusMethodNotAllowed},
		"a missing parent":       {"/private/nothing/here/", http.StatusConflict},
		"outside the folder":     {"/private/../../escaped/", http.StatusNotFound},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			if res := mkcol(t, server, item.path, "john", "doe"); res.StatusCode != item.want {
				t.Errorf("status = %d, want %d", res.StatusCode, item.want)
			}
		})
	}
}

// RFC 4918 has a body describe the folder being made, which is not something
// this server understands.
func TestMkcolRefusesABody(t *testing.T) {
	server := newServer(t, nil)

	res := basic(t, server, methodMkcol, "/private/new/", "john", "doe",
		strings.NewReader("<propertyupdate/>"))
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", res.StatusCode)
	}
}

func TestMoveRenamesInPlace(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/before.txt", "kept")

	res := move(t, server, "/private/before.txt", "/private/after.txt", "john", "doe")
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", res.StatusCode)
	}
	if got := server.read(t, "private/after.txt"); got != "kept" {
		t.Errorf("the content changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(server.base, "private", "before.txt")); !os.IsNotExist(err) {
		t.Error("the old name is still there")
	}
	if record := server.logs.find("http rename"); record == nil {
		t.Error("a rename has to be reported")
	} else if record["from"] != "/private/before.txt" || record["to"] != "/private/after.txt" {
		t.Errorf("rename record = %v", record)
	}
}

// A folder is renamed the same way a file is, with everything still in it.
func TestMoveRenamesAFolder(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/before/kept.txt", "x")

	if res := move(t, server, "/private/before/", "/private/after/", "john", "doe"); res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", res.StatusCode)
	}
	if got := server.read(t, "private/after/kept.txt"); got != "x" {
		t.Errorf("the folder did not come with its content: %q", got)
	}
}

// What this offers is a rename. A Destination in another folder would make it a
// move, which is a reach nothing here checks for.
func TestMoveOnlyRenames(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/here/one.txt", "x")
	server.write(t, "private/there/taken.txt", "x")

	cases := map[string]struct {
		to   string
		want int
	}{
		"another folder":            {"/private/there/one.txt", http.StatusBadRequest},
		"the folder above":          {"/private/one.txt", http.StatusBadRequest},
		"outside the served folder": {"/private/here/../../../escaped.txt", http.StatusNotFound},
		"the served folder itself":  {"/", http.StatusNotFound},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			res := move(t, server, "/private/here/one.txt", item.to, "john", "doe")
			if res.StatusCode != item.want {
				t.Errorf("status = %d, want %d", res.StatusCode, item.want)
			}
		})
	}
	if got := server.read(t, "private/here/one.txt"); got != "x" {
		t.Errorf("the file moved anyway: %q", got)
	}
}

// A name that is taken is refused with the status that says so, because a bare
// 404 could not be told apart from a source that is not there.
func TestMoveRefusesATakenName(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/one.txt", "one")
	server.write(t, "private/two.txt", "two")

	res := move(t, server, "/private/one.txt", "/private/two.txt", "john", "doe")
	if res.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412", res.StatusCode)
	}
	if got := server.read(t, "private/two.txt"); got != "two" {
		t.Errorf("the file was overwritten: %q", got)
	}
}

func TestMoveNeedsADestination(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/one.txt", "one")

	res := basic(t, server, methodMove, "/private/one.txt", "john", "doe", nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", res.StatusCode)
	}
}

// The account's paths are checked against where the name lands as well as
// where it came from, so a rename cannot carry a file out of its scope.
func TestMoveChecksTheDestinationAgainstThePaths(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		scoped := fullUser("john", "doe")
		scoped.Paths = []string{"^/private/keep/.*"}
		cfg.Users = []config.User{scoped}
		cfg.PathsRequireAuth = []string{"^/private/.*"}
	})
	server.write(t, "private/keep/one.txt", "x")

	// the source is inside the scope; a sibling of the folder is not, and the
	// listing of it is what the pattern is written against
	res := move(t, server, "/private/keep/one.txt", "/private/keep/../one.txt", "john", "doe")
	if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 400 or 403", res.StatusCode)
	}
	if got := server.read(t, "private/keep/one.txt"); got != "x" {
		t.Errorf("the file moved anyway: %q", got)
	}
}

// Creating a folder is the create right, and renaming is that plus the right to
// take a name away.
func TestNewMethodsNeedTheRights(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		creator := fullUser("creator", "pw")
		creator.AllowUserFileDelete = new(false)
		remover := fullUser("remover", "pw")
		remover.AllowUserFileCreate = new(false)
		remover.AllowUserFolderCreate = new(false)
		cfg.Users = []config.User{
			fullUser("john", "doe"), creator, remover, readOnlyUser("reader", "pw"),
		}
	})
	server.write(t, "private/one.txt", "x")

	cases := []struct {
		user   string
		mkcol  int
		rename int
	}{
		{"john", http.StatusCreated, http.StatusNoContent},
		{"creator", http.StatusCreated, http.StatusForbidden},
		{"remover", http.StatusForbidden, http.StatusForbidden},
		{"reader", http.StatusForbidden, http.StatusForbidden},
	}
	for _, item := range cases {
		t.Run(item.user, func(t *testing.T) {
			password := "pw"
			if item.user == "john" {
				password = "doe"
			}
			res := mkcol(t, server, "/private/made-by-"+item.user+"/", item.user, password)
			if res.StatusCode != item.mkcol {
				t.Errorf("MKCOL status = %d, want %d", res.StatusCode, item.mkcol)
			}
			res = move(t, server, "/private/one.txt", "/private/by-"+item.user+".txt", item.user, password)
			if res.StatusCode != item.rename {
				t.Errorf("MOVE status = %d, want %d", res.StatusCode, item.rename)
			}
			if res.StatusCode == http.StatusNoContent {
				// put it back for the accounts that come after
				move(t, server, "/private/by-"+item.user+".txt", "/private/one.txt", "john", "doe")
			}
		})
	}
}

// methodsRequireAuth was written into the configurations that exist before
// MKCOL and MOVE were answered at all, so a file on disk names PUT and DELETE
// and not them. An upgrade must not leave the two new writes public.
func TestExistingConfigStillProtectsTheNewMethods(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = []string{"PUT", "DELETE", "POST"}
		cfg.PathsRequireAuth = nil
	})
	server.write(t, "one.txt", "x")

	req, _ := http.NewRequest(methodMkcol, server.url("/anyone/"), nil)
	if res := do(t, req); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("MKCOL status = %d, want 401", res.StatusCode)
	}
	req, _ = http.NewRequest(methodMove, server.url("/one.txt"), nil)
	req.Header.Set("Destination", "/two.txt")
	if res := do(t, req); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("MOVE status = %d, want 401", res.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(server.base, "anyone")); !os.IsNotExist(err) {
		t.Error("an unauthenticated MKCOL created a folder")
	}
}

// A request that names another origin outright is refused, whatever it would
// otherwise have been allowed to do.
func TestWritesFromAnotherOriginAreRefused(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "private/one.txt", "x")

	for _, method := range []string{http.MethodDelete, methodMkcol, methodMove} {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequest(method, server.url("/private/one.txt"), nil)
			req.SetBasicAuth("john", "doe")
			req.Header.Set("Origin", "http://somewhere.else")
			req.Header.Set("Destination", "/private/two.txt")
			if res := do(t, req); res.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", res.StatusCode)
			}
		})
	}
	if got := server.read(t, "private/one.txt"); got != "x" {
		t.Errorf("the file was touched: %q", got)
	}
}

// The page offers only what the account behind it may actually do, so that a
// reader is not shown controls that would answer 403.
func TestListingOffersOnlyWhatTheAccountMayDo(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe"), readOnlyUser("reader", "pw")}
		cfg.PathsRequireAuth = []string{"^/.*"}
	})
	server.write(t, "one.txt", "x")

	res := basic(t, server, http.MethodGet, "/", "reader", "pw", nil)
	body := bodyOf(t, res)
	for _, gone := range []string{`id="new-folder"`, `id="upload"`, `data-do="rename"`, `data-do="delete"`, `id="drop"`} {
		if strings.Contains(body, gone) {
			t.Errorf("a read-only account is offered %q", gone)
		}
	}

	res = basic(t, server, http.MethodGet, "/", "john", "doe", nil)
	body = bodyOf(t, res)
	for _, want := range []string{`id="new-folder"`, `id="upload"`, `data-do="rename"`, `data-do="delete"`, `id="drop"`} {
		if !strings.Contains(body, want) {
			t.Errorf("a full account is not offered %q", want)
		}
	}
}

// Deleting a file and deleting a folder are two rights, so the trash button is
// offered per row: on the files for the one, on the folders for the other.
func TestListingOffersDeletePerRow(t *testing.T) {
	server := newServer(t, func(cfg *httpConfig) {
		files := fullUser("files", "pw")
		files.AllowUserFolderDelete = new(false)
		folders := fullUser("folders", "pw")
		folders.AllowUserFileDelete = new(false)
		cfg.Users = []config.User{files, folders}
		cfg.PathsRequireAuth = []string{"^/.*"}
	})
	server.write(t, "one.txt", "x")
	server.mkdir(t, "sub")

	trash := func(body, name string) bool {
		return strings.Contains(body, `aria-label="Delete `+name+`"`)
	}
	body := bodyOf(t, basic(t, server, http.MethodGet, "/", "files", "pw", nil))
	if !trash(body, "one.txt") || trash(body, "sub") {
		t.Errorf("the file deleter is offered the wrong rows:\n%s", body)
	}
	body = bodyOf(t, basic(t, server, http.MethodGet, "/", "folders", "pw", nil))
	if trash(body, "one.txt") || !trash(body, "sub") {
		t.Errorf("the folder deleter is offered the wrong rows:\n%s", body)
	}
}

// A public server offers what a public request may do, which is what the
// dispatch lets one do rather than what an account would have been allowed.
func TestListingFollowsWhatAPublicRequestMayDo(t *testing.T) {
	server := newServer(t, publicServer)
	server.write(t, "one.txt", "x")

	_, body := get(t, server, "/")
	for _, want := range []string{`id="new-folder"`, `data-do="rename"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q", want)
		}
	}

	locked := newServer(t, func(cfg *httpConfig) {
		cfg.MethodsRequireAuth = []string{"PUT", "DELETE", "POST"}
		cfg.PathsRequireAuth = nil
	})
	locked.write(t, "one.txt", "x")
	_, body = get(t, locked, "/")
	for _, gone := range []string{`id="new-folder"`, `data-do="rename"`, `data-do="delete"`} {
		if strings.Contains(body, gone) {
			t.Errorf("a request that could not write is offered %q", gone)
		}
	}
}

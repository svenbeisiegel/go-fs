package remote_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/remote"
	"go-fs/internal/remote/remotetest"
)

func artifactoryLogin(host *remotetest.ArtifactoryHost) remote.Login {
	return remote.Login{Type: config.ServerTypeArtifactory, URL: host.URL, Token: host.Token}
}

func openArtifactory(t *testing.T, host *remotetest.ArtifactoryHost) remote.FS {
	t.Helper()
	login, err := artifactoryLogin(host).Checked(false)
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := remote.Open(context.Background(), login, sshConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsys.Close() })
	return fsys
}

func TestArtifactoryLoginIsChecked(t *testing.T) {
	login, err := remote.Login{Type: config.ServerTypeArtifactory, URL: " https://acme.jfrog.io/ ",
		Token: " abc ", Host: "ignored", Username: "ignored"}.Checked(false)
	if err != nil {
		t.Fatal(err)
	}
	if login.URL != "https://acme.jfrog.io/artifactory" || login.Token != "abc" || login.Host != "" || login.Username != "" {
		t.Errorf("the login reads %+v", login)
	}
	if login.Shown() != "acme.jfrog.io" || login.Where("/libs/a.txt") != "https://acme.jfrog.io/artifactory/libs/a.txt" {
		t.Errorf("the host is shown as %q, %q", login.Shown(), login.Where("/libs/a.txt"))
	}
	if login.Who() != "the token" {
		t.Errorf("the login is known as %q", login.Who())
	}
	for name, login := range map[string]remote.Login{
		"no url":      {Type: config.ServerTypeArtifactory, Token: "abc"},
		"no scheme":   {Type: config.ServerTypeArtifactory, URL: "acme.jfrog.io", Token: "abc"},
		"no token":    {Type: config.ServerTypeArtifactory, URL: "https://acme.jfrog.io"},
		"a login":     {Type: config.ServerTypeArtifactory, URL: "https://u:p@acme.jfrog.io", Token: "abc"},
		"another url": {Type: config.ServerTypeArtifactory, URL: "ftp://acme.jfrog.io", Token: "abc"},
	} {
		if _, err := login.Checked(false); err == nil {
			t.Errorf("a login with %s was accepted", name)
		}
	}
	if _, err := (remote.Login{Type: config.ServerTypeArtifactory, URL: "https://acme.jfrog.io"}).Checked(true); err == nil {
		t.Error("the key of an Artifactory was asked for")
	}

	server := config.Server{Name: "artifacts", Type: config.ServerTypeArtifactory,
		URL: "https://acme.jfrog.io/artifactory", Token: "abc"}
	if back := remote.FromServer(server).ConfigServer("artifacts"); back != server {
		t.Errorf("the server came back as %+v", back)
	}
}

func TestArtifactoryTest(t *testing.T) {
	host := remotetest.NewArtifactoryHost(t, "secret", "libs")
	ctx := context.Background()
	login, err := artifactoryLogin(host).Checked(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Test(ctx, login, sshConfig()); err != nil {
		t.Errorf("the right token failed: %v", err)
	}
	login.Token = "wrong"
	if err := remote.Test(ctx, login, sshConfig()); err == nil || !strings.Contains(err.Error(), "refused the token") {
		t.Errorf("a wrong token answered %v", err)
	}
	login.Token = "secret"
	login.URL = strings.TrimSuffix(host.URL, "/artifactory") + "/elsewhere"
	if err := remote.Test(ctx, login, sshConfig()); err == nil || !strings.Contains(err.Error(), "has no Artifactory") {
		t.Errorf("an address without an Artifactory answered %v", err)
	}
}

func TestArtifactoryFS(t *testing.T) {
	for _, oss := range []bool{false, true} {
		name := "pro"
		if oss {
			name = "oss"
		}
		t.Run(name, func(t *testing.T) {
			host := remotetest.NewArtifactoryHost(t, "secret", "libs", "docs")
			host.OSS.Store(oss)
			host.Write(t, "libs/org/a b;1.txt", "hello")
			fsys := openArtifactory(t, host)

			home, err := fsys.Resolve("")
			if err != nil || home != "/" {
				t.Fatalf("the login starts at %q, %v", home, err)
			}
			top, err := fsys.ReadDir("/")
			if err != nil || len(top) != 2 || top[0].Name() != "docs" || !top[1].IsDir() {
				t.Fatalf("the top lists %v, %v", names(top), err)
			}
			if info, err := fsys.Stat("/libs"); err != nil || !info.IsDir() {
				t.Errorf("a repository is %v, %v", info, err)
			}
			inner, err := fsys.ReadDir("/libs/org")
			if err != nil || len(inner) != 1 || inner[0].Name() != "a b;1.txt" || inner[0].IsDir() {
				t.Fatalf("a folder lists %v, %v", names(inner), err)
			}
			if size := inner[0].Size(); oss && size != 0 || !oss && size != 5 {
				t.Errorf("the listing gives the size %d", size)
			}
			info, err := fsys.Stat("/libs/org/a b;1.txt")
			if err != nil || info.IsDir() || info.Size() != 5 || info.ModTime().IsZero() {
				t.Errorf("a file is %+v, %v", info, err)
			}
			if _, err := fsys.Stat("/libs/none"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a missing file answered %v", err)
			}

			// a read from wherever it was sought to
			file, err := fsys.Open("/libs/org/a b;1.txt")
			if err != nil {
				t.Fatal(err)
			}
			if end, err := file.Seek(0, io.SeekEnd); err != nil || end != 5 {
				t.Errorf("the end is %d, %v", end, err)
			}
			if _, err := file.Seek(2, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if b, err := io.ReadAll(file); err != nil || string(b) != "llo" {
				t.Errorf("from 2 on reads %q, %v", b, err)
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if b, err := io.ReadAll(file); err != nil || string(b) != "hello" {
				t.Errorf("from the start reads %q, %v", b, err)
			}
			_ = file.Close()

			if n, err := fsys.Put("/docs/new/up.txt", strings.NewReader("uploaded"), 8); err != nil || n != 8 {
				t.Fatalf("the upload wrote %d, %v", n, err)
			}
			if got := host.Read(t, "docs/new/up.txt"); got != "uploaded" {
				t.Errorf("the upload holds %q", got)
			}
			if _, err := fsys.Put("/docs/empty.txt", strings.NewReader(""), 0); err != nil {
				t.Errorf("an empty upload failed: %v", err)
			}
			if _, err := fsys.Put("/top.txt", strings.NewReader("x"), 1); !errors.Is(err, fs.ErrPermission) {
				t.Errorf("a file beside the repositories answered %v", err)
			}
			if err := fsys.Mkdir("/docs/folder"); err != nil {
				t.Fatal(err)
			}
			if info, err := fsys.Stat("/docs/folder"); err != nil || !info.IsDir() {
				t.Errorf("the new folder is %v, %v", info, err)
			}
			if err := fsys.Mkdir("/newrepo"); !errors.Is(err, fs.ErrPermission) {
				t.Errorf("a new repository answered %v", err)
			}

			err = fsys.Rename("/docs/new/up.txt", "/docs/folder/moved.txt")
			if oss {
				if err == nil || !strings.Contains(err.Error(), "only in Artifactory Pro") {
					t.Errorf("a rename without Pro answered %v", err)
				}
			} else if err != nil || host.Read(t, "docs/folder/moved.txt") != "uploaded" {
				t.Errorf("the rename answered %v", err)
			}

			if err := fsys.RemoveDir("/libs/org"); err == nil {
				t.Error("a folder with a file in it was removed")
			}
			if err := fsys.Remove("/libs/org/a b;1.txt"); err != nil {
				t.Fatal(err)
			}
			if err := fsys.RemoveDir("/libs/org"); err != nil {
				t.Errorf("an empty folder was not removed: %v", err)
			}
			if _, err := fsys.Stat("/libs/org"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the removed folder answers %v", err)
			}
			if err := fsys.RemoveDir("/libs"); !errors.Is(err, fs.ErrPermission) {
				t.Errorf("removing a repository answered %v", err)
			}
		})
	}
}

func names(infos []fs.FileInfo) []string {
	var found []string
	for _, info := range infos {
		found = append(found, info.Name())
	}
	return found
}

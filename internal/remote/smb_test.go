package remote

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hirochachacha/go-smb2"

	"go-fs/internal/config"
)

func TestSMBLoginIsChecked(t *testing.T) {
	login, err := Login{Type: config.ServerTypeSMB, Host: " files.example.com ", Username: ` CORP\alice `}.Checked(false)
	if err != nil {
		t.Fatalf("an SMB login without a host key was refused: %v", err)
	}
	if login.Port != 445 || login.Host != "files.example.com" || login.Username != `CORP\alice` {
		t.Errorf("the login reads %+v", login)
	}
	if login.Shown() != "files.example.com" || login.Where("/public/in") != "smb://files.example.com/public/in" {
		t.Errorf("the host is shown as %q, %q", login.Shown(), login.Where("/public/in"))
	}
	login.Port = 4445
	if login.Shown() != "files.example.com:4445" {
		t.Errorf("the host on another port is shown as %q", login.Shown())
	}
	if _, err := (Login{Type: config.ServerTypeSMB, Host: "files.example.com"}).Checked(false); err == nil {
		t.Error("an SMB login without a username was accepted")
	}
	if _, _, err := HostKey(context.Background(), login, config.Default().General.SSH); err == nil ||
		!strings.Contains(err.Error(), "shows no key") {
		t.Errorf("the key of an SMB host answered %v", err)
	}
}

func TestSMBUser(t *testing.T) {
	for username, want := range map[string][2]string{
		"alice":             {"", "alice"},
		`CORP\alice`:        {"CORP", "alice"},
		"alice@corp.local":  {"", "alice@corp.local"},
		`corp.local\alice`:  {"corp.local", "alice"},
		`CORP\alice\deeper`: {"CORP", `alice\deeper`},
	} {
		if domain, user := smbUser(username); domain != want[0] || user != want[1] {
			t.Errorf("smbUser(%q) = %q, %q; want %q, %q", username, domain, user, want[0], want[1])
		}
	}
}

func TestSharesShown(t *testing.T) {
	got := sharesShown([]string{"public", "IPC$", "ADMIN$", "C$", "Backups", "", "media"})
	if want := []string{"Backups", "media", "public"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the shares shown are %q, want %q", got, want)
	}
}

func TestSMBErrorsAreThoseOfFS(t *testing.T) {
	for code, want := range map[uint32]error{
		statusObjectNameNotFound:  fs.ErrNotExist,
		statusObjectPathNotFound:  fs.ErrNotExist,
		statusNoSuchFile:          fs.ErrNotExist,
		statusBadNetworkName:      fs.ErrNotExist,
		statusAccessDenied:        fs.ErrPermission,
		statusNetworkAccessDenied: fs.ErrPermission,
		statusObjectNameCollision: fs.ErrExist,
	} {
		err := smbErr(&os.PathError{Op: "open", Path: `in\a.txt`, Err: &smb2.ResponseError{Code: code}})
		if !errors.Is(err, want) {
			t.Errorf("status %#x is %v, not %v", code, err, want)
		}
		if !strings.Contains(err.Error(), "in/a.txt") {
			t.Errorf("status %#x lost the path: %v", code, err)
		}
	}
	err := smbErr(&os.LinkError{Op: "rename", Old: `a`, New: `b`, Err: &smb2.ResponseError{Code: statusAccessDenied}})
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("a refused rename is %v", err)
	}
	err = smbErr(&os.PathError{Op: "remove", Path: "in", Err: &smb2.ResponseError{Code: statusDirectoryNotEmpty}})
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a folder that is not empty is %v", err)
	}
	if err := smbErr(&smb2.ResponseError{Code: 0xC0000001}); errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		t.Errorf("an unknown status is %v", err)
	}
}

func TestSMBFailure(t *testing.T) {
	login := Login{Type: config.ServerTypeSMB, Host: "files.example.com", Port: 445, Username: `CORP\alice`}
	if err := smbFailure(login, &smb2.ResponseError{Code: statusLogonFailure}); err.Error() != `files.example.com refused the login of CORP\alice` {
		t.Errorf("a wrong password reads %v", err)
	}
	if err := smbFailure(login, &smb2.ResponseError{Code: statusPasswordExpired}); !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired password reads %v", err)
	}
	if err := smbFailure(login, errors.New("connection refused")); err.Error() != "files.example.com: connection refused" {
		t.Errorf("another failure reads %v", err)
	}
}

func TestSMBRefusesWhatIsNotInAShare(t *testing.T) {
	s := &smbFS{}
	for name, err := range map[string]error{
		"a file at the top":     func() error { _, err := s.Put("/a.txt", strings.NewReader(""), 0); return err }(),
		"a folder at the top":   s.Mkdir("/public"),
		"a share removed":       s.RemoveDir("/public"),
		"a share renamed":       s.Rename("/public", "/other"),
		"a file renamed to top": s.Rename("/public/a.txt", "/a.txt"),
	} {
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("%s answered %v", name, err)
		}
	}
	if err := s.Rename("/public/a.txt", "/other/a.txt"); err == nil || !strings.Contains(err.Error(), "another share") {
		t.Errorf("a move to another share answered %v", err)
	}
	if p, _ := s.Resolve(""); p != "/" {
		t.Errorf("the login starts at %q", p)
	}
	if info, err := s.Stat("/"); err != nil || !info.IsDir() {
		t.Errorf("the top is %v, %v", info, err)
	}
}

func TestSMBHostThatIsNotThere(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	login := Login{Type: config.ServerTypeSMB, Host: "127.0.0.1", Port: port, Username: "alice", Password: "secret"}
	err = Test(context.Background(), login, config.Default().General.SSH)
	if err == nil || !strings.HasPrefix(err.Error(), login.Shown()+": ") {
		t.Errorf("a host that is not there answered %v", err)
	}
}

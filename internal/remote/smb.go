package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// An SMB host, a Windows file server or a Samba, is reached by SMB 2 or 3 and
// logged in to by NTLM with the username and the password; a username of
// DOMAIN\user logs in to that domain. Its files are in shares, so the top of
// the host, /, lists the shares the login may see as folders, and
// /<share>/<path> is a file or a folder in one. The shares of the
// administrator and of the host itself, those whose names end in $, are left
// out of the list; they are still reached by their path. A host shows no key
// that is accepted first: what it is is only known by the login it takes.

// NT status codes an SMB host answers with that go-fs tells apart, from
// [MS-ERREF] 2.3.1.
const (
	statusNoSuchFile          = 0xC000000F
	statusAccessDenied        = 0xC0000022
	statusObjectNameNotFound  = 0xC0000034
	statusObjectNameCollision = 0xC0000035
	statusObjectPathNotFound  = 0xC000003A
	statusLogonFailure        = 0xC000006D
	statusAccountRestriction  = 0xC000006E
	statusPasswordExpired     = 0xC0000071
	statusAccountDisabled     = 0xC0000072
	statusFileIsADirectory    = 0xC00000BA
	statusNetworkAccessDenied = 0xC00000CA
	statusBadNetworkName      = 0xC00000CC
	statusDirectoryNotEmpty   = 0xC0000101
	statusNotADirectory       = 0xC0000103
	statusAccountLockedOut    = 0xC0000234
)

// smbStatus is what an NT status the host answered means, in the words a page
// shows, and the error of io/fs it is, if any.
type smbStatus struct {
	text string
	is   error
}

var smbStatuses = map[uint32]smbStatus{
	statusNoSuchFile:          {"file does not exist", fs.ErrNotExist},
	statusObjectNameNotFound:  {"file does not exist", fs.ErrNotExist},
	statusObjectPathNotFound:  {"file does not exist", fs.ErrNotExist},
	statusBadNetworkName:      {"the host has no such share", fs.ErrNotExist},
	statusAccessDenied:        {"permission denied", fs.ErrPermission},
	statusNetworkAccessDenied: {"permission denied", fs.ErrPermission},
	statusObjectNameCollision: {"file already exists", fs.ErrExist},
	statusDirectoryNotEmpty:   {"the folder is not empty", nil},
	statusNotADirectory:       {"not a folder", nil},
	statusFileIsADirectory:    {"is a folder", nil},
}

// smbStatusError is an NT status the host answered, which is the error of
// io/fs it means.
type smbStatusError struct {
	code   uint32
	status smbStatus
}

func (e smbStatusError) Error() string        { return e.status.text }
func (e smbStatusError) Is(target error) bool { return e.status.is != nil && target == e.status.is }

// smbErr makes what the host answered an error of io/fs where it is one, in
// place inside the *os.PathError or *os.LinkError go-smb2 wraps it in, so
// that the path stays named.
func smbErr(err error) error {
	switch e := err.(type) {
	case nil:
		return nil
	case *os.PathError:
		return &os.PathError{Op: e.Op, Path: smbPath(e.Path), Err: smbErr(e.Err)}
	case *os.LinkError:
		return &os.LinkError{Op: e.Op, Old: smbPath(e.Old), New: smbPath(e.New), Err: smbErr(e.Err)}
	case *smb2.ResponseError:
		if status, ok := smbStatuses[e.Code]; ok {
			return smbStatusError{code: e.Code, status: status}
		}
	}
	return err
}

// smbPath is a path go-smb2 named, with the slashes of the rest of go-fs.
func smbPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// smbCode is the NT status an error is, 0 for one that is not.
func smbCode(err error) uint32 {
	var response *smb2.ResponseError
	if errors.As(err, &response) {
		return response.Code
	}
	var status smbStatusError
	if errors.As(err, &status) {
		return status.code
	}
	return 0
}

// smbUser splits a username into the domain and the user, DOMAIN\user or
// user@domain naming one. A user@domain is handed on as it is, as NTLM takes
// it that way too.
func smbUser(username string) (domain, user string) {
	if domain, user, ok := strings.Cut(username, `\`); ok {
		return domain, user
	}
	return "", username
}

// smbFailure says why an SMB host could not be reached or logged in to, in
// the words a page shows.
func smbFailure(l Login, err error) error {
	switch smbCode(err) {
	case statusLogonFailure:
		return fmt.Errorf("%s refused the login of %s", l.Shown(), l.Username)
	case statusAccountDisabled, statusAccountLockedOut, statusAccountRestriction:
		return fmt.Errorf("%s refused the login of %s: the account is disabled, locked or restricted", l.Shown(), l.Username)
	case statusPasswordExpired:
		return fmt.Errorf("%s refused the login of %s: the password has expired", l.Shown(), l.Username)
	}
	return fmt.Errorf("%s: %w", l.Shown(), smbErr(err))
}

// smbFS is a host logged in to by SMB.
type smbFS struct {
	ctx     context.Context
	conn    net.Conn
	session *smb2.Session
	// shares are those mounted, by their name as it was asked for, whatever
	// its case
	mu     sync.Mutex
	shares map[string]*smb2.Share
}

// openSMB dials a host and logs in to it, within HandshakeTimeout. The
// connection is cut as soon as ctx ends, which is what stops whatever waits
// on it.
func openSMB(ctx context.Context, l Login) (FS, error) {
	dialCtx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", l.Address())
	if err != nil {
		return nil, smbFailure(l, err)
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	domain, user := smbUser(l.Username)
	smb := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: l.Password, Domain: domain}}
	session, err := smb.DialContext(dialCtx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, smbFailure(l, err)
	}
	return &smbFS{ctx: ctx, conn: conn, session: session.WithContext(ctx), shares: map[string]*smb2.Share{}}, nil
}

// share is a share of the host, mounted the first time it is asked for.
func (s *smbFS) share(name string) (*smb2.Share, error) {
	key := strings.ToLower(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if share, ok := s.shares[key]; ok {
		return share, nil
	}
	share, err := s.session.Mount(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: "/" + name, Err: smbErr(err)}
	}
	share = share.WithContext(s.ctx)
	s.shares[key] = share
	return share, nil
}

// in is the share a clean absolute path is in, and the path in it.
func (s *smbFS) in(p string) (*smb2.Share, string, error) {
	name, rest := split(p)
	share, err := s.share(name)
	return share, rest, err
}

// inShare refuses a path that is not in a share, which what writes cannot
// be: a share is created, renamed and removed on the host itself.
func inShare(p, what string) error {
	if _, rest := split(p); rest == "" {
		return fmt.Errorf("%s: %w", what, fs.ErrPermission)
	}
	return nil
}

// smbFolder is the top of the host, or a share, as a folder.
type smbFolder struct{ name string }

func (i smbFolder) Name() string       { return i.name }
func (i smbFolder) Size() int64        { return 0 }
func (i smbFolder) ModTime() time.Time { return time.Time{} }
func (i smbFolder) IsDir() bool        { return true }
func (i smbFolder) Sys() any           { return nil }
func (i smbFolder) Mode() fs.FileMode  { return fs.ModeDir | 0o755 }

// sharesShown are the shares of a list that are listed: not those whose name
// ends in $, which are of the administrator and of the host itself, sorted
// whatever their case.
func sharesShown(names []string) []string {
	shown := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" && !strings.HasSuffix(name, "$") {
			shown = append(shown, name)
		}
	}
	sort.Slice(shown, func(i, j int) bool { return strings.ToLower(shown[i]) < strings.ToLower(shown[j]) })
	return shown
}

func (s *smbFS) Resolve(p string) (string, error) {
	return path.Clean("/" + p), nil
}

func (s *smbFS) Stat(p string) (fs.FileInfo, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		return smbFolder{name: "/"}, nil
	}
	share, rest, err := s.in(p)
	if err != nil {
		return nil, err
	}
	info, err := share.Stat(rest)
	if err != nil {
		return nil, smbErr(err)
	}
	if rest == "" {
		// the top of a share is named after the share
		return smbFolder{name: path.Base(p)}, nil
	}
	return info, nil
}

// Lstat is Stat: a link on an SMB host is followed by the host, and go-smb2
// only reads those of Windows.
func (s *smbFS) Lstat(p string) (fs.FileInfo, error) { return s.Stat(p) }

func (s *smbFS) ReadDir(p string) ([]fs.FileInfo, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		names, err := s.session.ListSharenames()
		if err != nil {
			return nil, fmt.Errorf("the host does not list its shares; open one by its path: %w", smbErr(err))
		}
		shown := sharesShown(names)
		infos := make([]fs.FileInfo, 0, len(shown))
		for _, name := range shown {
			infos = append(infos, smbFolder{name: name})
		}
		return infos, nil
	}
	share, rest, err := s.in(p)
	if err != nil {
		return nil, err
	}
	infos, err := share.ReadDir(rest)
	if err != nil {
		return nil, smbErr(err)
	}
	found := infos[:0]
	for _, info := range infos {
		if name := info.Name(); name != "." && name != ".." {
			found = append(found, info)
		}
	}
	return found, nil
}

func (s *smbFS) Open(p string) (io.ReadSeekCloser, error) {
	p = path.Clean("/" + p)
	if err := inShare(p, "a share is a folder"); err != nil {
		return nil, err
	}
	share, rest, err := s.in(p)
	if err != nil {
		return nil, err
	}
	f, err := share.Open(rest)
	if err != nil {
		return nil, smbErr(err)
	}
	return f, nil
}

// Put writes the file under a hidden name beside where it goes and renames it
// once all of it is there, so that a write that is stopped or fails never
// leaves half a file under the real name. What was written is taken away
// again when anything fails.
func (s *smbFS) Put(final string, body io.Reader, _ int64) (int64, error) {
	final = path.Clean("/" + final)
	if err := inShare(final, "a file goes into a share"); err != nil {
		return 0, err
	}
	share, rest, err := s.in(final)
	if err != nil {
		return 0, err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return 0, err
	}
	part := path.Join(path.Dir(rest), "."+path.Base(rest)+".go-fs-"+hex.EncodeToString(suffix)+".part")
	out, err := share.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, smbErr(err)
	}
	written, err := out.ReadFrom(body)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = smbReplace(share, part, rest)
	}
	if err != nil {
		_ = share.Remove(part)
	}
	return written, smbErr(err)
}

// smbReplace puts a file that was written in place, removing the file that is
// there first, since a rename on SMB does not replace one. A folder that is
// there is left as it is, and the file is not put.
func smbReplace(share *smb2.Share, from, to string) error {
	info, err := share.Stat(to)
	switch {
	case err != nil && errors.Is(smbErr(err), fs.ErrNotExist):
	case err != nil:
		return err
	case info.IsDir():
		return fmt.Errorf("%s is a folder", path.Base(to))
	default:
		if err := share.Remove(to); err != nil {
			return err
		}
	}
	return share.Rename(from, to)
}

func (s *smbFS) Mkdir(p string) error {
	p = path.Clean("/" + p)
	if err := inShare(p, "a share is created on the host itself"); err != nil {
		return err
	}
	share, rest, err := s.in(p)
	if err != nil {
		return err
	}
	return smbErr(share.Mkdir(rest, 0o755))
}

// Rename moves within a share: SMB has no move from one share to another.
func (s *smbFS) Rename(from, to string) error {
	from, to = path.Clean("/"+from), path.Clean("/"+to)
	if err := inShare(from, "a share is renamed on the host itself"); err != nil {
		return err
	}
	if err := inShare(to, "a file goes into a share"); err != nil {
		return err
	}
	fromShare, _ := split(from)
	toShare, _ := split(to)
	if !strings.EqualFold(fromShare, toShare) {
		return fmt.Errorf("%s cannot be moved to another share", from)
	}
	share, rest, err := s.in(from)
	if err != nil {
		return err
	}
	_, toRest := split(to)
	return smbErr(share.Rename(rest, toRest))
}

// Remove removes a file. go-smb2 removes a file and a folder with nothing in
// it alike, so a folder is refused here.
func (s *smbFS) Remove(p string) error {
	return s.remove(p, false)
}

// RemoveDir removes a folder with nothing in it; the host refuses one that
// has something.
func (s *smbFS) RemoveDir(p string) error {
	return s.remove(p, true)
}

func (s *smbFS) remove(p string, folder bool) error {
	p = path.Clean("/" + p)
	if err := inShare(p, "a share is removed on the host itself"); err != nil {
		return err
	}
	share, rest, err := s.in(p)
	if err != nil {
		return err
	}
	info, err := share.Stat(rest)
	if err != nil {
		return smbErr(err)
	}
	switch {
	case folder && !info.IsDir():
		return fmt.Errorf("%s is not a folder", p)
	case !folder && info.IsDir():
		return fmt.Errorf("%s is a folder", p)
	}
	return smbErr(share.Remove(rest))
}

func (s *smbFS) Close() error {
	s.mu.Lock()
	for _, share := range s.shares {
		_ = share.Umount()
	}
	s.shares = nil
	s.mu.Unlock()
	err := s.session.Logoff()
	if closeErr := s.conn.Close(); err == nil {
		err = closeErr
	}
	return err
}

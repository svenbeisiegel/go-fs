package sftp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"

	"go-fs/internal/vfs"
)

// session is the state one authenticated client has while its SFTP subsystem
// runs: which account it is, and where its transfers are logged. The account
// itself is looked up per request rather than held, see account below.
type session struct {
	server *Server
	name   string
	log    *slog.Logger
}

// account resolves the account this session belongs to against the
// configuration as it stands right now.
//
// It is deliberately not held from the handshake: an account is checked again
// on every request, so a right taken away by a reload applies to the next
// request the client makes, and an account that was removed can do nothing at
// all rather than keeping what it had until it disconnects.
func (s *session) account() (*account, error) {
	user := s.server.settings().users[s.name]
	if user == nil {
		s.log.Info("sftp account is no longer configured, refusing the request")
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	return user, nil
}

func (s *Server) handlers(name string, log *slog.Logger) sftp.Handlers {
	sess := &session{server: s, name: name, log: log}
	return sftp.Handlers{
		FileGet:  sess,
		FilePut:  sess,
		FileCmd:  sess,
		FileList: sess,
	}
}

// resolve maps a client path onto the filesystem. Client paths are absolute,
// so they are resolved against the root of the virtual filesystem; the same
// vfs the FTP and TFTP servers use rejects ".." and symbolic links that leave
// the base folder.
func (s *session) resolve(user *account, clientPath string) (vfs.Target, error) {
	target := user.root.Resolve("/", clientPath)
	if !target.Valid {
		s.log.Debug("sftp path refused", "path", clientPath)
		return target, sftp.ErrSSHFxPermissionDenied
	}
	return target, nil
}

// trace is the protocol trace, the counterpart of the FTP server's "ftp <"
// record: one line per request naming the method and the path it is about.
func (s *session) trace(r *sftp.Request) {
	if r.Target != "" {
		s.log.Debug("sftp <", "method", r.Method, "path", r.Filepath, "target", r.Target)
		return
	}
	s.log.Debug("sftp <", "method", r.Method, "path", r.Filepath)
}

// denied records a request the account's rights do not cover. The client is
// told "permission denied" and nothing more, so this is the only place that
// says which right it was.
func (s *session) denied(r *sftp.Request, right string) error {
	s.log.Debug("sftp request refused, the account lacks the right",
		"method", r.Method, "path", r.Filepath, "right", right)
	return sftp.ErrSSHFxPermissionDenied
}

// failed records an operating system error on the way to the client. The
// library maps it to an SFTP status, which keeps the message but not the
// detail an operator needs, such as which file it was.
func (s *session) failed(r *sftp.Request, err error) error {
	s.log.Debug("sftp request failed", "method", r.Method, "path", r.Filepath, "error", err)
	return err
}

// Fileread serves a read, which needs the retrieve right.
func (s *session) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	s.trace(r)
	user, err := s.account()
	if err != nil {
		return nil, err
	}
	if !user.perms.FileRetrieve {
		return nil, s.denied(r, "allowUserFileRetrieve")
	}
	target, err := s.resolve(user, r.Filepath)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(target.Path)
	if err != nil {
		return nil, s.failed(r, err)
	}
	return &countingReader{file: file, session: s, virtual: target.Virtual, started: time.Now()}, nil
}

// Filewrite serves a write. A new file needs the create right and an existing
// one the overwrite right, the same split the FTP STOR command makes.
func (s *session) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	s.trace(r)
	user, err := s.account()
	if err != nil {
		return nil, err
	}
	target, err := s.resolve(user, r.Filepath)
	if err != nil {
		return nil, err
	}

	_, statErr := os.Stat(target.Path)
	exists := statErr == nil
	if exists && !user.perms.FileOverwrite {
		return nil, s.denied(r, "allowUserFileOverwrite")
	}
	if !exists && !user.perms.FileCreate {
		return nil, s.denied(r, "allowUserFileCreate")
	}

	// The library hands us an io.WriterAt and the client counts its own
	// offsets from zero, so an append is served by shifting those offsets past
	// what the file already holds. O_APPEND itself cannot be used: the
	// standard library refuses WriteAt on a file opened with it.
	var base int64
	flags := os.O_WRONLY | os.O_CREATE
	pflags := r.Pflags()
	if pflags.Trunc {
		flags |= os.O_TRUNC
	}
	if pflags.Excl {
		flags |= os.O_EXCL
	}
	if pflags.Append && exists {
		info, err := os.Stat(target.Path)
		if err != nil {
			return nil, s.failed(r, err)
		}
		base = info.Size()
	}

	file, err := os.OpenFile(target.Path, flags, 0o644)
	if err != nil {
		return nil, s.failed(r, err)
	}
	return &countingWriter{file: file, session: s, virtual: target.Virtual, base: base, started: time.Now()}, nil
}

// Filecmd serves everything that changes the folder rather than a file's
// content. Each method needs the right that matches what it does, and a rename
// needs both, because it creates one name and removes another.
func (s *session) Filecmd(r *sftp.Request) error {
	s.trace(r)
	user, err := s.account()
	if err != nil {
		return err
	}
	target, err := s.resolve(user, r.Filepath)
	if err != nil {
		return err
	}

	switch r.Method {
	case "Remove":
		if !user.perms.FileDelete || target.IsRoot() {
			return s.denied(r, "allowUserFileDelete")
		}
		info, err := os.Stat(target.Path)
		if err != nil {
			return s.failed(r, err)
		}
		if info.IsDir() {
			// removing a folder is Rmdir, which has its own right
			s.log.Debug("sftp remove refused, the path is a folder", "path", target.Virtual)
			return sftp.ErrSSHFxFailure
		}
		if err := os.Remove(target.Path); err != nil {
			return s.failed(r, err)
		}
		// every removal is recorded, as the HTTP server does: a file that is
		// gone is the question the log is most often asked
		s.log.Info("sftp delete", "file", target.Virtual, "bytes", info.Size())
		return nil

	case "Rmdir":
		// the base folder itself is not the client's to remove: it would take
		// the served tree with it and leave every path invalid
		if !user.perms.FolderDelete || target.IsRoot() {
			return s.denied(r, "allowUserFolderDelete")
		}
		info, err := os.Stat(target.Path)
		if err != nil {
			return s.failed(r, err)
		}
		if !info.IsDir() {
			s.log.Debug("sftp rmdir refused, the path is not a folder", "path", target.Virtual)
			return sftp.ErrSSHFxFailure
		}
		// rmdir removes an empty folder, here as everywhere else: a tree of
		// files is only deleted by an account that may delete files, one by one
		if err := os.Remove(target.Path); err != nil {
			return s.failed(r, err)
		}
		s.log.Info("sftp folder delete", "folder", target.Virtual)
		return nil

	case "Mkdir":
		if !user.perms.FolderCreate {
			return s.denied(r, "allowUserFolderCreate")
		}
		if _, err := os.Stat(target.Path); err == nil {
			s.log.Debug("sftp mkdir refused, the path exists", "path", target.Virtual)
			return sftp.ErrSSHFxFailure
		}
		if err := os.MkdirAll(target.Path, 0o755); err != nil {
			return s.failed(r, err)
		}
		s.log.Info("sftp mkdir", "folder", target.Virtual)
		return nil

	case "Rename", "PosixRename":
		if !user.perms.FileCreate || !user.perms.FileDelete || target.IsRoot() {
			return s.denied(r, "allowUserFileCreate and allowUserFileDelete")
		}
		destination, err := s.resolve(user, r.Target)
		if err != nil {
			return err
		}
		if destination.IsRoot() {
			return s.denied(r, "the base folder is not a rename target")
		}
		if r.Method == "Rename" {
			// plain rename must not clobber, POSIX rename may
			if _, err := os.Stat(destination.Path); err == nil {
				s.log.Debug("sftp rename refused, the destination exists",
					"from", target.Virtual, "to", destination.Virtual)
				return sftp.ErrSSHFxFailure
			}
		}
		if err := os.Rename(target.Path, destination.Path); err != nil {
			return s.failed(r, err)
		}
		s.log.Info("sftp rename", "from", target.Virtual, "to", destination.Virtual)
		return nil

	case "Setstat", "Fsetstat":
		// changing mode, times or size is a change to the file, so it needs
		// the same right as MFMT and SITE CHMOD do over FTP
		if !user.perms.FileOverwrite || target.IsRoot() {
			return s.denied(r, "allowUserFileOverwrite")
		}
		if err := s.setstat(target, r); err != nil {
			return s.failed(r, err)
		}
		return nil

	case "Symlink", "Link":
		// links are never created: they are the one thing that could point out
		// of the base folder, and nothing needs them here
		s.log.Debug("sftp request unsupported", "method", r.Method, "path", r.Filepath)
		return sftp.ErrSSHFxOpUnsupported
	}
	s.log.Debug("sftp request unsupported", "method", r.Method, "path", r.Filepath)
	return sftp.ErrSSHFxOpUnsupported
}

// setstat applies the attributes a SETSTAT request carries.
func (s *session) setstat(target vfs.Target, r *sftp.Request) error {
	attrs := r.Attributes()
	flags := r.AttrFlags()
	if flags.Size {
		if err := os.Truncate(target.Path, int64(attrs.Size)); err != nil {
			return err
		}
		s.log.Debug("sftp truncate", "file", target.Virtual, "size", attrs.Size)
	}
	if flags.Permissions {
		if err := os.Chmod(target.Path, attrs.FileMode().Perm()); err != nil {
			return err
		}
		s.log.Info("sftp chmod", "file", target.Virtual,
			"mode", fmt.Sprintf("%04o", attrs.FileMode().Perm()))
	}
	if flags.Acmodtime {
		if err := os.Chtimes(target.Path, attrs.AccessTime(), attrs.ModTime()); err != nil {
			return err
		}
		s.log.Debug("sftp modification time set", "file", target.Virtual, "time", attrs.ModTime())
	}
	// ownership is not ours to change, and a request to do so is not an error
	if flags.UidGid {
		s.log.Debug("sftp ownership change ignored", "file", target.Virtual)
	}
	return nil
}

// Filelist serves listing and stat, which every account may do, exactly as
// LIST needs no right over FTP.
func (s *session) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	s.trace(r)
	user, err := s.account()
	if err != nil {
		return nil, err
	}
	target, err := s.resolve(user, r.Filepath)
	if err != nil {
		return nil, err
	}

	switch r.Method {
	case "List":
		entries, err := os.ReadDir(target.Path)
		if err != nil {
			return nil, s.failed(r, err)
		}
		infos := make([]os.FileInfo, 0, len(entries))
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				// a file that vanished between the read and the stat is
				// skipped rather than failing the whole listing
				continue
			}
			infos = append(infos, info)
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() })
		return listerAt(infos), nil

	case "Stat":
		info, err := os.Stat(target.Path)
		if err != nil {
			return nil, s.failed(r, err)
		}
		return listerAt{info}, nil

	case "Readlink":
		// the client is told where a link points only if the target stays
		// inside the base folder
		destination, err := os.Readlink(target.Path)
		if err != nil {
			return nil, s.failed(r, err)
		}
		// a relative target is relative to the folder the link sits in; an
		// absolute one is already a path in the served tree
		resolved := user.root.Resolve(path.Dir(target.Virtual), destination)
		if !resolved.Valid {
			s.log.Debug("sftp readlink refused, the link leaves the base folder",
				"path", target.Virtual, "destination", destination)
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		info, err := os.Stat(resolved.Path)
		if err != nil {
			return nil, s.failed(r, err)
		}
		return listerAt{renamed{FileInfo: info, name: resolved.Virtual}}, nil
	}
	s.log.Debug("sftp request unsupported", "method", r.Method, "path", r.Filepath)
	return nil, sftp.ErrSSHFxOpUnsupported
}

// listerAt serves a directory listing in the chunks the client asks for.
type listerAt []os.FileInfo

func (l listerAt) ListAt(target []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(target, l[offset:])
	if n < len(target) {
		return n, io.EOF
	}
	return n, nil
}

// renamed reports a different name for a FileInfo, which Readlink needs.
type renamed struct {
	os.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }

// countingReader and countingWriter carry a transfer's byte count so that the
// log record can report it. The request server closes handles that implement
// io.Closer, which is where the record is written.
type countingReader struct {
	file    *os.File
	session *session
	virtual string
	started time.Time
	bytes   atomic.Int64
	// failure is the first read error, if there was one, so the record can
	// say the transfer did not go as it should have
	failure failure
}

func (c *countingReader) ReadAt(b []byte, offset int64) (int, error) {
	n, err := c.file.ReadAt(b, offset)
	c.bytes.Add(int64(n))
	if err != nil && !errors.Is(err, io.EOF) {
		c.failure.record(err)
	}
	return n, err
}

func (c *countingReader) Close() error {
	err := c.file.Close()
	if failed := c.failure.get(); failed != nil {
		c.session.log.Info("sftp download failed", "file", c.virtual, "bytes", c.bytes.Load(),
			"took", time.Since(c.started).Round(time.Millisecond), "error", failed)
		return err
	}
	c.session.log.Info("sftp download", "file", c.virtual, "bytes", c.bytes.Load(),
		"took", time.Since(c.started).Round(time.Millisecond))
	return err
}

type countingWriter struct {
	file    *os.File
	session *session
	virtual string
	started time.Time
	// base is what an append starts from, zero for every other open
	base    int64
	bytes   atomic.Int64
	failure failure
}

func (c *countingWriter) WriteAt(b []byte, offset int64) (int, error) {
	n, err := c.file.WriteAt(b, c.base+offset)
	c.bytes.Add(int64(n))
	if err != nil {
		c.failure.record(err)
	}
	return n, err
}

func (c *countingWriter) Close() error {
	err := c.file.Close()
	if failed := c.failure.get(); failed != nil || err != nil {
		// a write that failed, or a close that did, means the file on disk is
		// not what the client sent; a disk that is full is the usual reason
		c.session.log.Warn("sftp upload failed", "file", c.virtual, "bytes", c.bytes.Load(),
			"took", time.Since(c.started).Round(time.Millisecond),
			"error", errors.Join(failed, err))
		return err
	}
	c.session.log.Info("sftp upload", "file", c.virtual, "bytes", c.bytes.Load(),
		"took", time.Since(c.started).Round(time.Millisecond))
	return err
}

// failure keeps the first error of a transfer. The request server calls
// ReadAt and WriteAt from several goroutines, so it is locked.
type failure struct {
	mu  sync.Mutex
	err error
}

func (f *failure) record(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil {
		f.err = err
	}
}

func (f *failure) get() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

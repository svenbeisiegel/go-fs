package remote

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"go-fs/internal/config"
)

// FS is a host once it was logged in to, whatever the protocol: what the file
// listing sends to and the page of a stored server browses. Paths are of the
// host, with slashes, and absolute once Resolve made them so. What goes wrong
// wraps fs.ErrNotExist for a path that is not there and fs.ErrPermission for
// one the login may not reach, which is what a page tells apart.
type FS interface {
	// Resolve makes a path absolute and clean, "" being where the login
	// starts.
	Resolve(p string) (string, error)
	// Stat is what a path is, a link being what it leads to.
	Stat(p string) (fs.FileInfo, error)
	// Lstat is what a path is, a link being the link.
	Lstat(p string) (fs.FileInfo, error)
	// ReadDir lists a folder, a link being what it leads to, without . and
	// ...
	ReadDir(p string) ([]fs.FileInfo, error)
	// Open reads a file, from wherever it is sought to.
	Open(p string) (io.ReadSeekCloser, error)
	// Put writes a file whole, replacing what is there, so that nothing is
	// found under its name before all of it is there. size is how long the
	// body is, -1 when that is not known. It reports how much was written.
	Put(p string, body io.Reader, size int64) (int64, error)
	// Mkdir creates a folder in one that is there.
	Mkdir(p string) error
	// Rename moves a file or a folder to a name that is free.
	Rename(from, to string) error
	// Remove removes a file.
	Remove(p string) error
	// RemoveDir removes a folder with nothing in it, and fails on one that
	// has something.
	RemoveDir(p string) error
	// Close logs out.
	Close() error
}

// Open logs in to a host, with a login Checked read. Whatever it holds open
// lives as long as ctx, which is what stops a transfer that hangs.
func Open(ctx context.Context, l Login, sshCfg config.SSH) (FS, error) {
	switch l.Type {
	case config.ServerTypeSFTP:
		return openSFTPFS(ctx, l, sshCfg)
	case config.ServerTypeArtifactory:
		return openArtifactory(ctx, l), nil
	}
	return nil, fmt.Errorf("%q is not a protocol go-fs knows", l.Type)
}

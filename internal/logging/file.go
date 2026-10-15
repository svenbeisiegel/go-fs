package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// File is a log file that is rotated by size, for where there is no standard
// output that anything collects: a Windows service has none. When a record
// would take the file past MaxSize, the file becomes <path>.1, an older .1
// becomes .2 and so on, and the oldest beyond Keep is removed.
type File struct {
	mu   sync.Mutex
	path string
	file *os.File
	size int64
	// MaxSize is the size a file is rotated at, and Keep how many rotated
	// files are kept beside the current one.
	MaxSize int64
	Keep    int
}

// The defaults of OpenFile: 60 MiB of log at most, in six files.
const (
	defaultMaxSize = 10 << 20
	defaultKeep    = 5
)

// OpenFile opens the log file at path for appending, creating it and its
// folder when they do not exist. Nobody but the account go-fs runs as can read
// it: a debug trace names the paths and the accounts of every request.
func OpenFile(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f := &File{path: path, MaxSize: defaultMaxSize, Keep: defaultKeep}
	if err := f.open(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *File) open() error {
	file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	f.file, f.size = file, info.Size()
	return nil
}

// Write appends one record, rotating first when it would not fit. A record
// larger than MaxSize is still written whole, to a file of its own.
func (f *File) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return 0, os.ErrClosed
	}
	if f.size > 0 && f.size+int64(len(p)) > f.MaxSize {
		if err := f.rotate(); err != nil {
			// the record is not lost over a file that cannot be renamed, a
			// virus scanner holding it on Windows for instance: it goes on
			// growing until the next attempt succeeds
			fmt.Fprintf(os.Stderr, "go-fs: cannot rotate %s: %v\n", f.path, err)
		}
	}
	n, err := f.file.Write(p)
	f.size += int64(n)
	return n, err
}

// rotate shifts the rotated files up by one and starts a new file. The current
// file is closed first, which is what Windows needs to rename it.
func (f *File) rotate() error {
	if err := f.file.Close(); err != nil {
		return err
	}
	f.file = nil
	_ = os.Remove(fmt.Sprintf("%s.%d", f.path, f.Keep))
	for i := f.Keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", f.path, i), fmt.Sprintf("%s.%d", f.path, i+1))
	}
	renamed := os.Rename(f.path, f.path+".1")
	if f.Keep < 1 {
		_ = os.Remove(f.path + ".1")
	}
	if err := f.open(); err != nil {
		return err
	}
	return renamed
}

// Close closes the current file.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}

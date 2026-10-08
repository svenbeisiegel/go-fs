package remote

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"go-fs/internal/cryptomator"
)

// A server may keep its files in a vault of Cryptomator, a folder of it
// whose files and names are encrypted, so that whoever runs the server only
// ever sees ciphertext. vaultFS is such a server once the vault is unlocked:
// an FS over the FS of the server, whose paths are the cleartext ones of the
// vault, / being its top, and which encrypts what is written to it and
// decrypts what is read. The server sees the vault and nothing beside it.
// What the vault keeps where is in package cryptomator.

// errStopped is what the encryption of a file is stopped with once the
// server stopped reading it.
var errStopped = errors.New("the server stopped reading")

// errLink is a link of the vault, which go-fs neither follows nor makes.
var errLink = errors.New("links in a vault are not followed")

type vaultFS struct {
	inner FS
	// root is the folder of the server the vault is.
	root  string
	vault *cryptomator.Vault
	// dirs are the IDs of the folders of the vault looked up so far, by
	// their cleartext paths; looking one up reads the server once for each
	// folder on the way.
	mu   sync.Mutex
	dirs map[string]string
}

// maxSmallFile is the most a file the vault keeps for itself, a key file, an
// ID or a long name, may be.
const maxSmallFile = 1 << 20

// openVault unlocks the vault at root on the server, with password. The
// server is logged out of again when that fails.
func openVault(inner FS, root, password string) (opened FS, err error) {
	defer func() {
		if err != nil {
			_ = inner.Close()
		}
	}()
	root, err = inner.Resolve(root)
	if err != nil {
		return nil, err
	}
	vaultFile, err := readSmall(inner, path.Join(root, cryptomator.VaultFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s is not a vault: %w", root, err)
	}
	if err != nil {
		return nil, err
	}
	masterkey, err := readSmall(inner, path.Join(root, cryptomator.MasterkeyFile))
	if err != nil {
		return nil, err
	}
	vault, err := cryptomator.Unlock(vaultFile, masterkey, password)
	if err != nil {
		return nil, err
	}
	return &vaultFS{inner: inner, root: root, vault: vault, dirs: map[string]string{"/": ""}}, nil
}

// createVault makes a new vault at root on the server, a folder that is
// either not there yet or has nothing in it, and answers its recovery key.
func createVault(inner FS, root, password string) (string, error) {
	root, err := inner.Resolve(root)
	if err != nil {
		return "", err
	}
	if root == "/" {
		return "", errors.New("a vault is a folder of the server, not the top of it")
	}
	info, err := inner.Stat(root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := inner.Mkdir(root); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case !info.IsDir():
		return "", fmt.Errorf("%s is a file", root)
	default:
		entries, err := inner.ReadDir(root)
		if err != nil {
			return "", err
		}
		if len(entries) > 0 {
			return "", fmt.Errorf("%s holds files already: a vault is made in an empty folder", root)
		}
	}
	vault, files, recovery, err := cryptomator.Create(password)
	if err != nil {
		return "", err
	}
	v := &vaultFS{inner: inner, root: root, vault: vault, dirs: map[string]string{"/": ""}}
	if err := inner.Mkdir(path.Join(root, cryptomator.DataFolder)); err != nil {
		return "", err
	}
	if err := v.makeDirFolder(""); err != nil {
		return "", err
	}
	// the key file first, as the vault file is what says a vault is there
	for _, name := range []string{cryptomator.MasterkeyFile, cryptomator.VaultFile} {
		if _, err := inner.Put(path.Join(root, name), bytes.NewReader(files[name]), int64(len(files[name]))); err != nil {
			return "", err
		}
	}
	return recovery, nil
}

// readSmall reads a file the vault keeps for itself.
func readSmall(fsys FS, p string) ([]byte, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSmallFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSmallFile {
		return nil, fmt.Errorf("%s is too long to be what a vault keeps there", p)
	}
	return b, nil
}

// putSmall writes a file the vault keeps for itself.
func putSmall(fsys FS, p string, b []byte) error {
	_, err := fsys.Put(p, bytes.NewReader(b), int64(len(b)))
	return err
}

// node is what a file or a folder of the vault is kept as on the server.
type node struct {
	// path is where the node is on the server.
	path string
	// name is the encrypted name, which a shortened node keeps in NameFile.
	name  string
	short bool
}

// contents is where the content of the file of the node is.
func (n node) contents() string {
	if n.short {
		return path.Join(n.path, cryptomator.ContentsFile)
	}
	return n.path
}

// nodeOf is the node of the file or the folder named name in the folder of
// the vault with the ID dirID.
func (v *vaultFS) nodeOf(dirID, name string) node {
	encrypted := v.vault.EncryptName(name, dirID)
	kept, short := v.vault.Shorten(encrypted)
	return node{path: path.Join(v.dirFolder(dirID), kept), name: encrypted, short: short}
}

// dirFolder is the folder of the server the folder of the vault with the ID
// is kept in.
func (v *vaultFS) dirFolder(dirID string) string {
	return path.Join(v.root, v.vault.DirPath(dirID))
}

// vaultInfo is a file or a folder of the vault, under its cleartext name.
type vaultInfo struct {
	name string
	size int64
	mod  time.Time
	dir  bool
}

func (i vaultInfo) Name() string       { return i.name }
func (i vaultInfo) Size() int64        { return i.size }
func (i vaultInfo) ModTime() time.Time { return i.mod }
func (i vaultInfo) IsDir() bool        { return i.dir }
func (i vaultInfo) Sys() any           { return nil }
func (i vaultInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}

// clean is a cleartext path of the vault, absolute and clean.
func (v *vaultFS) clean(p string) string { return path.Clean("/" + p) }

// lookup finds the node of the file or the folder at p, and what it is; the
// top of the vault is a folder and has none.
func (v *vaultFS) lookup(p string) (node, vaultInfo, error) {
	if p == "/" {
		return node{}, vaultInfo{name: "/", dir: true}, nil
	}
	parentID, err := v.dirID(path.Dir(p))
	if err != nil {
		return node{}, vaultInfo{}, err
	}
	n := v.nodeOf(parentID, path.Base(p))
	info, err := v.inner.Stat(n.path)
	if err != nil {
		return node{}, vaultInfo{}, v.failure(p, err)
	}
	found, err := v.classify(p, n, info)
	return n, found, err
}

// classify is what a node is: a file is kept as a file, unless its name is
// shortened, a folder as a folder holding DirFile.
func (v *vaultFS) classify(p string, n node, info fs.FileInfo) (vaultInfo, error) {
	found := vaultInfo{name: path.Base(p), mod: info.ModTime()}
	if !info.IsDir() {
		found.size = cryptomator.CleartextSize(info.Size())
		if n.short || found.size < 0 {
			return vaultInfo{}, fmt.Errorf("%s: %w", p, cryptomator.ErrCorrupt)
		}
		return found, nil
	}
	if n.short {
		contents, err := v.inner.Stat(n.contents())
		if err == nil {
			found.size = cryptomator.CleartextSize(contents.Size())
			found.mod = contents.ModTime()
			return found, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return vaultInfo{}, v.failure(p, err)
		}
	}
	found.dir = true
	return found, nil
}

// dirID is the ID of the folder of the vault at p, read from the node of the
// folder, and from the folders above it, as far as they were not before.
func (v *vaultFS) dirID(p string) (string, error) {
	v.mu.Lock()
	id, ok := v.dirs[p]
	v.mu.Unlock()
	if ok {
		return id, nil
	}
	parentID, err := v.dirID(path.Dir(p))
	if err != nil {
		return "", err
	}
	n := v.nodeOf(parentID, path.Base(p))
	b, err := readSmall(v.inner, path.Join(n.path, cryptomator.DirFile))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", v.failure(p, err)
		}
		if _, linkErr := v.inner.Stat(path.Join(n.path, cryptomator.SymlinkFile)); linkErr == nil {
			return "", fmt.Errorf("%s: %w", p, errLink)
		}
		if info, statErr := v.inner.Stat(n.path); statErr == nil && (!info.IsDir() || n.short) {
			return "", fmt.Errorf("%s is not a folder", p)
		}
		return "", fmt.Errorf("%s: %w", p, fs.ErrNotExist)
	}
	id = string(b)
	v.mu.Lock()
	v.dirs[p] = id
	v.mu.Unlock()
	return id, nil
}

// forget drops what was looked up at p and below, once it moved or went.
func (v *vaultFS) forget(p string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for known := range v.dirs {
		if known == p || strings.HasPrefix(known, p+"/") {
			delete(v.dirs, known)
		}
	}
}

// failure is what went wrong on the server under the cleartext path, rather
// than the encrypted one the server names, as far as it is one of io/fs; nil
// when nothing did.
func (v *vaultFS) failure(p string, err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{fs.ErrNotExist, fs.ErrPermission, fs.ErrExist} {
		if errors.Is(err, known) {
			return fmt.Errorf("%s: %w", p, known)
		}
	}
	return fmt.Errorf("%s: %w", p, err)
}

func (v *vaultFS) Resolve(p string) (string, error) { return v.clean(p), nil }

func (v *vaultFS) Stat(p string) (fs.FileInfo, error) {
	p = v.clean(p)
	if p == "/" {
		info, err := v.inner.Stat(v.dirFolder(""))
		if err != nil {
			return nil, v.failure(p, err)
		}
		return vaultInfo{name: "/", mod: info.ModTime(), dir: true}, nil
	}
	_, info, err := v.lookup(p)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// Lstat is Stat: links of a vault are not followed, so there are none.
func (v *vaultFS) Lstat(p string) (fs.FileInfo, error) { return v.Stat(p) }

func (v *vaultFS) ReadDir(p string) ([]fs.FileInfo, error) {
	p = v.clean(p)
	id, err := v.dirID(p)
	if err != nil {
		return nil, err
	}
	entries, err := v.inner.ReadDir(v.dirFolder(id))
	if err != nil {
		return nil, v.failure(p, err)
	}
	found := make([]fs.FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, ok := v.entry(p, id, entry)
		if ok {
			found = append(found, info)
		}
	}
	return found, nil
}

// entry is what an entry of the folder of the vault with the ID dirID is,
// and false for one that is not a file or a folder of the vault: its own ID,
// a link, what another app left there, or a name that does not decrypt.
func (v *vaultFS) entry(folder, dirID string, entry fs.FileInfo) (fs.FileInfo, bool) {
	kept := entry.Name()
	n := node{path: path.Join(v.dirFolder(dirID), kept), name: kept}
	switch {
	case strings.HasSuffix(kept, cryptomator.Suffix) && kept != cryptomator.DirIDFile:
	case strings.HasSuffix(kept, cryptomator.ShortSuffix) && entry.IsDir():
		b, err := readSmall(v.inner, path.Join(n.path, cryptomator.NameFile))
		if err != nil {
			return nil, false
		}
		n.name, n.short = string(b), true
	default:
		return nil, false
	}
	name, err := v.vault.DecryptName(n.name, dirID)
	if err != nil {
		return nil, false
	}
	// a folder that is not shortened is taken for one without asking the
	// server what it holds, so that a listing is one request; a link among
	// them fails once it is gone into
	info, err := v.classify(path.Join(folder, name), n, entry)
	if err != nil {
		return nil, false
	}
	return info, true
}

// vaultFile is a file of the vault open for reading.
type vaultFile struct {
	*cryptomator.Reader
	io.Closer
}

func (v *vaultFS) Open(p string) (io.ReadSeekCloser, error) {
	p = v.clean(p)
	n, info, err := v.lookup(p)
	if err != nil {
		return nil, err
	}
	if info.dir {
		return nil, fmt.Errorf("%s is a folder", p)
	}
	in, err := v.inner.Open(n.contents())
	if err != nil {
		return nil, v.failure(p, err)
	}
	r, err := v.vault.NewReader(in, cryptomator.CiphertextSize(info.size))
	if err != nil {
		_ = in.Close()
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return vaultFile{Reader: r, Closer: in}, nil
}

// Put encrypts the file on its way to the server, which keeps it whole or
// not at all as it does any file; a shortened node is made first and the
// content put into it.
func (v *vaultFS) Put(p string, body io.Reader, size int64) (int64, error) {
	p = v.clean(p)
	if p == "/" {
		return 0, fmt.Errorf("%s is a folder", p)
	}
	parentID, err := v.dirID(path.Dir(p))
	if err != nil {
		return 0, err
	}
	n := v.nodeOf(parentID, path.Base(p))
	if info, err := v.inner.Stat(n.path); err == nil {
		existing, err := v.classify(p, n, info)
		if err != nil {
			return 0, err
		}
		if existing.dir {
			return 0, fmt.Errorf("%s is a folder", p)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, v.failure(p, err)
	} else if n.short {
		if err := v.inner.Mkdir(n.path); err != nil {
			return 0, v.failure(p, err)
		}
		if err := putSmall(v.inner, path.Join(n.path, cryptomator.NameFile), []byte(n.name)); err != nil {
			return 0, v.failure(p, err)
		}
	}
	return v.encrypt(p, n.contents(), body, size)
}

// encrypt writes body to the server at target, encrypted as it is read.
func (v *vaultFS) encrypt(p, target string, body io.Reader, size int64) (int64, error) {
	pr, pw := io.Pipe()
	var written int64
	done := make(chan error, 1)
	go func() {
		w, err := v.vault.NewWriter(pw)
		if err == nil {
			written, err = io.Copy(w, body)
			if closeErr := w.Close(); err == nil {
				err = closeErr
			}
		}
		_ = pw.CloseWithError(err)
		done <- err
	}()
	_, err := v.inner.Put(target, pr, cryptomator.CiphertextSize(size))
	// a server that gave up before the end leaves the encryption waiting;
	// what the body failed with is said rather than what the server did then
	_ = pr.CloseWithError(errStopped)
	if encryptErr := <-done; encryptErr != nil && !errors.Is(encryptErr, errStopped) {
		err = encryptErr
	}
	if err != nil {
		return written, v.failure(p, err)
	}
	return written, nil
}

// Mkdir makes the folder the content of the new folder is kept in before its
// node, so that one stopped half way leaves a folder nothing leads to rather
// than a node that leads nowhere.
func (v *vaultFS) Mkdir(p string) error {
	p = v.clean(p)
	if p == "/" {
		return fmt.Errorf("%s: %w", p, fs.ErrExist)
	}
	parentID, err := v.dirID(path.Dir(p))
	if err != nil {
		return err
	}
	n := v.nodeOf(parentID, path.Base(p))
	if _, err := v.inner.Stat(n.path); err == nil {
		return fmt.Errorf("%s: %w", p, fs.ErrExist)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return v.failure(p, err)
	}
	id, err := cryptomator.NewDirID()
	if err != nil {
		return err
	}
	if err := v.makeDirFolder(id); err != nil {
		return v.failure(p, err)
	}
	if err := v.inner.Mkdir(n.path); err != nil {
		return v.failure(p, err)
	}
	if n.short {
		if err := putSmall(v.inner, path.Join(n.path, cryptomator.NameFile), []byte(n.name)); err != nil {
			return v.failure(p, err)
		}
	}
	if err := putSmall(v.inner, path.Join(n.path, cryptomator.DirFile), []byte(id)); err != nil {
		return v.failure(p, err)
	}
	return nil
}

// makeDirFolder makes the folder the folder of the vault with the ID is kept
// in, with the one above it where that is not there yet, and its DirIDFile.
func (v *vaultFS) makeDirFolder(id string) error {
	folder := v.dirFolder(id)
	if err := v.inner.Mkdir(path.Dir(folder)); err != nil && !errors.Is(err, fs.ErrExist) {
		// a server may refuse a folder that is there with another error
		if info, statErr := v.inner.Stat(path.Dir(folder)); statErr != nil || !info.IsDir() {
			return err
		}
	}
	if err := v.inner.Mkdir(folder); err != nil {
		return err
	}
	var sealed bytes.Buffer
	w, err := v.vault.NewWriter(&sealed)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, id); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return putSmall(v.inner, path.Join(folder, cryptomator.DirIDFile), sealed.Bytes())
}

// Rename moves the node of the file or the folder under its new name in its
// new folder; what a folder holds stays where it is kept. A name that is
// shortened in one place and not in the other takes the node apart.
func (v *vaultFS) Rename(from, to string) error {
	from, to = v.clean(from), v.clean(to)
	if from == "/" || to == "/" {
		return fmt.Errorf("%s: %w", from, fs.ErrPermission)
	}
	src, info, err := v.lookup(from)
	if err != nil {
		return err
	}
	toParentID, err := v.dirID(path.Dir(to))
	if err != nil {
		return err
	}
	dst := v.nodeOf(toParentID, path.Base(to))
	if _, err := v.inner.Stat(dst.path); err == nil {
		return fmt.Errorf("%s: %w", to, fs.ErrExist)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return v.failure(to, err)
	}
	defer v.forget(from)
	switch {
	case src.short == dst.short || info.dir:
		// a folder is a node folder either way, which only gains or loses
		// its NameFile
		if err := v.inner.Rename(src.path, dst.path); err != nil {
			return v.failure(from, err)
		}
		if src.short && !dst.short {
			return v.failure(to, v.inner.Remove(path.Join(dst.path, cryptomator.NameFile)))
		}
		if dst.short {
			if err := putSmall(v.inner, path.Join(dst.path, cryptomator.NameFile), []byte(dst.name)); err != nil {
				return v.failure(to, err)
			}
		}
		return nil
	case dst.short:
		if err := v.inner.Mkdir(dst.path); err != nil {
			return v.failure(to, err)
		}
		if err := putSmall(v.inner, path.Join(dst.path, cryptomator.NameFile), []byte(dst.name)); err != nil {
			return v.failure(to, err)
		}
		return v.failure(from, v.inner.Rename(src.path, dst.contents()))
	default:
		if err := v.inner.Rename(src.contents(), dst.path); err != nil {
			return v.failure(from, err)
		}
		return v.removeNode(from, src)
	}
}

func (v *vaultFS) Remove(p string) error {
	p = v.clean(p)
	if p == "/" {
		return fmt.Errorf("%s is a folder", p)
	}
	n, info, err := v.lookup(p)
	if err != nil {
		return err
	}
	if info.dir {
		return fmt.Errorf("%s is a folder", p)
	}
	if !n.short {
		return v.failure(p, v.inner.Remove(n.path))
	}
	if err := v.inner.Remove(n.contents()); err != nil {
		return v.failure(p, err)
	}
	return v.removeNode(p, n)
}

// removeNode removes a node folder that has nothing in it besides what says
// what it is.
func (v *vaultFS) removeNode(p string, n node) error {
	for _, name := range []string{cryptomator.DirFile, cryptomator.NameFile} {
		if err := v.inner.Remove(path.Join(n.path, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return v.failure(p, err)
		}
	}
	return v.failure(p, v.inner.RemoveDir(n.path))
}

// RemoveDir removes the node of the folder before the folder its content is
// kept in, so that one stopped half way leaves a folder nothing leads to.
func (v *vaultFS) RemoveDir(p string) error {
	p = v.clean(p)
	if p == "/" {
		return fmt.Errorf("%s: %w", p, fs.ErrPermission)
	}
	n, info, err := v.lookup(p)
	if err != nil {
		return err
	}
	if !info.dir {
		return fmt.Errorf("%s is not a folder", p)
	}
	id, err := v.dirID(p)
	if err != nil {
		return err
	}
	folder := v.dirFolder(id)
	entries, err := v.inner.ReadDir(folder)
	if err != nil {
		return v.failure(p, err)
	}
	for _, entry := range entries {
		if entry.Name() != cryptomator.DirIDFile {
			return fmt.Errorf("%s: %w", p, errNotEmpty)
		}
	}
	if err := v.removeNode(p, n); err != nil {
		return err
	}
	v.forget(p)
	if err := v.inner.Remove(path.Join(folder, cryptomator.DirIDFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return v.failure(p, err)
	}
	return v.failure(p, v.inner.RemoveDir(folder))
}

func (v *vaultFS) Close() error { return v.inner.Close() }

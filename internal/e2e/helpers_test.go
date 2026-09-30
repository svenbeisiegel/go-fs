// Package e2e runs the HTTP, FTP and SFTP servers side by side over one served
// folder and one list of accounts, the way the supervisor does, and checks that
// the protocols agree: a right granted or withheld in [[users]] has to mean the
// same thing whichever protocol the client arrives by.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go-fs/internal/config"
	"go-fs/internal/ftp"
	"go-fs/internal/httpd"
	sftpd "go-fs/internal/sftp"
)

// allMethods makes every HTTP method need an account, so that an account's
// rights decide every request as they do over FTP and SFTP, where there is no
// such thing as a public request.
var allMethods = []string{"GET", "HEAD", "PUT", "DELETE", "POST", "MKCOL", "MOVE"}

// right names one of the allowUser* switches of an account.
type right int

const (
	retrieve right = iota
	create
	overwrite
	deleteFile
	folderCreate
	folderDelete
)

var allRights = []right{retrieve, create, overwrite, deleteFile, folderCreate, folderDelete}

func (r right) String() string {
	return [...]string{"retrieve", "create", "overwrite", "delete", "folderCreate", "folderDelete"}[r]
}

// account is an entry of [[users]] with a password, every protocol switched
// on and exactly the rights given.
func account(name, password string, rights ...right) config.User {
	user := config.User{
		Username: name,
		Password: password,
		HTTP:     true,
		FTP:      true,
		SFTP:     true,
		Paths:    []string{"^/.*"},
	}
	for _, r := range rights {
		switch r {
		case retrieve:
			user.AllowUserFileRetrieve = new(true)
		case create:
			user.AllowUserFileCreate = new(true)
		case overwrite:
			user.AllowUserFileOverwrite = new(true)
		case deleteFile:
			user.AllowUserFileDelete = new(true)
		case folderCreate:
			user.AllowUserFolderCreate = new(true)
		case folderDelete:
			user.AllowUserFolderDelete = new(true)
		}
	}
	return user
}

// passivePorts hands each cluster its own FTP passive range. The ftp package's
// own tests count up from 41000 and may run at the same time as these.
var passivePorts = struct {
	sync.Mutex
	next int
}{next: 47000}

func reservePassivePorts(count int) int {
	passivePorts.Lock()
	defer passivePorts.Unlock()
	port := passivePorts.next
	passivePorts.next += count + 1
	return port
}

// cluster is the three servers over one folder.
type cluster struct {
	base string
	cfg  config.Config
	http *httpd.Server
	ftp  *ftp.Server
	sftp *sftpd.Server
}

// newCluster starts HTTP, FTP and SFTP on ephemeral ports over one fresh
// folder with the given accounts. tune may change the configuration before
// the servers start.
func newCluster(t *testing.T, users []config.User, tune func(*config.Config)) *cluster {
	t.Helper()
	base := t.TempDir()

	cfg := config.Default()
	cfg.General.Basefolder = base
	cfg.Users = users

	cfg.HTTP.Enabled = true
	cfg.HTTP.Port = 0
	cfg.HTTP.Basefolder = base
	cfg.HTTP.UploadStagingFolder = t.TempDir()
	cfg.HTTP.LoginFailureDelay = 0
	cfg.HTTP.LoginAttempts = 0
	cfg.HTTP.MethodsRequireAuth = allMethods
	cfg.HTTP.PathsRequireAuth = nil

	cfg.FTP.Enabled = true
	cfg.FTP.Port = 0
	cfg.FTP.Basefolder = base
	cfg.FTP.MaxConnections = 8
	cfg.FTP.PassiveMinPort = reservePassivePorts(cfg.FTP.MaxConnections)
	cfg.FTP.PassiveMaxPort = cfg.FTP.PassiveMinPort + cfg.FTP.MaxConnections
	cfg.FTP.LoginFailureDelay = 0

	cfg.SFTP.Enabled = true
	cfg.SFTP.Port = 0
	cfg.SFTP.Basefolder = base
	cfg.SFTP.LoginFailureDelay = 0

	if tune != nil {
		tune(&cfg)
	}

	log := discardLogger()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	web, err := httpd.New(cfg.HTTP, cfg.HTTPS, cfg.HTTPUsers(), "", log)
	if err != nil {
		t.Fatalf("httpd.New: %v", err)
	}
	files, err := ftp.New(cfg.FTP, cfg.FTPS, cfg.FTPUsers(), log)
	if err != nil {
		t.Fatalf("ftp.New: %v", err)
	}
	secure, err := sftpd.New(cfg.SFTP, cfg.SFTPUsers(), log)
	if err != nil {
		t.Fatalf("sftp.New: %v", err)
	}
	for name, server := range map[string]interface {
		Start(context.Context) error
		Shutdown(context.Context) error
	}{"http": web, "ftp": files, "sftp": secure} {
		if err := server.Start(ctx); err != nil {
			t.Fatalf("%s Start: %v", name, err)
		}
		t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	}
	return &cluster{base: base, cfg: cfg, http: web, ftp: files, sftp: secure}
}

// reload hands a changed list of accounts to every server, as the supervisor
// does when the file changes.
func (c *cluster) reload(t *testing.T, users []config.User) {
	t.Helper()
	c.cfg.Users = users
	if err := c.http.Reload(c.cfg.HTTP, c.cfg.HTTPS, c.cfg.HTTPUsers()); err != nil {
		t.Fatalf("http Reload: %v", err)
	}
	if err := c.ftp.Reload(c.cfg.FTP, c.cfg.FTPS, c.cfg.FTPUsers()); err != nil {
		t.Fatalf("ftp Reload: %v", err)
	}
	if err := c.sftp.Reload(c.cfg.SFTP, c.cfg.SFTPUsers()); err != nil {
		t.Fatalf("sftp Reload: %v", err)
	}
}

func (c *cluster) path(name string) string {
	return filepath.Join(c.base, filepath.FromSlash(strings.TrimPrefix(name, "/")))
}

func (c *cluster) write(t *testing.T, name string, content []byte) {
	t.Helper()
	path := c.path(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (c *cluster) mkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(c.path(name), 0o755); err != nil {
		t.Fatal(err)
	}
}

// read returns the file's content, or nil when it is not there.
func (c *cluster) read(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(c.path(name))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func (c *cluster) exists(name string) bool {
	_, err := os.Stat(c.path(name))
	return err == nil
}

// reset empties the folder, so every step of a test starts from the same
// state whatever the step before it did.
func (c *cluster) reset(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(c.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(c.base, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

func portOf(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return strconv.Itoa(tcp.Port)
	}
	return "0"
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// client is what the tests do to the folder, independent of the protocol it
// is done by. Every method answers an error for a refusal instead of failing
// the test, because a refusal is what half the cases expect.
type client interface {
	get(path string) ([]byte, error)
	put(path string, content []byte) error
	remove(path string) error
	mkdir(path string) error
	rmdir(path string) error
	rename(from, to string) error
}

// protocols are the ways a client logs in, by name.
var protocols = []struct {
	name  string
	login func(t *testing.T, c *cluster, name, password string) (client, error)
}{
	{"http", loginHTTP},
	{"ftp", loginFTP},
	{"sftp", loginSFTP},
}

// ---- HTTP

type httpClient struct {
	base     string
	name     string
	password string
	token    *http.Cookie
	http     *http.Client
}

// loginHTTP checks the credentials with a request only an account may make,
// so that a wrong password fails here as it does at the other protocols' login.
func loginHTTP(t *testing.T, c *cluster, name, password string) (client, error) {
	t.Helper()
	web := &httpClient{
		base:     "http://" + net.JoinHostPort("127.0.0.1", portOf(c.http.Addr())),
		name:     name,
		password: password,
		http: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	res, err := web.do(http.MethodHead, "/", nil, nil)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("http login refused: %s", res.Status)
	}
	return web, nil
}

func (c *httpClient) url(path string) string {
	return c.base + (&url.URL{Path: path}).EscapedPath()
}

func (c *httpClient) do(method, path string, body []byte, header http.Header) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.url(path), reader)
	if err != nil {
		return nil, err
	}
	for key, values := range header {
		req.Header[key] = values
	}
	if c.token != nil {
		req.AddCookie(c.token)
	} else {
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(c.name+":"+c.password)))
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// expect sends a request and answers an error unless the status is a success.
func (c *httpClient) expect(method, path string, body []byte, header http.Header) ([]byte, error) {
	res, err := c.do(method, path, body, header)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	content, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("%s %s: %s", method, path, res.Status)
	}
	return content, nil
}

func (c *httpClient) get(path string) ([]byte, error) {
	return c.expect(http.MethodGet, path, nil, nil)
}

func (c *httpClient) put(path string, content []byte) error {
	_, err := c.expect(http.MethodPut, path, content,
		http.Header{"Content-Type": {"application/octet-stream"}})
	return err
}

func (c *httpClient) remove(path string) error {
	_, err := c.expect(http.MethodDelete, path, nil, nil)
	return err
}

func (c *httpClient) mkdir(path string) error {
	_, err := c.expect("MKCOL", path, nil, nil)
	return err
}

func (c *httpClient) rmdir(path string) error {
	_, err := c.expect(http.MethodDelete, path, nil, nil)
	return err
}

func (c *httpClient) rename(from, to string) error {
	_, err := c.expect("MOVE", from, nil, http.Header{"Destination": {(&url.URL{Path: to}).EscapedPath()}})
	return err
}

// ---- FTP

type ftpClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

func loginFTP(t *testing.T, c *cluster, name, password string) (client, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", portOf(c.ftp.Addr())), 5*time.Second)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := &ftpClient{t: t, conn: conn, reader: bufio.NewReader(conn)}
	if reply := client.reply(); !strings.HasPrefix(reply, "220") {
		return nil, fmt.Errorf("ftp greeting: %s", reply)
	}
	reply := client.command("USER " + name)
	if strings.HasPrefix(reply, "331") {
		reply = client.command("PASS " + password)
	}
	if !strings.HasPrefix(reply, "23") {
		return nil, fmt.Errorf("ftp login refused: %s", reply)
	}
	// binary, so that what arrives is byte for byte what was sent
	if err := client.expect("TYPE I"); err != nil {
		return nil, err
	}
	return client, nil
}

// reply reads a complete reply, following a multi line answer to its end.
func (c *ftpClient) reply() string {
	c.t.Helper()
	read := func() string {
		_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return "000 connection closed: " + err.Error()
		}
		return strings.TrimRight(line, "\r\n")
	}
	first := read()
	if len(first) < 4 || first[3] != '-' {
		return first
	}
	for {
		if next := read(); strings.HasPrefix(next, first[:3]+" ") || strings.HasPrefix(next, "000") {
			return next
		}
	}
}

func (c *ftpClient) command(line string) string {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		return "000 cannot send: " + err.Error()
	}
	return c.reply()
}

// expect sends a command and answers an error unless the reply is a success.
func (c *ftpClient) expect(line string) error {
	if reply := c.command(line); !strings.HasPrefix(reply, "2") && !strings.HasPrefix(reply, "3") {
		return fmt.Errorf("%s: %s", line, reply)
	}
	return nil
}

// passive opens a data connection.
func (c *ftpClient) passive() (net.Conn, error) {
	reply := c.command("EPSV")
	open, closing := strings.Index(reply, "|||"), strings.LastIndex(reply, "|")
	if !strings.HasPrefix(reply, "229") || open < 0 || closing <= open+3 {
		return nil, fmt.Errorf("EPSV: %s", reply)
	}
	return net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", reply[open+3:closing]), 5*time.Second)
}

// transfer runs a command that moves data, writing upload to the data
// connection or reading from it when upload is nil.
func (c *ftpClient) transfer(line string, upload []byte) ([]byte, error) {
	data, err := c.passive()
	if err != nil {
		return nil, err
	}
	defer data.Close()
	if reply := c.command(line); !strings.HasPrefix(reply, "150") && !strings.HasPrefix(reply, "125") {
		return nil, fmt.Errorf("%s: %s", line, reply)
	}
	var content []byte
	_ = data.SetDeadline(time.Now().Add(30 * time.Second))
	if upload != nil {
		_, err = data.Write(upload)
	} else {
		content, err = io.ReadAll(data)
	}
	_ = data.Close()
	reply := c.reply()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", line, err)
	}
	if !strings.HasPrefix(reply, "226") {
		return nil, fmt.Errorf("%s: %s", line, reply)
	}
	return content, nil
}

func (c *ftpClient) get(path string) ([]byte, error) {
	return c.transfer("RETR "+path, nil)
}

// getFrom is RETR after REST, a download resumed at offset.
func (c *ftpClient) getFrom(path string, offset int64) ([]byte, error) {
	if err := c.expect(fmt.Sprintf("REST %d", offset)); err != nil {
		return nil, err
	}
	return c.get(path)
}

func (c *ftpClient) put(path string, content []byte) error {
	if content == nil {
		content = []byte{}
	}
	_, err := c.transfer("STOR "+path, content)
	return err
}

func (c *ftpClient) remove(path string) error { return c.expect("DELE " + path) }
func (c *ftpClient) mkdir(path string) error  { return c.expect("MKD " + path) }
func (c *ftpClient) rmdir(path string) error  { return c.expect("RMD " + path) }

func (c *ftpClient) rename(from, to string) error {
	if reply := c.command("RNFR " + from); !strings.HasPrefix(reply, "350") {
		return fmt.Errorf("RNFR %s: %s", from, reply)
	}
	return c.expect("RNTO " + to)
}

// ---- SFTP

type sftpClient struct {
	*sftp.Client
}

func loginSFTP(t *testing.T, c *cluster, name, password string) (client, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", portOf(c.sftp.Addr())), &ssh.ClientConfig{
		User:            name,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	session, err := sftp.NewClient(conn)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = session.Close() })
	return &sftpClient{session}, nil
}

func (c *sftpClient) get(path string) ([]byte, error) {
	file, err := c.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func (c *sftpClient) put(path string, content []byte) error {
	file, err := c.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (c *sftpClient) remove(path string) error     { return c.Remove(path) }
func (c *sftpClient) mkdir(path string) error      { return c.Mkdir(path) }
func (c *sftpClient) rmdir(path string) error      { return c.RemoveDirectory(path) }
func (c *sftpClient) rename(from, to string) error { return c.Rename(from, to) }

// loginHTTPSession logs in through the login form and answers a client that
// sends the session token it was handed instead of credentials.
func loginHTTPSession(t *testing.T, c *cluster, name, password string) (*httpClient, error) {
	t.Helper()
	cl, err := loginHTTP(t, c, name, password)
	if err != nil {
		return nil, err
	}
	web := cl.(*httpClient)
	form := url.Values{"username": {name}, "password": {password}}
	req, err := http.NewRequest(http.MethodPost, web.base+"/?go-fs=login", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res, err := web.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "goFsSessionToken" && cookie.Value != "" {
			return &httpClient{base: web.base, token: cookie, http: web.http}, nil
		}
	}
	return nil, fmt.Errorf("the login form handed out no session token: %s", res.Status)
}

// Package config reads and writes the go-fs configuration file.
//
// The file is TOML. Every key is optional: a value that is absent keeps the
// built-in default, which mirrors the defaults of the original Node
// implementation. Load therefore unmarshals onto a fully populated defaults
// struct rather than onto a zero value.
package config

import (
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/crypto/ssh"
)

//go:embed template.toml
var template []byte

// Template returns the documented starter configuration.
func Template() []byte {
	return template
}

// Config is the whole configuration file.
type Config struct {
	General General `toml:"general"`
	Users   []User  `toml:"users"`
	Tokens  []Token `toml:"tokens"`
	FTP     FTP     `toml:"ftp"`
	FTPS    FTPS    `toml:"ftps"`
	SFTP    SFTP    `toml:"sftp"`
	HTTP    HTTP    `toml:"http"`
	HTTPS   HTTPS   `toml:"https"`
	TFTP    TFTP    `toml:"tftp"`
}

// General holds what every server shares.
type General struct {
	// Basefolder is the folder the servers fall back to when their own
	// section does not name one, so that a configuration where they all serve
	// the same tree says it once. It has to be an absolute path.
	Basefolder string `toml:"basefolder"`

	// ReloadConfig watches the configuration file and applies what changes in
	// it without a restart. A file that does not parse or does not validate is
	// reported and ignored, so a half-written save cannot take a server down.
	ReloadConfig bool `toml:"reloadConfig"`
	// ReloadInterval is how many seconds pass between two checks of the file.
	ReloadInterval int `toml:"reloadInterval"`

	// LogLevel is one of debug, info, warn, error. The protocol trace that
	// the original reported as 'log' events is written at debug level. It can
	// be changed without a restart: a reload switches the running logger over.
	LogLevel string `toml:"logLevel"`
	// LogFormat is text or json. Changing it needs a restart.
	LogFormat string `toml:"logFormat"`
}

// FTPS configures the TLS interface of the FTP server. It is a section of its
// own because TOML tables are top level; the folders, accounts and limits of
// [ftp] apply to this listener too.
type FTPS struct {
	// Enabled makes the server listen on Port and offer AUTH TLS on the plain
	// port. It is independent of FTP.Enabled: with that one off the server
	// serves implicit FTPS only.
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
	// Cert and Key are PEM file paths. When both are empty a self-signed
	// certificate is generated at startup.
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

// User is one entry of the [[users]] list, which every server draws its
// accounts from. An entry says which servers it may log in to, and its rights
// are one set that holds on all of them: a right granted once applies to FTP,
// SFTP and HTTP alike. There is no default account and no implicit one: a name
// that is not listed cannot log in anywhere. There is nothing special about the
// account named "anonymous": it is an ordinary entry that sets
// allowLoginWithoutPassword.
//
// The permission flags are pointers only so that Save can leave an unset key
// out of the file; every one of them denies by default.
type User struct {
	Username string `toml:"username"`
	Password string `toml:"password"`

	// FTP, SFTP and HTTP are the servers this account may log in to, each off
	// unless it is switched on. An entry that enables none is an account
	// nobody can use, which is a way to keep one without serving it.
	FTP  bool `toml:"ftp,omitempty"`
	SFTP bool `toml:"sftp,omitempty"`
	HTTP bool `toml:"http,omitempty"`
	// S3 lets the account use the S3 API of the HTTP server, with its username
	// as the access key and its password as the secret key. It is independent
	// of HTTP, and the same Paths and rights apply to it.
	S3 bool `toml:"s3,omitempty"`
	// Registry lets the account push to and delete from the container
	// registry of the HTTP server (see HTTP.RegistryBaseFolder), logging in
	// with its username and password, and pull from it where
	// RegistryAnonymousRead is off. It is independent of HTTP; Paths and the
	// rights below do not apply to it.
	Registry bool `toml:"registry,omitempty"`

	// Basefolder is the folder this account sees on FTP and SFTP instead of
	// the server's own. HTTP scopes an account by Paths instead and ignores
	// it.
	Basefolder string `toml:"basefolder,omitempty"`
	// Paths are regular expressions matched against an HTTP request path,
	// after it has been normalized, so that ".." cannot be used to slip past
	// one. An HTTP account with no pattern can reach nothing; FTP and SFTP
	// ignore them.
	Paths []string `toml:"paths,omitempty"`

	// AllowLoginWithoutPassword accepts the account on FTP with any password
	// or none. SSH and HTTP have no anonymous login, so it means nothing
	// there.
	AllowLoginWithoutPassword *bool `toml:"allowLoginWithoutPassword,omitempty"`
	// AuthorizedKeys are SSH public keys in authorized_keys format, one entry
	// per line as ssh-keygen writes them. They are how an SFTP account logs in
	// with a key instead of a password; the other servers ignore them.
	AuthorizedKeys []string `toml:"authorizedKeys,omitempty"`

	AllowUserFileCreate    *bool `toml:"allowUserFileCreate,omitempty"`
	AllowUserFileRetrieve  *bool `toml:"allowUserFileRetrieve,omitempty"`
	AllowUserFileOverwrite *bool `toml:"allowUserFileOverwrite,omitempty"`
	AllowUserFileDelete    *bool `toml:"allowUserFileDelete,omitempty"`
	AllowUserFolderDelete  *bool `toml:"allowUserFolderDelete,omitempty"`
	AllowUserFolderCreate  *bool `toml:"allowUserFolderCreate,omitempty"`

	// IsAdmin lets the account into the admin interface, the page that edits
	// this file, which the HTTP server serves at ?go-fs=admin. Reaching it
	// takes a session, so the account also has to set http.
	IsAdmin bool `toml:"isAdmin,omitempty"`
}

// Permissions resolves the user entry. Every right has to be granted
// explicitly: an account that sets none of the flags can log in and look
// around, and nothing else.
func (u User) Permissions() Permissions {
	return Permissions{
		Basefolder:      u.Basefolder,
		LoginNoPassword: boolOr(u.AllowLoginWithoutPassword, false),
		FileCreate:      boolOr(u.AllowUserFileCreate, false),
		FileRetrieve:    boolOr(u.AllowUserFileRetrieve, false),
		FileOverwrite:   boolOr(u.AllowUserFileOverwrite, false),
		FileDelete:      boolOr(u.AllowUserFileDelete, false),
		FolderDelete:    boolOr(u.AllowUserFolderDelete, false),
		FolderCreate:    boolOr(u.AllowUserFolderCreate, false),
	}
}

// Permissions is what a logged in session is allowed to do.
type Permissions struct {
	Basefolder      string
	LoginNoPassword bool
	FileCreate      bool
	FileRetrieve    bool
	FileOverwrite   bool
	FileDelete      bool
	FolderDelete    bool
	FolderCreate    bool
	// SelfUpdate lets a bearer token replace the go-fs binary; accounts never
	// have it, an admin updates through a session instead.
	SelfUpdate bool
}

// Token is a bearer token for the HTTP server: a credential a script or an API
// client sends as "Authorization: Bearer <token>" instead of a username and a
// password. Only the HTTP server reads tokens, on its plain and its TLS
// listener alike; FTP, SFTP and TFTP never see them.
//
// The file holds a hash of the token, never the token itself, so whoever reads
// the file or its backup cannot use one. The admin interface shows a new
// token once, when it creates it; a token that is lost is replaced, not
// recovered.
type Token struct {
	// Name labels the token in the admin interface and in the logs, where it
	// appears as "token:<name>".
	Name string `toml:"name"`
	// Hash is the SHA-256 of the token, hex encoded. The admin interface
	// fills it in when it creates a token.
	Hash string `toml:"hash"`
	// Expires is when the token stops being accepted, as an RFC 3339 time
	// such as 2026-12-31T23:59:59Z. A token without one never expires.
	Expires string `toml:"expires,omitempty"`

	// Paths are regular expressions matched against the request path, after
	// it has been normalized. A token with no pattern can reach nothing.
	Paths []string `toml:"paths,omitempty"`

	AllowUserFileCreate    *bool `toml:"allowUserFileCreate,omitempty"`
	AllowUserFileRetrieve  *bool `toml:"allowUserFileRetrieve,omitempty"`
	AllowUserFileOverwrite *bool `toml:"allowUserFileOverwrite,omitempty"`
	AllowUserFileDelete    *bool `toml:"allowUserFileDelete,omitempty"`
	AllowUserFolderDelete  *bool `toml:"allowUserFolderDelete,omitempty"`
	AllowUserFolderCreate  *bool `toml:"allowUserFolderCreate,omitempty"`

	// AllowSelfUpdate lets the token upload a new go-fs binary to
	// ?go-fs=update, which needs http.enableSelfUpdate as well. It is
	// independent of paths.
	AllowSelfUpdate *bool `toml:"allowSelfUpdate,omitempty"`
}

// Permissions resolves the token entry the way User.Permissions resolves an
// account: every right has to be granted explicitly.
func (t Token) Permissions() Permissions {
	return Permissions{
		FileCreate:    boolOr(t.AllowUserFileCreate, false),
		FileRetrieve:  boolOr(t.AllowUserFileRetrieve, false),
		FileOverwrite: boolOr(t.AllowUserFileOverwrite, false),
		FileDelete:    boolOr(t.AllowUserFileDelete, false),
		FolderDelete:  boolOr(t.AllowUserFolderDelete, false),
		FolderCreate:  boolOr(t.AllowUserFolderCreate, false),
		SelfUpdate:    boolOr(t.AllowSelfUpdate, false),
	}
}

// ExpiresAt is when the token stops being accepted, and false for a token that
// never expires. A value that does not parse is refused by Validate, so here it
// reads as already expired rather than as forever.
func (t Token) ExpiresAt() (time.Time, bool) {
	if t.Expires == "" {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, t.Expires)
	if err != nil {
		return time.Time{}, true
	}
	return at, true
}

// FTPUsers, SFTPUsers, HTTPUsers and S3Users are the entries a server serves:
// the ones that switch it on. Each server is handed its own list, so it never
// sees an account that is not meant for it.
func (c Config) FTPUsers() []User  { return c.usersFor(func(u User) bool { return u.FTP }) }
func (c Config) SFTPUsers() []User { return c.usersFor(func(u User) bool { return u.SFTP }) }
func (c Config) HTTPUsers() []User { return c.usersFor(func(u User) bool { return u.HTTP }) }
func (c Config) S3Users() []User   { return c.usersFor(func(u User) bool { return u.S3 }) }

// HTTPServerUsers are the entries the HTTP server serves in any way: over
// http, over its S3 API, over its container registry or over several. The
// server tells them apart itself, by the http, s3 and registry switches of
// each entry.
func (c Config) HTTPServerUsers() []User {
	return c.usersFor(func(u User) bool { return u.HTTP || u.S3 || u.Registry })
}

func (c Config) usersFor(serves func(User) bool) []User {
	var users []User
	for _, user := range c.Users {
		if serves(user) {
			users = append(users, user)
		}
	}
	return users
}

// FTP configures the FTP server.
type FTP struct {
	// Enabled serves the plain control port. The TLS listener has its own
	// switch in [ftps]; the rest of this section applies to both.
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
	// Address is the interface the control ports and the passive data ports
	// bind to. Empty binds every interface.
	Address    string `toml:"address"`
	Basefolder string `toml:"basefolder"`

	MaxConnections int `toml:"maxConnections"`

	// PassiveMinPort and PassiveMaxPort bound the ports a passive data
	// connection is accepted on, which is the range a firewall in front of the
	// server has to open. It should be at least as wide as MaxConnections,
	// since a transfer holds one port for as long as it runs.
	PassiveMinPort int `toml:"passiveMinPort"`
	PassiveMaxPort int `toml:"passiveMaxPort"`
	// ActiveSourcePort is the local port an active data connection is opened
	// from, 0 to let the system pick one. RFC 959 uses 20, which is what a
	// firewall written for active FTP expects; on unix a port below 1024 needs
	// the privilege to bind it.
	ActiveSourcePort int `toml:"activeSourcePort"`
	// PassiveAddress is the address a PASV reply names, for a server behind
	// NAT or in a container whose own address is not the one clients reach it
	// at. Empty names the address the control connection arrived on, which is
	// right whenever there is nothing translating in between. It has to be an
	// IPv4 address, because that is all a PASV reply can carry; EPSV names no
	// address at all and is unaffected.
	PassiveAddress string `toml:"passiveAddress"`

	IdleTimeout int `toml:"idleTimeout"`
	DataTimeout int `toml:"dataTimeout"`
	// TransferIdleTimeout is how many seconds a running transfer may move
	// nothing before it is dropped, 0 disables it. It bounds a transfer by how
	// long it stalls rather than by how long it takes, so a download of any
	// size finishes while a client that stops reading gives its slot back
	// instead of holding one until it disconnects.
	TransferIdleTimeout int `toml:"transferIdleTimeout"`
	MaxCommandLength    int `toml:"maxCommandLength"`
	// LoginFailureDelay is the delay in seconds before a wrong password is
	// answered, which slows down guessing.
	LoginFailureDelay int `toml:"loginFailureDelay"`

	// AllowFtpBounce permits PORT and EPRT to name a host other than the
	// client (RFC 2577).
	AllowFtpBounce bool `toml:"allowFtpBounce"`
	// AllowForeignDataConnection permits passive data connections from a
	// different address than the control connection.
	AllowForeignDataConnection bool `toml:"allowForeignDataConnection"`
}

// SFTP configures the SFTP server, which is the SFTP subsystem of an SSH
// server. Its accounts are the entries of [[users]] that set sftp; each of
// those needs a password or at least one authorized key, and
// allowLoginWithoutPassword has no meaning here, because SSH has no equivalent
// of an anonymous login.
type SFTP struct {
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
	// Address is the interface the listener binds to. Empty binds every one.
	Address    string `toml:"address"`
	Basefolder string `toml:"basefolder"`

	// HostKey is the SSH host key itself rather than a path to it, base64 of
	// its PEM encoding, so that the whole configuration stays in one file.
	// When it is empty a key is generated at startup, which every client will
	// report as a changed host key after a restart.
	HostKey string `toml:"hostkey"`

	MaxConnections int `toml:"maxConnections"`
	// IdleTimeout is the number of seconds without any traffic after which a
	// connection is closed, 0 disables it.
	IdleTimeout int `toml:"idleTimeout"`
	// LoginFailureDelay is the delay in seconds before a wrong password is
	// answered, which slows down guessing.
	LoginFailureDelay int `toml:"loginFailureDelay"`
}

// HTTP configures the HTTP file server: browsing and downloading with GET,
// uploading with PUT, removing with DELETE, creating a folder with MKCOL and
// renaming with MOVE.
//
// Access has two layers. A request is public unless its method is in
// MethodsRequireAuth or its path matches one of PathsRequireAuth; when it is
// not public it has to be answered by one of the [[users]] entries that set
// http, and that account's own paths and rights then decide what it may do.
type HTTP struct {
	// Enabled serves the plain port. The TLS listener has its own switch in
	// [https]; the rest of this section applies to both.
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
	// Address is the interface both listeners bind to. Empty binds every one.
	Address    string `toml:"address"`
	Basefolder string `toml:"basefolder"`

	// Realm is what clients are challenged with and, because it is hashed into
	// the digest response, changing it invalidates saved credentials.
	Realm string `toml:"realm"`

	// EnableAdminInterface serves the web interface that edits this file at
	// ?go-fs=admin on both listeners. It is reachable only by an account that
	// sets isAdmin and has logged in through the browser; the page carries
	// every password in the file, so it belongs on the https listener.
	EnableAdminInterface bool `toml:"enableAdminInterface"`
	// EnableSelfUpdate accepts a new go-fs binary at ?go-fs=update, which then
	// replaces the running one and restarts it. Only a file signed with a key
	// built into this binary is accepted, and only from a token that sets
	// allowSelfUpdate or from the session of an account that sets isAdmin.
	EnableSelfUpdate bool `toml:"enableSelfUpdate"`
	// EnableS3 answers requests signed with AWS Signature Version 4 as the S3
	// API, on both listeners. Every folder directly in Basefolder is a bucket,
	// found by its name ignoring case, in the one region, S3Region, and only
	// the accounts that set s3 may use it.
	EnableS3 bool `toml:"enableS3"`
	// RegistryBaseFolder serves an OCI container registry under /v2/ on both
	// listeners and keeps its blobs, manifests and tags in this folder. Empty
	// turns the registry off. It has to be an absolute path to an existing
	// folder that neither is nor contains nor lies inside a folder any server
	// serves, since everything in it is managed by the registry alone.
	RegistryBaseFolder string `toml:"registryBaseFolder"`
	// RegistryAnonymousRead lets anyone pull from the registry without
	// credentials. With it off, pulling takes an account that sets registry,
	// as pushing and deleting always do.
	RegistryAnonymousRead bool `toml:"registryAnonymousRead"`

	MaxConnections int `toml:"maxConnections"`
	// ReadTimeout, WriteTimeout and IdleTimeout are seconds, 0 disables one.
	// WriteTimeout is off by default: it would cap the duration of a download.
	// ReadTimeout does the equivalent job for an upload, but as an idle
	// timeout rather than a hard cap: it is how long a PUT may go without any
	// data arriving, reset on every chunk received, so it does not cut off a
	// large upload that is merely slow.
	ReadTimeout  int `toml:"readTimeout"`
	WriteTimeout int `toml:"writeTimeout"`
	IdleTimeout  int `toml:"idleTimeout"`
	// MaxUploadSize is the largest accepted body in bytes, 0 means no limit.
	MaxUploadSize int64 `toml:"maxUploadSize"`
	// MaxChunkSize is the largest a single Content-Range chunk of an upload
	// may be, in bytes. It exists so that a reverse proxy with a hard
	// per-request duration or body-size cap (Cloudflare's ~100 second rule
	// was the motivating case) never sees a request large enough to trip it:
	// a large file is still accepted, just never in one request. 0 disables
	// chunked upload — a PUT carrying Content-Range is then refused.
	MaxChunkSize int64 `toml:"maxChunkSize"`
	// UploadStagingFolder holds the not-yet-finalized bytes of a chunked
	// upload. It must not be inside Basefolder: nothing in vfs or the
	// directory listing filters partial files out, so a staging file inside
	// the served tree would be visible and downloadable while still being
	// written. Empty defaults to a "go-fs-uploads" folder under the OS temp
	// directory, created as needed. It should stay on the same filesystem as
	// Basefolder, so finishing a chunked upload is a fast, atomic rename
	// rather than a slow or outright-failing cross-device move.
	UploadStagingFolder string `toml:"uploadStagingFolder"`
	// SessionTokenLifetime is how long a browser stays logged in after using
	// the login form, in seconds. It bounds a token that cannot be withdrawn:
	// a signed token is accepted until it runs out, whoever holds it.
	SessionTokenLifetime int `toml:"httpSessionTokenLifetime"`
	// SessionTokenSecret is the key the login tokens are signed with, base64
	// of at least 32 random bytes:
	//   head -c 32 /dev/urandom | base64
	// With it empty a key is generated at every start, which logs every
	// browser out on a restart and stops two hosts serving the same folder
	// from sharing a login. Changing it needs a restart.
	SessionTokenSecret string `toml:"httpSessionTokenSecret"`
	// ShareLinkSecret is the key a file's share link is signed with: a link
	// carries ?key= with an HMAC-SHA512 over the file's path, modification
	// time and size, which lets anyone holding it download that one file
	// without an account until the file changes. It is generated and written
	// into this file at the first start; changing it revokes every link handed
	// out so far.
	ShareLinkSecret string `toml:"shareLinkSecret"`
	// LoginFailureDelay is the delay in seconds before a rejected request is
	// answered, which slows down guessing.
	LoginFailureDelay int `toml:"loginFailureDelay"`
	// LoginAttempts is how many wrong passwords a client address may send in
	// LoginLockout seconds before it is refused. 0 turns the lock off.
	LoginAttempts int `toml:"loginAttempts"`
	// LoginLockout is how long a locked client is refused, in seconds. It is
	// also the window the attempts are counted over.
	LoginLockout int `toml:"loginLockout"`
	// TrustedProxies are the addresses, or CIDR ranges, of the proxies in front
	// of this server. A request from one of them is recorded under the client
	// in X-Forwarded-For, and X-Forwarded-Proto says whether the session cookie
	// is marked Secure. From anywhere else both headers are ignored.
	TrustedProxies []string `toml:"trustedProxies"`

	// MethodsRequireAuth are the methods that always need an account. MKCOL
	// and MOVE do not have to be listed: MKCOL is protected wherever PUT is,
	// and MOVE wherever PUT or DELETE is, so a configuration written before
	// they existed still covers them.
	MethodsRequireAuth []string `toml:"methodsRequireAuth"`
	// PathsRequireAuth are regular expressions; a request whose path matches
	// one of them needs an account whatever its method.
	PathsRequireAuth []string `toml:"pathsRequireAuth"`

	Cleanup []Cleanup `toml:"cleanup"`
}

// S3Region is the one region the S3 API of the HTTP server answers for. It is
// not a key of the file, because there is nothing to choose between.
const S3Region = "us-east-1"

// HTTPS configures the TLS interface of the HTTP server. It is a section of
// its own because TOML tables are top level; the folder, accounts and limits
// of [http] apply to this listener too.
type HTTPS struct {
	// Enabled makes the server listen on Port. It is independent of
	// HTTP.Enabled: with that one off the server serves HTTPS only.
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
	// Cert and Key are PEM file paths. When both are empty a self-signed
	// certificate is generated at startup.
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

// Cleanup keeps a folder from growing without bound: everything but the Keep
// newest files in it is deleted, once an hour.
type Cleanup struct {
	Path string `toml:"path"`
	Keep int    `toml:"keep"`
}

// TFTP configures the TFTP server.
type TFTP struct {
	Enabled    bool   `toml:"enabled"`
	Port       int    `toml:"port"`
	Address    string `toml:"address"`
	Type       string `toml:"type"`
	Basefolder string `toml:"basefolder"`

	AllowRead            bool `toml:"allowRead"`
	AllowWrite           bool `toml:"allowWrite"`
	AllowOverwrite       bool `toml:"allowOverwrite"`
	AllowCreateDirectory bool `toml:"allowCreateDirectory"`

	MaxConnections        int   `toml:"maxConnections"`
	MaxConnectionsPerHost int   `toml:"maxConnectionsPerHost"`
	Timeout               int   `toml:"timeout"`
	MaxTimeout            int   `toml:"maxTimeout"`
	Retries               int   `toml:"retries"`
	TransferTimeout       int   `toml:"transferTimeout"`
	MaxBlockSize          int   `toml:"maxBlockSize"`
	MaxWindowSize         int   `toml:"maxWindowSize"`
	MaxFileSize           int64 `toml:"maxFileSize"`
}

// Default returns the configuration that applies when nothing is set. The
// values match the FTPdefaults, UserDefaults and TFTPdefaults of the original.
func Default() Config {
	return Config{
		General: General{
			ReloadConfig:   true,
			ReloadInterval: 5,
			LogLevel:       "info",
			LogFormat:      "text",
		},
		FTP: FTP{
			Enabled:             true,
			Port:                21,
			MaxConnections:      10,
			PassiveMinPort:      1024,
			PassiveMaxPort:      1034,
			ActiveSourcePort:    0,
			IdleTimeout:         600,
			DataTimeout:         5,
			TransferIdleTimeout: 300,
			MaxCommandLength:    4096,
			LoginFailureDelay:   1,
		},
		FTPS: FTPS{
			Port: 990,
		},
		// SFTP is the one server that is off by default: a configuration
		// written for an earlier version has no [sftp] section, and starting
		// an SSH listener on such an upgrade would be a surprise.
		SFTP: SFTP{
			Port:              22,
			MaxConnections:    10,
			IdleTimeout:       600,
			LoginFailureDelay: 1,
		},
		HTTP: HTTP{
			Port:                  9080,
			Realm:                 "go-fs",
			EnableAdminInterface:  true,
			EnableS3:              true,
			RegistryAnonymousRead: true,
			MaxConnections:        100,
			ReadTimeout:           120,
			IdleTimeout:           120,
			MaxChunkSize:          50 << 20, // 50 MB
			SessionTokenLifetime:  3600,
			LoginFailureDelay:     1,
			LoginAttempts:         5,
			LoginLockout:          60,
			MethodsRequireAuth:    []string{"PUT", "DELETE", "POST", "MKCOL", "MOVE"},
		},
		HTTPS: HTTPS{
			Port: 9443,
		},
		TFTP: TFTP{
			Enabled:               true,
			Port:                  69,
			AllowRead:             true,
			AllowCreateDirectory:  true,
			MaxConnections:        10,
			MaxConnectionsPerHost: 5,
			Timeout:               5,
			MaxTimeout:            60,
			Retries:               3,
			TransferTimeout:       300,
			MaxBlockSize:          1468,
			MaxWindowSize:         16,
		},
	}
}

// Parse unmarshals data onto the defaults and stops there. It is what an editor
// of this file wants: the sections say what the file says, so that writing the
// result back does not turn an inherited value into an explicit one.
func Parse(data []byte) (Config, error) {
	cfg := Default()
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// retired names the keys a configuration file may still hold and what replaced
// them. A file that sets one is read rather than refused — go-toml ignores a
// key no field claims — so the only thing left to do is say so, which is what
// RetiredKeys is for.
var retired = map[string]string{
	"http.sessionTimeout": "http.httpSessionTokenLifetime",
	// the accounts of every server are one list now
	"ftp.users":  "[[users]] with ftp = true",
	"sftp.users": "[[users]] with sftp = true",
	"http.users": "[[users]] with http = true",
	// the [log] section moved into [general]
	"log.level":  "general.logLevel",
	"log.format": "general.logFormat",
	// the admin interface is served by the http server and logs in with one
	// of its accounts, so it has no listener and no account of its own
	"general.adminInterfaceEnabled":  "http.enableAdminInterface",
	"general.adminInterfaceAddress":  "http.address",
	"general.adminInterfacePort":     "http.port or https.port",
	"general.adminInterfaceUseHttps": "https.enabled",
	"general.adminUsername":          "[[users]] with isAdmin = true",
	"general.adminPassword":          "[[users]] with isAdmin = true",
	"general.adminCert":              "https.cert",
	"general.adminKey":               "https.key",
	// every http account may log in through the browser, and the session
	// cookie is scoped to the root
	"users.cookie":     "nothing: every http account may log in through the browser",
	"users.cookiePath": "nothing: the session cookie is always scoped to /",
}

// RetiredKeys reports the retired keys a file still sets, each as
// "old is ignored, use new". It parses loosely into a tree of tables and
// reports nothing for a file it cannot read: this is a courtesy on top of a
// configuration that has already loaded, not a check of its own.
//
// A section is either one table or, as [[users]] is, an array of them; a key
// set in any entry of the array is reported once.
func RetiredKeys(data []byte) []string {
	var tree map[string]any
	if err := toml.Unmarshal(data, &tree); err != nil {
		return nil
	}
	found := make([]string, 0, len(retired))
	for key, replacement := range retired {
		section, name, _ := strings.Cut(key, ".")
		if setsKey(tree[section], name) {
			found = append(found, fmt.Sprintf("%s is ignored, use %s", key, replacement))
		}
	}
	sort.Strings(found)
	return found
}

// setsKey reports whether a loosely parsed section, a table or an array of
// tables, sets name anywhere in it.
func setsKey(section any, name string) bool {
	switch section := section.(type) {
	case map[string]any:
		_, set := section[name]
		return set
	case []any:
		for _, entry := range section {
			if table, ok := entry.(map[string]any); ok {
				if _, set := table[name]; set {
					return true
				}
			}
		}
	case []map[string]any:
		for _, table := range section {
			if _, set := table[name]; set {
				return true
			}
		}
	}
	return false
}

// Load reads path onto the defaults and validates the result.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default(), err
	}
	cfg, err := Parse(data)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	cfg = cfg.Resolved()
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Resolved is a copy that hands general.basefolder to every server that did not
// name one of its own. It is applied before validation, so an error names the
// section the folder ended up in rather than the one it came from.
//
// The copy is shallow, which is safe because only string fields are written.
func (c Config) Resolved() Config {
	if c.General.Basefolder == "" {
		return c
	}
	for _, folder := range []*string{
		&c.FTP.Basefolder,
		&c.SFTP.Basefolder,
		&c.HTTP.Basefolder,
		&c.TFTP.Basefolder,
	} {
		if *folder == "" {
			*folder = c.General.Basefolder
		}
	}
	return c
}

// Save writes the configuration back as TOML.
func Save(path string, cfg Config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

// exampleSecrets are the passwords this project prints in its own README and
// starter configuration. One of them in a live file is not a password at all:
// it is on every page anyone reads before installing this.
var exampleSecrets = map[string]bool{"doe": true, "mustermann": true}

// ExampleAccounts names the accounts whose password is one of those, so that a
// server never comes up quietly protected by a password anyone can look up. It
// covers the servers that are switched off too, since the day they are switched
// on is not the day anyone rereads the passwords.
func (c Config) ExampleAccounts() []string {
	var found []string
	note := func(where, name string) {
		found = append(found, fmt.Sprintf("%s %q", where, name))
	}
	for i, user := range c.Users {
		if exampleSecrets[user.Password] {
			note(fmt.Sprintf("users[%d]", i), user.Username)
		}
	}
	return found
}

// LooseFilePermissions reports a configuration file that anyone but its owner
// can read, and the mode it has. The file holds every password and every
// private key in one place, so it deserves what a private key deserves. It is
// reported rather than refused, since a container image with one owner and one
// process is a legitimate reason not to care.
//
// Windows has no such bits to read: the mode the standard library reports there
// is synthesised, so nothing is claimed about it.
func LooseFilePermissions(path string) (os.FileMode, bool) {
	if runtime.GOOS == "windows" {
		return 0, false
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	mode := info.Mode().Perm()
	return mode, mode&0o077 != 0
}

// Validate reports configuration that cannot work.
func (c Config) Validate() error {
	switch c.General.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("general.logLevel %q is not one of debug, info, warn, error", c.General.LogLevel)
	}
	switch c.General.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("general.logFormat %q is not one of text, json", c.General.LogFormat)
	}
	if c.General.ReloadInterval < 1 {
		return errors.New("general.reloadInterval has to be at least 1")
	}
	if c.General.Basefolder != "" {
		if !filepath.IsAbs(c.General.Basefolder) {
			return fmt.Errorf("general.basefolder %q has to be an absolute path",
				c.General.Basefolder)
		}
		if err := checkFolder("general.basefolder", c.General.Basefolder); err != nil {
			return err
		}
	}
	if !c.FTP.Enabled && !c.FTPS.Enabled && !c.SFTP.Enabled &&
		!c.HTTP.Enabled && !c.HTTPS.Enabled && !c.TFTP.Enabled {
		return errors.New("no server is enabled, nothing to do")
	}
	if err := c.validateUsers(); err != nil {
		return err
	}
	if err := c.validateTokens(); err != nil {
		return err
	}
	if c.FTP.Enabled || c.FTPS.Enabled {
		if err := c.validateFTP(); err != nil {
			return err
		}
	}
	if c.SFTP.Enabled {
		if err := c.SFTP.validate(); err != nil {
			return err
		}
	}
	if c.HTTP.Enabled || c.HTTPS.Enabled {
		if err := c.validateHTTP(); err != nil {
			return err
		}
	}
	if c.TFTP.Enabled {
		if err := c.TFTP.validate(); err != nil {
			return err
		}
	}
	return nil
}

// validateUsers checks the account list. The rules that hold for every entry
// are checked first; what a server needs of its accounts is checked only for
// the entries that switch it on, so a key-only SFTP account is not asked for
// the password an HTTP account needs. It runs whether or not that server is
// enabled: the entry is what is wrong, and -check should say so before the day
// the server is switched on.
func (c Config) validateUsers() error {
	seen := map[string]bool{}
	for i, user := range c.Users {
		where := fmt.Sprintf("users[%d]", i)
		if user.Username == "" {
			return fmt.Errorf("%s has no username", where)
		}
		// every server resolves an account by name on every request, so two
		// entries with the same name would make which rights apply a matter
		// of order
		if seen[user.Username] {
			return fmt.Errorf("%s: %q is configured twice", where, user.Username)
		}
		seen[user.Username] = true

		if (user.FTP || user.SFTP) && user.Basefolder != "" {
			if err := checkFolder(where+".basefolder", user.Basefolder); err != nil {
				return err
			}
		}
		if user.SFTP {
			// the keys are parsed here as well as at startup, so that -check
			// reports a key that would stop the server rather than passing it
			for k, entry := range user.AuthorizedKeys {
				if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry)); err != nil {
					return fmt.Errorf("%s.authorizedKeys[%d]: %w", where, k, err)
				}
			}
			if user.Password == "" && len(user.AuthorizedKeys) == 0 {
				return fmt.Errorf("%s %q has neither a password nor an authorized key, "+
					"so it could never log in to sftp", where, user.Username)
			}
		}
		if user.HTTP || user.S3 {
			server := "http"
			if !user.HTTP {
				server = "s3"
			}
			if user.Password == "" {
				return fmt.Errorf("%s %q has no password, which %s needs", where, user.Username, server)
			}
			for k, pattern := range user.Paths {
				if _, err := regexp.Compile(pattern); err != nil {
					return fmt.Errorf("%s.paths[%d]: %w", where, k, err)
				}
			}
		}
		// the username is the access key, and a signature names it in a
		// "Credential=<key>/<date>/<region>/s3/aws4_request" field, which a
		// slash, a comma or a space would cut short
		if user.S3 && strings.ContainsAny(user.Username, "/, \t\r\n") {
			return fmt.Errorf("%s %q sets s3, and an S3 access key cannot hold a slash, "+
				"a comma or white space", where, user.Username)
		}
		if user.Registry {
			if user.Password == "" {
				return fmt.Errorf("%s %q has no password, which registry needs", where, user.Username)
			}
			// HTTP Basic splits the credentials at the first colon, so a name
			// that holds one could never be sent
			if strings.Contains(user.Username, ":") {
				return fmt.Errorf("%s %q sets registry, and a registry username cannot hold a colon",
					where, user.Username)
			}
		}
		// the admin interface is reached with a session, and only an http
		// account ever holds one
		if user.IsAdmin && !user.HTTP {
			return fmt.Errorf("%s %q sets isAdmin but not http, "+
				"which the admin interface needs to log in", where, user.Username)
		}
	}
	return nil
}

// validateTokens checks the bearer tokens. Like validateUsers it runs whether
// or not the HTTP server is enabled.
func (c Config) validateTokens() error {
	names := map[string]bool{}
	hashes := map[string]bool{}
	for i, token := range c.Tokens {
		where := fmt.Sprintf("tokens[%d]", i)
		if token.Name == "" {
			return fmt.Errorf("%s has no name", where)
		}
		if names[token.Name] {
			return fmt.Errorf("%s: %q is configured twice", where, token.Name)
		}
		names[token.Name] = true
		if !ValidTokenHash(token.Hash) {
			return fmt.Errorf("%s %q: hash has to be the hex encoded SHA-256 of the token, "+
				"64 characters", where, token.Name)
		}
		// two entries with the same hash are one token with two sets of rights
		if hashes[strings.ToLower(token.Hash)] {
			return fmt.Errorf("%s %q has the same hash as another token", where, token.Name)
		}
		hashes[strings.ToLower(token.Hash)] = true
		if token.Expires != "" {
			if _, err := time.Parse(time.RFC3339, token.Expires); err != nil {
				return fmt.Errorf("%s %q: expires %q is not an RFC 3339 time "+
					"such as 2026-12-31T23:59:59Z", where, token.Name, token.Expires)
			}
		}
		for k, pattern := range token.Paths {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("%s.paths[%d]: %w", where, k, err)
			}
		}
	}
	return nil
}

// validateHTTP checks the HTTP service, whose settings straddle [http] and
// [https] the way the FTP ones straddle [ftp] and [ftps].
func (c Config) validateHTTP() error {
	if c.HTTP.Enabled {
		if err := checkPort("http.port", c.HTTP.Port); err != nil {
			return err
		}
	}
	if c.HTTPS.Enabled {
		if err := checkPort("https.port", c.HTTPS.Port); err != nil {
			return err
		}
		if err := checkPair("https.cert", c.HTTPS.Cert, "https.key", c.HTTPS.Key); err != nil {
			return err
		}
	}
	h := c.HTTP
	if err := checkAddress("http.address", h.Address); err != nil {
		return err
	}
	if h.MaxConnections < 1 {
		return errors.New("http.maxConnections has to be at least 1")
	}
	// 0 would hand out tokens that have already expired
	if h.SessionTokenLifetime < 1 {
		return errors.New("http.httpSessionTokenLifetime has to be at least 1")
	}
	// checked here rather than at the first login, so that a key too short to
	// sign with is reported by -check and not by a user who cannot log in
	if h.SessionTokenSecret != "" {
		if _, err := DecodeSessionSecret(h.SessionTokenSecret); err != nil {
			return fmt.Errorf("http.httpSessionTokenSecret: %w", err)
		}
	}
	if h.ShareLinkSecret != "" && len(h.ShareLinkSecret) < MinShareSecret {
		return fmt.Errorf("http.shareLinkSecret has to be at least %d characters", MinShareSecret)
	}
	if h.LoginAttempts < 0 {
		return errors.New("http.loginAttempts cannot be negative")
	}
	if h.LoginLockout < 1 {
		return errors.New("http.loginLockout has to be at least 1")
	}
	for i, proxy := range h.TrustedProxies {
		if _, err := ParseProxy(proxy); err != nil {
			return fmt.Errorf("http.trustedProxies[%d]: %w", i, err)
		}
	}
	if h.MaxUploadSize < 0 {
		return errors.New("http.maxUploadSize cannot be negative")
	}
	if h.MaxChunkSize < 0 {
		return errors.New("http.maxChunkSize cannot be negative")
	}
	if h.MaxUploadSize > 0 && h.MaxChunkSize > 0 && h.MaxChunkSize > h.MaxUploadSize {
		return errors.New("http.maxChunkSize cannot be larger than http.maxUploadSize")
	}
	if h.UploadStagingFolder != "" && !filepath.IsAbs(h.UploadStagingFolder) {
		return errors.New("http.uploadStagingFolder has to be an absolute path")
	}
	if h.Realm == "" {
		return errors.New("http.realm is not set")
	}
	for i, pattern := range h.PathsRequireAuth {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("http.pathsRequireAuth[%d]: %w", i, err)
		}
	}
	for i, entry := range h.Cleanup {
		if entry.Path == "" {
			return fmt.Errorf("http.cleanup[%d] has no path", i)
		}
		if entry.Keep < 0 {
			return fmt.Errorf("http.cleanup[%d].keep cannot be negative", i)
		}
	}
	if err := c.validateRegistry(); err != nil {
		return err
	}
	return checkFolder("http.basefolder", h.Basefolder)
}

// validateRegistry checks http.registryBaseFolder. The registry is the only
// thing that may write to its folder: a served folder that overlapped it would
// let a file upload replace a blob under its digest, or a listing show them.
func (c Config) validateRegistry() error {
	folder := c.HTTP.RegistryBaseFolder
	if folder == "" {
		return nil
	}
	if !filepath.IsAbs(folder) {
		return fmt.Errorf("http.registryBaseFolder %q has to be an absolute path", folder)
	}
	if err := checkFolder("http.registryBaseFolder", folder); err != nil {
		return err
	}
	served := []struct{ name, folder string }{
		{"general.basefolder", c.General.Basefolder},
		{"ftp.basefolder", c.FTP.Basefolder},
		{"sftp.basefolder", c.SFTP.Basefolder},
		{"http.basefolder", c.HTTP.Basefolder},
		{"tftp.basefolder", c.TFTP.Basefolder},
	}
	for i, user := range c.Users {
		served = append(served, struct{ name, folder string }{
			fmt.Sprintf("users[%d].basefolder", i), user.Basefolder})
	}
	registry := comparablePath(folder)
	for _, other := range served {
		if other.folder == "" {
			continue
		}
		if overlaps(registry, comparablePath(other.folder)) {
			return fmt.Errorf("http.registryBaseFolder %q overlaps %s %q; "+
				"it has to be a folder of its own", folder, other.name, other.folder)
		}
	}
	return nil
}

// comparablePath is a folder as it is on disk, with its links resolved where
// it exists, so that two spellings of one folder compare equal.
func comparablePath(folder string) string {
	if resolved, err := filepath.EvalSymlinks(folder); err == nil {
		folder = resolved
	}
	return filepath.Clean(folder)
}

// overlaps reports whether one folder is, holds or lies inside the other.
func overlaps(a, b string) bool {
	inside := func(child, parent string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return inside(a, b) || inside(b, a)
}

// ParseProxy reads one entry of http.trustedProxies: an address, or a CIDR
// range. A single address is returned as the range that holds only it, so the
// caller has one kind of thing to compare against.
func ParseProxy(entry string) (netip.Prefix, error) {
	trimmed := strings.TrimSpace(entry)
	if strings.Contains(trimmed, "/") {
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap().WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// validateFTP checks the FTP service, whose settings straddle [ftp] and [ftps].
// Everything but the two ports is shared, so it is checked whenever either
// listener is enabled.
func (c Config) validateFTP() error {
	if c.FTP.Enabled {
		if err := checkPort("ftp.port", c.FTP.Port); err != nil {
			return err
		}
	}
	if c.FTPS.Enabled {
		if err := checkPort("ftps.port", c.FTPS.Port); err != nil {
			return err
		}
		if err := checkPair("ftps.cert", c.FTPS.Cert, "ftps.key", c.FTPS.Key); err != nil {
			return err
		}
	}
	f := c.FTP
	if err := checkAddress("ftp.address", f.Address); err != nil {
		return err
	}
	if f.MaxConnections < 1 {
		return errors.New("ftp.maxConnections has to be at least 1")
	}
	// 0 would make every passive transfer fail: the wait for the data
	// connection would time out before the client could open it
	if f.DataTimeout < 1 {
		return errors.New("ftp.dataTimeout has to be at least 1")
	}
	if f.TransferIdleTimeout < 0 {
		return errors.New("ftp.transferIdleTimeout cannot be negative")
	}
	if err := checkPort("ftp.passiveMinPort", f.PassiveMinPort); err != nil {
		return err
	}
	if err := checkPort("ftp.passiveMaxPort", f.PassiveMaxPort); err != nil {
		return err
	}
	if f.PassiveMinPort > f.PassiveMaxPort {
		return fmt.Errorf("ftp.passiveMinPort %d is above ftp.passiveMaxPort %d",
			f.PassiveMinPort, f.PassiveMaxPort)
	}
	// 0 is the setting that leaves the source port to the system, so it is the
	// one value outside the port range that means something here
	if f.ActiveSourcePort != 0 {
		if err := checkPort("ftp.activeSourcePort", f.ActiveSourcePort); err != nil {
			return err
		}
	}
	// a PASV reply carries four octets and nothing else, so the address it
	// names has to be one that fits in them
	if f.PassiveAddress != "" {
		parsed := net.ParseIP(f.PassiveAddress)
		if parsed == nil || parsed.To4() == nil {
			return fmt.Errorf("ftp.passiveAddress %q is not an IPv4 address, "+
				"which is the only kind a PASV reply can name", f.PassiveAddress)
		}
	}
	if f.MaxCommandLength < 16 {
		return errors.New("ftp.maxCommandLength has to be at least 16")
	}
	if err := checkFolder("ftp.basefolder", f.Basefolder); err != nil {
		return err
	}
	return nil
}

func (s SFTP) validate() error {
	if err := checkPort("sftp.port", s.Port); err != nil {
		return err
	}
	if err := checkAddress("sftp.address", s.Address); err != nil {
		return err
	}
	if s.MaxConnections < 1 {
		return errors.New("sftp.maxConnections has to be at least 1")
	}
	// The key material is in this file, not in files it points at, so a broken
	// one is reported here rather than at the first start.
	if s.HostKey != "" {
		if _, err := DecodeHostKey(s.HostKey); err != nil {
			return fmt.Errorf("sftp.hostkey: %w", err)
		}
	}
	if err := checkFolder("sftp.basefolder", s.Basefolder); err != nil {
		return err
	}
	return nil
}

func (t TFTP) validate() error {
	if err := checkPort("tftp.port", t.Port); err != nil {
		return err
	}
	switch t.Type {
	case "", "udp4", "udp6":
	default:
		return fmt.Errorf("tftp.type %q is not one of udp4, udp6", t.Type)
	}
	if t.MaxConnections < 1 {
		return errors.New("tftp.maxConnections has to be at least 1")
	}
	if t.MaxConnectionsPerHost < 1 {
		return errors.New("tftp.maxConnectionsPerHost has to be at least 1")
	}
	if t.Timeout < 1 {
		return errors.New("tftp.timeout has to be at least 1")
	}
	if t.MaxTimeout < t.Timeout {
		return errors.New("tftp.maxTimeout has to be at least tftp.timeout")
	}
	if t.Retries < 0 {
		return errors.New("tftp.retries cannot be negative")
	}
	if t.MaxBlockSize < 8 || t.MaxBlockSize > 65464 {
		return fmt.Errorf("tftp.maxBlockSize %d is outside 8..65464", t.MaxBlockSize)
	}
	if t.MaxWindowSize < 1 {
		return errors.New("tftp.maxWindowSize has to be at least 1")
	}
	if t.MaxFileSize < 0 {
		return errors.New("tftp.maxFileSize cannot be negative")
	}
	return checkFolder("tftp.basefolder", t.Basefolder)
}

// checkPair reports a certificate and private key that cannot be served. Both
// are decoded and matched against each other, so a truncated paste, a key put
// into the certificate field or a key belonging to another certificate is
// reported by -check and refused by the web interface, rather than stopping
// the listener at the next start.
func checkPair(certName, cert, keyName, key string) error {
	if (cert == "") != (key == "") {
		return fmt.Errorf("%s and %s have to be set together", certName, keyName)
	}
	if cert == "" {
		return nil
	}
	certPEM, err := DecodeCertificate(cert)
	if err != nil {
		return fmt.Errorf("%s: %w", certName, err)
	}
	keyPEM, err := DecodePrivateKey(key)
	if err != nil {
		return fmt.Errorf("%s: %w", keyName, err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("%s and %s: %w", certName, keyName, err)
	}
	return nil
}

// checkAddress reports an address that is not one this host could bind. An
// empty address is every interface, which is the default everywhere.
func checkAddress(name, address string) error {
	if address == "" {
		return nil
	}
	if net.ParseIP(address) == nil {
		return fmt.Errorf("%s %q is not an address", name, address)
	}
	return nil
}

func checkPort(name string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s %d is out of range", name, port)
	}
	return nil
}

func checkFolder(name, folder string) error {
	if folder == "" {
		return fmt.Errorf("%s is not set", name)
	}
	info, err := os.Stat(folder)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %q is not a folder", name, folder)
	}
	return nil
}

func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

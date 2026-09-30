# go-fs

go-fileserver: FTP, FTPS, SFTP, HTTP, HTTPS and TFTP in a single statically
linked binary, configured from one TOML file, with hot reload and a web
interface for editing it, served by the HTTP server to its admin accounts. The FTP and TFTP servers are a
port of the Node.js [jsftpd](https://github.com/svenbeisiegel/jsftpd); the HTTP
server is a port of an Express one.

## Build

Requires Go 1.27 or newer.

```shell
make build          # the same five binaries, stamped as a dev build
make test           # the test suite
make race           # the test suite under the race detector
make release        # all five release binaries into dist/ with checksums
```

`make release` cross compiles for linux and windows on amd64 and arm64, and for
macOS on arm64. Builds use `CGO_ENABLED=0`, so the binary carries no host
dependencies: on Linux and Windows it is fully static, on macOS it links only
`libSystem` as the operating system requires.

## Versioning

The released version lives in the `VERSION` file, which is the one place to bump
it. The two build targets stamp it differently:

| Target | Version stamped | Artifact |
|---|---|---|
| `make release` | `1.0.0` | `dist/go-fs_1.0.0_linux_amd64`, one per platform |
| `make build` | `1.0.0-dev-20260904-222134` | `dist/go-fs_1.0.0-dev-20260904-222134_linux_amd64`, one per platform |

The two targets differ only in the version they stamp: both cross compile the
same five binaries into `dist/`, with checksums, after emptying it. `make build`
appends `-dev-<YYYYmmdd-HHMMSS>`, so a locally built binary always says when it
was built and can never be mistaken for a release.

Both also copy the documented starter configuration into `dist/go-fs.toml`,
which is the name the binary reads when `-config` is not given, so an unpacked
`dist/` is ready to edit and run. It is the same file the binary embeds and
`-init` writes, so the shipped configuration always matches the build.

`go-fs -version` prints whichever version was stamped, and a plain `go build .`
reports `1.0.0-dev`. Pass `VERSION=` to override for a single build, for example
`make release VERSION=1.1` from a release pipeline.

## Run

```shell
go-fs -init /etc/go-fs.toml     # write a documented starter configuration
$EDITOR /etc/go-fs.toml         # set the folders and the accounts
go-fs -config /etc/go-fs.toml -check   # report configuration problems
go-fs -config /etc/go-fs.toml
```

| Flag | Meaning |
|---|---|
| `-config <path>` | configuration file, `go-fs.toml` by default |
| `-init <path>` | write a documented starter configuration and exit |
| `-check` | load the configuration, report problems and exit |
| `-version` | print the version and exit |

`SIGINT` and `SIGTERM` shut the servers down, dropping open connections and
aborting running transfers.

Serving on ports 21 and 69 needs privileges. Prefer a service manager that binds
them for you, or run on high ports behind a redirect.

## Configuration

One TOML file with a `[general]`, a `[[users]]` list, an `[ftp]`, an `[ftps]`,
an `[sftp]`, an `[http]`, an `[https]` and a `[tftp]` section.
Every key is optional and keeps the documented default when absent, so a
working file can be this short:

```toml
[general]
basefolder = "/srv/files"

[[users]]
username = "john"
password = "doe"
ftp = true

[ftp]
port = 2121

[tftp]
port = 6969
allowWrite = true
```

`general.basefolder` is the folder every server falls back to when its own
section does not name one, which is usually what you want — they all serve the
same tree. It has to be an absolute path and it has to exist. A section that
sets its own `basefolder` keeps it, so one server can be pointed somewhere else
without repeating the folder for the rest.

### Reloading

With `general.reloadConfig` on, which it is by default, the file is checked
every `reloadInterval` seconds and changes are applied without a restart. On
unix `kill -HUP` reloads on demand whether or not the watch is on.

What happens depends on what changed:

| Changed | Effect |
|---|---|
| accounts, permissions, paths, limits, timeouts, the cleanup list | applied to the running server, **nothing is dropped** — a download in flight finishes |
| a port, a `basefolder`, a TLS certificate, an SSH host key | that one server is restarted and its connections drop; the other four are untouched |
| a server switched on or off | it is started or stopped, the others untouched |

A file that does not parse or does not validate is reported at error level and
ignored, so a half-written save cannot take a server down — the last good
configuration keeps serving. The same goes for a change one server rejects, a
malformed authorized key say: that server keeps running as it was while the
others take the new file.

An account is checked again on every request, so a browser session or a live
connection never outlives the rights it was granted by more than the request it
is in.

`go-fs.example.toml` is the fully commented version, and the same file
`-init` writes.

### Accounts

Accounts are one `[[users]]` table each, and every server draws from the same
list: an account is configured once, with one password, and says which servers
it may log in to with `ftp = true`, `sftp = true` and `http = true`, each off
unless set. There is no default account, so a name that is not listed cannot
log in anywhere, and a name is listed once — the same person on FTP and HTTP is
one entry with both switches on. An entry that switches nothing on is kept
without being served, which is the way to park an account.

Each account may have its own `basefolder`, which FTP and SFTP serve instead of
the server's; HTTP scopes an account by `paths` instead. `allowLoginWithoutPassword`
is read by FTP alone, `authorizedKeys` by SFTP alone and `paths` by HTTP alone;
the servers a key does not apply to ignore it.

**The shipped file defines no account.** The examples in it are commented out on
purpose, so a fresh configuration serves nobody until you put a name and a
password of your own in — rather than starting life with the ones printed on
this page. A password that is still one of those is reported at warning level
every time the server starts, as is a configuration file that more than its
owner can read.

Every right an account has is granted explicitly — `allowUserFileCreate`,
`allowUserFileRetrieve`, `allowUserFileOverwrite`, `allowUserFileDelete`,
`allowUserFolderCreate` and `allowUserFolderDelete` all deny when they are not
set, so an account that lists none of them can log in and look around and
nothing more. The rights are one set that holds on every server the account
uses: `allowUserFileDelete = true` lets it delete over FTP, SFTP and HTTP alike.

An operation that does two things needs both rights, and no right reaches
further than its name says:

| Operation | Needs |
|---|---|
| `RMD`, `XRMD`, SFTP `rmdir`, HTTP `DELETE` of a folder | `allowUserFolderDelete`, and the folder has to be empty |
| `RMDA` | `allowUserFolderDelete` **and** `allowUserFileDelete`, since what it removes is files |
| `RNFR`/`RNTO`, SFTP rename, HTTP `MOVE` | `allowUserFileCreate` **and** `allowUserFileDelete`: a rename makes one name and unmakes another |
| `MFMT`, `SITE CHMOD`, SFTP setstat | `allowUserFileOverwrite`, since they change the file |
| HTTP `PUT` of a new name | `allowUserFileCreate` |
| HTTP `PUT` over a file that exists | `allowUserFileOverwrite`; without it the name is taken |
| HTTP `MKCOL` | `allowUserFolderCreate` |
| HTTP `DELETE` of a file | `allowUserFileDelete` |
| HTTP `GET`, `HEAD` and the listing, where an account is required | `allowUserFileRetrieve` — where the request is public no account is asked |

Anonymous access is not a setting of its own, just an account that takes no
password:

```toml
[[users]]
username = "anonymous"
password = ""
ftp = true
allowLoginWithoutPassword = true
allowUserFileRetrieve = true
```

**Upgrading from a file with `[[ftp.users]]`, `[[sftp.users]]` or
`[[http.users]]`:** those tables are not read any more. The file still loads,
with no accounts, and the server says so at warning level on every start. Move
each entry under `[[users]]`, add the switch of the server it was listed under,
and for an HTTP account replace `allowUserFileUpload = true` with
`allowUserFileCreate = true` and `allowUserFolderCreate = true`, and add
`allowUserFileRetrieve = true` if it reads paths that require an account.

Every server confines every request to its base folder. Symbolic links are
resolved before that check, so a link inside the folder cannot be used to reach
out of it, and the base folder itself can never be renamed or removed by a
client.

### The web interface

A browser interface for the whole file. It has no listener of its own: the HTTP
server serves it, at `?go-fs=admin` on any folder it lists, to an account that
sets `isAdmin` and has logged in through the browser.

```toml
[[users]]
username = "root"
password = "..."
http = true
isAdmin = true

[http]
enabled = true
enableAdminInterface = true   # the default
```

Log in on the listing page as that account and an **Admin** button appears in
the header, next to **Log out**; it leads to `https://host:9443/?go-fs=admin`
(the listing also turns `/#/admin` into that address). Nobody else is answered:
a browser with no session is sent to the login page, a session of an account
that does not set `isAdmin` is `403`, and the account's password sent as a
Basic or Digest header is `401` — the interface takes a session established
through the form and nothing else. `enableAdminInterface = false` switches it
off, which a reload applies without a restart.

It shows every section of the configuration as a tab, with the accounts on a
**USERS** tab of their own between GENERAL and FTP, and every repeated table —
`[[users]]`, `[[http.cleanup]]` — as a list of records that can be added to and
removed from. Each record folds up to one line naming it, `john · ftp, http`,
and starts folded, so a long account list reads as a list of names and one
opens to be edited. Each key comes with the comment that documents it in
`go-fs.example.toml`. One **Apply** button writes
the file; the watcher above then applies it, so the same rules hold — accounts
change without dropping anything, a port restarts one server.

The form is generated by reflecting over the configuration struct rather than
written out, so a key added to the file appears in the browser with nothing else
to do.

Three things to know about it:

* **Apply rewrites the file through the TOML writer.** Every key is written out
  explicitly and the comments are lost. The previous file is kept beside it as
  `go-fs.toml.bak`, and the fully commented original is always `-init` away.
* **It is as exposed as the HTTP server is.** The page shows and edits every
  password in the file, so serve it over `[https]`: with `http.enabled = true`
  on an address other than the loopback one, the admin session and every
  password on the page cross the network in the clear, and the server says so
  at startup. Keep the plain port on `127.0.0.1`, or behind a proxy that
  terminates TLS and is listed in `http.trustedProxies`, or off.
* **The file it edits holds every private key.** That is what makes the upload
  below possible, and it is a reason to keep the file at `chmod 600`.

**Upgrading from a file with `general.adminInterfaceEnabled`,
`adminInterfacePort`, `adminUsername` and the other `admin*` keys:** they are
not read any more, and the server says so at warning level on every start.
Give one of the `[[users]]` entries `http = true` and `isAdmin = true`
instead, and reach the interface through the HTTP or HTTPS
port; the old separate listener is gone, and `adminCert`/`adminKey` are what
`https.cert`/`https.key` are for.

Certificates and keys are not typed in. Each of `ftps.cert`, `ftps.key`,
`https.cert`, `https.key` and `sftp.hostkey` comes with:

* **Upload** — pick a `.pem`, `.crt` or `.key` file. The server parses it with
  the same code it uses at startup, so a file it accepts is a file it will start
  with, and refuses the rest by name: a key picked for a certificate box says
  so, and a leftover file path says what to write instead.
* **Generate** — makes a real self-signed pair, or a real host key, instead of
  the throwaway the server makes at every start. Generating a certificate fills
  its private key too. Because it is stored, it survives a restart, and clients
  stop reporting that the host key changed.
* a line under the box saying what is actually stored there — `certificate
  CN=example, expires 2027-01-01`, `ssh-ed25519 host key, SHA256:…` — since
  base64 on its own says nothing.

Neither button writes anything: the value lands on the page, and the single
Apply writes it.

Nothing is written until it would load: what is posted is validated exactly as
the file is at startup, so the page reports what `-check` would report and a
configuration that could not start is never written. A file that cannot be
written says so before anything is edited.

### The FTP data channel

FTP carries its data on a second connection, and which end opens it is the
client's choice. Both are always served; what the configuration decides is the
ports each one uses, which is what a firewall in front of the server has to be
told.

```toml
[ftp]
# passive (PASV, EPSV): the client connects in, on a port out of this range
passiveMinPort = 1024
passiveMaxPort = 1034
# the address a PASV reply names, empty for the one the client connected to
passiveAddress = ""
# active (PORT, EPRT): the server connects out, from this port
activeSourcePort = 0
```

**Passive** takes one port out of the range for the length of a transfer, so
the range should hold at least `maxConnections` ports; a narrower one is
allowed and warned about at startup, and a transfer that finds none free is
refused rather than straying outside it. Open the whole range in the firewall.

**Active** leaves from `activeSourcePort`. `0`, the default, lets the system
pick an ephemeral port, which a firewall cannot name; `20` is the port RFC 959
uses and what a firewall written for active FTP expects, though binding it on
unix needs the privilege for ports below 1024. The socket asks for
`SO_REUSEADDR`, so one fixed port still serves transfers running at the same
time and back to back, which would otherwise collide with the last connection's
`TIME_WAIT`.

**Behind NAT**, in a container or through a port forward, the address the server
sees on its own socket is not the one clients reach it at, and a `PASV` reply
that names it sends them nowhere. `passiveAddress` is what they are told
instead. It has to be IPv4, which is all a `PASV` reply can carry; `EPSV` names
no address at all and needs nothing here.

All of these apply to the next transfer, so changing them — in the file or in
the web interface — never drops a connection.

### Bind addresses and stalled transfers

`ftp.address`, `sftp.address` and `http.address` name the interface each server
binds to, empty for all of them, as `tftp.address` already did. The FTP one
covers the passive data ports too, so they follow the control port onto the same
interface.

`ftp.transferIdleTimeout`, 300 seconds by default, is how long a running
transfer may move nothing before it is dropped. It bounds a stall rather than
the length of a transfer, so a download of any size finishes as long as it keeps
moving, while a client that opens the data connection and then stops reading
gives its connection slot back instead of holding one until it disconnects.
`idleTimeout` does not apply while a transfer is running: a client busy on the
data connection owes nothing on the control one.

### Notable defaults

| Key | Default | Why |
|---|---|---|
| `ftp.allowFtpBounce` | `false` | `PORT`/`EPRT` may only name the connected client, otherwise the server can reach third parties on its behalf (RFC 2577) |
| `ftp.allowForeignDataConnection` | `false` | only the client that asked for a passive port may connect to it |
| `ftp.activeSourcePort` | `0` | the system picks the port an active data connection leaves from, since a fixed one below 1024 needs privilege |
| `ftp.idleTimeout` | `600` | an idle control connection does not hold a slot forever, though a running transfer is never idle |
| `ftp.transferIdleTimeout` | `300` | a transfer that stalls gives its slot back, however long a moving one takes |
| `ftp.loginFailureDelay` | `1` | a wrong password is answered after a second, which slows guessing |
| `http.loginAttempts`, `http.loginLockout` | `5`, `60` | an address that sends five wrong passwords in a minute is refused for a minute, at once |
| `http.trustedProxies` | `[]` | a forwarded address, and a forwarded `https`, is believed only from a proxy listed here |
| `users[].ftp`, `users[].sftp`, `users[].http` | `false` | an account logs in only to the servers it switches on |
| `users[].allowUser*` | `false` | an account is granted only the rights its table lists |
| `sftp.enabled`, `http.enabled` | `false` | both are off by default, so an upgrade never opens a port on its own |
| `tftp.allowWrite` | `false` | read only unless switched on |
| `tftp.maxBlockSize` | `1468` | keeps a block inside a typical ethernet MTU so datagrams are not IP fragmented |
| `tftp.maxTimeout` | `60` | a client cannot negotiate a retransmit interval that pins a transfer slot |
| `tftp.maxConnectionsPerHost` | `5` | one host cannot take every slot |
| `[[users]]` in the shipped file | none | the examples are commented out, so a fresh configuration serves nobody |

## TLS

Set `[ftps] enabled = true` to listen on `ftps.port` and offer `AUTH TLS` on the
plain port. `cert` and `key` hold the certificate and its private key
themselves, base64 of the PEM, the way `sftp.hostkey` does — not paths to files:

```shell
base64 < server.crt | tr -d "\n"    # into cert
base64 < server.key | tr -d "\n"    # into key
```

The web interface does this for you: press **Upload** beside either key and pick
the file. A whole chain in one file is kept whole, and a key protected by a
passphrase is refused, since there is nobody to ask for one at startup.

Keeping the material in the file means the configuration is one file that can be
copied to another host, and go-fs needs no read access outside it. It also means
the file holds private keys as base64, which is *encoding, not encryption*: it
deserves the permissions a private key deserves, `chmod 600` and an owner that
is not shared.

`-check` decodes both halves and matches them against each other, so a truncated
paste, a key put into the certificate key, or a key belonging to a different
certificate is reported by name before the server tries to serve it.

`PROT P`, which asks for the data connection to be protected, is refused on a
plaintext control connection: answering it there would promise exactly what the
server then cannot deliver, and the client would send its data in the clear
believing otherwise.

`[ftps]` is a section of its own only because TOML tables are top level: it
configures the same server, which serves the folders, accounts and limits of
`[ftp]` on both listeners. The two `enabled` switches are independent, so
`ftp.enabled = false` with `ftps.enabled = true` serves implicit FTPS with
nothing on the plaintext port.

With `cert` and `key` empty the server generates a self-signed certificate at
startup and says so. That certificate changes on every restart and proves no
identity; it is there so the TLS interface works out of the box for a test, not
for production.

## SFTP

SFTP is the file transfer subsystem of SSH, so `[sftp]` runs an SSH server. It
serves only that subsystem: a `shell` or `exec` request is refused, and there is
no way to run anything on the host through it.

```toml
[[users]]
username = "john"
password = "doe"
sftp = true
allowUserFileRetrieve = true

[[users]]
username = "max"
sftp = true
authorizedKeys = ["ssh-ed25519 AAAAC3Nz... max@laptop"]
allowUserFileRetrieve = true
allowUserFileCreate = true

[sftp]
enabled = true
port = 2222
basefolder = "/srv/sftp"
hostkey = ""
```

The accounts are the `[[users]]` entries that set `sftp = true`. An account
authenticates with a password, with a public key, or with either when both are
configured. `authorizedKeys` entries are `authorized_keys` lines, the content
of an `id_*.pub` file. `allowLoginWithoutPassword` means nothing here — SSH has
no anonymous login — so an account needs a password or a key, and one with
neither is refused at startup rather than left unusable.

The host key lives in the configuration itself rather than in a separate file,
as every certificate and key here does: `hostkey` is base64 of its PEM encoding,
on one line. With it empty a key is generated at every start, which makes every
client report a changed host key, so set it for anything but a first look —
with **Generate** in the web interface, or by hand:

```shell
ssh-keygen -q -t ed25519 -N "" -f hostkey && base64 < hostkey | tr -d "\n"
```

## HTTP

`[http]` serves the folder over HTTP: `GET` browses and downloads, `PUT`
uploads, `DELETE` removes, `MKCOL` creates a folder and `MOVE` renames one entry
in place. `[https]` is the same server on a TLS port, with `cert` and `key`
holding the material as in `[ftps]`, and the two `enabled` switches are
independent.

Browsing it in a browser gives a listing that sorts on any column, filters as you
type, and — for an account that holds the rights — uploads by drag and drop,
creates folders, renames and deletes. It needs no assets from anywhere: the page
carries its own style and script, so every URL the server answers stays a path in
`basefolder`. Without JavaScript the listing still renders and the column headers
still sort, as ordinary links.

Access has two layers, which is what the Express server it replaces did:

```toml
[[users]]
username = "john"
password = "doe"
http = true
paths = ["^/private/.*"]
allowUserFileRetrieve = true
allowUserFileCreate = true
allowUserFileOverwrite = true
allowUserFolderCreate = true
allowUserFileDelete = true
allowUserFolderDelete = true

[http]
enabled = true
port = 9080
basefolder = "/srv/http"
methodsRequireAuth = ["PUT", "DELETE", "POST", "MKCOL", "MOVE"]
pathsRequireAuth = ["^/private/.*"]
httpSessionTokenLifetime = 3600
httpSessionTokenSecret = ""
loginAttempts = 5
loginLockout = 60
trustedProxies = []
```

A request is **public** unless its method is in `methodsRequireAuth` or its path
matches one of `pathsRequireAuth`. Anything else has to be answered by one of
the `[[users]]` entries that set `http = true`, and that account's own `paths`
then decide what it may reach, and its rights what it may do there: the same
`allowUser*` flags as on the other servers, mapped as the table under Accounts
says — `allowUserFileCreate` for a `PUT` of a new name, `allowUserFileOverwrite`
for a `PUT` over a file that exists, `allowUserFolderCreate` for `MKCOL`,
`allowUserFileDelete` and `allowUserFolderDelete` for `DELETE` of the one or
the other, create and delete both for `MOVE`, and `allowUserFileRetrieve` for
reading and listing, all false unless set. A public `PUT` never replaces a file
whoever is signed in; that takes the right. A path an account may not reach is
`403`, not another challenge.

`MKCOL` and `MOVE` do not have to appear in `methodsRequireAuth`: `MKCOL` is
protected wherever `PUT` is and `MOVE` wherever `PUT` or `DELETE` is, so a
configuration written before those methods existed still covers them.

`paths` are matched against the request path **after** it has been normalized,
so `/private/../secret` is tested as `/secret` and cannot be used to slip past a
pattern. A pattern is tested against the path both with and without a trailing
slash, so `^/private/.*` covers the listing of `/private` itself and not only
what is inside it — a listing names every file in the folder, so it cannot be
the one public thing about it.

Both Digest and Basic authentication are accepted, and a **program** is
challenged exactly as it always was: the challenge offers Digest, with SHA-256
for Chromium and Firefox and MD5 for everything else, which is what those
clients handle; `realm` is hashed into the response, so changing it makes saved
credentials stop matching. A digest response is bound to the path it was made
for and to a nonce that is good for five minutes, so a header captured off the
wire cannot be turned on another path or replayed later; a client that still has
the credentials answers the stale challenge without asking anyone. `curl -u`,
scripts and the legacy client are unaffected by everything below.

**Wrong passwords are counted per client address.** The login form, Basic and
Digest share one count: an address that sends `loginAttempts` of them inside
`loginLockout` seconds is refused for that long, at once and without a look at
what it sent. A program is answered `429` with `Retry-After`, and no challenge,
since a challenge asks for the very thing the lock refuses to read; a browser
is sent to the login page, which says so. A stale digest nonce is not a wrong
password and is not counted, a right password clears the count, and a session
token is never refused, so someone logged in behind the same address as a
guesser keeps their login. `loginFailureDelay` still holds every counted
failure for a second; the lock is what bounds how many of those one address
can cause. `loginAttempts = 0` switches the lock off.

The credential check takes the same time whichever name is sent: the name and
the password are compared for every account, so an account that exists is
refused no faster than one that does not.

### Logging in from a browser

Any HTTP account may log in through the page; programs keep using Basic or
Digest and are handed no session they did not ask for. A browser that has
to authenticate is sent to a login form of this server's own instead of being
challenged, so its native password box never appears: a `401` has to carry
`WWW-Authenticate` (RFC 9110 §15.5.2), and that header is precisely what raises
that box, so the answer is a redirect to a page that comes back `200`. The page
carries a **Log in** button when nobody is signed in, and the account name and a
**Log out** button when somebody is — and, for an account that sets `isAdmin`,
an **Admin** button that opens the web interface described above.

A browser is recognised by `Sec-Fetch-Mode`, which every current browser sends on
every request and no program sends, falling back to `text/html` in `Accept` for a
browser too old for it. A client that sends `X-Disable-Session` is treated as a
program. Where the configuration has no HTTP account at all there is nobody to
log in as, so there is no login page and a browser is challenged as a program is.

The login and logout endpoints have no paths of their own: they are
`?go-fs=login` and `?go-fs=logout` on the path being asked for. Every URL this
server answers is a path in the served folder — which is also why the page's
style and script are inlined rather than fetched — so a `/login` would shadow a
real name, while a query key can shadow nothing. It is also why there is no
`next` parameter to get wrong: the login page for `/private/` *is* `/private/`.

A successful login is carried by a **JSON Web Token** (RFC 7519) signed with
HMAC-SHA256 (RFC 7515) in the `goFsSessionToken` cookie, which is `HttpOnly`,
`SameSite=Lax` and `Secure` over TLS, scoped to `/`. The token carries
`iss`, `sub` (the account name), `aud`, `iat`, `nbf`, `exp`, `jti` and a
fingerprint of the credentials — and **nothing else**. It deliberately does not
carry the paths or the rights: those are looked up from the configuration as it
stands on every request, so a token can never reach further than the account
behind it does right now, and a `paths` narrowed by a reload takes effect at
once. Verification pins the algorithm to HS256, so a token that says `alg: none`
or names an asymmetric algorithm is refused rather than trusted.

`httpSessionTokenLifetime` is how long a login lasts, one hour by default. It
matters, because a signed token cannot be withdrawn once it is out: logging out
clears the browser's own copy, but a stolen token works until it expires. The
three things that do cut one short are that lifetime, changing the account's
password — which changes the fingerprint, so every browser logged in under the
old one is signed out — and removing the account.

**Behind a reverse proxy**, list it in `trustedProxies`, as an address or a
CIDR range. A request from one of them is recorded, counted and locked under
the client named in `X-Forwarded-For` — the rightmost entry that is not itself
a listed proxy, since the leftmost is whatever the client wrote — and
`X-Forwarded-Proto: https` marks the session cookie `Secure`, as the server's
own TLS listener does. From any other address both headers are the client's
word and are ignored, so without the setting every client behind a proxy
shares the proxy's address and the cookie is only `Secure` on `[https]`.

A browser that still remembers Basic credentials from before the login form
existed sends them with everything. Beside a session for the same account they
count as that session, so the page offers its logout and the admin interface
opens; beside a session for another account, or none, the header is what it
always was.

`httpSessionTokenSecret` is the signing key, base64 of at least 32 random bytes:

```
head -c 32 /dev/urandom | base64
```

Leave it empty and a key is generated at every start, which is enough for a look
around but logs every browser out on a restart and stops two hosts serving the
same folder from sharing a login. Changing it needs a restart, as the TLS
certificate does. The web interface will generate one for you.

`http.sessionTimeout` was what this used to be called, before the session became
a token that expires rather than a row in memory. A file that still sets it
loads, and says on startup that it is ignored.

`[[http.cleanup]]` keeps a folder from growing without bound: once an hour
everything but the newest `keep` files in it is removed. It is the one thing in
go-fs that deletes without a client asking, so every removal is logged.

## Logging and diagnostics

Everything the program has to say goes to **standard output**, one record per
line, so whatever runs it — a terminal, systemd, a container — collects the log
the way it collects any other program's. Nothing is written to a file by go-fs
itself. Errors that stop it from starting at all, a configuration that does not
parse say, go to standard error before any logger exists.

```toml
[general]
logLevel = "info"    # debug, info, warn, error
logFormat = "text"   # text or json
```

`logFormat = "json"` writes one JSON object per line for a log collector;
`text` is `key=value` for a person. `logLevel` can be **changed without a
restart**: edit the file, and the watcher applies the new level within
`reloadInterval` seconds (`kill -HUP` applies it at once). That is the way to
look at a problem on a running server — switch to `debug`, reproduce, switch
back. `logFormat` needs a restart, and a reload that changes it says so. (An
older file's `[log]` section with `level` and `format` is ignored, and the
server says so at startup.)

What each level holds:

| Level | What is written |
|---|---|
| `error` | a server that cannot start or reload, a request handler that panicked, a file operation that failed on the server's side |
| `warn` | a generated (temporary) certificate, host key or session secret; a certificate that has expired or expires within 30 days; a configuration key this version no longer reads; a password out of the documentation; a request from another origin; an FTP passive port that cannot be opened |
| `info` | startup with the version, Go version, platform, PID and configuration path; every listener; every reload and what it changed; every login, logoff, refused login and refused connection; every download, upload, delete, mkdir, rename and chmod, with the account, the file, the byte count and how long it took; every transfer that failed and why; every TFTP request that was refused and why; shutdown with the signal that caused it |
| `debug` | the protocol trace: every FTP command and reply (the password masked), every SFTP request, every HTTP request and response with status, size and duration, every TFTP packet exchange, every connection as it comes and goes, and the reason behind every refusal. Every debug record carries `source=file.go:line`, which says where in the program it was written |

Records are structured: a message and `key=value` attributes. The attributes
are consistent across the servers, so `grep user=alice` or `jq 'select(.user
== "alice")'` finds everything one account did whichever protocol it used, and
`client=` on a connection scoped record ties a session's trace together:

```
time=2026-09-17T14:32:01.123+02:00 level=INFO msg="ftp login" client=10.0.0.5:51234 user=alice address=10.0.0.5 total=1
time=2026-09-17T14:32:04.456+02:00 level=INFO msg="ftp upload" client=10.0.0.5:51234 user=alice file=/in/report.pdf bytes=182044 address=10.0.0.5 took=312ms
time=2026-09-17T14:32:09.789+02:00 level=INFO msg="ftp data connection failed" client=10.0.0.5:51234 user=alice mode=passive timeout=30s error="the data connection was not established"
```

Things worth knowing when reading a log:

- **A refused password is `info`**, under `ftp login refused`, `sftp login
  refused` and `http login refused`, with the account name and the address it
  came from. The reason — no such account, wrong password, an account that
  only has keys — is only in the `debug` trace, since the client is never told
  either. An SSH key that is not authorized is `debug` too, with its
  fingerprint, because a client offers every key it has before the right one;
  a client that runs out of keys and gives up shows as `sftp connection closed
  by authenticating client`.
- **`ftp data connection failed`** is nearly always a firewall or a NAT between
  the two ends. `mode=passive` means the client could not reach a port in
  `passiveMinPort`–`passiveMaxPort`; `mode=active` means the server could not
  reach the client. See [The FTP data channel](#the-ftp-data-channel).
- **`tftp request refused`** names the file and the reason, since TFTP has no
  login and a client that "cannot get the file" is otherwise invisible.
  `tftp transfer failed` says how far a transfer got and why it stopped.
- **`http response`** at `debug` is the access log: method, path, status, bytes
  and duration for every request, including the ones that never reached a
  handler.
- **`the configuration file changed but says the same thing`** is what a save
  that touched nothing looks like; `applying the changed configuration
  sections=ftp,log` names what did change.
- The SFTP host key fingerprint and the TLS certificate's subject, names and
  expiry are logged at startup, so a client's complaint about either can be
  checked against what the server actually serves.

A crash prints Go's panic and stack trace to standard error; a panic inside an
HTTP request handler is recovered by the server and logged at `error` with the
stack trace, so the request fails but the server keeps running.

## What is implemented

**FTP** — RFC 959 with RFC 2228 (`AUTH`, `PBSZ`, `PROT`), RFC 2389 (`FEAT`,
`OPTS`), RFC 2428 (`EPRT`, `EPSV`, `EPSV ALL`), RFC 3659 (`MLST`, `MLSD`,
`MDTM`, `SIZE`, `REST`) and the RFC 775 `X` aliases:

```
ABOR ACCT ALLO APPE AUTH CDUP CLNT CWD DELE EPRT EPSV FEAT HELP LIST MDTM MFMT
MKD MLSD MLST MODE NLST NOOP OPTS PASS PASV PBSZ PORT PROT PWD QUIT REST RETR
RMD RMDA RNFR RNTO SITE SIZE STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD
XPWD XRMD
```

`SITE CHMOD` and `SITE HELP` are the implemented `SITE` subcommands.

**SFTP** — version 3 of the SFTP protocol over SSH, through
`golang.org/x/crypto/ssh` and `github.com/pkg/sftp`: open, read, write, append,
truncate, directory listing, stat, rename, remove, mkdir, rmdir and setstat.
Creating symbolic links is refused, because a link is the one thing that could
point out of the base folder.

**HTTP** — `GET` for downloads and a browsable listing, `PUT` for
`application/octet-stream` and multipart uploads, `DELETE` for a file or an
empty folder, Basic (RFC 7617) and Digest (RFC 7616, with the RFC 2069 form)
authentication, browser login with a signed session token (JWT, RFC 7519), and
the legacy `dls_directory_reader` listing endpoint. Downloads answer range requests, so a large one can be resumed.

**TFTP** — the protocol has no accounts and no passwords and no way to carry
them, so anyone who can reach `tftp.port` can read what `allowRead` allows and
write what `allowWrite` allows. It is on by default, read only, because that is
what the implementation it replaces did; turn it off unless the network it sits
on is one where that is what you want. An upload is written beside its
destination and renamed over it when it completes, so a transfer that breaks off
leaves neither an empty file nor a truncated one.

RFC 1350 in `octet` and `netascii` mode, with the option extension of
RFC 2347, the `blksize`, `timeout` and `tsize` options of RFC 2348 and RFC 2349,
and windowed reads per RFC 7440.


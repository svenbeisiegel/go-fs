# go-fs

go-fileserver: FTP, FTPS, SFTP, HTTP, HTTPS, an S3 compatible API and TFTP in a
single statically linked binary, configured from one TOML file, with hot reload
and a web interface for editing it, served by the HTTP server to its admin
accounts.

## Build

Requires Go 1.27 or newer.

```shell
make build          # the same five binaries, stamped as a dev build
make test           # the test suite
make race           # the test suite under the race detector
make release        # all five release binaries into dist/ with checksums
make sign           # signed .update files for the binaries in dist/
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

With the signing key in `GOFS_SIGNING_KEY`, `make release` also writes a signed
`dist/go-fs_1.0.0_linux_amd64.update` next to each binary: the file a running
go-fs accepts as an update over HTTP (see [Updating over HTTP](#updating-over-http)).
The release workflow refuses to run without the key.

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
it may log in to with `ftp = true`, `sftp = true` and `http = true`, whether
it may use the [S3 API](#s3) with `s3 = true`, and whether it may push to the
[container registry](#container-registry) with `registry = true`, each off
unless set. There is no default account, so a name that is not listed cannot
log in anywhere, and a name is listed once — the same person on FTP and HTTP is
one entry with both switches on. An entry that switches nothing on is kept
without being served, which is the way to park an account.

Each account may have its own `basefolder`, which FTP and SFTP serve instead of
the server's; HTTP scopes an account by `paths` instead. `allowLoginWithoutPassword`
is read by FTP alone, `authorizedKeys` by SFTP alone and `paths` by HTTP and S3;
the servers a key does not apply to ignore it. The container registry reads
neither `paths` nor the rights below: `registry = true` is the whole of what an
account may do there.

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
| S3 `GetObject`, `HeadObject`, the listings | `allowUserFileRetrieve`; a listing leaves out what `paths` do not reach |
| S3 `PutObject`, and completing a multipart upload | `allowUserFileCreate` for a new key, `allowUserFileOverwrite` for one that exists |
| S3 `PutObject` of a key ending in `/` | `allowUserFolderCreate` |
| S3 `DeleteObject` | `allowUserFileDelete`, or `allowUserFolderDelete` for a key ending in `/` |
| S3 `CopyObject`, `UploadPartCopy` | `allowUserFileRetrieve` on the source, and create or overwrite on the target |
| Registry push, tag and delete | `registry`; the rights above do not apply |
| Registry pull | nothing while `http.registryAnonymousRead` is on, `registry` when it is off |

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
| `users[].ftp`, `users[].sftp`, `users[].http`, `users[].s3` | `false` | an account logs in only to the servers it switches on |
| `http.enableS3` | `true` | the S3 API is there wherever the HTTP server is, and serves only the accounts that set `s3` |
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
creates folders, renames and deletes. Each row has an options menu with
**Download** — a folder downloads as one `.tar.xz` — and, where the account may,
**Rename** and **Delete**. It needs no assets from anywhere: the page
carries its own style and script, so every URL the server answers stays a path in
`basefolder`. Without JavaScript the listing still renders and the column headers
still sort, as ordinary links.

Access has two layers:

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
shareLinkSecret = ""          # generated at the first start, see "Sharing a file"
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

Both Digest and Basic authentication are accepted. A **program** is challenged
with Digest, using SHA-256 for Chromium and Firefox and MD5 for everything
else, which is what those clients handle; `realm` is hashed into the response, so changing it makes saved
credentials stop matching. A digest response is bound to the path it was made
for and to a nonce that is good for five minutes, so a header captured off the
wire cannot be turned on another path or replayed later; a client that still has
the credentials answers the stale challenge without asking anyone. `curl -u`
and scripts are unaffected by everything below.

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

### Bearer tokens

A script or an API client can use a **bearer token** instead of an account.
Tokens are listed under `[[tokens]]` and managed on the **TOKENS** tab of the
admin interface, next to USERS:

1. Give the token a name and a lifetime in days; `0` means it never expires.
2. The page shows the new token once. Copy it before pressing **Apply**, which
   writes the entry. The file holds only the token's SHA-256 hash, so a lost
   token has to be replaced; it cannot be recovered.

Clients send the token as a header, on the plain port and the TLS port alike:

```sh
curl -H "Authorization: Bearer gofs_…" https://host:9443/reports/today.csv
curl -H "Authorization: Bearer gofs_…" -T build.zip https://host:9443/uploads/build.zip
```

What a token may do is set on its own entry:

- **Rights:** the same `allowUser*` rights as an account.
- **`paths`:** regular expressions matched against the request path. A token
  with no pattern can reach nothing.
- **`expires`:** an RFC 3339 time. Edit it to extend a token, or clear it to
  make the token permanent.

Only the HTTP server accepts tokens. FTP, SFTP and TFTP never see them.

A token is not a session, so it cannot open the admin interface. It also
counts in the login lock: an unknown token is counted as a wrong password.

An unknown or expired token is answered `401` with
`WWW-Authenticate: Bearer error="invalid_token"`, even on a public path, so the
client learns that its token is not accepted.

Removing a token from the file revokes it within one reload.

### S3

The HTTP server also answers the **S3 API**, on its plain port and its TLS port
alike, so that S3 clients such as the aws CLI, rclone and the AWS SDKs can use
the served folder. It is on by default with
`http.enableS3 = true`; each account that should use it sets `s3 = true`:

```toml
[[users]]
username = "backup"      # the access key
password = "…"           # the secret key
s3 = true
paths = ["^/backups/.*"]
allowUserFileRetrieve = true
allowUserFileCreate = true
allowUserFolderCreate = true
```

| | |
|---|---|
| Endpoint | `https://host:9443` (or the plain port) |
| Buckets | every folder directly in `http.basefolder`, by its name ignoring case |
| Region | `us-east-1`, the one region, fixed |
| Access key / secret key | the account's `username` / `password` |
| Addressing | path style only: `https://host:9443/<folder>/<key>` |

Each folder directly in `http.basefolder` is a bucket holding that folder exactly
as HTTP shows it: `s3://docs/a.txt` is the file served at `/docs/a.txt`, and the
account's `paths` are matched against that same path. A file directly in
`http.basefolder` is in no bucket and cannot be reached over S3. A bucket name is
matched against the folder names ignoring case, so `s3://docs/` reaches the
folder `Docs`, and the folder is named as it is spelled on disk in every answer.
Where two folders differ in case only, the one spelled as asked wins, and
otherwise the first by name. `ListBuckets` lists the folders the account's
`paths` reach. Its rights mean what they mean everywhere else, so an account has
the same reach over S3 as over HTTP. The region is shown read-only on the HTTP
tab of the admin interface and cannot be changed. Buckets cannot be created or
removed over S3: make or remove the folder instead. `s3` is independent of `http`: an
account that sets only `s3` cannot log in to the page or send Basic credentials.

Only requests signed with AWS Signature Version 4 are S3 requests, in the
`Authorization` header or as a presigned URL. Everything else is served as it
always was, so a bucket's folder is still reached as `/docs` over HTTP, and
nothing is public over S3. A request signed for another region is refused
with the answer AWS gives, which tells the SDKs to sign for `us-east-1`.
Signatures are checked against the clock with 15 minutes of slack, and a wrong
secret key counts against the address in the same lock as a wrong password.

Clients have to be set to path style and to the region. For example:

```shell
aws configure set default.s3.addressing_style path
aws --endpoint-url https://host:9443 --region us-east-1 s3 ls
aws --endpoint-url https://host:9443 --region us-east-1 s3 ls s3://backups/
aws --endpoint-url https://host:9443 --region us-east-1 s3 cp report.pdf s3://backups/2026/
```

Version 1 of the aws CLI presigns URLs with Signature Version 2 unless told
otherwise, so `aws s3 presign` needs
`aws configure set default.s3.signature_version s3v4` there; version 2 of the
CLI signs with version 4 already.

```ini
# rclone.conf
[go-fs]
type = s3
provider = Other
endpoint = https://host:9443
region = us-east-1
force_path_style = true
access_key_id = backup
secret_access_key = …
```

What is served:

- **Reading.** `ListBuckets`, `HeadBucket`, `GetBucketLocation`,
  `ListObjects` and `ListObjectsV2` (with `prefix`, `delimiter`, paging and
  `encoding-type=url`), `GetObject` with ranges and conditions, `HeadObject`,
  and presigned downloads.
- **Folders.** A folder is a common prefix in a listing. `PutObject` of an empty
  key ending in `/` creates one, as every S3 client does. A folder with nothing
  in it is listed as that `folder/` key.
- **Uploading.** `PutObject`, and multipart upload with `UploadPart`,
  `UploadPartCopy`, `ListParts`, `ListMultipartUploads`, `Complete…` and
  `Abort…`. The body may be signed, unsigned or `aws-chunked` with or without
  chunk signatures. `Content-MD5` and the `x-amz-checksum-*` of CRC32, CRC32C,
  CRC64NVME, SHA-1 and SHA-256 are verified, whether they come as a header or
  as a trailer. An upload is staged in `http.uploadStagingFolder` and only
  moved into place once every hash matches; `maxUploadSize` applies.
  Unfinished multipart uploads are swept after 24 hours.
- **Renaming.** S3 has no rename. Clients rename with `CopyObject` (or
  `UploadPartCopy` for a large file) and a `DeleteObject`, and rename a folder
  one key at a time. Here too the data is copied, so renaming a large folder
  takes as long as copying it, and it needs `allowUserFileRetrieve`, create and
  delete. An account without the delete right is left with the copy.
- **Deleting.** `DeleteObject` and `DeleteObjects`. A folder is removed only
  when it is empty. When a delete leaves the folders above it empty, they are
  removed as well for an account with `allowUserFolderDelete`: that is how a
  folder behaves in S3, and it is what makes a renamed folder disappear from
  its old place.

What is not served: virtual-hosted addressing (`main.host`), versioning, ACLs,
policies, tagging and object lock, which are answered `NotImplemented`; user
metadata, which is accepted and not stored; and Signature Version 2, which is
not taken for an S3 request at all.

- **ETags.** A listing, `HeadObject` and `GetObject` give each file an ETag
  derived from its size and modification time, in the multipart form
  `"…-1"`, so that clients do not take it for an MD5. The ETag of an upload is
  the MD5 of what arrived, and the ETag of a completed multipart upload is
  S3's own form for one.
- **Listing without a delimiter.** This reads every folder below the prefix
  and sorts the result, so on a very large tree it is slow.
- **The password is the secret key.** Changing it breaks every client
  configured with the old one. SigV4 never sends the key, but a request
  captured over plain HTTP allows a password to be guessed offline, as a Digest
  response does, so give S3 accounts long random passwords and use the TLS
  port.

### Container registry

The HTTP server can also be a **container registry**: docker, podman, buildx,
crane and every other client of the
[OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)
v1.1 push images to it and pull them from it, on its plain port and its TLS
port alike. It is off until `http.registryBaseFolder` names the folder the
registry keeps its images in; each account that should push sets
`registry = true`:

```toml
[http]
enabled = true
registryBaseFolder = "/srv/registry"
registryAnonymousRead = true

[[users]]
username = "ci"
password = "…"
registry = true
```

```shell
docker login host:9443
docker tag app:latest host:9443/team/app:1.0
docker push host:9443/team/app:1.0
docker pull host:9443/team/app:1.0
```

| | |
|---|---|
| Endpoint | `host:9443` (or the plain port), under `/v2/` |
| Storage | `http.registryBaseFolder`, which nothing else may serve |
| Pulling | anyone while `http.registryAnonymousRead = true` (the default), otherwise an account that sets `registry` |
| Pushing, tagging, deleting | an account that sets `registry` |
| Credentials | a token from `/v2/_token`, fetched with the account's username and password as `docker login` does, or HTTP Basic on every request |

The folder has to exist, and it must be none of the folders the servers serve,
nor hold one or lie inside one: go-fs refuses to start with it otherwise, and
`-check` says why. Everything in it is managed by the registry, which addresses
content by its digest alone, so a layer that several images, architectures or
repositories share is stored once. While the registry is on it answers every path under `/v2`, so a folder
`v2` in `http.basefolder` cannot be reached over HTTP; go-fs says so at warning
level. Both settings take effect on a reload.

`registry` is independent of `http`: an account that sets only `registry`
cannot reach the file tree, and an `http` account that does not set it may
pull where pulling is public and is refused with `403` where it is not.

Clients log in the way every public registry has them do: `/v2/` answers
`401` with a `Bearer` challenge that names `/v2/_token`, the client fetches a
token there, with the username and password it was given by `docker login` or
without any, and sends the token with every request after. A token without an
account pulls where pulling is public; a token of an account that sets
`registry` does everything. Tokens are signed with the key of the browser
sessions, `http.httpSessionTokenSecret`, but cannot stand in for one, and are
accepted for five minutes; changing the account's password ends them at once.
A request may also carry Basic credentials itself, which is what `curl -u`
sends. A wrong password counts against the address in the same lock as
everywhere else, so `docker login` with a wrong one fails as it should.

**Several architectures under one tag.** A tag names either an image for one
platform or an index that lists one image per platform, which is what
`docker buildx build --platform linux/amd64,linux/arm64 --push` pushes and what
a pull picks the right image from. go-fs also builds that index itself: an
image pushed to a tag that holds an image for another platform joins it in an
index instead of replacing it, so images built on an amd64 and an arm64
machine and pushed separately end up under one tag:

```shell
# on an amd64 machine
docker push host:9443/team/app:1.0
# on an arm64 machine
docker push host:9443/team/app:1.0
docker manifest inspect host:9443/team/app:1.0   # lists linux/amd64 and linux/arm64
```

The platform comes from the image's configuration. An image for a platform
the tag already holds replaces that entry and the attestations buildx attached
to it; an index that is pushed, and an artifact that is not an image, replace
the tag as they are. The push is answered with the digest of what was pushed,
and the tag then names the index, which the registry keeps only for as long as
a tag points to it.

**Browsing the registry.** While the registry is on, the listing has a
**Registry** button next to **Log in**. It opens a page that looks like the
listing and has its own **Files** button to go back. By default the page lists
every tag on a row of its own, such as `my-company/tool:1.2.3`. **Folders**
shows namespaces and repositories as folders instead, and opening a
repository shows its tags. Each tag carries a badge for every architecture it
holds (`amd64`, `arm64`, `arm/v7`; the OS is only shown when it is not Linux),
and the columns can be sorted by name, push time and size. The options menu
of a tag offers:

- **Details:** digests, media types, push time, sizes, the configuration and
  layers of each platform, and the other tags on the same image.
- **Copy pull command.**
- **Push to registry…:** copies the tag to another registry (see below).
- **Delete tag:** only for a session of an account that sets `registry`.

**Copying images between registries.** With a session of an account that
sets `registry`, the page can also copy images to and from other registries.
Each dialog takes the image (name and tag) and an optional login, and has to
be **validated** before anything is copied: Validate reaches the other
registry with that login and lists the architectures there are to copy, all
ticked. Untick the ones to leave out, then press Pull or Push. Changing the
image or the login takes the validation back. With every architecture ticked
the image is copied as it is and keeps its digest; with some left out, only
those that are ticked (and their attestations) are copied, into an index of
their own with a digest of its own. The server does the copying itself, in
the background: the dialog shows how many blobs and bytes have been moved, can
stop the transfer, and may be closed while it runs; the banner then says how
it ended.

- **Pull image** (top right) fetches an image such as
  `docker.io/library/nginx:1.27`, `ghcr.io/org/app:v1` or
  `registry.example.com:5000/team/tool:v2@sha256:…` into this registry.
  References are read as docker reads them: `nginx` is
  `docker.io/library/nginx:latest`. The image is stored under the path of its
  reference without the registry, `library/nginx:1.27` and `org/app:v1` here,
  and replaces what that tag held. Validate lists the architectures the image
  offers, and the pull fetches the very image that was validated, even if the
  tag moves in between.
- **Push to registry…** copies a tag to the image named, prefilled with the
  tag's own name: put the registry in front, `ghcr.io/my-org/team/app:1.0`,
  or change the name and tag as well. Validate proves that the login may push
  there, says whether the tag is there already, and lists the architectures
  of the tag here. Blobs the other registry already has are not sent again.

Both take an optional username and password (or access token) for the other
registry; they are used for that one transfer, never stored and never logged.
The other registry is reached over HTTPS unless the address starts with
`http://`, as it may for a test registry on `localhost`. **Validate
Connection**, ticked by default, checks the other registry's TLS certificate
as any client would; untick it to accept whatever certificate it shows, a
self-signed one or one of an internal CA (`"skipVerify": true` in the body of
the endpoints, which validate when it is left out). Changing it takes the
validation back like the login does. Blobs are checked
against their digests, and `maxUploadSize` applies to each as it does to a
push. Note that the server connects to whatever host is typed in, from its own
network: give `registry` only to accounts that may do that.

**Importing image archives.** **Import** (top right) stores the images of an
archive that a tool wrote to a file instead of pushing them, so no docker
daemon is needed in between. Pick the file there and it is uploaded in chunks
of `maxChunkSize` (one piece when that is `0`), or use **Import into
registry…** in the options menu of an archive in the listing, which reads that
file where it is; for this the account also needs the right to download that
file. The archive may be a plain tar or compressed with gzip, zstd, xz or
bzip2, and is in one of two formats:

| Format | Written by | Stored as |
|---|---|---|
| OCI image layout (`oci-layout`, `index.json`, `blobs/`) | `docker save` 25 and later, `docker save` with the containerd image store, `ctr images export` (the tool to use on a Kubernetes node, as `crictl` has no export), `nerdctl save`, `podman save --format oci-archive`, `skopeo copy … oci-archive:`, `buildah push … oci-archive:`, a tar of a `crane pull --format oci` folder | as it is: manifests and indexes keep their digests, signatures stay valid |
| `docker save` (`manifest.json`) | `docker save` before 25, `podman save` (`docker-archive`, also `-m`), `skopeo copy … docker-archive:`, `crane pull` (`tarball` and `legacy`), k3s and RKE2 airgap bundles | with a manifest the registry builds, since the archive has none: the image gets a digest of its own, and layers are kept as the archive has them, uncompressed for `docker save` |

The server reads the archive once, checking every blob against its digest,
and then lists the images it found: their names, the architectures of each,
and the `repository:tag` each would be stored under, which is the name the
archive gives without the registry, as a pull names it
(`docker.io/library/alpine:3.20` becomes `library/alpine:3.20`). A tag alone,
as `skopeo` writes it, goes with the archive's file name. Change the targets,
add tags, untick images or architectures, then press Import. An index whose
architectures the archive holds only some of, as `ctr images export` leaves
it without `--all-platforms`, is stored with those, in an index of its own.
Up to 30 minutes are given for that choice before what was read is let go.
Nothing is stored until it is made, and the blobs and manifests then go in
together, so a cleanup in between never takes half an image. What is not an
image archive is named as such: the file system of a container
(`docker export`, `crane export`), a zip, a Singularity image, a `dir:` copy of
skopeo, a save of a Docker older than 1.10. `maxUploadSize` applies to the
uploaded archive and to each file in it. The uploaded archive and what was
read are kept under `registryBaseFolder/_uploads` while the import runs and
removed when it ends.

Who may see the page follows who may pull. With
`http.registryAnonymousRead = false` a visitor is sent to the login page
first. The form then also accepts accounts that set only `registry`; their
session reaches the registry page and nothing in the file tree.

What is served:

- **Pulling.** Manifests by tag or digest, blobs with ranges, the tag list and
  the `_catalog` of repositories, both paged with `n` and `last`, and the
  referrers of a manifest with the `artifactType` filter.
- **Pushing.** Blob uploads in one request, in chunks with `Content-Range`, or
  streamed in one `PATCH` as docker sends them, and mounted from another
  repository. Every blob is checked against its digest before it is stored,
  SHA-256 and SHA-512 alike. `maxUploadSize` applies to a blob as a whole,
  `maxChunkSize` does not. Manifests are the OCI image manifest and index and
  Docker's schema 2 manifest and manifest list; a manifest is refused while a
  blob or manifest it refers to is not in the repository.
- **Deleting.** A tag, a manifest with the tags pointing to it, and a blob.

Cleanup runs with the hourly sweep: an upload nothing has been added to for
24 hours is removed, and so is a blob that no manifest of any repository refers
to and that has not been pushed or mounted in the last 24 hours. A manifest
stays until it is deleted, tagged or not: an image a newer push has taken the
tag from can still be pulled by its digest, and its blobs are kept for it.
An account that sets `registry` can also run it at once with **Clean up** on
the registry page (`POST ?go-fs=registry-cleanup`), which answers with how many
blobs it removed and how many bytes that freed. It removes the unreferenced
blobs older than 10 minutes rather than 24 hours, so what a deleted tag left
behind goes right away while a push under way keeps its layers; uploads are
swept as the hourly cleanup sweeps them.

- **Plain HTTP.** Docker only talks to a registry over plain HTTP when it is
  `localhost` or listed in `insecure-registries` of the daemon's
  configuration; use the TLS port everywhere else.
- **`http.writeTimeout`** caps how long a pull of a large layer may take, as
  it caps any download.

### Updating over HTTP

A running go-fs can be updated through its own HTTP or HTTPS port. The upload is
a release's `.update` file: the go-fs binary with an ed25519 signature appended.
go-fs checks the file, replaces its executable, and restarts into the new
version. The configuration file is not touched.

It is off by default. Turn it on with `http.enableSelfUpdate = true`, and allow
at least one client:

- **A bearer token** that sets `allowSelfUpdate = true`, for scripts. The token's
  `paths` do not matter here.
- **An admin's browser session.** The admin interface then shows an **UPDATE**
  tab with the running version and an upload button.

Basic and Digest credentials are refused, even for an admin account, for the
same reason the admin interface refuses them.

```sh
# what is running, to pick the matching file
curl -H "Authorization: Bearer gofs_…" "https://host:9443/?go-fs=update"
# {"version":"1.1.0","os":"linux","arch":"arm64","executable":"/opt/go-fs/go-fs","pid":812,"keys":["d1db60358969ad82"]}

# upload it; go-fs answers, then restarts
curl -T go-fs_1.2.0_linux_arm64.update -H "Authorization: Bearer gofs_…" \
     "https://host:9443/?go-fs=update"
# {"previous":"1.1.0","restarting":true,"version":"1.2.0"}
```

Before anything changes, the upload has to pass these checks, in this order:

1. **Signature.** The file must be signed with a key built into the *running*
   binary. The keys are compiled in from `internal/selfupdate/keys.txt`, so
   nothing at runtime can add one, including an admin editing the
   configuration. Nothing in the file is run before its signature has been
   checked.
2. **Platform.** The executable header must match the server's own OS and
   architecture.
3. **Smoke test.** The new binary is run with `-version` and must answer as
   go-fs.

| Status | Meaning |
|---|---|
| `202` | accepted; go-fs restarts right after answering |
| `400` | the file carries no signature, e.g. a plain binary instead of the `.update` file |
| `409` | another update is in progress |
| `413` | larger than 256 MiB |
| `422` | unknown key, bad signature, wrong platform, or not a go-fs binary |
| `503` | this build trusts no signing key |

The signature is cut off before the binary is installed, so what lands on disk
is byte for byte the release build. On macOS the operating system's own code
signature therefore stays valid.

How the executable is replaced:

- The new binary is written into the folder that holds the executable, so that
  folder has to be writable by the account go-fs runs as.
- The running binary is renamed to `<executable>.old` and kept as the way back.
  The next update replaces it.
- On Linux and macOS go-fs restarts with `exec`: the process keeps its PID,
  arguments and environment, so systemd, launchd, a container or a terminal
  keeps tracking it.
- On Windows go-fs starts the new version as a new process and exits. Whatever
  started the old process sees it end. `pid` in the answer to `GET` shows the
  new process.
- If the new binary cannot be moved into place, the previous one is restored
  and started again, so the servers come back either way.
- Open connections are dropped by the restart, as they are by `SIGTERM`.

Without `http.httpSessionTokenSecret` the restart also logs every browser out,
the admin page included.

**Signing key.** Generate the key pair once:

```sh
go run ./tools/sign -generate
```

The command prints a private key and a public key:

- Store the private key as the `GOFS_SIGNING_KEY` secret of the repository, which
  the release workflow signs with.
- Add the public key as a line of `internal/selfupdate/keys.txt` and commit it.
  Builds from then on trust it.

To sign a build by hand:

```sh
GOFS_SIGNING_KEY=… go run ./tools/sign -in go-fs_linux_arm64 -out go-fs_linux_arm64.update
```

A fork that signs its own builds can add its key at build time instead of
editing `keys.txt`, with
`-ldflags "-X go-fs/internal/selfupdate.buildKeys=<public key>"`.

To rotate the key:

1. Add the new public key to `keys.txt`.
2. Release a version still signed with the old key, and roll it out.
3. Switch the secret to the new key and remove the old one from `keys.txt`.

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

A browser that remembers Basic credentials sends them with every request.
Beside a session for the same account they count as that session, so the page
offers its logout and the admin interface opens; beside a session for another
account, or none, the header authenticates the request on its own.

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

### Downloading a folder

**Download** on a folder in the listing saves the whole folder as
`<folder>.tar.xz`. The endpoint is `?go-fs=archive` on the folder (`GET`, or
`HEAD` for the headers alone), so a program can ask for it too:

```shell
curl -u john:doe -o photos.tar.xz 'https://example.com/photos/?go-fs=archive'
```

The archive is packed while it is sent, so nothing is staged on the server and
the answer carries no `Content-Length`. It needs the right that listing the
folder needs, and what goes into it is decided entry by entry as a `GET` of that
entry would be: a sub-folder that `pathsRequireAuth` or the account's `paths`
keep from the requester is left out. A symbolic link goes in as the file it
points to while that file is inside `basefolder`; a link to a folder, or to
anything outside, is left out. Compressing takes one CPU core of the server:
text and other data that compresses well packs at around 80 MB/s, but data that
does not — video, images, archives — at well under 10 MB/s, so a large folder of
those takes a while. `writeTimeout`, where set, caps an archive the way it caps
any download.

### Sharing a file

**Share…** in the row menu of a file hands out a link that downloads that
one file without an account, for passing a protected file to someone who has
none. The dialog shows the full link to copy. It is the file's own URL with
`?key=` added:

```text
https://example.com/osem/file.extension?key=3f9c…  (128 hex characters)
```

The download names the file in its `Content-Disposition` header, which a
browser follows. Command-line clients only use the header when asked to.
Without that, `wget` names the file after the URL, key included:

```shell
wget --content-disposition 'https://example.com/osem/file.extension?key=3f9c…'
curl -OJ 'https://example.com/osem/file.extension?key=3f9c…'
```

The key is an HMAC-SHA512, keyed by `http.shareLinkSecret`, over the file's
path, its modification time and its size. Nothing is stored on the server: the
key is computed again from the file at every request, so a link stops working
as soon as the file is changed, touched, renamed or replaced. A link only reads.
It answers `GET` and `HEAD` of the file it was made for, and nothing else: a
folder, another file or any other method with the key is authenticated as it
would be without it. A key that no longer matches is ignored, so a signed-in
account holding an old link still gets the file.

Any account that is signed in, with a session, Basic, Digest or a bearer token,
and may read the file can make a link. The endpoint is `?go-fs=share` on the
file and answers the path and query of the link as JSON:

```shell
curl -u john:doe 'https://example.com/osem/file.extension?go-fs=share'
{"path":"/osem/file.extension?key=3f9c…"}
```

`http.shareLinkSecret` is generated and written into the configuration file at
the first start, with the rest of the file left as it was. The admin interface
shows it read-only. Changing it by hand revokes every link handed out so far.
If the file cannot be written, a key is made for this run only, and the links
stop working at the next restart.

### Fetching a file from a URL

An account that has logged in through the form, and may create files in a
folder, has a **Fetch** button at the top right of that folder's listing. The
dialog takes an `http://` or `https://` URL, an optional username and password
(or token), sent as Basic, and, folded away under **HTTP headers**, any headers
to send along, one `Name: value` per line, such as `Accept:
application/octet-stream` or `PRIVATE-TOKEN: …`. Headers the connection
decides itself (`Host`, `Content-Length`, `Connection`, `Proxy-*` and the
like) are refused, and so is an `Authorization` header next to a username.
**Validate Connection**, ticked by default, checks the TLS certificate of an
`https://` URL; untick it to accept whatever certificate the remote shows,
such as a self-signed one. It holds for the redirects as well.

The server downloads the file itself, in the background, as the registry page
pulls an image, and finishes it whether or not a page is still open: closing
or reloading the page does not stop it. The dialog waits only until the remote
has answered; an error such as a `404` or a name that is taken is shown there,
and once the download has begun the dialog closes. Several downloads can run
side by side. While any runs, a button left of the filter, in every listing of
the account, shows how fast they go together, and its background fills from
left to right as far as they have got. It opens **Downloads**, which lists
each with its name, the share that has arrived, its speed and **Stop**, which
stops it and takes it off the list; a download that failed stays there with
its reason until it is cleared. When one finishes into the folder on the
screen, the page reloads to show the file; elsewhere the banner says so.
Redirects are followed, ten at most, and the login and an `Authorization`
header go only to the scheme, host and port they were given for, while the
other headers follow the redirect. The file is stored as sent: a body with a
`Content-Encoding` is not decoded.

The file is named by the `filename` of the answer's `Content-Disposition`
where there is one, and by the last segment of the URL the redirects ended at
otherwise; only the last segment of either is used, so the file always lands
in the folder shown. A name that is taken is replaced only for an account that
sets `allowUserFileOverwrite`, as for an upload. `maxUploadSize` applies, and
the bytes are staged in `http.uploadStagingFolder` until the download is
complete. At most eight fetches run at once, all accounts together, apart
from the registry's pulls and pushes, of which at most four do.

Fetch is offered to a session only: not to Basic, Digest or bearer
credentials, which have `PUT` for the same job, and not to anyone where `PUT`
is public. The endpoints are `?go-fs=fetch` (`POST` of `url`, `username`,
`password`, `headers` and `skipVerify`) and
`?go-fs=fetch-job&id=…` (`GET` for the progress, `DELETE` to stop and clear)
on the folder, and `?go-fs=fetch-jobs` (`GET`), on any folder, for the
account's downloads that have not been cleared, with `name`, `folder`,
`phase` (`downloading` once the remote has answered), `bytesDone`,
`bytesTotal` and `bytesPerSecond`. Note that the server connects to whatever host is typed in, from its
own network, internal addresses included: give the right to create files only
to accounts that may do that.

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
`application/octet-stream` (or no `Content-Type`, as `curl -T` sends) and multipart uploads, `DELETE` for a file or an
empty folder, Basic (RFC 7617) and Digest (RFC 7616, with the RFC 2069 form)
authentication, bearer tokens (RFC 6750) for scripts, browser login with a signed session token (JWT, RFC 7519), and
the `dls_directory_reader` listing endpoint. Downloads answer range requests, so a large one can be resumed.
The OSEM directory scanner (the HTTPS storage provider) posts to `dls_directory_reader.php` and `.asp` with its fixed
credentials in the form (`PHP_DLS_USER`, `PHP_DLS_PW`) instead of an `Authorization` header, as the original
scripts expected. A POST that carries them needs what browsing the listed folder with `GET` needs, so it works
with POST in `methodsRequireAuth`. The pair is public, so it opens no protected folder. A folder in
`pathsRequireAuth`, or any folder when `GET` is protected, still needs Basic, Digest or bearer credentials as well.

**S3** — the object API of Amazon S3 on the HTTP listeners, authenticated with
AWS Signature Version 4 (header, presigned URL, signed and unsigned
`aws-chunked` bodies with trailers), path style, with every top-level folder a bucket, in one region.
Bucket: `ListBuckets`, `HeadBucket`, `GetBucketLocation`, `GetBucketVersioning`,
`ListObjects`, `ListObjectsV2`, `ListMultipartUploads`, `DeleteObjects`, and
`CreateBucket` of a bucket whose folder exists. Object: `GetObject`, `HeadObject`,
`PutObject`, `CopyObject`, `DeleteObject`, `CreateMultipartUpload`,
`UploadPart`, `UploadPartCopy`, `ListParts`, `CompleteMultipartUpload` and
`AbortMultipartUpload`.

**Registry** — the OCI Distribution Specification v1.1 under `/v2/` on the HTTP
listeners, with the Bearer token flow of the Docker registry (a JWT, RFC 7519,
from `/v2/_token`) and HTTP Basic authentication: pulling manifests and blobs,
monolithic, chunked, streamed and mounted blob uploads, pushing and deleting
manifests and tags, the tag list, the `_catalog` extension and the referrers
API. OCI image manifests and indexes and Docker schema 2 manifests and
manifest lists; SHA-256 and SHA-512 digests. Images for different platforms
pushed to one tag are merged into an index.

**TFTP** — the protocol has no accounts and no passwords and no way to carry
them, so anyone who can reach `tftp.port` can read what `allowRead` allows and
write what `allowWrite` allows. It is on by default, read only; turn it off
unless the network it sits on is one where that is what you want. An upload is written beside its
destination and renamed over it when it completes, so a transfer that breaks off
leaves neither an empty file nor a truncated one.

RFC 1350 in `octet` and `netascii` mode, with the option extension of
RFC 2347, the `blksize`, `timeout` and `tsize` options of RFC 2348 and RFC 2349,
and windowed reads per RFC 7440.


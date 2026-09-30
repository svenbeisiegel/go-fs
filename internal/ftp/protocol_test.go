package ftp

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

func TestTypeParsing(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	cases := []struct{ command, want string }{
		{"TYPE A", "200 Type set to ASCII"},
		{"TYPE I", "200 Type set to BINARY"},
		// the optional second format parameter is accepted
		{"TYPE A N", "200 Type set to ASCII"},
		{"TYPE L 8", "200 Type set to BINARY"},
		// unsupported types and formats are refused instead of silently ignored
		{"TYPE E", "504 Unsupported type E"},
		{"TYPE A T", "504 Only non-print format is supported"},
		{"TYPE L 7", "504 Only 8 bit byte size is supported"},
		{"TYPE", "501 Syntax error in parameters"},
	}
	for _, tc := range cases {
		c.send("%s", tc.command)
		if got := c.reply(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.command, got, tc.want)
		}
	}
}

func TestSizeIsRefusedInAsciiMode(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "sizefile", "data")
	c := connect(t, server)
	c.login()

	c.send("TYPE A")
	c.expect("200 Type set to ASCII")
	c.send("SIZE sizefile")
	c.expect("550 SIZE not allowed in ASCII mode")

	c.send("TYPE I")
	c.expect("200 Type set to BINARY")
	c.send("SIZE sizefile")
	c.expect("213 4")
	c.send("SIZE nosuchfile")
	c.expect("550 File not found")
}

func TestEpsvAllLocksOutTheOtherDataCommands(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("EPSV ALL")
	c.expect("200 EPSV ALL command successful")

	for _, command := range []string{"PASV", "PORT 127,0,0,1,4,1", "EPRT |1|127.0.0.1|1025|"} {
		c.send("%s", command)
		c.expect("501 EPSV ALL in effect")
	}

	// EPSV itself keeps working
	c.send("EPSV")
	c.expectCode("229")
}

func TestEpsvProtocolArgument(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("EPSV 1")
	c.expectCode("229")
	c.send("EPSV 9")
	c.expect("522 Network protocol not supported, use (1,2)")
}

func TestPortToAForeignAddressIsRefused(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("PORT 192,0,2,1,4,1")
	c.expect("501 Port command not allowed")

	// a privileged port is refused as well
	c.send("PORT 127,0,0,1,0,25")
	c.expect("501 Port command not allowed")

	// and a malformed argument
	c.send("PORT something")
	c.expect("501 Port command failed")
	c.send("PORT 999,0,0,1,4,1")
	c.expect("501 Port command failed")
}

func TestEprtToAForeignAddressIsRefused(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("EPRT |1|192.0.2.1|20000|")
	c.expect("501 Extended port command not allowed")
	c.send("EPRT something")
	c.expect("501 Extended port command failed")
	c.send("EPRT |1|notanaddress|20000|")
	c.expect("501 Extended port command failed")
}

func TestPortToAForeignAddressWithBounceAllowed(t *testing.T) {
	server := newServer(t, func(cfg *ftpConfig) { cfg.AllowFtpBounce = true })
	c := connect(t, server)
	c.login()

	c.send("PORT 192,0,2,1,4,1")
	c.expect("200 Port command successful")
}

func TestForeignPassiveDataConnectionIsRefused(t *testing.T) {
	external := externalAddress()
	if external == "" {
		t.Skip("no external IPv4 interface to test with")
	}
	server := newServer(t, nil)
	server.write(t, "hello.txt", "content")

	// the control connection arrives on the external address
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(external, strconv.Itoa(server.port)), 3*time.Second)
	if err != nil {
		t.Skipf("cannot reach the server on %s: %v", external, err)
	}
	defer func() { _ = conn.Close() }()
	c := &client{t: t, conn: conn, reader: newReader(conn)}
	c.expect("220 Welcome")
	c.login()

	c.send("EPSV")
	reply := c.expectCode("229")
	port := portFromEpsv(t, reply)

	// the data connection arrives from a different address and is dropped
	data, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("connecting to the data port: %v", err)
	}
	defer func() { _ = data.Close() }()
	_ = data.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := data.Read(buf); err == nil {
		t.Error("the foreign data connection should have been dropped")
	}
}

func TestSymlinkOutOfBasefolderIsRefused(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := newServer(t, nil)
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(server.base, "link.txt")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(server.base, "escape")); err != nil {
		t.Fatal(err)
	}

	c := connect(t, server)
	c.login()

	data := c.passive(server)
	defer func() { _ = data.Close() }()
	c.send("RETR link.txt")
	c.expect(`550 Transfer failed "link.txt"`)

	c.send("SIZE link.txt")
	c.expect("550 File not found")

	// and writing through a symlinked folder
	c.send("STOR escape/planted.txt")
	c.expect(`550 Transfer failed "escape/planted.txt"`)
	if _, err := os.Stat(filepath.Join(outside, "planted.txt")); err == nil {
		t.Error("the file was written outside the base folder")
	}
}

func TestMdtmAndMfmt(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "my test file", "data")
	c := connect(t, server)
	c.login()

	c.send("MDTM nosuchfile")
	c.expect("550 File not found")

	// the file name may contain spaces, so only the first space splits
	c.send("MFMT 20150215120000 my test file")
	c.expect("253 Date/time changed okay")
	c.send("MDTM my test file")
	reply := c.expectCode("213")
	if !strings.HasPrefix(reply, "213 20150215") {
		t.Errorf("MDTM = %q", reply)
	}

	c.send("MFMT notatime myfile")
	c.expect("501 Syntax error in time format")
	c.send("MFMT 20150215120000")
	c.expect("501 Syntax error in parameters")
	c.send("MFMT 20150215120000 nosuchfile")
	c.expect("550 File does not exist")
}

func TestMfmtWithoutOverwritePermission(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFileOverwrite = &no
		cfg.Users = []config.User{user}
	})
	c := connect(t, server)
	c.login()

	c.send("MFMT 20150215120000 myfile")
	c.expect("550 Permission denied")
}

func TestSiteChmod(t *testing.T) {
	server := newServer(t, nil)
	path := server.write(t, "hello.txt", "data")
	c := connect(t, server)
	c.login()

	c.send("SITE CHMOD 600 hello.txt")
	c.expect("200 SITE CHMOD command successful")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}

	c.send("SITE HELP")
	c.expect("214 The following SITE commands are recognized: CHMOD HELP")
	c.send("SITE BOGUS")
	c.expect("504 Unknown SITE command BOGUS")
	c.send("SITE CHMOD 644")
	c.expect("501 Syntax error in parameters")
	c.send("SITE CHMOD rwx hello.txt")
	c.expect("501 Syntax error in mode")
	c.send("SITE CHMOD 644 nosuchfile")
	c.expect("550 File does not exist")
}

func TestSiteChmodWithoutPermission(t *testing.T) {
	no := false
	server := newServer(t, func(cfg *ftpConfig) {
		user := fullUser("john")
		user.AllowUserFileOverwrite = &no
		cfg.Users = []config.User{user}
	})
	server.write(t, "hello.txt", "data")
	c := connect(t, server)
	c.login()

	c.send("SITE CHMOD 600 hello.txt")
	c.expect("550 Permission denied")
}

func TestHelp(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	c.send("HELP")
	reply := c.expectCode("214")
	if !strings.HasPrefix(reply, "214-The following commands are recognized") {
		t.Errorf("HELP = %q", reply)
	}
	if !strings.Contains(reply, "RETR") || !strings.Contains(reply, "214 Help OK") {
		t.Errorf("HELP = %q", reply)
	}

	c.send("HELP retr")
	c.expect("214 Syntax: RETR")
	c.send("HELP BOGUS")
	c.expect("504 Unknown command BOGUS")
}

func TestSimpleCommands(t *testing.T) {
	server := newServer(t, nil)
	c := connect(t, server)
	c.login()

	cases := []struct{ command, want string }{
		{"NOOP", "200 NOOP ok"},
		{"SYST", "215 UNIX"},
		{"CLNT tests", "200 Don't care"},
		{"ALLO 1024", "202 No storage allocation necessary"},
		{"ACCT someaccount", "202 Account not required"},
		{"MODE S", "200 Mode set to Stream"},
		{"MODE B", "504 Only stream mode is supported"},
		{"STRU F", "200 Structure set to File"},
		{"STRU R", "504 Only file structure is supported"},
		{"PROT P", "503 PBSZ missing"},
		{"PBSZ 0", "200 PBSZ=0"},
		{"PROT C", "200 Protection level is C"},
		// this control connection is plaintext, so there is no protection to
		// promise the data connection
		{"PROT P", "534 Protection level P needs a secure control connection"},
		{"PROT Z", "534 Protection level must be C or P"},
	}
	for _, tc := range cases {
		c.send("%s", tc.command)
		if got := c.reply(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.command, got, tc.want)
		}
	}
}

func TestStat(t *testing.T) {
	server := newServer(t, nil)
	server.write(t, "hello.txt", "hello world")
	c := connect(t, server)
	c.login()

	c.send("STAT")
	reply := c.expectCode("211")
	if !strings.Contains(reply, "Logged in as john") || !strings.Contains(reply, "TYPE: BINARY") {
		t.Errorf("STAT = %q", reply)
	}

	c.send("STAT hello.txt")
	reply = c.expectCode("213")
	if !strings.Contains(reply, "hello.txt") || !strings.Contains(reply, "213 End") {
		t.Errorf("STAT hello.txt = %q", reply)
	}

	c.send("STAT nosuchfile")
	c.expect("450 File not found")
}

func TestImplicitTLS(t *testing.T) {
	server := newTLSServer(t, nil)
	c := connectTLS(t, server)
	c.login()

	c.send("PWD")
	c.expect(`257 "/" is current directory`)
}

// ftp.enabled off with ftps.enabled on serves implicit FTPS and nothing on the
// plaintext port.
func TestFTPSWithoutThePlainListener(t *testing.T) {
	server := newTLSServer(t, func(cfg *ftpConfig) {
		cfg.Enabled = false
	})
	if addr := server.Addr(); addr != nil {
		t.Errorf("the plain listener is bound at %v, it should not exist", addr)
	}
	if server.SecureAddr() == nil {
		t.Fatal("the tls listener is not bound")
	}

	c := connectTLS(t, server)
	c.login()
	c.send("PWD")
	c.expect(`257 "/" is current directory`)
}

func TestExplicitTLSUpgrade(t *testing.T) {
	server := newTLSServer(t, nil)
	c := connect(t, server)

	c.send("AUTH TLS")
	c.expect("234 Using authentication type TLS")

	// from here the control connection speaks TLS
	secure := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
	if err := secure.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	upgraded := &client{t: t, conn: secure, reader: newReader(secure)}
	upgraded.login()
	upgraded.send("PWD")
	upgraded.expect(`257 "/" is current directory`)
}

func TestAuthWithAnUnsupportedType(t *testing.T) {
	server := newTLSServer(t, nil)
	c := connect(t, server)
	c.send("AUTH NONE")
	c.expect("504 Unsupported auth type NONE")
}

func TestProtectedDataConnection(t *testing.T) {
	server := newTLSServer(t, nil)
	server.write(t, "hello.txt", "secret payload")

	c := connectTLS(t, server)
	c.login()
	c.send("PBSZ 0")
	c.expect("200 PBSZ=0")
	c.send("PROT P")
	c.expect("200 Protection level is P")

	c.send("EPSV")
	reply := c.expectCode("229")
	port := portFromEpsv(t, reply)

	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	data := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})

	c.send("RETR hello.txt")
	c.expectCode("150")

	_ = data.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := data.Read(buf)
	if string(buf[:n]) != "secret payload" {
		t.Errorf("content = %q", buf[:n])
	}
	_ = data.Close()
	c.expectCode("226")
}

// PROT P says the data connection is protected. Promising that on a plaintext
// control connection would be a promise the server cannot keep, and the client
// would send its data in the clear believing otherwise; over TLS it is the
// truth and is accepted.
func TestProtectionLevelNeedsASecureConnection(t *testing.T) {
	server := newTLSServer(t, nil)

	plain := connect(t, server)
	plain.login()
	plain.send("PBSZ 0")
	plain.expect("200 PBSZ=0")
	plain.send("PROT P")
	plain.expect("534 Protection level P needs a secure control connection")

	secure := connectTLS(t, server)
	secure.login()
	secure.send("PBSZ 0")
	secure.expect("200 PBSZ=0")
	secure.send("PROT P")
	secure.expect("200 Protection level is P")
}

package ftp

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-fs/internal/vfs"
)

// features advertised by FEAT (RFC 2389). Only actual protocol extensions
// belong here, not every implemented command.
var features = []string{
	"AUTH TLS",
	"AUTH SSL",
	"CLNT",
	"EPRT",
	"EPSV",
	"MDTM",
	"MFMT",
	"MLST type*;size*;modify*;",
	"PBSZ",
	"PROT",
	"REST STREAM",
	"SIZE",
	"UTF8",
}

var preAuthCommands map[string]handler
var authCommands map[string]handler

func init() {
	preAuthCommands = map[string]handler{
		"USER": cmdUser,
		"PASS": cmdPass,
		"AUTH": func(c *conn, arg string) { c.handleAuth(arg) },
		"NOOP": cmdNoop,
		"QUIT": cmdQuit,
		"FEAT": cmdFeat,
		"SYST": cmdSyst,
		"OPTS": cmdOpts,
		"HELP": cmdHelp,
		"ACCT": cmdAcct,
	}

	authCommands = map[string]handler{
		"QUIT": cmdQuit,
		"PWD":  cmdPwd,
		"XPWD": cmdPwd,
		"CLNT": cmdClnt,
		"PBSZ": cmdPbsz,
		"OPTS": cmdOpts,
		"PROT": cmdProt,
		"FEAT": cmdFeat,
		"CWD":  cmdCwd,
		"XCWD": cmdCwd,
		"CDUP": cmdCdup,
		"XCUP": cmdCdup,
		"SIZE": cmdSize,
		"DELE": cmdDele,
		"RMD":  cmdRmd(false),
		"RMDA": cmdRmd(true),
		"XRMD": cmdRmd(false),
		"MKD":  cmdMkd,
		"XMKD": cmdMkd,
		"LIST": cmdList(formatLIST),
		"NLST": cmdList(formatNLST),
		"MLSD": cmdList(formatMLSD),
		"MLST": cmdMlst,
		"PORT": cmdPort,
		"PASV": cmdPasv,
		"EPRT": cmdEprt,
		"EPSV": cmdEpsv,
		"RETR": cmdRetr,
		"REST": cmdRest,
		"STOR": cmdStor("STOR"),
		"APPE": cmdStor("APPE"),
		"STOU": cmdStor("STOU"),
		"SYST": cmdSyst,
		"TYPE": cmdType,
		"RNFR": cmdRnfr,
		"RNTO": cmdRnto,
		"MFMT": cmdMfmt,
		"MDTM": cmdMdtm,
		"NOOP": cmdNoop,
		"MODE": cmdMode,
		"STRU": cmdStru,
		"ABOR": cmdAbor,
		"STAT": cmdStat,
		"HELP": cmdHelp,
		"ALLO": cmdAllo,
		"ACCT": cmdAcct,
		"SITE": cmdSite,
	}
}

func cmdNoop(c *conn, _ string) { c.reply("200", "NOOP ok") }
func cmdQuit(c *conn, _ string) { c.replyAndClose("221", "Goodbye") }
func cmdSyst(c *conn, _ string) { c.reply("215", "UNIX") }
func cmdClnt(c *conn, _ string) { c.reply("200", "Don't care") }
func cmdAllo(c *conn, _ string) { c.reply("202", "No storage allocation necessary") }
func cmdAcct(c *conn, _ string) { c.reply("202", "Account not required") }

func cmdPwd(c *conn, _ string) {
	c.reply("257", fmt.Sprintf("%q is current directory", c.cwd))
}

func cmdFeat(c *conn, _ string) {
	c.replyMulti("211", "Features:\r\n "+strings.Join(features, "\r\n ")+"\r\n211 End")
}

func cmdPbsz(c *conn, arg string) {
	c.pbszDone = true
	c.reply("200", "PBSZ="+arg)
}

func cmdProt(c *conn, arg string) {
	if !c.pbszDone {
		c.reply("503", "PBSZ missing")
		return
	}
	switch arg {
	case "C", "P":
		// PROT P promises the data connection is protected. Answering 200 on a
		// plaintext control connection would promise exactly what this cannot
		// then deliver, and the client would send its data in the clear
		// believing otherwise.
		if arg == "P" && (!c.secure.get() || c.server.tls == nil) {
			c.reply("534", "Protection level P needs a secure control connection")
			return
		}
		c.protected = arg == "P"
		c.reply("200", "Protection level is "+arg)
	default:
		c.reply("534", "Protection level must be C or P")
	}
}

// cmdOpts handles OPTS, including the MLST fact selection of RFC 3659.
func cmdOpts(c *conn, arg string) {
	option := strings.ToLower(arg)
	switch option {
	case "utf8 on":
		c.reply("200", "UTF8 ON")
		return
	case "utf8 off":
		c.reply("200", "UTF8 OFF")
		return
	}
	if option == "mlst" || strings.HasPrefix(option, "mlst ") {
		requested := map[string]bool{}
		for _, fact := range strings.Split(strings.TrimSpace(option[4:]), ";") {
			if fact = strings.TrimSpace(fact); fact != "" {
				requested[fact] = true
			}
		}
		// unsupported facts are dropped, the reply states what was taken
		selected := map[string]bool{}
		var names []string
		for _, fact := range supportedFacts {
			if requested[fact] {
				selected[fact] = true
				names = append(names, fact)
			}
		}
		c.mlstFacts = selected
		list := ""
		if len(names) > 0 {
			list = strings.Join(names, ";") + ";"
		}
		c.reply("200", "MLST OPTS "+list)
		return
	}
	c.reply("451", "Not supported")
}

// cmdCwd handles CWD.
func cmdCwd(c *conn, arg string) {
	virtual, escaped := vfs.Normalize(c.cwd, arg)
	if escaped {
		// going up from the root is a no-op, as with any chrooted server
		if c.cwd == "/" && strings.TrimSpace(arg) == ".." {
			c.reply("250", fmt.Sprintf("CWD successful. %q is current directory", c.cwd))
			return
		}
		c.reply("530", "CWD not successful")
		return
	}
	folder := vfs.AsFolder(virtual)
	target := c.root.Resolve("/", folder)
	if !target.Valid {
		c.log.Debug("ftp CWD path refused", "path", arg)
		c.reply("530", "CWD not successful")
		return
	}
	if info, err := os.Stat(target.Path); err != nil || !info.IsDir() {
		c.log.Debug("ftp CWD folder not found", "path", folder, "error", err)
		c.reply("530", "CWD not successful")
		return
	}
	c.cwd = folder
	c.reply("250", fmt.Sprintf("CWD successful. %q is current directory", c.cwd))
}

func cmdCdup(c *conn, _ string) { cmdCwd(c, "..") }

func cmdSize(c *conn, arg string) {
	if c.asciiMode {
		c.reply("550", "SIZE not allowed in ASCII mode")
		return
	}
	target := c.root.Resolve(c.cwd, arg)
	if target.Valid {
		if info, err := os.Stat(target.Path); err == nil && info.Mode().IsRegular() {
			c.reply("213", strconv.FormatInt(info.Size(), 10))
			return
		}
	}
	c.reply("550", "File not found")
}

func cmdDele(c *conn, arg string) {
	target := c.root.Resolve(c.cwd, arg)
	if target.Valid {
		if info, err := os.Stat(target.Path); err == nil && info.Mode().IsRegular() {
			if !c.perms.FileDelete {
				c.log.Debug("ftp DELE refused, the account may not delete files", "file", target.Virtual)
				c.reply("550", "Permission denied")
				return
			}
			if err := os.Remove(target.Path); err != nil {
				c.log.Warn("ftp delete failed", "user", c.username, "file", target.Virtual, "error", err)
				c.reply("550", "File not found")
				return
			}
			// every removal is recorded, as the HTTP server does: a file that
			// is gone is the question the log is most often asked
			c.log.Info("ftp delete", "user", c.username, "file", target.Virtual,
				"bytes", info.Size(), "address", c.remoteAddr)
			c.reply("250", "File deleted successfully")
			return
		}
	}
	c.log.Debug("ftp DELE file not found", "path", arg)
	c.reply("550", "File not found")
}

// cmdRmd handles RMD and its aliases.
//
// RMD and XRMD remove an empty folder, which is what rmdir does and what a
// client sending them expects. RMDA is the extension that removes a folder with
// everything in it, so it also needs the right that removes files: an account
// granted only allowUserFolderDelete may drop an empty folder, never a tree of
// files it may not delete one by one.
func cmdRmd(recursive bool) handler {
	return func(c *conn, arg string) {
		target := c.root.Resolve(c.cwd, arg)
		// the base folder itself is not the client's to remove: it would take
		// the served tree with it and leave every path invalid
		if !c.perms.FolderDelete || !target.Valid || target.IsRoot() {
			c.log.Debug("ftp RMD refused", "path", arg, "allowed", c.perms.FolderDelete,
				"valid", target.Valid, "root", target.IsRoot())
			c.reply("550", "Permission denied")
			return
		}
		if recursive && !c.perms.FileDelete {
			c.log.Debug("ftp RMDA refused, the account may not delete files", "folder", target.Virtual)
			c.reply("550", "Permission denied")
			return
		}
		if info, err := os.Stat(target.Path); err != nil || !info.IsDir() {
			c.log.Debug("ftp RMD folder not found", "path", arg, "error", err)
			c.reply("550", "Folder not found")
			return
		}
		if !recursive {
			entries, err := os.ReadDir(target.Path)
			if err != nil {
				c.log.Debug("ftp RMD cannot read the folder", "folder", target.Virtual, "error", err)
				c.reply("550", "Folder not found")
				return
			}
			if len(entries) > 0 {
				c.log.Debug("ftp RMD refused, the folder is not empty",
					"folder", target.Virtual, "entries", len(entries))
				c.reply("550", "Folder is not empty")
				return
			}
		}
		remove := os.Remove
		if recursive {
			remove = os.RemoveAll
		}
		if err := remove(target.Path); err != nil {
			c.log.Warn("ftp folder delete failed", "user", c.username,
				"folder", target.Virtual, "recursive", recursive, "error", err)
			c.reply("550", "Folder not found")
			return
		}
		c.log.Info("ftp folder delete", "user", c.username, "folder", target.Virtual,
			"recursive", recursive, "address", c.remoteAddr)
		c.reply("250", "Folder deleted successfully")
	}
}

func cmdMkd(c *conn, arg string) {
	target := c.root.Resolve(c.cwd, arg)
	if !c.perms.FolderCreate || !target.Valid {
		c.log.Debug("ftp MKD refused", "path", arg, "allowed", c.perms.FolderCreate, "valid", target.Valid)
		c.reply("550", "Permission denied")
		return
	}
	if info, err := os.Stat(target.Path); err == nil && info.IsDir() {
		c.log.Debug("ftp MKD refused, the folder exists", "folder", target.Virtual)
		c.reply("550", "Folder exists")
		return
	}
	if err := os.MkdirAll(target.Path, 0o755); err != nil {
		c.log.Warn("ftp mkdir failed", "user", c.username, "folder", target.Virtual, "error", err)
		c.reply("550", "Permission denied")
		return
	}
	c.log.Info("ftp mkdir", "user", c.username, "folder", target.Virtual, "address", c.remoteAddr)
	c.reply("250", "Folder created successfully")
}

// cmdType handles TYPE, including the optional second format parameter.
func cmdType(c *conn, arg string) {
	parts := strings.Fields(arg)
	if len(parts) == 0 {
		c.reply("501", "Syntax error in parameters")
		return
	}
	kind := strings.ToUpper(parts[0])
	parameter := ""
	if len(parts) > 1 {
		parameter = strings.ToUpper(parts[1])
	}

	switch kind {
	case "A":
		// the second format parameter is optional, only non-print is supported
		if parameter != "" && parameter != "N" {
			c.reply("504", "Only non-print format is supported")
			return
		}
		c.asciiMode = true
		c.reply("200", "Type set to ASCII")
	case "I", "L":
		if kind == "L" && parameter != "" && parameter != "8" {
			c.reply("504", "Only 8 bit byte size is supported")
			return
		}
		c.asciiMode = false
		c.reply("200", "Type set to BINARY")
	default:
		c.reply("504", "Unsupported type "+kind)
	}
}

func cmdMode(c *conn, arg string) {
	if strings.EqualFold(arg, "S") {
		c.reply("200", "Mode set to Stream")
		return
	}
	c.reply("504", "Only stream mode is supported")
}

func cmdStru(c *conn, arg string) {
	if strings.EqualFold(arg, "F") {
		c.reply("200", "Structure set to File")
		return
	}
	c.reply("504", "Only file structure is supported")
}

// cmdRnfr handles RNFR. A rename creates one name and removes another, so it
// takes both rights, which is the rule the SFTP server follows too.
func cmdRnfr(c *conn, arg string) {
	if !c.perms.FileCreate || !c.perms.FileDelete {
		c.log.Debug("ftp RNFR refused, a rename needs the create and the delete right",
			"create", c.perms.FileCreate, "delete", c.perms.FileDelete)
		c.reply("550", "Permission denied")
		return
	}
	target := c.root.Resolve(c.cwd, arg)
	if target.Valid && !target.IsRoot() {
		if info, err := os.Stat(target.Path); err == nil && info.Mode().IsRegular() {
			c.renameFrom = target.Path
			c.renameFromVirtual = target.Virtual
			c.reply("350", "File exists")
			return
		}
	}
	c.log.Debug("ftp RNFR file not found", "path", arg)
	c.reply("550", "File does not exist")
}

func cmdRnto(c *conn, arg string) {
	if !c.perms.FileCreate || !c.perms.FileDelete {
		c.log.Debug("ftp RNTO refused, a rename needs the create and the delete right",
			"create", c.perms.FileCreate, "delete", c.perms.FileDelete)
		c.reply("550", "Permission denied")
		return
	}
	target := c.root.Resolve(c.cwd, arg)
	if c.renameFrom == "" || !target.Valid || target.IsRoot() {
		c.log.Debug("ftp RNTO refused", "path", arg, "pending", c.renameFrom != "",
			"valid", target.Valid, "root", target.IsRoot())
		c.reply("550", "File already exists")
		return
	}
	if _, err := os.Stat(target.Path); err == nil {
		c.log.Debug("ftp RNTO refused, the destination exists", "to", target.Virtual)
		c.reply("550", "File already exists")
		return
	}
	if err := os.Rename(c.renameFrom, target.Path); err != nil {
		c.log.Warn("ftp rename failed", "user", c.username,
			"from", c.renameFromVirtual, "to", target.Virtual, "error", err)
		c.reply("550", "File rename failed")
		return
	}
	c.log.Info("ftp rename", "user", c.username, "from", c.renameFromVirtual,
		"to", target.Virtual, "address", c.remoteAddr)
	c.renameFrom = ""
	c.renameFromVirtual = ""
	c.reply("250", "File renamed successfully")
}

func cmdMdtm(c *conn, arg string) {
	target := c.root.Resolve(c.cwd, arg)
	if target.Valid {
		if info, err := os.Stat(target.Path); err == nil && info.Mode().IsRegular() {
			c.reply("213", formatMLSDTime(info.ModTime()))
			return
		}
	}
	c.reply("550", "File not found")
}

var timestampPattern = regexp.MustCompile(`^\d{14}$`)

// cmdMfmt handles MFMT. The argument is a timestamp and a file name, which may
// itself contain spaces, so it is split on the first space only.
func cmdMfmt(c *conn, arg string) {
	stamp, name, found := strings.Cut(arg, " ")
	if !found {
		c.reply("501", "Syntax error in parameters")
		return
	}
	when, err := time.Parse("20060102150405", stamp)
	if !timestampPattern.MatchString(stamp) || err != nil {
		c.reply("501", "Syntax error in time format")
		return
	}
	if !c.perms.FileOverwrite {
		c.reply("550", "Permission denied")
		return
	}
	target := c.root.Resolve(c.cwd, strings.TrimSpace(name))
	if target.Valid {
		if info, err := os.Stat(target.Path); err == nil && info.Mode().IsRegular() {
			if err := os.Chtimes(target.Path, when, when); err != nil {
				c.log.Warn("ftp cannot set the modification time", "user", c.username,
					"file", target.Virtual, "error", err)
				c.reply("550", "File does not exist")
				return
			}
			c.log.Debug("ftp modification time set", "file", target.Virtual, "time", when)
			c.reply("253", "Date/time changed okay")
			return
		}
	}
	c.reply("550", "File does not exist")
}

func cmdStat(c *conn, arg string) {
	if arg == "" {
		mode := "BINARY"
		if c.asciiMode {
			mode = "ASCII"
		}
		c.replyMulti("211", fmt.Sprintf("Status:\r\n Connected to %s\r\n Logged in as %s\r\n TYPE: %s\r\n211 End",
			c.remoteAddr, c.username, mode))
		return
	}
	target := c.root.Resolve(c.cwd, arg)
	if !target.Valid {
		c.reply("450", "File not found")
		return
	}
	info, err := os.Stat(target.Path)
	if err != nil {
		c.reply("450", "File not found")
		return
	}
	permissions := "-r--r--r--"
	if info.IsDir() {
		permissions = "dr--r--r--"
	}
	size := "0"
	if !info.IsDir() {
		size = strconv.FormatInt(info.Size(), 10)
	}
	line := fmt.Sprintf("%s 1 %s %s %s %s %s",
		permissions, c.username, c.username, padSize(size),
		formatLISTTime(info.ModTime()), filepath.Base(target.Path))
	c.replyMulti("213", "Status:\r\n "+line+"\r\n213 End")
}

var modePattern = regexp.MustCompile(`^[0-7]{3,4}$`)

// cmdSite handles SITE, of which CHMOD and HELP are implemented.
func cmdSite(c *conn, arg string) {
	sub, parameter, _ := strings.Cut(arg, " ")
	sub = strings.ToUpper(strings.TrimSpace(sub))
	parameter = strings.TrimSpace(parameter)

	switch sub {
	case "HELP":
		c.reply("214", "The following SITE commands are recognized: CHMOD HELP")
		return
	case "CHMOD":
	default:
		c.reply("504", "Unknown SITE command "+sub)
		return
	}

	mode, name, found := strings.Cut(parameter, " ")
	if !found {
		c.reply("501", "Syntax error in parameters")
		return
	}
	if !modePattern.MatchString(mode) {
		c.reply("501", "Syntax error in mode")
		return
	}
	if !c.perms.FileOverwrite {
		c.reply("550", "Permission denied")
		return
	}
	target := c.root.Resolve(c.cwd, strings.TrimSpace(name))
	if !target.Valid || target.IsRoot() {
		c.reply("550", "File does not exist")
		return
	}
	if _, err := os.Stat(target.Path); err != nil {
		c.reply("550", "File does not exist")
		return
	}
	bits, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		c.reply("501", "Syntax error in mode")
		return
	}
	if err := os.Chmod(target.Path, os.FileMode(bits)); err != nil {
		c.log.Warn("ftp chmod failed", "user", c.username, "file", target.Virtual,
			"mode", mode, "error", err)
		c.reply("550", "File does not exist")
		return
	}
	c.log.Info("ftp chmod", "user", c.username, "file", target.Virtual, "mode", mode,
		"address", c.remoteAddr)
	c.reply("200", "SITE CHMOD command successful")
}

// cmdHelp lists the recognised commands, or explains a single one.
func cmdHelp(c *conn, arg string) {
	wanted := strings.ToUpper(strings.TrimSpace(arg))
	if wanted != "" {
		_, inAuth := authCommands[wanted]
		_, inPre := preAuthCommands[wanted]
		if inAuth || inPre {
			c.reply("214", "Syntax: "+wanted)
			return
		}
		c.reply("504", "Unknown command "+wanted)
		return
	}

	seen := map[string]bool{}
	var names []string
	for _, table := range []map[string]handler{preAuthCommands, authCommands} {
		for name := range table {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)

	var lines []string
	for i := 0; i < len(names); i += 8 {
		lines = append(lines, " "+strings.Join(names[i:min(i+8, len(names))], " "))
	}
	c.replyMulti("214", "The following commands are recognized\r\n"+
		strings.Join(lines, "\r\n")+"\r\n214 Help OK")
}

package ftp

import (
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-fs/internal/vfs"
)

// supportedFacts are the MLST facts this server can report (RFC 3659).
var supportedFacts = []string{"type", "size", "modify"}

type listFormat int

const (
	formatLIST listFormat = iota
	formatNLST
	formatMLSD
)

// parseListArgument splits a listing argument into the unix style flags a
// client may send, as in "LIST -la", and the optional path that follows them.
func parseListArgument(arg string) string {
	var parts []string
	for _, token := range strings.Fields(arg) {
		if strings.HasPrefix(token, "-") {
			continue
		}
		parts = append(parts, token)
	}
	return strings.Join(parts, " ")
}

// facts renders the MLST facts of an entry, honouring the selection made with
// OPTS MLST.
func (c *conn) facts(info fs.FileInfo) string {
	var out []string
	if c.mlstFacts["type"] {
		kind := "file"
		if info.IsDir() {
			kind = "dir"
		}
		out = append(out, "type="+kind)
	}
	if c.mlstFacts["size"] && !info.IsDir() {
		out = append(out, "size="+strconv.FormatInt(info.Size(), 10))
	}
	if c.mlstFacts["modify"] {
		out = append(out, "modify="+formatMLSDTime(info.ModTime()))
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, ";") + ";"
}

// formatEntry renders one directory entry in the requested format.
func (c *conn) formatEntry(format listFormat, name string, info fs.FileInfo) string {
	switch format {
	case formatNLST:
		return name + "\r\n"
	case formatMLSD:
		return c.facts(info) + " " + name + "\r\n"
	default:
		permissions := "-r--r--r--"
		if info.IsDir() {
			permissions = "dr--r--r--"
		}
		size := "0"
		if !info.IsDir() {
			size = strconv.FormatInt(info.Size(), 10)
		}
		return fmt.Sprintf("%s 1 %s %s %s %s %s\r\n",
			permissions, c.username, c.username, padSize(size),
			formatLISTTime(info.ModTime()), name)
	}
}

// buildListing renders the listing of a folder, or of a single file when the
// client named one. It reports false when the path does not exist.
func (c *conn) buildListing(format listFormat, osPath string) (string, bool) {
	info, err := os.Stat(osPath)
	if err != nil {
		c.log.Debug("ftp listing target not found", "error", err)
		return "", false
	}

	folder := osPath
	var names []string
	if info.IsDir() {
		entries, err := os.ReadDir(osPath)
		if err != nil {
			// a folder that exists but cannot be read is a permission problem
			// on the server, which the client's 550 does not say
			c.log.Warn("ftp cannot read the folder", "user", c.username, "error", err)
			return "", false
		}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
	} else {
		folder = filepath.Dir(osPath)
		names = []string{filepath.Base(osPath)}
	}

	var out strings.Builder
	for _, name := range names {
		entryInfo, err := os.Stat(filepath.Join(folder, name))
		if err != nil {
			// the entry vanished or is not reachable, skip it rather than
			// letting one broken link break the whole listing
			continue
		}
		out.WriteString(c.formatEntry(format, name, entryInfo))
	}
	return out.String(), true
}

// cmdList handles LIST, NLST and MLSD.
func cmdList(format listFormat) handler {
	return func(c *conn, arg string) {
		target := c.root.Resolve(c.cwd, parseListArgument(arg))
		if !target.Valid {
			c.log.Debug("ftp listing path refused", "path", arg)
			c.reply("550", "Directory not found")
			return
		}
		if _, err := os.Stat(target.Path); err != nil {
			c.log.Debug("ftp listing target not found", "path", target.Virtual, "error", err)
			c.reply("550", "Directory not found")
			return
		}
		relative := vfs.AsFolder(target.Virtual)

		c.withData("", func(data net.Conn) (string, string) {
			listing, ok := c.buildListing(format, target.Path)
			if !ok {
				return "550", "Directory not found"
			}
			if listing == "" {
				listing = "\r\n"
			}
			if _, err := io.WriteString(data, listing); err != nil {
				c.log.Debug("ftp listing transfer failed", "path", relative, "error", err)
				return "550", fmt.Sprintf("Transfer failed %q", relative)
			}
			c.log.Debug("ftp listing sent", "path", relative, "bytes", len(listing))
			return "226", fmt.Sprintf("Successfully transferred %q", relative)
		})
	}
}

// cmdMlst handles MLST. Unlike MLSD the answer goes over the control
// connection (RFC 3659).
func cmdMlst(c *conn, arg string) {
	target := c.root.Resolve(c.cwd, parseListArgument(arg))
	if !target.Valid {
		c.reply("550", "File not found")
		return
	}
	info, err := os.Stat(target.Path)
	if err != nil {
		c.reply("550", "File not found")
		return
	}
	entry := c.facts(info) + " " + target.Virtual
	c.replyMulti("250", "Listing "+target.Virtual+"\r\n "+entry+"\r\n250 End")
}

// padSize right aligns a size in the 13 column field of a LIST line.
func padSize(size string) string {
	if len(size) >= 13 {
		return size
	}
	return strings.Repeat(" ", 13-len(size)) + size
}

func formatLISTTime(when time.Time) string {
	return when.Format("Jan 02 15:04")
}

func formatMLSDTime(when time.Time) string {
	return when.Format("20060102150405")
}

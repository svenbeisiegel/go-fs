package config

import (
	_ "embed"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"sync"
)

// The source of this file's own package is embedded so that the doc comments
// above every field can be read at runtime. They already document every key of
// the configuration file, and the admin interface shows them as the help text
// of the form field it generates, which keeps one description rather than two
// that have to be kept in step.
//
//go:embed config.go
var source []byte

var (
	docsOnce sync.Once
	docs     map[string]string
)

// Docs maps "StructName.FieldName" to the doc comment above that field, as a
// single line. A field with no comment is absent, and a source that cannot be
// parsed yields an empty map rather than an error: help text is a convenience,
// and its absence must not stop the server.
func Docs() map[string]string {
	docsOnce.Do(func() {
		docs = parseDocs(source)
	})
	return docs
}

func parseDocs(src []byte) map[string]string {
	found := make(map[string]string)
	file, err := parser.ParseFile(token.NewFileSet(), "config.go", src, parser.ParseComments)
	if err != nil {
		return found
	}

	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structure, ok := spec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range structure.Fields.List {
			// a comment above the field, or failing that one after it
			text := commentText(field.Doc)
			if text == "" {
				text = commentText(field.Comment)
			}
			if text == "" {
				continue
			}
			// several names on one line share the comment, as
			// "Cert and Key are PEM file paths" does
			for _, name := range field.Names {
				found[spec.Name.Name+"."+name.Name] = text
			}
		}
		return true
	})
	return found
}

// commentText joins a comment group into one line, so that a description
// wrapped over four source lines reads as a sentence in the browser.
func commentText(group *ast.CommentGroup) string {
	if group == nil {
		return ""
	}
	return strings.Join(strings.Fields(group.Text()), " ")
}

// assignment matches a key line of the template, whether it is live or
// commented out: "port = 21" and "# basefolder = \"/srv/ftp\"" both name a key.
// The value has to be a whole one, a string, a number, a switch or an array
// that opens on this line, so that a sentence of a description that happens to
// begin "http = true, whose..." is read as the prose it is.
var assignment = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]*)\s*=\s*("[^"]*"|true|false|-?\d+|\[.*)$`)

// header matches a table line, "[ftp]" or "[[users]]", and nothing else that
// starts with a bracket, so that an example array in a description is not
// taken for a table.
var header = regexp.MustCompile(`^\[\[?([A-Za-z][A-Za-z0-9_.]*)\]\]?$`)

var (
	templateOnce sync.Once
	templateDocs map[string]string
)

// TemplateDocs maps a key of the configuration file to the comment above it in
// the shipped template, as a single line. Keys are the path the file uses, so
// "ftp.maxConnections", and a repeated table contributes its fields once,
// "users.username".
//
// The template is the fuller of the two descriptions and the one written for
// whoever edits the file, so the admin interface prefers it and falls back to
// the Go doc comment of the field.
//
// What is read is the paragraph directly above a key or a table header. A
// comment above a run of keys with no blank line between them describes every
// key of the run, the way "cert" and "key" share one. Everything else, a
// paragraph set apart by a blank line or a comment after a key that is
// followed by one, is for the reader of the file alone.
func TemplateDocs() map[string]string {
	templateOnce.Do(func() {
		templateDocs = parseTemplateDocs(template)
	})
	return templateDocs
}

func parseTemplateDocs(src []byte) map[string]string {
	found := make(map[string]string)
	section := ""
	var pending []string
	// an array value spans several lines; they are values, not prose
	inArray := false
	// the description the previous key line got, and whether nothing but key
	// lines has come since, so that the next key of the run shares it
	last := ""
	adjacent := false

	keep := func(key, text string) {
		if text != "" && key != "" {
			if _, seen := found[key]; !seen {
				found[key] = text
			}
		}
		pending = nil
	}
	// record attaches the description above a key line to that key, and notes
	// whether the value it opens continues on the following lines
	record := func(key, line string) {
		text := strings.Join(pending, " ")
		if text == "" && adjacent {
			text = last
		}
		if section != "" {
			keep(section+"."+key, text)
		}
		pending = nil
		last = text
		adjacent = true
		inArray = strings.Count(line, "[") > strings.Count(line, "]")
	}
	// enter attaches the description above a table header to the table itself,
	// which is what the tab and the record list are labelled with
	enter := func(name string) {
		keep(name, strings.Join(pending, " "))
		section = name
		inArray = false
		adjacent = false
	}

	for _, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		commented := strings.HasPrefix(strings.TrimSpace(line), "#")

		switch {
		case inArray:
			if strings.Contains(trimmed, "]") {
				inArray = false
			}

		case trimmed == "":
			pending = nil
			adjacent = false

		case header.MatchString(trimmed):
			enter(header.FindStringSubmatch(trimmed)[1])

		case assignment.MatchString(trimmed):
			record(assignment.FindStringSubmatch(trimmed)[1], trimmed)

		case commented:
			pending = append(pending, trimmed)
			adjacent = false

		default:
			pending = nil
			adjacent = false
		}
	}
	return found
}

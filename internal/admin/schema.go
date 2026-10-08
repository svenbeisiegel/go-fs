package admin

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"go-fs/internal/config"
)

// The form is generated rather than written. Every field of config.Config
// carries the toml tag that names its key in the file, so reflecting over the
// struct yields the whole configuration, and a key added to the struct appears
// in the browser on the next build with nothing else to do.

// Schema is what the page renders.
type Schema struct {
	Sections []Section `json:"sections"`
}

// Section is one top level table of the file, shown as one tab.
type Section struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Help   string  `json:"help,omitempty"`
	Fields []Field `json:"fields"`
	// Tables are the tables that repeat, [[http.cleanup]] and the like. The
	// tab shows each of them as a list with one record per entry.
	Tables []Table `json:"tables"`
	// Direct says the section is itself a repeated table, [[users]] at the top
	// of the file: its value is the list of records rather than a map of
	// keys, and Tables holds exactly one entry describing them.
	Direct bool `json:"direct,omitempty"`
	// Subsections are the tables nested in the section, [general.ssh] and the
	// like, one level deep. The tab shows each under a tab of its own below
	// the section's, after a first one, main, that holds the section's own
	// keys; a section without any has no such row.
	Subsections []Section `json:"subsections,omitempty"`

	// index locates a subsection in its section, as it does for a field.
	index int
}

// Table is a repeated table inside a section.
type Table struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Help   string  `json:"help,omitempty"`
	Fields []Field `json:"fields"`
	// Create is what a new record is made from, empty for a record that
	// starts blank. "token" makes the page ask the server for a new bearer
	// token, which it shows once and keeps only the hash of.
	Create string `json:"create,omitempty"`

	// index locates the slice in its section, as it does for a field.
	index int
}

// Field is one key. Kind is what the page renders it as: text, secret, bool,
// int or lines, the last being a list of strings, one per line.
type Field struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Help  string `json:"help,omitempty"`
	Kind  string `json:"kind"`

	// Upload is the kind of key material the field holds, empty for a field
	// that holds none. It gives the page its Upload and Generate buttons and
	// tells the server what an uploaded file has to be.
	Upload string `json:"upload,omitempty"`
	// Pair is the key of the private key belonging to a certificate, which is
	// what lets one Generate fill both halves of a pair.
	Pair string `json:"pair,omitempty"`
	// Summary marks a field of a record that says what the record is when it
	// is folded up: its first text, and every plain switch. The page knows
	// the name of no setting, so which fields those are is decided here, by
	// their shape.
	Summary bool `json:"summary,omitempty"`
	// ReadOnly is a value the page shows and sends back but does not let
	// anyone type into, because it is made by the server: a token's hash.
	ReadOnly bool `json:"readOnly,omitempty"`

	// index locates the field in its struct, so that reading and writing a
	// value walks the same path the schema was built from.
	index int
	// fixed is the value of a field that is not a key of the file at all but
	// a constant of the server, shown beside the keys it belongs with: the S3
	// region. It is read from here, never from the file, and what
	// the page posts for it is ignored.
	fixed    string
	constant bool
}

// fixedFields are the constants shown on a section's tab, each after the key
// it is placed behind. They are read-only, since there is nothing to choose.
var fixedFields = map[string][]struct {
	after string
	field Field
}{
	"http": {
		{"enableS3", Field{Key: "s3Region", Label: "s3Region", Kind: kindText, ReadOnly: true,
			Help:  "The one region the S3 API answers for; clients have to sign their requests for it. It is fixed and cannot be changed.",
			fixed: config.S3Region, constant: true}},
	},
}

// serverMade are the keys of a section the server writes into the file itself
// and nobody types in: the share link secret is generated at the first start,
// and changing it would revoke every link handed out, so the page only shows
// it and sends it back as it came.
var serverMade = map[string]bool{"http.shareLinkSecret": true}

// withFixed places the constants of a section among its fields.
func withFixed(section string, fields []Field) []Field {
	for _, entry := range fixedFields[section] {
		at := len(fields)
		for i, field := range fields {
			if field.Key == entry.after {
				at = i + 1
				break
			}
		}
		fields = append(fields[:at], append([]Field{entry.field}, fields[at:]...)...)
	}
	return fields
}

const (
	kindText   = "text"
	kindSecret = "secret"
	kindBool   = "bool"
	kindInt    = "int"
	kindLines  = "lines"
)

// build reflects over config.Config. The second result names the fields the
// walk did not recognise, which the server logs rather than dropping in
// silence, so that a shape this does not handle yet is noticed at startup.
func build() (Schema, []string) {
	var schema Schema
	var skipped []string

	configType := reflect.TypeOf(config.Config{})
	for i := range configType.NumField() {
		field := configType.Field(i)
		key := tomlName(field)
		switch {
		case key == "":
			skipped = append(skipped, field.Name)
			continue

		case field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Struct:
			// a list at the top of the file is a tab of its own, holding
			// nothing but its records
			table, missed := buildTable(field, key, i)
			// the tab carries the description; the list under it is the tab
			table.Help = ""
			schema.Sections = append(schema.Sections, Section{
				Key: key, Label: strings.ToUpper(key), Help: help(key, ""),
				Fields: []Field{}, Tables: []Table{table}, Direct: true,
			})
			skipped = append(skipped, missed...)
			continue

		case field.Type.Kind() != reflect.Struct:
			skipped = append(skipped, field.Name)
			continue
		}
		section, missed := buildSection(field.Type, key, true)
		section.Label = strings.ToUpper(key)
		section.Help = help(key, "")
		schema.Sections = append(schema.Sections, section)
		skipped = append(skipped, missed...)
	}
	return schema, skipped
}

// buildSection walks the keys of one table of the file, path being its name
// in the file, "ftp" or "general.ssh". A struct among them is a subsection
// when nested allows one, which it does at the top level only: the tab has
// room for one row of tabs below its own.
func buildSection(structure reflect.Type, path string, nested bool) (Section, []string) {
	var skipped []string
	key := path[strings.LastIndex(path, ".")+1:]
	section := Section{Key: key, Label: key, Fields: []Field{}}
	for k := range structure.NumField() {
		inner := structure.Field(k)
		name := tomlName(inner)
		if name == "" {
			continue
		}
		switch kind, ok := kindOf(inner.Type); {
		case ok:
			made := newField(name, kind, k, path+"."+name, structure.Name()+"."+inner.Name)
			made.ReadOnly = serverMade[path+"."+name]
			section.Fields = append(section.Fields, made)

		case inner.Type.Kind() == reflect.Slice && inner.Type.Elem().Kind() == reflect.Struct:
			table, missed := buildTable(inner, path+"."+name, k)
			section.Tables = append(section.Tables, table)
			skipped = append(skipped, missed...)

		case inner.Type.Kind() == reflect.Struct && nested:
			sub, missed := buildSection(inner.Type, path+"."+name, false)
			sub.Help = help(path+"."+name, structure.Name()+"."+inner.Name)
			sub.index = k
			section.Subsections = append(section.Subsections, sub)
			skipped = append(skipped, missed...)

		default:
			skipped = append(skipped, structure.Name()+"."+inner.Name)
		}
	}
	pairUp(section.Fields)
	section.Fields = withFixed(path, section.Fields)
	return section, skipped
}

func buildTable(field reflect.StructField, path string, index int) (Table, []string) {
	var skipped []string
	element := field.Type.Elem()
	table := Table{
		Key:    tomlName(field),
		Label:  tomlName(field),
		Help:   help(path, ""),
		index:  index,
		Fields: make([]Field, 0, element.NumField()),
	}
	// a token is not typed in: its hash comes from the server, which made the
	// token, and so does when it expires
	isToken := element == reflect.TypeOf(config.Token{})
	if isToken {
		table.Create = config.KindToken
	}
	hasText := false
	for i := range element.NumField() {
		inner := element.Field(i)
		name := tomlName(inner)
		if name == "" {
			continue
		}
		kind, ok := kindOf(inner.Type)
		if !ok {
			skipped = append(skipped, element.Name()+"."+inner.Name)
			continue
		}
		field := newField(name, kind, i, path+"."+name, element.Name()+"."+inner.Name)
		// what names a folded record: its first text (the username, the path)
		// and the switches, which are the plain bools; the pointers are the
		// rights, and a record is not summed up by its rights
		field.Summary = (kind == kindText && !hasText) || inner.Type.Kind() == reflect.Bool
		if isToken {
			switch inner.Name {
			case "Hash":
				field.ReadOnly = true
			case "Expires":
				// a folded token says until when it works
				field.Summary = true
			}
		}
		if kind == kindText {
			hasText = true
		}
		table.Fields = append(table.Fields, field)
	}
	return table, skipped
}

func newField(name, kind string, index int, path, source string) Field {
	if kind == kindText && secret(name) {
		kind = kindSecret
	}
	return Field{
		Key: name, Label: name, Help: help(path, source), Kind: kind,
		Upload: material(name), index: index,
	}
}

// kindOf reports how a field is edited, and whether it is one this can edit at
// all.
func kindOf(fieldType reflect.Type) (string, bool) {
	switch fieldType.Kind() {
	case reflect.Bool:
		return kindBool, true
	case reflect.String:
		return kindText, true
	case reflect.Int, reflect.Int64:
		return kindInt, true
	case reflect.Pointer:
		if fieldType.Elem().Kind() == reflect.Bool {
			return kindBool, true
		}
	case reflect.Slice:
		if fieldType.Elem().Kind() == reflect.String {
			return kindLines, true
		}
	}
	return "", false
}

// secret reports the fields the page masks: the passwords, and the private
// keys now that the file holds the key itself. A certificate is public and is
// not one of them.
func secret(name string) bool {
	if strings.Contains(strings.ToLower(name), "password") || strings.EqualFold(name, "shareLinkSecret") {
		return true
	}
	kind := material(name)
	return kind == config.KindTLSKey || kind == config.KindSSHKey ||
		kind == config.KindSessionSecret
}

// material reports the kind of key material a key holds, which is what gives
// the field its Upload and Generate buttons.
//
// The name is matched exactly rather than by substring, so that a section added
// later with a cert and key pair gets the buttons with nothing else to do,
// while an unrelated future apiKey is not mistaken for a private key.
func material(name string) string {
	switch strings.ToLower(name) {
	case "cert":
		return config.KindCertificate
	case "key":
		return config.KindTLSKey
	case "hostkey":
		return config.KindSSHKey
	case "httpsessiontokensecret":
		return config.KindSessionSecret
	}
	return ""
}

// pairUp gives every certificate in a section the name of its private key, so
// that Generate can fill both at once. A certificate without one in the same
// section keeps an empty Pair and generates nothing.
func pairUp(fields []Field) {
	var key string
	for _, field := range fields {
		if field.Upload == config.KindTLSKey {
			key = field.Key
		}
	}
	for i := range fields {
		if fields[i].Upload == config.KindCertificate {
			fields[i].Pair = key
		}
	}
}

// help prefers the comment in the shipped template, which is the description
// written for whoever edits the file, and falls back to the doc comment above
// the field in the source.
func help(path, source string) string {
	if text := config.TemplateDocs()[path]; text != "" {
		return text
	}
	return config.Docs()[source]
}

// tomlName is the key a field has in the file, or "" for one that has none.
func tomlName(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("toml")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	return name
}

// Values renders a configuration as the tree the page edits: the toml keys of
// the schema, with the values the file holds.
func (s Schema) Values(cfg config.Config) map[string]any {
	root := reflect.ValueOf(cfg)
	values := make(map[string]any, len(s.Sections))
	for i, section := range s.Sections {
		if section.Direct {
			values[section.Key] = section.Tables[0].records(root.Field(i))
			continue
		}
		values[section.Key] = section.values(root.Field(i))
	}
	return values
}

// Summaries describes every value that holds key material, keyed "ftps.cert"
// and the like. Base64 tells the reader nothing about what is stored, so the
// page shows this line under the box instead.
func (s Schema) Summaries(values map[string]any) map[string]string {
	summaries := make(map[string]string)
	for _, section := range s.Sections {
		if held, ok := values[section.Key].(map[string]any); ok {
			section.summaries(section.Key, held, summaries)
		}
	}
	return summaries
}

// summaries adds the descriptions of the key material in one section and its
// subsections, path being the section's name in the file.
func (s Section) summaries(path string, held map[string]any, into map[string]string) {
	for _, field := range s.Fields {
		if field.Upload == "" {
			continue
		}
		value, _ := held[field.Key].(string)
		if text := config.Describe(field.Upload, value); text != "" {
			into[path+"."+field.Key] = text
		}
	}
	for _, sub := range s.Subsections {
		if inner, ok := held[sub.Key].(map[string]any); ok {
			sub.summaries(path+"."+sub.Key, inner, into)
		}
	}
}

func (s Section) values(from reflect.Value) map[string]any {
	values := make(map[string]any, len(s.Fields)+len(s.Tables)+len(s.Subsections))
	for _, sub := range s.Subsections {
		values[sub.Key] = sub.values(from.Field(sub.index))
	}
	for _, field := range s.Fields {
		if field.constant {
			values[field.Key] = field.fixed
			continue
		}
		values[field.Key] = read(from.Field(field.index))
	}
	for _, table := range s.Tables {
		values[table.Key] = table.records(from.Field(table.index))
	}
	return values
}

// records renders one repeated table, one map per entry.
func (t Table) records(slice reflect.Value) []any {
	records := make([]any, 0, slice.Len())
	for i := range slice.Len() {
		record := make(map[string]any, len(t.Fields))
		for _, field := range t.Fields {
			record[field.Key] = read(slice.Index(i).Field(field.index))
		}
		records = append(records, record)
	}
	return records
}

// read turns one field into a value the browser can hold. A pointer to a bool
// that is unset reads as false: unset and false mean the same thing for every
// one of them, because a permission is denied unless it is granted.
func read(value reflect.Value) any {
	switch value.Kind() {
	case reflect.Pointer:
		return !value.IsNil() && value.Elem().Bool()
	case reflect.Slice:
		lines := make([]string, 0, value.Len())
		for i := range value.Len() {
			lines = append(lines, value.Index(i).String())
		}
		return lines
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int64:
		return value.Int()
	default:
		return value.String()
	}
}

// Apply builds a configuration from what the page posted. It starts from the
// defaults, so a key the page does not know about keeps its default rather than
// its zero value, and coerces every value into the type the field actually has.
func (s Schema) Apply(values map[string]any) (config.Config, error) {
	cfg := config.Default()
	root := reflect.ValueOf(&cfg).Elem()
	for i, section := range s.Sections {
		if section.Direct {
			raw, ok := values[section.Key]
			if !ok {
				continue
			}
			if err := section.Tables[0].apply(root.Field(i), raw, section.Key); err != nil {
				return cfg, err
			}
			continue
		}
		posted, ok := values[section.Key].(map[string]any)
		if !ok {
			continue
		}
		if err := section.apply(root.Field(i), posted, section.Key); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// apply writes what the page posted for one section into it, path being the
// section's name in the file, which an error names the key by.
func (s Section) apply(into reflect.Value, posted map[string]any, path string) error {
	for _, field := range s.Fields {
		value, ok := posted[field.Key]
		if !ok || field.constant {
			continue
		}
		if err := write(into.Field(field.index), value); err != nil {
			return fmt.Errorf("%s.%s: %w", path, field.Key, err)
		}
	}

	for _, table := range s.Tables {
		raw, ok := posted[table.Key]
		if !ok {
			continue
		}
		if err := table.apply(into.Field(table.index), raw, path+"."+table.Key); err != nil {
			return err
		}
	}

	for _, sub := range s.Subsections {
		raw, ok := posted[sub.Key]
		if !ok {
			continue
		}
		inner, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s.%s is not a table", path, sub.Key)
		}
		if err := sub.apply(into.Field(sub.index), inner, path+"."+sub.Key); err != nil {
			return err
		}
	}
	return nil
}

// apply replaces one repeated table with what the page posted for it. path
// names the table in an error, "http.cleanup" or "users".
func (t Table) apply(slice reflect.Value, raw any, path string) error {
	records, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s is not a list of records", path)
	}
	built := reflect.MakeSlice(slice.Type(), len(records), len(records))
	for i, entry := range records {
		fields, ok := entry.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%d] is not a record", path, i)
		}
		for _, field := range t.Fields {
			value, ok := fields[field.Key]
			if !ok {
				continue
			}
			if err := write(built.Index(i).Field(field.index), value); err != nil {
				return fmt.Errorf("%s[%d].%s: %w", path, i, field.Key, err)
			}
		}
	}
	slice.Set(built)
	return nil
}

// write coerces one posted value into the field it belongs to. JSON has one
// number type, so a port arrives as a float and has to be put back into an int
// rather than assigned.
func write(into reflect.Value, value any) error {
	switch into.Kind() {
	case reflect.Bool:
		flag, err := asBool(value)
		if err != nil {
			return err
		}
		into.SetBool(flag)

	case reflect.Pointer:
		flag, err := asBool(value)
		if err != nil {
			return err
		}
		// written out even when it is false, so that what the page shows and
		// what the file says are the same thing
		into.Set(reflect.ValueOf(&flag))

	case reflect.String:
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("%v is not a text value", value)
		}
		into.SetString(text)

	case reflect.Int, reflect.Int64:
		number, err := asInt(value)
		if err != nil {
			return err
		}
		if into.OverflowInt(number) {
			return fmt.Errorf("%d does not fit", number)
		}
		into.SetInt(number)

	case reflect.Slice:
		entries, err := asStrings(value)
		if err != nil {
			return err
		}
		lines := reflect.MakeSlice(into.Type(), 0, len(entries))
		for _, entry := range entries {
			lines = reflect.Append(lines, reflect.ValueOf(entry))
		}
		into.Set(lines)
	}
	return nil
}

// asStrings accepts a list as JSON decodes one and as Values produces one.
func asStrings(value any) ([]string, error) {
	switch typed := value.(type) {
	case []string:
		return typed, nil
	case []any:
		entries := make([]string, 0, len(typed))
		for _, entry := range typed {
			text, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("%v is not a text value", entry)
			}
			entries = append(entries, text)
		}
		return entries, nil
	}
	return nil, fmt.Errorf("%v is not a list", value)
}

func asBool(value any) (bool, error) {
	switch typed := value.(type) {
	case bool:
		return typed, nil
	case string:
		return typed == "true", nil
	}
	return false, fmt.Errorf("%v is not true or false", value)
}

func asInt(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case float64:
		if typed != float64(int64(typed)) {
			return 0, fmt.Errorf("%v is not a whole number", typed)
		}
		return int64(typed), nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, nil
		}
		number, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number", typed)
		}
		return number, nil
	}
	return 0, fmt.Errorf("%v is not a number", value)
}

package admin

import (
	"reflect"
	"testing"

	"go-fs/internal/config"
)

// TestSchemaCoversTheWholeFile is the test that keeps the interface flexible:
// the form is generated, so every section and every repeated table of the
// configuration has to appear in it without anyone adding it by hand.
func TestSchemaCoversTheWholeFile(t *testing.T) {
	schema, skipped := build()
	if len(skipped) != 0 {
		t.Fatalf("the schema cannot edit %v", skipped)
	}

	sections := make(map[string]Section, len(schema.Sections))
	for _, section := range schema.Sections {
		sections[section.Key] = section
	}
	for _, name := range []string{"general", "users", "ftp", "ftps", "sftp", "http", "https", "tftp"} {
		if _, ok := sections[name]; !ok {
			t.Errorf("the schema has no %s section", name)
		}
	}
	if len(sections) != reflect.TypeOf(config.Config{}).NumField() {
		t.Errorf("the schema has %d sections, the configuration has %d",
			len(sections), reflect.TypeOf(config.Config{}).NumField())
	}

	tables := map[string]int{"ftp": 0, "sftp": 0, "http": 1, "general": 0, "users": 1}
	for name, want := range tables {
		if got := len(sections[name].Tables); got != want {
			t.Errorf("%s has %d repeated tables, want %d", name, got, want)
		}
	}

	// the accounts are a list at the top of the file, and their tab sits
	// where the file has them: between general and the first server
	if !sections["users"].Direct || sections["ftp"].Direct {
		t.Error("users is the direct section, and the only one")
	}
	if len(sections["users"].Fields) != 0 || sections["users"].Fields == nil {
		t.Errorf("users has fields of its own: %v", sections["users"].Fields)
	}
	var order []string
	for _, section := range schema.Sections[:3] {
		order = append(order, section.Key)
	}
	if want := []string{"general", "users", "ftp"}; !reflect.DeepEqual(order, want) {
		t.Errorf("the tabs open %v, want %v", order, want)
	}
}

// TestSummaryFields checks what a folded record is named by: its first text
// and its switches, and not its rights or its secrets.
func TestSummaryFields(t *testing.T) {
	schema, _ := build()
	summary := make(map[string]bool)
	for _, section := range schema.Sections {
		for _, table := range section.Tables {
			for _, field := range table.Fields {
				summary[section.Key+"."+table.Key+"."+field.Key] = field.Summary
			}
		}
	}
	for key, want := range map[string]bool{
		"users.users.username":            true,
		"users.users.ftp":                 true,
		"users.users.sftp":                true,
		"users.users.http":                true,
		"users.users.isAdmin":             true,
		"users.users.password":            false,
		"users.users.basefolder":          false,
		"users.users.allowUserFileCreate": false,
		"http.cleanup.path":               true,
		"http.cleanup.keep":               false,
	} {
		if summary[key] != want {
			t.Errorf("%s summary = %v, want %v", key, summary[key], want)
		}
	}
}

// TestFieldKinds checks the four shapes the page renders, including that a
// password is masked and a public key is not.
func TestFieldKinds(t *testing.T) {
	schema, _ := build()
	kinds := make(map[string]string)
	for _, section := range schema.Sections {
		for _, field := range section.Fields {
			kinds[section.Key+"."+field.Key] = field.Kind
		}
		for _, table := range section.Tables {
			for _, field := range table.Fields {
				kinds[section.Key+"."+table.Key+"."+field.Key] = field.Kind
			}
		}
	}

	for key, want := range map[string]string{
		"ftp.enabled":                     kindBool,
		"ftp.port":                        kindInt,
		"ftp.basefolder":                  kindText,
		"http.maxUploadSize":              kindInt,
		"http.methodsRequireAuth":         kindLines,
		"general.logLevel":                kindText,
		"http.enableAdminInterface":       kindBool,
		"users.users.isAdmin":             kindBool,
		"sftp.hostkey":                    kindSecret,
		"users.users.password":            kindSecret,
		"users.users.ftp":                 kindBool,
		"users.users.allowUserFileCreate": kindBool,
		"users.users.authorizedKeys":      kindLines,
		"users.users.paths":               kindLines,
		"http.cleanup.keep":               kindInt,
	} {
		if kinds[key] != want {
			t.Errorf("%s is %q, want %q", key, kinds[key], want)
		}
	}
}

// TestHelpComesFromTheFile checks that the description a field carries is the
// comment that documents it, so that documenting a key once documents it in the
// browser too.
func TestHelpComesFromTheFile(t *testing.T) {
	schema, _ := build()
	help := make(map[string]string)
	for _, section := range schema.Sections {
		for _, field := range section.Fields {
			help[section.Key+"."+field.Key] = field.Help
		}
		for _, table := range section.Tables {
			for _, field := range table.Fields {
				help[section.Key+"."+table.Key+"."+field.Key] = field.Help
			}
		}
	}
	if _, ok := help["ftp.maxConnections"]; !ok {
		t.Fatal("ftp.maxConnections is not in the schema")
	}
	if help["ftp.maxConnections"] != "maximum simultaneous control connections" {
		t.Errorf("ftp.maxConnections help is %q", help["ftp.maxConnections"])
	}
	// one comment above several keys: every one of them carries it, so that
	// the page shows the help icon on each
	for _, key := range []string{"users.users.sftp", "users.users.http"} {
		if help[key] == "" || help[key] != help["users.users.ftp"] {
			t.Errorf("%s help is %q, want that of users.ftp %q", key, help[key], help["users.users.ftp"])
		}
	}
	if help["ftps.key"] == "" || help["ftps.key"] != help["ftps.cert"] {
		t.Errorf("ftps.key help is %q, want that of ftps.cert", help["ftps.key"])
	}
}

// TestValuesRoundTrip is what Apply relies on: what the page is given, posted
// back unchanged, has to describe the same configuration.
func TestValuesRoundTrip(t *testing.T) {
	schema, _ := build()

	yes := true
	cfg := config.Default()
	cfg.General.Basefolder = "/srv/files"
	cfg.HTTP.MaxUploadSize = 1 << 30
	cfg.Users = []config.User{
		{Username: "john", Password: "doe", FTP: true, HTTP: true, Paths: []string{"^/public/"}, AllowUserFileRetrieve: &yes},
		{Username: "anonymous", FTP: true, AllowLoginWithoutPassword: &yes},
		{Username: "max", SFTP: true, AuthorizedKeys: []string{"ssh-ed25519 AAAA max@laptop"}},
	}
	cfg.HTTP.Cleanup = []config.Cleanup{{Path: "/iso", Keep: 10}}

	first := schema.Values(cfg)
	if records, ok := first["users"].([]any); !ok || len(records) != 3 {
		t.Errorf("users renders as %v, want its three records", first["users"])
	}
	applied, err := schema.Apply(roundTripJSON(t, first))
	if err != nil {
		t.Fatal(err)
	}
	if second := schema.Values(applied); !reflect.DeepEqual(first, second) {
		t.Errorf("the values changed on the way through\nbefore %v\nafter  %v", first, second)
	}

	// the parts a round trip must not lose
	if len(applied.Users) != 3 || applied.Users[0].Username != "john" {
		t.Errorf("the accounts did not survive: %+v", applied.Users)
	}
	if !applied.Users[0].FTP || !applied.Users[0].HTTP || applied.Users[0].SFTP {
		t.Errorf("the switches did not survive: %+v", applied.Users[0])
	}
	if !applied.Users[0].Permissions().FileRetrieve {
		t.Error("a granted permission did not survive")
	}
	if applied.Users[0].Permissions().FileCreate {
		t.Error("a permission that was never granted came back granted")
	}
	if applied.HTTP.MaxUploadSize != 1<<30 {
		t.Errorf("http.maxUploadSize is %d", applied.HTTP.MaxUploadSize)
	}
	if applied.HTTP.Cleanup[0].Keep != 10 {
		t.Errorf("http.cleanup did not survive: %+v", applied.HTTP.Cleanup)
	}
	if applied.Users[2].AuthorizedKeys[0] != "ssh-ed25519 AAAA max@laptop" {
		t.Errorf("the authorized key did not survive: %+v", applied.Users[2])
	}
}

// TestInheritedBasefolderStaysInherited guards the reason the interface parses
// the file rather than loading it: a section that leans on general.basefolder
// must not come back with its own copy of it.
func TestInheritedBasefolderStaysInherited(t *testing.T) {
	schema, _ := build()
	cfg := config.Default()
	cfg.General.Basefolder = "/srv/files"

	applied, err := schema.Apply(roundTripJSON(t, schema.Values(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	for name, folder := range map[string]string{
		"ftp":  applied.FTP.Basefolder,
		"sftp": applied.SFTP.Basefolder,
		"http": applied.HTTP.Basefolder,
		"tftp": applied.TFTP.Basefolder,
	} {
		if folder != "" {
			t.Errorf("%s.basefolder became %q, it should still be inherited", name, folder)
		}
	}
	if applied.Resolved().FTP.Basefolder != "/srv/files" {
		t.Error("the fallback is no longer applied")
	}
}

// TestApplyCoercesNumbers covers what JSON does to an integer: it arrives as a
// float, or as the text of an input box.
func TestApplyCoercesNumbers(t *testing.T) {
	schema, _ := build()
	values := schema.Values(config.Default())
	values["ftp"].(map[string]any)["port"] = "2121"
	values["http"].(map[string]any)["maxConnections"] = float64(50)
	values["tftp"].(map[string]any)["port"] = ""

	applied, err := schema.Apply(values)
	if err != nil {
		t.Fatal(err)
	}
	if applied.FTP.Port != 2121 || applied.HTTP.MaxConnections != 50 || applied.TFTP.Port != 0 {
		t.Errorf("ftp.port %d, http.maxConnections %d, tftp.port %d",
			applied.FTP.Port, applied.HTTP.MaxConnections, applied.TFTP.Port)
	}

	values["ftp"].(map[string]any)["port"] = "twentyone"
	if _, err := schema.Apply(values); err == nil {
		t.Error("a port that is not a number was accepted")
	}
}

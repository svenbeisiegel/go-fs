package admin

import (
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"go-fs/internal/config"
)

// A table nested in a section, [general.ssh], is a subsection of it: the page
// shows it under a tab of its own below the section's, and its keys are read
// and written as a table inside the section's.
func TestANestedTableIsASubsection(t *testing.T) {
	schema, skipped := build()
	if len(skipped) != 0 {
		t.Fatalf("the schema cannot edit %v", skipped)
	}
	var general Section
	for _, section := range schema.Sections {
		if section.Key == "general" {
			general = section
		}
		if section.Key != "general" && len(section.Subsections) != 0 {
			t.Errorf("%s has subsections %v", section.Key, section.Subsections)
		}
	}
	if len(general.Subsections) != 1 || general.Subsections[0].Key != "ssh" {
		t.Fatalf("general has the subsections %+v, want ssh alone", general.Subsections)
	}
	ssh := general.Subsections[0]
	if ssh.Label != "ssh" || !strings.Contains(ssh.Help, "2 MB") {
		t.Errorf("ssh is labelled %q with the help %q", ssh.Label, ssh.Help)
	}
	kinds := make(map[string]string)
	for _, field := range ssh.Fields {
		kinds[field.Key] = field.Kind
		if field.Help == "" {
			t.Errorf("general.ssh.%s has no help", field.Key)
		}
	}
	for key, want := range map[string]string{"ciphers": kindLines, "banner": kindLines, "maxSessions": kindInt} {
		if kinds[key] != want {
			t.Errorf("general.ssh.%s is %q, want %q", key, kinds[key], want)
		}
	}
	// the section's own keys stay where they were, and none of the nested
	// ones is among them
	for _, field := range general.Fields {
		if field.Key == "ciphers" || field.Key == "ssh" {
			t.Errorf("general has the key %s of its own", field.Key)
		}
	}
}

func TestASubsectionRoundTrips(t *testing.T) {
	schema, _ := build()
	cfg := config.Default()
	cfg.General.SSH.Ciphers = []string{"aes128-gcm@openssh.com"}
	cfg.General.SSH.MaxSessions = 3
	cfg.General.SSH.Banner = []string{"one", "two"}

	first := schema.Values(cfg)
	nested, ok := first["general"].(map[string]any)["ssh"].(map[string]any)
	if !ok {
		t.Fatalf("general.ssh renders as %v", first["general"])
	}
	if nested["maxSessions"] != int64(3) {
		t.Errorf("general.ssh.maxSessions renders as %v", nested["maxSessions"])
	}
	applied, err := schema.Apply(roundTripJSON(t, first))
	if err != nil {
		t.Fatal(err)
	}
	// compared as rendered, since an empty list comes back empty rather than
	// nil, which means the same
	if second := schema.Values(applied)["general"].(map[string]any)["ssh"]; !reflect.DeepEqual(nested, second) {
		t.Errorf("general.ssh came back as %v, want %v", second, nested)
	}

	// an error in it names the key by its whole path
	first["general"].(map[string]any)["ssh"].(map[string]any)["maxSessions"] = "many"
	if _, err := schema.Apply(roundTripJSON(t, first)); err == nil ||
		!strings.Contains(err.Error(), "general.ssh.maxSessions") {
		t.Errorf("err = %v, want it to name general.ssh.maxSessions", err)
	}
}

func TestApplyWritesASubsection(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)

	body := get(t, front)
	ssh := section(t, body.Values, "general")["ssh"].(map[string]any)
	ssh["ciphers"] = []string{"chacha20-poly1305@openssh.com"}
	ssh["maxSessions"] = 4
	if status, answer := post(t, front, body.Values, nil); status != http.StatusOK {
		t.Fatalf("apply answered %d: %s", status, answer)
	}

	written, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if written.General.SSH.MaxSessions != 4 ||
		!reflect.DeepEqual(written.General.SSH.Ciphers, []string{"chacha20-poly1305@openssh.com"}) {
		t.Errorf("the file says %+v", written.General.SSH)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "[general.ssh]") {
		t.Errorf("the file has no [general.ssh] table:\n%s", data)
	}

	// and one the configuration refuses is refused with its path
	body = get(t, front)
	section(t, body.Values, "general")["ssh"].(map[string]any)["ciphers"] = []string{"aes128-gmc"}
	status, answer := post(t, front, body.Values, nil)
	if status != http.StatusBadRequest || !strings.Contains(answer, "general.ssh.ciphers") {
		t.Errorf("an unknown cipher answered %d: %s", status, answer)
	}
}

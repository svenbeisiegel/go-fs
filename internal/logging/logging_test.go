package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSetLevelReachesDerivedLoggers(t *testing.T) {
	var out bytes.Buffer
	root := NewTo(&out, "info", "text")
	derived := root.With("client", "1.2.3.4")

	derived.Debug("hidden")
	if out.Len() != 0 {
		t.Fatalf("a debug record got through at info: %q", out.String())
	}

	if !root.SetLevel("debug") {
		t.Fatal("switching to debug has to report a change")
	}
	if root.SetLevel("debug") {
		t.Fatal("switching to the same level is not a change")
	}
	derived.Debug("shown")
	if !strings.Contains(out.String(), "shown") {
		t.Fatalf("a debug record has to reach a logger derived before the switch: %q", out.String())
	}
	if root.Level() != slog.LevelDebug {
		t.Errorf("Level = %v", root.Level())
	}
}

func TestDebugRecordsCarryTheirSource(t *testing.T) {
	var out bytes.Buffer
	root := NewTo(&out, "debug", "json")
	root.Debug("traced")
	root.Info("plain")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("records = %q", lines)
	}
	var traced, plain map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &traced); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &plain); err != nil {
		t.Fatal(err)
	}
	if source, _ := traced["source"].(string); !strings.HasPrefix(source, "logging_test.go:") {
		t.Errorf("debug source = %q", traced["source"])
	}
	if _, present := plain["source"]; present {
		t.Errorf("an info record must not carry a source: %v", plain)
	}
}

func TestDurationsAreStringsInJSON(t *testing.T) {
	var out bytes.Buffer
	root := NewTo(&out, "info", "json")
	root.Info("done", "took", 1500*time.Millisecond)
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["took"] != "1.5s" {
		t.Errorf("took = %v (%T), want the string 1.5s", record["took"], record["took"])
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "WARN": slog.LevelWarn,
		"error": slog.LevelError, "": slog.LevelInfo, "nonsense": slog.LevelInfo,
	}
	for name, want := range cases {
		if got := ParseLevel(name); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestHTTPErrorLogLevels(t *testing.T) {
	var out bytes.Buffer
	root := NewTo(&out, "debug", "json")
	errorLog := HTTPErrorLog(root.Logger, "http")

	errorLog.Print("http: TLS handshake error from 1.2.3.4:5: EOF")
	errorLog.Print("http: panic serving 1.2.3.4:5: boom\ngoroutine 1 [running]:")
	errorLog.Print("http: Accept error: too many open files")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("records = %q", lines)
	}
	want := []string{"DEBUG", "ERROR", "WARN"}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["level"] != want[i] {
			t.Errorf("record %d level = %v, want %s: %s", i, record["level"], want[i], line)
		}
		if record["server"] != "http" {
			t.Errorf("record %d server = %v", i, record["server"])
		}
	}
	if !strings.Contains(lines[1], "goroutine 1") {
		t.Errorf("the panic record has to carry the stack trace: %s", lines[1])
	}
}

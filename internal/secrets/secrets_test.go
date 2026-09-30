package secrets

import (
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	long := strings.Repeat("x", 4096)
	cases := []struct {
		a, b string
		want bool
	}{
		{"doe", "doe", true},
		{"", "", true},
		{long, long, true},
		{"doe", "Doe", false},
		{"doe", "doe ", false},
		{"doe", "", false},
		{"", "doe", false},
		{"short", long, false},
		{long, long[:len(long)-1] + "y", false},
		{"pässwörd", "pässwörd", true},
		{"pässwörd", "passwort", false},
	}
	for _, tc := range cases {
		if got := Match(tc.a, tc.b); got != tc.want {
			t.Errorf("Match(%.10q, %.10q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := MatchBytes([]byte(tc.a), []byte(tc.b)); got != tc.want {
			t.Errorf("MatchBytes(%.10q, %.10q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// A nil slice and an empty one are the same secret: nothing.
func TestMatchBytesTreatsNilAsEmpty(t *testing.T) {
	if !MatchBytes(nil, []byte{}) {
		t.Error("nil and empty should match")
	}
}

func FuzzMatch(f *testing.F) {
	f.Add("doe", "doe")
	f.Add("doe", "roe")
	f.Add("", "x")
	f.Fuzz(func(t *testing.T, a, b string) {
		if got := Match(a, b); got != (a == b) {
			t.Errorf("Match(%q, %q) = %v", a, b, got)
		}
	})
}

package rpm

import (
	"strconv"
	"strings"
)

// EVR is the epoch, version and release of a package or of a dependency.
type EVR struct {
	Epoch   string
	Version string
	Release string
}

// String is the EVR as rpm writes it, the epoch left out when there is none.
func (v EVR) String() string {
	s := v.Version
	if v.Epoch != "" && v.Epoch != "0" {
		s = v.Epoch + ":" + s
	}
	if v.Release != "" {
		s += "-" + v.Release
	}
	return s
}

// parseEVR splits the version of a dependency, [epoch:]version[-release].
func parseEVR(s string) EVR {
	var v EVR
	if i := strings.IndexByte(s, ':'); i >= 0 {
		v.Epoch, s = s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.Version, v.Release = s[:i], s[i+1:]
	} else {
		v.Version = s
	}
	return v
}

// Compare orders two EVRs the way rpm does: by epoch, a missing one being 0,
// then by version and by release, each compared by Vercmp. A release missing
// on either side is not compared.
func Compare(a, b EVR) int {
	ea, _ := strconv.ParseInt(orZero(a.Epoch), 10, 64)
	eb, _ := strconv.ParseInt(orZero(b.Epoch), 10, 64)
	switch {
	case ea < eb:
		return -1
	case ea > eb:
		return 1
	}
	if c := Vercmp(a.Version, b.Version); c != 0 {
		return c
	}
	if a.Release == "" || b.Release == "" {
		return 0
	}
	return Vercmp(a.Release, b.Release)
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// Vercmp compares two version strings as rpm's rpmvercmp does: split into
// runs of digits and of letters, compared run by run, digits numerically and
// above letters, a tilde sorting before everything, even the end, and a caret
// after the end but before anything else.
func Vercmp(a, b string) int {
	if a == b {
		return 0
	}
	isAlnum := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isAlpha := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

	for len(a) > 0 || len(b) > 0 {
		// separators are skipped, but not the tilde and the caret
		for len(a) > 0 && !isAlnum(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for len(b) > 0 && !isAlnum(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}

		// a tilde sorts before everything
		if len(a) > 0 && a[0] == '~' || len(b) > 0 && b[0] == '~' {
			if len(a) == 0 || a[0] != '~' {
				return 1
			}
			if len(b) == 0 || b[0] != '~' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}

		// a caret sorts after the end, and before anything else
		if len(a) > 0 && a[0] == '^' || len(b) > 0 && b[0] == '^' {
			if len(a) == 0 {
				return -1
			}
			if len(b) == 0 {
				return 1
			}
			if a[0] != '^' {
				return 1
			}
			if b[0] != '^' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}

		if len(a) == 0 || len(b) == 0 {
			break
		}

		run := isAlpha
		numeric := isDigit(a[0])
		if numeric {
			run = isDigit
		}
		i, j := 0, 0
		for i < len(a) && run(a[i]) {
			i++
		}
		for j < len(b) && run(b[j]) {
			j++
		}
		one, two := a[:i], b[:j]
		a, b = a[i:], b[j:]

		// the runs are of different kinds: a number is newer than letters
		if len(two) == 0 {
			if numeric {
				return 1
			}
			return -1
		}

		if numeric {
			one = strings.TrimLeft(one, "0")
			two = strings.TrimLeft(two, "0")
			if len(one) != len(two) {
				if len(one) > len(two) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(one, two); c != 0 {
			return c
		}
	}

	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	default:
		return 1
	}
}

package e2e

import (
	"bytes"
	"slices"
	"testing"

	"go-fs/internal/config"
)

// operation is one thing a client does to the folder: what it needs, how it is
// done, and how the folder shows whether it happened.
type operation struct {
	name  string
	needs []right
	do    func(client) error
	// happened reports from the disk alone whether the operation took effect,
	// so that a refusal which still changed something is caught too
	happened func(t *testing.T, c *cluster) bool
}

var (
	seed    = []byte("seed")
	written = []byte("written by the test")
)

// fixture is what every operation starts from: a file and an empty folder.
func fixture(t *testing.T, c *cluster) {
	t.Helper()
	c.reset(t)
	c.write(t, "/seed.txt", seed)
	c.mkdir(t, "/empty")
}

var operations = []operation{
	{
		name:  "download",
		needs: []right{retrieve},
		do: func(cl client) error {
			content, err := cl.get("/seed.txt")
			if err == nil && !bytes.Equal(content, seed) {
				return errMismatch
			}
			return err
		},
		happened: nil, // a download leaves nothing behind; its answer is the evidence
	},
	{
		name:  "upload a new file",
		needs: []right{create},
		do:    func(cl client) error { return cl.put("/new.txt", written) },
		happened: func(t *testing.T, c *cluster) bool {
			return bytes.Equal(c.read(t, "/new.txt"), written)
		},
	},
	{
		name:  "upload over a file",
		needs: []right{overwrite},
		do:    func(cl client) error { return cl.put("/seed.txt", written) },
		happened: func(t *testing.T, c *cluster) bool {
			return !bytes.Equal(c.read(t, "/seed.txt"), seed)
		},
	},
	{
		name:     "delete a file",
		needs:    []right{deleteFile},
		do:       func(cl client) error { return cl.remove("/seed.txt") },
		happened: func(t *testing.T, c *cluster) bool { return !c.exists("/seed.txt") },
	},
	{
		name:     "create a folder",
		needs:    []right{folderCreate},
		do:       func(cl client) error { return cl.mkdir("/made") },
		happened: func(t *testing.T, c *cluster) bool { return c.exists("/made") },
	},
	{
		name:     "delete an empty folder",
		needs:    []right{folderDelete},
		do:       func(cl client) error { return cl.rmdir("/empty") },
		happened: func(t *testing.T, c *cluster) bool { return !c.exists("/empty") },
	},
	{
		// a rename creates one name and removes another, so it needs both
		name:  "rename a file",
		needs: []right{create, deleteFile},
		do:    func(cl client) error { return cl.rename("/seed.txt", "/renamed.txt") },
		happened: func(t *testing.T, c *cluster) bool {
			return !c.exists("/seed.txt") || c.exists("/renamed.txt")
		},
	},
}

type mismatch struct{}

func (mismatch) Error() string { return "the download did not return the file's content" }

var errMismatch error = mismatch{}

// grants reports whether the rights cover everything an operation needs.
func grants(have []right, needs []right) bool {
	for _, need := range needs {
		if !slices.Contains(have, need) {
			return false
		}
	}
	return true
}

// without is every right but the one named.
func without(missing right) []right {
	return slices.DeleteFunc(slices.Clone(allRights), func(r right) bool { return r == missing })
}

// Each right is taken away from an otherwise complete account in turn, and
// every operation is tried over every protocol: an operation succeeds exactly
// when the account holds what it needs, and a refused one leaves the folder
// as it was. The complete account and the account with no rights at all bound
// the table on either side.
func TestRightsMeanTheSameOnEveryProtocol(t *testing.T) {
	type profile struct {
		name   string
		rights []right
	}
	profiles := []profile{{"every right", allRights}, {"no right", nil}}
	for _, r := range allRights {
		profiles = append(profiles, profile{"all but " + r.String(), without(r)})
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			c := newCluster(t, []config.User{account("john", "doe", p.rights...)}, nil)
			for _, proto := range protocols {
				cl, err := proto.login(t, c, "john", "doe")
				if err != nil {
					t.Fatalf("%s login: %v", proto.name, err)
				}
				for _, op := range operations {
					fixture(t, c)
					want := grants(p.rights, op.needs)
					err := op.do(cl)
					if allowed := err == nil; allowed != want {
						t.Errorf("%s %s: allowed=%v, want %v (err: %v)", proto.name, op.name, allowed, want, err)
					}
					if op.happened != nil {
						if happened := op.happened(t, c); happened != want {
							t.Errorf("%s %s: took effect=%v, want %v", proto.name, op.name, happened, want)
						}
					}
				}
			}
		})
	}
}

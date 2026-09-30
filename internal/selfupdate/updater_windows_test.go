package selfupdate

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// A virus scanner holds a new executable open for a moment after it is
// written; Apply waits for it rather than failing the update.
func TestApplyWaitsForAScanner(t *testing.T) {
	public, private := newKey(t)
	fake := buildFake(t, "go-fs 9.9.9")
	u := testUpdater(t, public)
	if _, err := u.Stage(context.Background(), bytes.NewReader(signed(t, private, fake))); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	// os.Open shares neither delete nor rename, as a scanner's handle does not
	held, err := os.Open(u.staged)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(time.Second)
		_ = held.Close()
	}()

	if err := u.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Equal(readFile(t, u.exe), fake) {
		t.Error("the executable is not the new binary")
	}
}

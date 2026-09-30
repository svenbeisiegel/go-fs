package tftp

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"
	"time"
)

func FuzzParseRequest(f *testing.F) {
	f.Add([]byte("\x00\x01file.txt\x00octet\x00"))
	f.Add([]byte("\x00\x02up.bin\x00netascii\x00blksize\x001428\x00tsize\x000\x00"))
	f.Add([]byte("\x00\x01\x00\x00"))
	f.Add([]byte("\x00\x01no terminator"))
	f.Add([]byte("\x00\x01f\x00octet\x00windowsize\x00"))
	cfg := limits{
		timeout:       time.Second,
		maxTimeout:    10 * time.Second,
		retries:       3,
		maxBlockSize:  maxProtocolBlockSize,
		maxWindowSize: 64,
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) < 2 {
			// dispatch drops these before they get here
			return
		}
		req, ok := parseRequest(msg)
		if !ok {
			return
		}
		for _, forRead := range []bool{true, false} {
			got := negotiate(req, cfg, forRead, 12345)
			if got.blockSize < minBlockSize || got.blockSize > maxProtocolBlockSize {
				t.Fatalf("negotiated block size %d is outside the protocol's range", got.blockSize)
			}
			if got.windowSize < 1 || got.windowSize > cfg.maxWindowSize {
				t.Fatalf("negotiated window size %d is outside 1..%d", got.windowSize, cfg.maxWindowSize)
			}
			if got.timeout <= 0 || got.timeout > cfg.maxTimeout {
				t.Fatalf("negotiated timeout %v is outside the configured limit", got.timeout)
			}
		}
	})
}

// Encoding to netascii and decoding again gives back the host text, except
// that a CR LF the host already had reads as a line ending and comes back as
// LF. The conversion must not depend on how the data is chunked.
func FuzzNetasciiRoundTrip(f *testing.F) {
	for _, seed := range []string{"", "plain", "a\nb", "a\rb", "a\r\nb", "\r", "\r\r\n\n\r", "\x00\r\x00"} {
		f.Add([]byte(seed), uint8(1))
	}
	f.Fuzz(func(t *testing.T, host []byte, chunk uint8) {
		size := int(chunk%16) + 1

		var encoded bytes.Buffer
		if _, err := io.Copy(&encoded, newNetasciiReader(iotest.OneByteReader(bytes.NewReader(host)))); err != nil {
			t.Fatal(err)
		}
		wire := encoded.Bytes()
		for i, b := range wire {
			if b == cr && (i+1 == len(wire) || (wire[i+1] != lf && wire[i+1] != nul)) {
				t.Fatalf("encoded %q has a bare CR at %d: %q", host, i, wire)
			}
		}

		var decoded bytes.Buffer
		writer := newNetasciiWriter(&decoded)
		for rest := wire; len(rest) > 0; {
			n := min(size, len(rest))
			if _, err := writer.Write(rest[:n]); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}

		want := bytes.ReplaceAll(host, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(decoded.Bytes(), want) {
			t.Fatalf("round trip of %q gave %q, want %q", host, decoded.Bytes(), want)
		}
	})
}

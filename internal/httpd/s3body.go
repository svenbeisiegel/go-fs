package httpd

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The body of an S3 upload comes in one of two shapes. It is the object
// itself, whose SHA-256 the signature covers unless the client declared it
// UNSIGNED-PAYLOAD; or it is aws-chunked, the object cut into chunks that each
// say how long they are and, unless the encoding is the unsigned one, carry a
// signature chained to the one before. Either may name a checksum of the
// object, in a header or in a trailer after the last chunk.

// maxChunkLine is the longest a chunk header or a trailer line may be.
const maxChunkLine = 4096

var errChunkMalformed = s3Err(http.StatusBadRequest, "IncompleteBody",
	"The aws-chunked body is malformed.")

var errChunkSignature = s3Err(http.StatusForbidden, "SignatureDoesNotMatch",
	"The signature of a chunk of the body does not match.")

// chunkedReader takes the aws-chunked encoding off a body.
type chunkedReader struct {
	r *bufio.Reader
	// signed says every chunk carries a signature, and trailer that a
	// trailer follows the last chunk
	signed, trailer bool
	// key, date, scope and previous are what the next signature is checked
	// against: previous starts as the signature of the request
	key            []byte
	date, scope    string
	previous       string
	chunkSignature string
	chunkHash      hash.Hash

	remaining int64
	started   bool
	done      bool
	err       error
	trailers  map[string]string
}

func newChunkedReader(body io.Reader, sig *s3Signature) *chunkedReader {
	return &chunkedReader{
		r:         bufio.NewReaderSize(body, 64<<10),
		signed:    sig.payload == payloadStreaming || sig.payload == payloadStreamingTrailer,
		trailer:   sig.payload == payloadStreamingTrailer || sig.payload == payloadStreamingUnsignedTrailer,
		key:       sig.key,
		date:      sig.date,
		scope:     sig.scope,
		previous:  sig.seed,
		chunkHash: sha256.New(),
		trailers:  map[string]string{},
	}
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	for c.remaining == 0 {
		if c.done {
			return 0, io.EOF
		}
		if err := c.next(); err != nil {
			c.err = err
			return 0, err
		}
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if c.signed {
		c.chunkHash.Write(p[:n])
	}
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		c.err = err
	}
	return n, err
}

// next finishes the chunk that was just read, and opens the one after it.
func (c *chunkedReader) next() error {
	if c.started {
		if err := c.expectLineEnd(); err != nil {
			return err
		}
		if err := c.verifyChunk(); err != nil {
			return err
		}
	}
	c.started = true
	line, err := c.readLine()
	if err != nil {
		return err
	}
	size, extension, _ := strings.Cut(line, ";")
	n, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
	if err != nil || n < 0 {
		return errChunkMalformed
	}
	if c.signed {
		signature, ok := strings.CutPrefix(strings.TrimSpace(extension), "chunk-signature=")
		if !ok || len(signature) != 64 {
			return errChunkMalformed
		}
		c.chunkSignature = strings.ToLower(signature)
		c.chunkHash.Reset()
	}
	c.remaining = n
	if n > 0 {
		return nil
	}

	// the last chunk is empty, and signed like any other
	c.done = true
	if c.signed {
		if err := c.verifyChunk(); err != nil {
			return err
		}
	}
	if c.trailer {
		return c.readTrailer()
	}
	return c.expectLineEnd()
}

func (c *chunkedReader) verifyChunk() error {
	if !c.signed {
		return nil
	}
	value := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.date + "\n" + c.scope + "\n" + c.previous + "\n" +
		emptySHA256 + "\n" + hex.EncodeToString(c.chunkHash.Sum(nil))
	if !hmac.Equal([]byte(signString(c.key, value)), []byte(c.chunkSignature)) {
		return errChunkSignature
	}
	c.previous = c.chunkSignature
	return nil
}

// readTrailer reads the headers after the last chunk up to the empty line that
// ends the body. A signed trailer ends with a signature over the rest of it.
func (c *chunkedReader) readTrailer() error {
	var signature string
	var canonical strings.Builder
	for {
		line, err := c.readLine()
		if errors.Is(err, io.ErrUnexpectedEOF) && signature == "" && !c.signed {
			// a body that stops after its trailer, without the empty line
			break
		}
		if err != nil {
			return err
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return errChunkMalformed
		}
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if name == "x-amz-trailer-signature" {
			signature = strings.ToLower(value)
			continue
		}
		c.trailers[name] = value
		canonical.WriteString(name + ":" + value + "\n")
	}
	if !c.signed {
		return nil
	}
	value := "AWS4-HMAC-SHA256-TRAILER\n" + c.date + "\n" + c.scope + "\n" + c.previous + "\n" +
		hexSHA256(canonical.String())
	if !hmac.Equal([]byte(signString(c.key, value)), []byte(signature)) {
		return errChunkSignature
	}
	return nil
}

// readLine reads one line and takes its line end off. A line longer than a
// chunk header could be is refused rather than buffered.
func (c *chunkedReader) readLine() (string, error) {
	line, err := c.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxChunkLine {
		return "", errChunkMalformed
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// expectLineEnd reads the CRLF that ends the data of a chunk.
func (c *chunkedReader) expectLineEnd() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	if line != "" {
		return errChunkMalformed
	}
	return nil
}

// crc64NVME is the CRC-64 the S3 API calls CRC64NVME, the one the SDKs use by
// default. hash/crc64 takes its polynomial reversed.
var crc64NVME = crc64.MakeTable(0x9a6c9329ac4bc9b5)

// checksum is one x-amz-checksum-* of an object: what the client said it is,
// and the hash that works out what it is.
type checksum struct {
	name string
	hash hash.Hash
	// want is the base64 value from the header, empty when it comes in the
	// trailer
	want string
}

func newChecksumHash(algorithm string) (hash.Hash, bool) {
	switch algorithm {
	case "crc32":
		return crc32.NewIEEE(), true
	case "crc32c":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli)), true
	case "crc64nvme":
		return crc64.New(crc64NVME), true
	case "sha1":
		return sha1.New(), true
	case "sha256":
		return sha256.New(), true
	}
	return nil, false
}

// requestChecksum finds the checksum a request names, in a header or as the
// trailer it announces. A request that names none has nil.
func requestChecksum(r *http.Request) (*checksum, *s3Error) {
	name := ""
	want := ""
	for header := range r.Header {
		lower := strings.ToLower(header)
		if algorithm, ok := strings.CutPrefix(lower, "x-amz-checksum-"); ok && algorithm != "type" &&
			algorithm != "mode" && algorithm != "algorithm" {
			name, want = algorithm, r.Header.Get(header)
		}
	}
	if trailer := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Amz-Trailer"))); trailer != "" {
		algorithm, ok := strings.CutPrefix(trailer, "x-amz-checksum-")
		if !ok {
			return nil, s3Err(http.StatusBadRequest, "InvalidRequest",
				"The trailer "+trailer+" is not one this server reads.")
		}
		name = algorithm
	}
	if name == "" {
		return nil, nil
	}
	sum, ok := newChecksumHash(name)
	if !ok {
		return nil, s3Err(http.StatusBadRequest, "InvalidRequest",
			"The checksum algorithm "+name+" is not supported.")
	}
	return &checksum{name: name, hash: sum, want: want}, nil
}

// s3Body is the body of an upload as the bytes of the object: the aws-chunked
// encoding taken off, and every hash the request declared worked out on the
// way, to be compared once the last byte is in.
type s3Body struct {
	io.Reader
	chunked  *chunkedReader
	md5      hash.Hash
	sha256   hash.Hash
	wantSHA  string
	wantMD5  []byte
	checksum *checksum
	// size is the length of the object the request declared, -1 when it
	// declared none
	size int64
}

// openS3Body wraps the body of a request whose signature has been verified.
func openS3Body(r *http.Request, sig *s3Signature) (*s3Body, *s3Error) {
	body := &s3Body{md5: md5.New(), size: r.ContentLength}
	if value := r.Header.Get("Content-MD5"); value != "" {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != md5.Size {
			return nil, s3Err(http.StatusBadRequest, "InvalidDigest",
				"The Content-MD5 you specified is not valid.")
		}
		body.wantMD5 = decoded
	}
	sum, failure := requestChecksum(r)
	if failure != nil {
		return nil, failure
	}
	body.checksum = sum

	var reader io.Reader = r.Body
	switch sig.payload {
	case payloadStreaming, payloadStreamingTrailer, payloadStreamingUnsignedTrailer:
		body.chunked = newChunkedReader(r.Body, sig)
		reader = body.chunked
		body.size = -1
		if declared := r.Header.Get("X-Amz-Decoded-Content-Length"); declared != "" {
			size, err := strconv.ParseInt(declared, 10, 64)
			if err != nil || size < 0 {
				return nil, s3Err(http.StatusBadRequest, "InvalidArgument",
					"x-amz-decoded-content-length is not a length.")
			}
			body.size = size
		}
	case payloadUnsigned:
	default:
		body.sha256 = sha256.New()
		body.wantSHA = sig.payload
	}

	writers := []io.Writer{body.md5}
	if body.sha256 != nil {
		writers = append(writers, body.sha256)
	}
	if body.checksum != nil {
		writers = append(writers, body.checksum.hash)
	}
	body.Reader = io.TeeReader(reader, io.MultiWriter(writers...))
	return body, nil
}

// verify compares what was read against every hash the request declared. It
// is called once the body has been read to its end.
func (b *s3Body) verify() *s3Error {
	if b.sha256 != nil && hex.EncodeToString(b.sha256.Sum(nil)) != strings.ToLower(b.wantSHA) {
		return s3Err(http.StatusBadRequest, "XAmzContentSHA256Mismatch",
			"The provided 'x-amz-content-sha256' header does not match what was computed.")
	}
	if b.wantMD5 != nil && !bytes.Equal(b.md5.Sum(nil), b.wantMD5) {
		return s3Err(http.StatusBadRequest, "BadDigest",
			"The Content-MD5 you specified did not match what we received.")
	}
	if b.checksum != nil {
		want := b.checksum.want
		if want == "" && b.chunked != nil {
			want = b.chunked.trailers["x-amz-checksum-"+b.checksum.name]
		}
		if want != "" && base64.StdEncoding.EncodeToString(b.checksum.hash.Sum(nil)) != want {
			return s3Err(http.StatusBadRequest, "BadDigest",
				"The "+strings.ToUpper(b.checksum.name)+" you specified did not match the calculated checksum.")
		}
	}
	return nil
}

// etag is the MD5 of what was read, quoted as an ETag is.
func (b *s3Body) etag() string {
	return `"` + hex.EncodeToString(b.md5.Sum(nil)) + `"`
}

// checksumHeader is the checksum the request named, as the response header
// that echoes it, or empty.
func (b *s3Body) checksumHeader() (string, string) {
	if b.checksum == nil {
		return "", ""
	}
	return "x-amz-checksum-" + b.checksum.name,
		base64.StdEncoding.EncodeToString(b.checksum.hash.Sum(nil))
}

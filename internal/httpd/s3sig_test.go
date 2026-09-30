package httpd

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-fs/internal/config"
)

// These are the worked examples of the AWS documentation for Signature
// Version 4 on S3: the same key, the same requests and the signatures AWS
// computed for them, so the canonical request is checked against the
// specification rather than against a reading of it.
const (
	exampleAccessKey = "AKIAIOSFODNN7EXAMPLE"
	exampleSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	exampleScope     = exampleAccessKey + "/20130524/us-east-1/s3/aws4_request"
)

var exampleTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

// exampleServer is a server that knows the account of the examples, and no
// listener: the signature is checked on a request built here.
func exampleServer(t *testing.T) (*Server, *settings) {
	t.Helper()
	accounts, err := buildAccounts([]config.User{{Username: exampleAccessKey, Password: exampleSecretKey,
		S3: true, Paths: []string{"^/.*"}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{log: discardLogger()}, &settings{s3accounts: accounts}
}

func TestSigV4MatchesTheAWSExamples(t *testing.T) {
	server, set := exampleServer(t)
	cases := []struct {
		name    string
		request func() *http.Request
	}{
		{"GET object", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
			r.Host = "examplebucket.s3.amazonaws.com"
			r.Header.Set("Range", "bytes=0-9")
			r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
			r.Header.Set("X-Amz-Date", "20130524T000000Z")
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exampleScope+
				",SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"+
				"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
			return r
		}},
		{"PUT object", func() *http.Request {
			r := httptest.NewRequest(http.MethodPut, "/test%24file.text", strings.NewReader("Welcome to Amazon S3."))
			r.Host = "examplebucket.s3.amazonaws.com"
			r.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
			r.Header.Set("X-Amz-Date", "20130524T000000Z")
			r.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
			r.Header.Set("X-Amz-Content-Sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exampleScope+
				",SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,"+
				"Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
			return r
		}},
		{"GET bucket lifecycle", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/?lifecycle", nil)
			r.Host = "examplebucket.s3.amazonaws.com"
			r.Header.Set("X-Amz-Date", "20130524T000000Z")
			r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exampleScope+
				",SignedHeaders=host;x-amz-content-sha256;x-amz-date,"+
				"Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")
			return r
		}},
		{"list objects", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/?max-keys=2&prefix=J", nil)
			r.Host = "examplebucket.s3.amazonaws.com"
			r.Header.Set("X-Amz-Date", "20130524T000000Z")
			r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exampleScope+
				",SignedHeaders=host;x-amz-content-sha256;x-amz-date,"+
				"Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
			return r
		}},
		{"presigned URL", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256"+
				"&X-Amz-Credential="+strings.ReplaceAll(exampleScope, "/", "%2F")+
				"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"+
				"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", nil)
			r.Host = "examplebucket.s3.amazonaws.com"
			return r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.request()
			if !isS3Request(r) {
				t.Fatal("the request is not recognised as an S3 request")
			}
			sig, failure := server.verifyS3(set, r, exampleTime)
			if failure != nil {
				t.Fatalf("refused: %v", failure)
			}
			if sig.user.name != exampleAccessKey {
				t.Errorf("signed by %q", sig.user.name)
			}

			// and a request that differs in anything signed is refused
			tampered := tc.request()
			tampered.Host = "other.s3.amazonaws.com"
			if _, failure := server.verifyS3(set, tampered, exampleTime); failure == nil ||
				failure.code != "SignatureDoesNotMatch" || !failure.failedLogin {
				t.Errorf("a changed host is %v", failure)
			}
		})
	}
}

func TestSigV4RefusesStaleAndMisdirectedRequests(t *testing.T) {
	server, set := exampleServer(t)
	get := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
		r.Host = "examplebucket.s3.amazonaws.com"
		r.Header.Set("Range", "bytes=0-9")
		r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
		r.Header.Set("X-Amz-Date", "20130524T000000Z")
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exampleScope+
			",SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"+
			"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
		return r
	}
	if _, failure := server.verifyS3(set, get(), exampleTime.Add(16*time.Minute)); failure == nil ||
		failure.code != "RequestTimeTooSkewed" {
		t.Errorf("a request signed too long ago is %v", failure)
	}
	elsewhere := get()
	elsewhere.Header.Set("Authorization", strings.Replace(elsewhere.Header.Get("Authorization"),
		"us-east-1", "eu-west-1", 1))
	failure := func() *s3Error { _, f := server.verifyS3(set, elsewhere, exampleTime); return f }()
	if failure == nil || failure.code != "AuthorizationHeaderMalformed" || failure.region != "us-east-1" {
		t.Errorf("a request for another region is %v", failure)
	}
	if failure != nil && failure.failedLogin {
		t.Error("a wrong region counts as a wrong password")
	}
	unknown := get()
	unknown.Header.Set("Authorization", strings.Replace(unknown.Header.Get("Authorization"),
		exampleAccessKey, "NOBODY", 1))
	if _, failure := server.verifyS3(set, unknown, exampleTime); failure == nil ||
		failure.code != "SignatureDoesNotMatch" {
		t.Errorf("an unknown access key is %v", failure)
	}
	missing := get()
	missing.Header.Del("X-Amz-Content-Sha256")
	if _, failure := server.verifyS3(set, missing, exampleTime); failure == nil || failure.code != "InvalidRequest" {
		t.Errorf("a request without x-amz-content-sha256 is %v", failure)
	}
}

// exampleChunks is the body of the AWS example of a signed streaming upload:
// 66560 bytes of "a", in a chunk of 65536, one of 1024 and the empty last one.
func exampleChunks(corrupt bool) []byte {
	var body bytes.Buffer
	for _, chunk := range []struct {
		size      int
		signature string
	}{
		{65536, "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"},
		{1024, "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"},
		{0, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"},
	} {
		body.WriteString(strconv.FormatInt(int64(chunk.size), 16) + ";chunk-signature=" + chunk.signature + "\r\n")
		data := bytes.Repeat([]byte("a"), chunk.size)
		if corrupt && chunk.size == 1024 {
			data[10] = 'b'
		}
		body.Write(data)
		body.WriteString("\r\n")
	}
	return body.Bytes()
}

func exampleStreamingRequest(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/examplebucket/chunkObject.txt", bytes.NewReader(body))
	r.Host = "s3.amazonaws.com"
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	r.Header.Set("X-Amz-Content-Sha256", payloadStreaming)
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", "66560")
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exampleScope+
		",SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;"+
		"x-amz-decoded-content-length;x-amz-storage-class,"+
		"Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
	return r
}

func TestSignedChunksMatchTheAWSExample(t *testing.T) {
	server, set := exampleServer(t)
	body := exampleChunks(false)
	if len(body) != 66824 {
		t.Fatalf("the example body is %d bytes, the documentation says 66824", len(body))
	}
	r := exampleStreamingRequest(body)
	sig, failure := server.verifyS3(set, r, exampleTime)
	if failure != nil {
		t.Fatalf("the seed signature is refused: %v", failure)
	}
	decoded, failure := openS3Body(r, sig)
	if failure != nil {
		t.Fatal(failure)
	}
	data, err := io.ReadAll(decoded)
	if err != nil {
		t.Fatalf("the chunks are refused: %v", err)
	}
	if !bytes.Equal(data, bytes.Repeat([]byte("a"), 66560)) {
		t.Errorf("decoded %d bytes", len(data))
	}
	if failure := decoded.verify(); failure != nil {
		t.Error(failure)
	}

	// a byte changed in a chunk breaks its signature
	r = exampleStreamingRequest(exampleChunks(true))
	sig, _ = server.verifyS3(set, r, exampleTime)
	decoded, _ = openS3Body(r, sig)
	_, err = io.ReadAll(decoded)
	var refused *s3Error
	if !errors.As(err, &refused) || refused.code != "SignatureDoesNotMatch" {
		t.Errorf("a changed chunk is read with %v", err)
	}
}

func TestUnsignedChunksWithTrailer(t *testing.T) {
	body := "5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n"
	r := httptest.NewRequest(http.MethodPut, "/main/a.txt", strings.NewReader(body))
	r.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
	r.Header.Set("X-Amz-Decoded-Content-Length", "11")
	decoded, failure := openS3Body(r, &s3Signature{payload: payloadStreamingUnsignedTrailer})
	if failure != nil {
		t.Fatal(failure)
	}
	data, err := io.ReadAll(decoded)
	if err != nil || string(data) != "hello world" {
		t.Fatalf("decoded %q, %v", data, err)
	}
	if failure := decoded.verify(); failure != nil {
		t.Errorf("the trailer checksum is refused: %v", failure)
	}

	wrong := strings.Replace(body, "DUoRhQ==", "AAAAAA==", 1)
	r = httptest.NewRequest(http.MethodPut, "/main/a.txt", strings.NewReader(wrong))
	r.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
	decoded, _ = openS3Body(r, &s3Signature{payload: payloadStreamingUnsignedTrailer})
	if _, err := io.ReadAll(decoded); err != nil {
		t.Fatal(err)
	}
	if failure := decoded.verify(); failure == nil || failure.code != "BadDigest" {
		t.Errorf("a wrong trailer checksum is %v", failure)
	}

	for _, broken := range []string{"zz\r\nhello\r\n", "5\r\nhel", "5\r\nhelloXX0\r\n\r\n", strings.Repeat("1", 5000)} {
		r = httptest.NewRequest(http.MethodPut, "/main/a.txt", strings.NewReader(broken))
		decoded, _ = openS3Body(r, &s3Signature{payload: payloadStreamingUnsignedTrailer})
		if _, err := io.ReadAll(decoded); err == nil {
			t.Errorf("%q is read without an error", broken[:min(len(broken), 20)])
		}
	}
}

// The CRC-64 the SDKs default to is the NVME one, which hash/crc64 does not
// have a table for; this is its check value.
func TestCRC64NVME(t *testing.T) {
	sum, _ := newChecksumHash("crc64nvme")
	sum.Write([]byte("123456789"))
	if got := sum.Sum(nil); !bytes.Equal(got, []byte{0xae, 0x8b, 0x14, 0x86, 0x0a, 0x79, 0x98, 0x88}) {
		t.Errorf("CRC-64/NVME of 123456789 is %x", got)
	}
}

func TestS3Escape(t *testing.T) {
	for in, want := range map[string]string{
		"/docs/a b.txt":  "/docs/a%20b.txt",
		"/ä+~_-.!*'()":   "/%C3%A4%2B~_-.%21%2A%27%28%29",
		"/a//b/":         "/a//b/",
		"key=value&x=y?": "key%3Dvalue%26x%3Dy%3F",
	} {
		if got := s3Escape(in, true); got != want {
			t.Errorf("s3Escape(%q) = %q, want %q", in, got, want)
		}
	}
	if got := s3Escape("a/b", false); got != "a%2Fb" {
		t.Errorf("a query value keeps its slash: %q", got)
	}
}

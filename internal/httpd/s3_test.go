package httpd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"go-fs/internal/config"
)

// The S3 API is tested with the AWS SDK rather than with a signer written
// for the tests, which would share every misreading of the specification with
// the code it tests.

// s3User is fullUser that may also use the S3 API.
func s3User(name, password string) config.User {
	user := fullUser(name, password)
	user.S3 = true
	return user
}

// newS3Server is newServer with the account "john"/"doe" on S3 as well.
func newS3Server(t *testing.T, tune func(*httpConfig)) *testServer {
	t.Helper()
	return newServer(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{s3User("john", "doe")}
		if tune != nil {
			tune(cfg)
		}
	})
}

// s3Client is an SDK client for the plain listener, signing as name/secret.
func (s *testServer) s3Client(name, secret string, tune ...func(*s3.Options)) *s3.Client {
	return s3.New(s3.Options{
		Region:           config.S3Region,
		Credentials:      credentials.NewStaticCredentialsProvider(name, secret, ""),
		BaseEndpoint:     aws.String(s.url("")),
		UsePathStyle:     true,
		RetryMaxAttempts: 1,
	}, tune...)
}

// secureS3Client is s3Client for the TLS listener, which the SDK sends its
// uploads to differently: unsigned, in chunks, with a checksum trailer.
func (s *testServer) secureS3Client(name, secret string) *s3.Client {
	port := s.SecureAddr().(*net.TCPAddr).Port
	return s3.New(s3.Options{
		Region:           config.S3Region,
		Credentials:      credentials.NewStaticCredentialsProvider(name, secret, ""),
		BaseEndpoint:     aws.String("https://127.0.0.1:" + strconv.Itoa(port)),
		UsePathStyle:     true,
		RetryMaxAttempts: 1,
		HTTPClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
	})
}

// errorCode is the S3 error code an SDK call failed with.
func errorCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("the call succeeded, and was expected to fail")
	}
	var api smithy.APIError
	if !errors.As(err, &api) {
		t.Fatalf("%v is not an S3 error", err)
	}
	return api.ErrorCode()
}

func put(t *testing.T, client *s3.Client, key, content string) *s3.PutObjectOutput {
	t.Helper()
	out, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(config.S3Bucket), Key: aws.String(key), Body: strings.NewReader(content)})
	if err != nil {
		t.Fatalf("PutObject %s: %v", key, err)
	}
	return out
}

func getObject(t *testing.T, client *s3.Client, key string) string {
	t.Helper()
	out, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(config.S3Bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("GetObject %s: %v", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// listAll lists every key and common prefix below a prefix, page by page.
func listAll(t *testing.T, client *s3.Client, prefix, delimiter string, pageSize int32) (keys, prefixes []string) {
	t.Helper()
	input := &s3.ListObjectsV2Input{Bucket: aws.String(config.S3Bucket), Prefix: aws.String(prefix)}
	if delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}
	if pageSize > 0 {
		input.MaxKeys = aws.Int32(pageSize)
	}
	pages := s3.NewListObjectsV2Paginator(client, input)
	for pages.HasMorePages() {
		page, err := pages.NextPage(context.Background())
		if err != nil {
			t.Fatalf("ListObjectsV2 %q: %v", prefix, err)
		}
		for _, object := range page.Contents {
			keys = append(keys, aws.ToString(object.Key))
		}
		for _, common := range page.CommonPrefixes {
			prefixes = append(prefixes, aws.ToString(common.Prefix))
		}
	}
	return keys, prefixes
}

func exists(server *testServer, name string) bool {
	_, err := os.Stat(filepath.Join(server.base, filepath.FromSlash(name)))
	return err == nil
}

func TestS3ServesTheFolderAsTheBucket(t *testing.T) {
	server := newS3Server(t, nil)
	client := server.s3Client("john", "doe")
	ctx := context.Background()

	buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets.Buckets) != 1 || aws.ToString(buckets.Buckets[0].Name) != "main" {
		t.Fatalf("buckets = %+v, want the one bucket main", buckets.Buckets)
	}
	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("main")}); err != nil {
		t.Fatalf("HeadBucket: %v", err)
	}
	location, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String("main")})
	if err != nil {
		t.Fatal(err)
	}
	if location.LocationConstraint != "" {
		t.Errorf("location = %q, want the empty one that means us-east-1", location.LocationConstraint)
	}

	// what S3 uploads is the file http serves, and the other way round
	out := put(t, client, "docs/report 1.txt", "hello over s3")
	if got := server.read(t, "docs/report 1.txt"); got != "hello over s3" {
		t.Errorf("the file holds %q", got)
	}
	if etag := aws.ToString(out.ETag); etag != `"`+md5Hex("hello over s3")+`"` {
		t.Errorf("the ETag of an upload is %s, want its MD5", etag)
	}
	res := basic(t, server, http.MethodGet, "/docs/report%201.txt", "john", "doe", nil)
	if body := bodyOf(t, res); body != "hello over s3" {
		t.Errorf("http serves %q", body)
	}
	server.write(t, "notes.txt", "written by http")
	if got := getObject(t, client, "notes.txt"); got != "written by http" {
		t.Errorf("s3 serves %q", got)
	}

	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("main"), Key: aws.String("notes.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToInt64(head.ContentLength) != int64(len("written by http")) {
		t.Errorf("HeadObject length = %d", aws.ToInt64(head.ContentLength))
	}
	ranged, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("main"),
		Key: aws.String("notes.txt"), Range: aws.String("bytes=0-6")})
	if err != nil {
		t.Fatal(err)
	}
	part, _ := io.ReadAll(ranged.Body)
	_ = ranged.Body.Close()
	if string(part) != "written" {
		t.Errorf("a range reads %q", part)
	}

	keys, prefixes := listAll(t, client, "", "/", 0)
	if !equal(keys, []string{"notes.txt"}) || !equal(prefixes, []string{"docs/"}) {
		t.Errorf("the top level lists %v and %v", keys, prefixes)
	}
	keys, _ = listAll(t, client, "docs/", "/", 0)
	if !equal(keys, []string{"docs/report 1.txt"}) {
		t.Errorf("docs/ lists %v", keys)
	}

	_, err = client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("main"), Key: aws.String("missing.txt")})
	if code := errorCode(t, err); code != "NoSuchKey" {
		t.Errorf("a missing key is %s", code)
	}
	// a folder is not a file of the same name
	_, err = client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("main"), Key: aws.String("docs")})
	if code := errorCode(t, err); code != "NoSuchKey" {
		t.Errorf("a folder read as a file is %s", code)
	}

	if record := server.logs.find("s3 upload"); record == nil || record["user"] != "john" {
		t.Errorf("the upload was not recorded: %v", record)
	}
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestS3ListsEveryKeyPageByPage(t *testing.T) {
	server := newS3Server(t, nil)
	client := server.s3Client("john", "doe")
	var want []string
	for _, name := range []string{"a.txt", "b/c.txt", "b/d/e.txt", "b-c.txt", "z.txt", "b/f.txt"} {
		server.write(t, name, name)
		want = append(want, name)
	}
	server.mkdir(t, "empty")
	want = append(want, "empty/")
	sort.Strings(want)

	keys, prefixes := listAll(t, client, "", "", 2)
	if !equal(keys, want) || len(prefixes) != 0 {
		t.Errorf("a recursive listing is %v, want %v", keys, want)
	}
	keys, _ = listAll(t, client, "b/", "", 1)
	if !equal(keys, []string{"b/c.txt", "b/d/e.txt", "b/f.txt"}) {
		t.Errorf("b/ lists %v", keys)
	}
	// a prefix that is not a whole name matches the names that begin with it
	keys, prefixes = listAll(t, client, "b", "/", 1)
	if !equal(keys, []string{"b-c.txt"}) || !equal(prefixes, []string{"b/"}) {
		t.Errorf("the prefix b lists %v and %v", keys, prefixes)
	}

	// the first version of the listing, which some clients still use
	v1, err := client.ListObjects(context.Background(), &s3.ListObjectsInput{
		Bucket: aws.String("main"), Delimiter: aws.String("/")})
	if err != nil {
		t.Fatal(err)
	}
	if len(v1.Contents) != 3 || len(v1.CommonPrefixes) != 2 {
		t.Errorf("ListObjects lists %d objects and %d prefixes", len(v1.Contents), len(v1.CommonPrefixes))
	}
}

func TestS3CreatesAndRemovesFolders(t *testing.T) {
	server := newS3Server(t, nil)
	client := server.s3Client("john", "doe")
	ctx := context.Background()

	put(t, client, "photos/2026/", "")
	if info, err := os.Stat(filepath.Join(server.base, "photos", "2026")); err != nil || !info.IsDir() {
		t.Fatalf("PutObject of photos/2026/ did not make the folder: %v", err)
	}
	_, prefixes := listAll(t, client, "photos/", "/", 0)
	if !equal(prefixes, []string{"photos/2026/"}) {
		t.Errorf("the new folder lists as %v", prefixes)
	}
	if _, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("main"),
		Key: aws.String("photos/2026/")}); err != nil {
		t.Errorf("the folder is not an object: %v", err)
	}
	_, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("main"),
		Key: aws.String("photos/x/"), Body: strings.NewReader("data")})
	if code := errorCode(t, err); code != "InvalidRequest" {
		t.Errorf("a folder with data is %s", code)
	}

	// deleting the last file of a folder leaves no empty folder behind, and a
	// folder that still holds something stays
	put(t, client, "photos/2026/a.jpg", "a")
	put(t, client, "photos/b.jpg", "b")
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("main"),
		Key: aws.String("photos/2026/a.jpg")}); err != nil {
		t.Fatal(err)
	}
	if exists(server, "photos/2026") {
		t.Error("the emptied folder is still there")
	}
	if !exists(server, "photos/b.jpg") {
		t.Error("the folder above it went as well")
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("main"),
		Key: aws.String("photos/")}); err != nil {
		t.Fatal(err)
	}
	if !exists(server, "photos/b.jpg") {
		t.Error("deleting the folder key removed what is in it")
	}
	// deleting what is not there is no error
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("main"),
		Key: aws.String("nothing.txt")}); err != nil {
		t.Errorf("deleting a missing key: %v", err)
	}
}

// Renaming over S3 is a copy and a delete, which is how every client does it,
// a folder one key at a time.
func TestS3RenamesByCopyAndDelete(t *testing.T) {
	server := newS3Server(t, nil)
	client := server.s3Client("john", "doe")
	ctx := context.Background()
	server.write(t, "old/a.txt", "first")
	server.write(t, "old/sub/b.txt", "second")
	server.mkdir(t, "old/empty")

	keys, _ := listAll(t, client, "old/", "", 0)
	for _, key := range keys {
		target := "new/" + strings.TrimPrefix(key, "old/")
		_, err := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("main"),
			Key: aws.String(target), CopySource: aws.String("main/" + key)})
		if err != nil {
			t.Fatalf("CopyObject %s: %v", key, err)
		}
	}
	var objects []types.ObjectIdentifier
	for _, key := range keys {
		objects = append(objects, types.ObjectIdentifier{Key: aws.String(key)})
	}
	deleted, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String("main"),
		Delete: &types.Delete{Objects: objects}})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.Errors) != 0 || len(deleted.Deleted) != len(keys) {
		t.Errorf("DeleteObjects: %d deleted, errors %+v", len(deleted.Deleted), deleted.Errors)
	}

	if exists(server, "old") {
		t.Error("the old folder is still there")
	}
	if server.read(t, "new/a.txt") != "first" || server.read(t, "new/sub/b.txt") != "second" {
		t.Error("the files did not arrive")
	}
	if !exists(server, "new/empty") {
		t.Error("the empty folder was not taken along")
	}

	// copying a key onto itself is only allowed as a metadata change
	_, err = client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("main"),
		Key: aws.String("new/a.txt"), CopySource: aws.String("main/new/a.txt")})
	if code := errorCode(t, err); code != "InvalidRequest" {
		t.Errorf("a copy onto itself is %s", code)
	}
	_, err = client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("main"),
		Key: aws.String("x.txt"), CopySource: aws.String("other/new/a.txt")})
	if code := errorCode(t, err); code != "NoSuchBucket" {
		t.Errorf("a copy from another bucket is %s", code)
	}
}

func TestS3MultipartUpload(t *testing.T) {
	server := newS3Server(t, nil)
	client := server.s3Client("john", "doe")
	ctx := context.Background()

	first := bytes.Repeat([]byte("a"), 5<<20)
	second := []byte("the end")
	created, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String("main"), Key: aws.String("big/file.bin")})
	if err != nil {
		t.Fatal(err)
	}
	var parts []types.CompletedPart
	for i, data := range [][]byte{first, second} {
		out, err := client.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String("main"),
			Key: aws.String("big/file.bin"), UploadId: created.UploadId,
			PartNumber: aws.Int32(int32(i + 1)), Body: bytes.NewReader(data)})
		if err != nil {
			t.Fatalf("UploadPart %d: %v", i+1, err)
		}
		parts = append(parts, types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(int32(i + 1))})
	}
	listed, err := client.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String("main"),
		Key: aws.String("big/file.bin"), UploadId: created.UploadId})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Parts) != 2 || aws.ToInt64(listed.Parts[1].Size) != int64(len(second)) {
		t.Errorf("ListParts = %+v", listed.Parts)
	}
	uploads, err := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String("main")})
	if err != nil {
		t.Fatal(err)
	}
	if len(uploads.Uploads) != 1 || aws.ToString(uploads.Uploads[0].Key) != "big/file.bin" {
		t.Errorf("ListMultipartUploads = %+v", uploads.Uploads)
	}
	// nothing is in the served folder until the upload is complete
	if exists(server, "big/file.bin") {
		t.Fatal("a part reached the served folder")
	}

	done, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: aws.String("main"), Key: aws.String("big/file.bin"), UploadId: created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(aws.ToString(done.ETag), `-2"`) {
		t.Errorf("the ETag of a multipart upload is %s", aws.ToString(done.ETag))
	}
	content, err := os.ReadFile(filepath.Join(server.base, "big", "file.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, append(append([]byte{}, first...), second...)) {
		t.Errorf("the joined file has %d bytes", len(content))
	}
	_, err = client.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String("main"),
		Key: aws.String("big/file.bin"), UploadId: created.UploadId, PartNumber: aws.Int32(3),
		Body: strings.NewReader("late")})
	if code := errorCode(t, err); code != "NoSuchUpload" {
		t.Errorf("a part for a completed upload is %s", code)
	}

	// a large file is copied, and so renamed, a part at a time
	copyUpload, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String("main"), Key: aws.String("big/copy.bin")})
	if err != nil {
		t.Fatal(err)
	}
	copied, err := client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{Bucket: aws.String("main"),
		Key: aws.String("big/copy.bin"), UploadId: copyUpload.UploadId, PartNumber: aws.Int32(1),
		CopySource: aws.String("main/big/file.bin"), CopySourceRange: aws.String("bytes=5242880-5242886")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: aws.String("main"), Key: aws.String("big/copy.bin"), UploadId: copyUpload.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
			{ETag: copied.CopyPartResult.ETag, PartNumber: aws.Int32(1)}}}}); err != nil {
		t.Fatal(err)
	}
	if got := server.read(t, "big/copy.bin"); got != "the end" {
		t.Errorf("the copied range is %q", got)
	}

	// an aborted upload is gone, and leaves nothing behind
	aborted, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String("main"), Key: aws.String("big/aborted.bin")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String("main"),
		Key: aws.String("big/aborted.bin"), UploadId: aborted.UploadId}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(uploadsFolder(server.settings()), aws.ToString(aborted.UploadId))); err == nil {
		t.Error("the aborted upload is still staged")
	}
}

// Over TLS the SDK sends an upload unsigned, in aws-chunked form, with its
// checksum in a trailer; over plain http it signs the body and sends the
// checksum as a header. Every algorithm the SDK offers is checked both ways.
func TestS3ChecksumsOverHTTPAndTLS(t *testing.T) {
	server := newServerWith(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{s3User("john", "doe")}
	}, func(https *config.HTTPS) { https.Enabled = true })
	ctx := context.Background()
	for name, client := range map[string]*s3.Client{
		"http": server.s3Client("john", "doe"), "https": server.secureS3Client("john", "doe")} {
		for _, algorithm := range []types.ChecksumAlgorithm{types.ChecksumAlgorithmCrc32,
			types.ChecksumAlgorithmCrc32c, types.ChecksumAlgorithmCrc64nvme,
			types.ChecksumAlgorithmSha1, types.ChecksumAlgorithmSha256} {
			key := name + "-" + strings.ToLower(string(algorithm)) + ".txt"
			content := strings.Repeat("sent over "+name+" ", 5000)
			_, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("main"),
				Key: aws.String(key), Body: strings.NewReader(content), ChecksumAlgorithm: algorithm})
			if err != nil {
				t.Errorf("%s with %s: %v", name, algorithm, err)
				continue
			}
			if server.read(t, key) != content {
				t.Errorf("%s with %s: the upload did not arrive whole", name, algorithm)
			}
		}
		if got := getObject(t, client, name+"-crc32.txt"); !strings.HasPrefix(got, "sent over "+name) {
			t.Errorf("the download over %s is %q", name, got[:min(len(got), 40)])
		}
	}

	// a checksum that does not match is refused, and nothing is stored
	_, err := server.s3Client("john", "doe").PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("main"),
		Key: aws.String("corrupt.txt"), Body: strings.NewReader("data"), ChecksumCRC32: aws.String("AAAAAA==")})
	if code := errorCode(t, err); code != "BadDigest" {
		t.Errorf("a wrong checksum is %s", code)
	}
	if exists(server, "corrupt.txt") {
		t.Error("the upload with the wrong checksum was stored")
	}
}

func TestS3PresignedURL(t *testing.T) {
	server := newS3Server(t, nil)
	server.write(t, "shared.txt", "presigned")
	presigner := s3.NewPresignClient(server.s3Client("john", "doe"))
	request, err := presigner.PresignGetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("main"), Key: aws.String("shared.txt")},
		s3.WithPresignExpires(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	res, body := get(t, server, strings.TrimPrefix(request.URL, server.url("")))
	if res.StatusCode != http.StatusOK || body != "presigned" {
		t.Errorf("a presigned URL is answered %d %q", res.StatusCode, body)
	}
	// and it is bound to what it was signed for
	res, _ = get(t, server, strings.Replace(strings.TrimPrefix(request.URL, server.url("")),
		"shared.txt", "other.txt", 1))
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("a presigned URL for another key is answered %d", res.StatusCode)
	}
}

// What an account may do over S3 is what it may do over http: the same paths
// and the same rights.
func TestS3HonoursPathsAndRights(t *testing.T) {
	reader := readOnlyUser("jane", "secret")
	reader.S3 = true
	scoped := s3User("max", "secret")
	scoped.Paths = []string{"^/public/.*"}
	server := newS3Server(t, func(cfg *httpConfig) {
		cfg.Users = append(cfg.Users, reader, scoped)
	})
	server.write(t, "public/a.txt", "public")
	server.write(t, "private/b.txt", "private")
	ctx := context.Background()

	jane := server.s3Client("jane", "secret")
	if got := getObject(t, jane, "private/b.txt"); got != "private" {
		t.Errorf("jane reads %q", got)
	}
	_, err := jane.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("main"),
		Key: aws.String("public/new.txt"), Body: strings.NewReader("x")})
	if code := errorCode(t, err); code != "AccessDenied" {
		t.Errorf("an upload without the right is %s", code)
	}
	_, err = jane.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("main"), Key: aws.String("public/a.txt")})
	if code := errorCode(t, err); code != "AccessDenied" {
		t.Errorf("a delete without the right is %s", code)
	}
	_, err = jane.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("main"),
		Key: aws.String("public/c.txt"), CopySource: aws.String("main/public/a.txt")})
	if code := errorCode(t, err); code != "AccessDenied" {
		t.Errorf("a copy without the right is %s", code)
	}

	maxClient := server.s3Client("max", "secret")
	keys, prefixes := listAll(t, maxClient, "", "/", 0)
	if len(keys) != 0 || !equal(prefixes, []string{"public/"}) {
		t.Errorf("max lists %v and %v", keys, prefixes)
	}
	keys, _ = listAll(t, maxClient, "", "", 0)
	if !equal(keys, []string{"public/a.txt"}) {
		t.Errorf("max lists %v recursively", keys)
	}
	_, err = maxClient.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("main"), Key: aws.String("private/b.txt")})
	if code := errorCode(t, err); code != "AccessDenied" {
		t.Errorf("a read outside the paths is %s", code)
	}
	_, err = maxClient.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("main"),
		Key: aws.String("public/stolen.txt"), CopySource: aws.String("main/private/b.txt")})
	if code := errorCode(t, err); code != "AccessDenied" {
		t.Errorf("a copy from outside the paths is %s", code)
	}
	if exists(server, "public/stolen.txt") {
		t.Error("the copy happened anyway")
	}
}

func TestS3RefusesWhatItDoesNotServe(t *testing.T) {
	server := newS3Server(t, func(cfg *httpConfig) {
		// an account that does not set s3 is not an S3 account
		cfg.Users = append(cfg.Users, fullUser("web", "only"))
	})
	ctx := context.Background()
	client := server.s3Client("john", "doe")

	for name, call := range map[string]func() error{
		"another bucket": func() error {
			_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("other")})
			return err
		},
		"creating a bucket": func() error {
			_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("other")})
			return err
		},
		"removing the bucket": func() error {
			_, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String("main")})
			return err
		},
		"a subresource": func() error {
			_, err := client.GetObjectAcl(ctx, &s3.GetObjectAclInput{Bucket: aws.String("main"), Key: aws.String("x")})
			return err
		},
	} {
		code := errorCode(t, call())
		if code != "NoSuchBucket" && code != "AccessDenied" && code != "NotImplemented" {
			t.Errorf("%s is %s", name, code)
		}
	}
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("main")}); err != nil {
		t.Errorf("making sure of the bucket main: %v", err)
	}

	_, err := server.s3Client("john", "wrong").ListBuckets(ctx, &s3.ListBucketsInput{})
	if code := errorCode(t, err); code != "SignatureDoesNotMatch" {
		t.Errorf("a wrong secret is %s", code)
	}
	_, err = server.s3Client("web", "only").ListBuckets(ctx, &s3.ListBucketsInput{})
	if code := errorCode(t, err); code != "SignatureDoesNotMatch" {
		t.Errorf("an account without s3 is %s", code)
	}
	if record := server.logs.find("s3 login refused"); record == nil {
		t.Error("a refused signature was not recorded")
	}
	_, err = server.s3Client("john", "doe", func(o *s3.Options) { o.Region = "eu-central-1" }).
		ListBuckets(ctx, &s3.ListBucketsInput{})
	if code := errorCode(t, err); code != "AuthorizationHeaderMalformed" {
		t.Errorf("a request signed for another region is %s", code)
	}
}

func TestS3CanBeSwitchedOff(t *testing.T) {
	server := newS3Server(t, func(cfg *httpConfig) { cfg.EnableS3 = false })
	_, err := server.s3Client("john", "doe").ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if code := errorCode(t, err); code != "AccessDenied" {
		t.Errorf("with enableS3 off a request is %s", code)
	}

	// and on again by a reload
	next := server.settings().cfg
	next.EnableS3 = true
	if err := server.Reload(next, server.settings().https, []config.User{s3User("john", "doe")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := server.s3Client("john", "doe").ListBuckets(context.Background(), &s3.ListBucketsInput{}); err != nil {
		t.Errorf("after the reload: %v", err)
	}
}

// An account that sets s3 and not http is an S3 account and nothing else.
func TestS3OnlyAccountHasNoHTTPLogin(t *testing.T) {
	only := s3User("keys", "secret")
	only.HTTP = false
	server := newServer(t, func(cfg *httpConfig) { cfg.Users = []config.User{only} })
	put(t, server.s3Client("keys", "secret"), "private/a.txt", "x")
	res := basic(t, server, http.MethodGet, "/private/a.txt", "keys", "secret", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("Basic with an s3-only account is answered %d", res.StatusCode)
	}
}

func TestS3WrongSignaturesLockTheAddress(t *testing.T) {
	server := newS3Server(t, func(cfg *httpConfig) {
		cfg.LoginAttempts = 2
		cfg.LoginLockout = 60
	})
	ctx := context.Background()
	for range 2 {
		_, err := server.s3Client("john", "wrong").ListBuckets(ctx, &s3.ListBucketsInput{})
		if code := errorCode(t, err); code != "SignatureDoesNotMatch" {
			t.Fatalf("a wrong secret is %s", code)
		}
	}
	_, err := server.s3Client("john", "doe").ListBuckets(ctx, &s3.ListBucketsInput{})
	if code := errorCode(t, err); code != "SlowDown" {
		t.Errorf("a locked address is answered %s", code)
	}
}

// A request that is not signed for S3 is served as it always was, whatever
// its path: a folder called main is still the folder main.
func TestUnsignedRequestsAreNotS3(t *testing.T) {
	server := newS3Server(t, publicServer)
	server.write(t, "main/file.txt", "a folder called main")
	res, body := get(t, server, "/main/file.txt")
	if res.StatusCode != http.StatusOK || body != "a folder called main" {
		t.Errorf("GET /main/file.txt is answered %d %q", res.StatusCode, body)
	}
	if got := getObject(t, server.s3Client("john", "doe"), "main/file.txt"); got != "a folder called main" {
		t.Errorf("over s3 it is %q", got)
	}
}

func TestS3RefusesKeysTheTreeCannotHold(t *testing.T) {
	server := newS3Server(t, nil)
	client := server.s3Client("john", "doe")
	for _, key := range []string{"a//b.txt", "a/./b.txt", "../escape.txt", "a/../../b.txt"} {
		_, err := client.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("main"),
			Key: aws.String(key), Body: strings.NewReader("x")})
		if err == nil {
			t.Errorf("%s was accepted", key)
		}
	}
	entries, _ := os.ReadDir(server.base)
	if len(entries) != 0 {
		t.Errorf("the refused keys left %v behind", entries)
	}
}

func TestS3HonoursMaxUploadSize(t *testing.T) {
	server := newS3Server(t, func(cfg *httpConfig) { cfg.MaxUploadSize = 10 })
	_, err := server.s3Client("john", "doe").PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("main"), Key: aws.String("big.txt"), Body: strings.NewReader("more than ten bytes")})
	if code := errorCode(t, err); code != "EntityTooLarge" {
		t.Errorf("an upload above maxUploadSize is %s", code)
	}
	if exists(server, "big.txt") {
		t.Error("the upload was stored anyway")
	}
}

// A conditional write creates the object only when there is none.
func TestS3ConditionalWrite(t *testing.T) {
	server := newS3Server(t, nil)
	client := server.s3Client("john", "doe")
	server.write(t, "taken.txt", "first")
	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("main"),
		Key: aws.String("taken.txt"), Body: strings.NewReader("second"), IfNoneMatch: aws.String("*")})
	if code := errorCode(t, err); code != "PreconditionFailed" {
		t.Errorf("If-None-Match: * on a taken key is %s", code)
	}
	if server.read(t, "taken.txt") != "first" {
		t.Error("the file was replaced")
	}
}

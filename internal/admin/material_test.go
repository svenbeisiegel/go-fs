package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-fs/internal/config"
	"go-fs/internal/tlsconf"
)

// send posts to one of the material endpoints and reports the status and the
// decoded answer, which is empty when the request was refused.
func send(t *testing.T, front *httptest.Server, path string, body any,
	headers map[string]string) (int, map[string]any, string) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, front.URL+path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	answer, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer answer.Body.Close()

	returned, _ := io.ReadAll(answer.Body)
	var decoded map[string]any
	_ = json.Unmarshal(returned, &decoded)
	return answer.StatusCode, decoded, strings.TrimSpace(string(returned))
}

// uploadFile posts a file the way the page does, base64 of its bytes.
func uploadFile(t *testing.T, front *httptest.Server, kind, name string,
	content []byte) (int, map[string]any, string) {
	t.Helper()
	return send(t, front, "/?go-fs=admin-upload", map[string]any{
		"kind":     kind,
		"filename": name,
		"content":  base64.StdEncoding.EncodeToString(content),
	}, nil)
}

// The six keys that hold key material get the buttons, and nothing else
// does. authorizedKeys in particular stays a plain list of pasted lines.
func TestSchemaMarksTheKeyMaterial(t *testing.T) {
	schema, _ := build()

	want := map[string]string{
		"ftps.cert":                   config.KindCertificate,
		"ftps.key":                    config.KindTLSKey,
		"https.cert":                  config.KindCertificate,
		"https.key":                   config.KindTLSKey,
		"sftp.hostkey":                config.KindSSHKey,
		"http.httpSessionTokenSecret": config.KindSessionSecret,
	}

	found := map[string]string{}
	for _, sec := range schema.Sections {
		for _, field := range sec.Fields {
			if field.Upload == "" {
				continue
			}
			found[sec.Key+"."+field.Key] = field.Upload
			if field.Upload == config.KindCertificate && field.Pair == "" {
				t.Errorf("%s.%s has no private key to generate with it", sec.Key, field.Key)
			}
			// a private key is masked, a certificate is not
			if wantSecret := field.Upload != config.KindCertificate; //
			wantSecret != (field.Kind == kindSecret) {
				t.Errorf("%s.%s has kind %q", sec.Key, field.Key, field.Kind)
			}
		}
		for _, table := range sec.Tables {
			for _, field := range table.Fields {
				if field.Upload != "" {
					t.Errorf("%s.%s.%s should not take an upload",
						sec.Key, table.Key, field.Key)
				}
			}
		}
	}

	for path, kind := range want {
		if found[path] != kind {
			t.Errorf("%s is marked %q, want %q", path, found[path], kind)
		}
	}
	if len(found) != len(want) {
		t.Errorf("marked %v, want exactly %v", found, want)
	}
}

func TestUploadAcceptsRealMaterial(t *testing.T) {
	_, front := testServer(t, testConfig(t))
	certPEM, keyPEM, err := tlsconf.SelfSignedPEM()
	if err != nil {
		t.Fatal(err)
	}

	status, answer, body := uploadFile(t, front, config.KindCertificate, "server.crt", certPEM)
	if status != http.StatusOK {
		t.Fatalf("uploading a certificate: %d %s", status, body)
	}
	value, _ := answer["value"].(string)
	if value != config.Encode(certPEM) {
		t.Error("the certificate did not come back as the value the file holds")
	}
	if summary, _ := answer["summary"].(string); !strings.Contains(summary, "certificate") {
		t.Errorf("summary = %q", summary)
	}
	// what the upload accepted has to be what the servers accept
	if _, err := config.DecodeCertificate(value); err != nil {
		t.Errorf("the stored value does not load: %v", err)
	}

	if status, _, body := uploadFile(t, front, config.KindTLSKey, "server.key", keyPEM); status != http.StatusOK {
		t.Fatalf("uploading a key: %d %s", status, body)
	}

	// a file that already holds the base64, prepared by hand
	status, answer, body = uploadFile(t, front, config.KindCertificate, "server.b64",
		[]byte(config.Encode(certPEM)))
	if status != http.StatusOK {
		t.Fatalf("uploading a prepared value: %d %s", status, body)
	}
	if answer["value"] != config.Encode(certPEM) {
		t.Error("a prepared value was encoded a second time")
	}
}

func TestUploadRefusesTheWrongFile(t *testing.T) {
	_, front := testServer(t, testConfig(t))
	certPEM, keyPEM, err := tlsconf.SelfSignedPEM()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		kind    string
		file    string
		content []byte
		status  int
		says    string
	}{
		{"a key in the certificate box", config.KindCertificate, "server.key",
			keyPEM, http.StatusBadRequest, "not a certificate"},
		{"a certificate in the key box", config.KindTLSKey, "server.crt",
			certPEM, http.StatusBadRequest, "not a private key"},
		{"something else entirely", config.KindCertificate, "notes.txt",
			[]byte("hello"), http.StatusBadRequest, "neither base64 nor PEM"},
		{"an empty file", config.KindCertificate, "empty.pem",
			nil, http.StatusBadRequest, "empty"},
		{"a file that is too large", config.KindCertificate, "big.pem",
			bytes.Repeat([]byte("x"), maxUpload+1), http.StatusRequestEntityTooLarge, "too large"},
		{"a kind that is not one", "sausage", "server.crt",
			certPEM, http.StatusBadRequest, "kind of key material"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, _, body := uploadFile(t, front, tc.kind, tc.file, tc.content)
			if status != tc.status {
				t.Fatalf("status = %d, want %d: %s", status, tc.status, body)
			}
			if !strings.Contains(body, tc.says) {
				t.Errorf("%q does not mention %q", body, tc.says)
			}
		})
	}

	// the name of the file is in the message, so the wrong one of several is
	// recognisable
	if _, _, body := uploadFile(t, front, config.KindCertificate, "server.key", keyPEM); //
	!strings.Contains(body, "server.key") {
		t.Errorf("%q does not name the file", body)
	}
}

func TestGenerateProducesMaterialTheServerAccepts(t *testing.T) {
	_, front := testServer(t, testConfig(t))

	status, answer, body := send(t, front, "/?go-fs=admin-generate",
		map[string]any{"kind": config.KindCertificate}, nil)
	if status != http.StatusOK {
		t.Fatalf("generating a certificate: %d %s", status, body)
	}
	cert, _ := answer["value"].(string)
	key, _ := answer["pairValue"].(string)
	if cert == "" || key == "" {
		t.Fatal("a certificate has to come with its key")
	}
	if _, err := tlsconf.Pair(cert, key); err != nil {
		t.Errorf("the generated pair does not load: %v", err)
	}
	if summary, _ := answer["pairSummary"].(string); !strings.Contains(summary, "private key") {
		t.Errorf("pairSummary = %q", summary)
	}

	status, answer, body = send(t, front, "/?go-fs=admin-generate",
		map[string]any{"kind": config.KindSSHKey}, nil)
	if status != http.StatusOK {
		t.Fatalf("generating a host key: %d %s", status, body)
	}
	hostKey, _ := answer["value"].(string)
	if _, err := config.DecodeHostKey(hostKey); err != nil {
		t.Errorf("the generated host key does not load: %v", err)
	}

	// a private key alone would match no certificate, so there is nothing to
	// generate for it
	if status, _, _ := send(t, front, "/?go-fs=admin-generate",
		map[string]any{"kind": config.KindTLSKey}, nil); status != http.StatusBadRequest {
		t.Errorf("generating a lone private key: %d", status)
	}
}

// A generated certificate is stored and applied like any other change: it goes
// into the file, and the file still validates.
func TestGeneratedMaterialSurvivesApply(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)

	_, generated, _ := send(t, front, "/?go-fs=admin-generate",
		map[string]any{"kind": config.KindCertificate}, nil)

	values := get(t, front).Values
	ftps := section(t, values, "ftps")
	ftps["enabled"] = true
	ftps["cert"] = generated["value"]
	ftps["key"] = generated["pairValue"]

	if status, body := post(t, front, roundTripJSON(t, values), nil); status != http.StatusOK {
		t.Fatalf("applying a generated pair: %d %s", status, body)
	}

	written, err := config.Load(path)
	if err != nil {
		t.Fatalf("the written file does not load: %v", err)
	}
	if written.FTPS.Cert != generated["value"] {
		t.Error("the certificate did not reach the file")
	}
	if _, err := tlsconf.Pair(written.FTPS.Cert, written.FTPS.Key); err != nil {
		t.Errorf("the pair in the file does not serve: %v", err)
	}

	// and the page describes what is now stored
	if summary := get(t, front).Summaries["ftps.cert"]; !strings.Contains(summary, "certificate") {
		t.Errorf("ftps.cert is described as %q", summary)
	}
}

// A pair that does not belong together is refused before the file is written,
// the way every other invalid change is.
func TestApplyRefusesAMismatchedPair(t *testing.T) {
	path := testConfig(t)
	_, front := testServer(t, path)

	_, first, _ := send(t, front, "/?go-fs=admin-generate", map[string]any{"kind": config.KindCertificate}, nil)
	_, second, _ := send(t, front, "/?go-fs=admin-generate", map[string]any{"kind": config.KindCertificate}, nil)

	values := get(t, front).Values
	ftps := section(t, values, "ftps")
	ftps["enabled"] = true
	ftps["cert"] = first["value"]
	ftps["key"] = second["pairValue"]

	status, body := post(t, front, roundTripJSON(t, values), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", status, body)
	}
	if !strings.Contains(body, "ftps.cert and ftps.key") {
		t.Errorf("%q does not name the pair", body)
	}

	if written, _ := config.Load(path); written.FTPS.Cert != "" {
		t.Error("the file was written even though the pair was refused")
	}
}

// The endpoints carry the same guards as Apply, since they are what puts a key
// into the configuration.
func TestMaterialEndpointsAreGuarded(t *testing.T) {
	_, front := testServer(t, testConfig(t))

	for _, path := range []string{"/?go-fs=admin-upload", "/?go-fs=admin-generate"} {
		// a form post, which is the shape a cross site request can take
		request, _ := http.NewRequest(http.MethodPost, front.URL+path,
			strings.NewReader("kind=certificate"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		answer, err := front.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		answer.Body.Close()
		if answer.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("%s took a form post: %d", path, answer.StatusCode)
		}

		// from somewhere else
		if status, _, _ := send(t, front, path, map[string]any{"kind": config.KindCertificate},
			map[string]string{"Origin": "https://elsewhere.example"}); status != http.StatusForbidden {
			t.Errorf("%s took a request from another origin: %d", path, status)
		}
	}
}

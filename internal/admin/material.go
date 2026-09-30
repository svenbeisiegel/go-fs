package admin

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"go-fs/internal/config"
	"go-fs/internal/tlsconf"
)

// Certificates and keys are values in the configuration file, so putting one
// there means putting the content of a file into a text box. These two
// endpoints do that for the reader: an upload validates a file and hands back
// the value it becomes, and a generate makes a new one.
//
// Neither writes anything. The value goes into the page and is written by the
// single Apply, which is the only thing in this interface that touches the
// file.

// maxUpload caps an uploaded file. A certificate chain is a few kilobytes;
// this leaves room for an unusually long one and stops anything else.
const maxUpload = 128 << 10

// upload is what the page posts. content is base64 of the file's bytes, which
// keeps the request JSON: multipart/form-data is a content type a cross site
// form can post, so accepting it would undo the check in posted.
type upload struct {
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// handleUpload validates an uploaded file and answers with the value it becomes.
//
// It validates with the same decoders the servers use at startup, so a file
// this accepts is a file the server will start with, and the reader finds out
// that a key is unusable while looking at it rather than after an Apply.
func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !h.posted(w, r) {
		return
	}

	var posted upload
	if err := json.NewDecoder(io.LimitReader(r.Body, 2*maxUpload)).Decode(&posted); err != nil {
		http.Error(w, "the body is not an upload: "+err.Error(), http.StatusBadRequest)
		return
	}

	content, err := base64.StdEncoding.DecodeString(posted.Content)
	if err != nil {
		http.Error(w, "the file could not be read", http.StatusBadRequest)
		return
	}
	if len(content) == 0 {
		http.Error(w, "the file is empty", http.StatusBadRequest)
		return
	}
	if len(content) > maxUpload {
		http.Error(w, "the file is too large to be a certificate or a key",
			http.StatusRequestEntityTooLarge)
		return
	}

	// a file holding base64 rather than PEM is what someone who has already
	// prepared the value for the file by hand will pick, so it is accepted too
	value := config.Encode(content)
	if trimmed := strings.TrimSpace(string(content)); !strings.HasPrefix(trimmed, "-----BEGIN") {
		value = trimmed
	}
	if _, err := config.Decode(posted.Kind, value); err != nil {
		http.Error(w, describeFile(posted.Filename)+" "+err.Error(), http.StatusBadRequest)
		return
	}

	h.log.Info("a file was uploaded to the admin interface",
		"kind", posted.Kind, "filename", posted.Filename, "address", addressOf(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"value":   value,
		"summary": config.Describe(posted.Kind, value),
	})
}

// handleGenerate makes new key material of the given kind. A certificate comes
// with its private key, since neither half is any use alone.
//
// It is the same certificate and the same kind of host key the servers make for
// themselves when nothing is configured; the difference is that this one is
// written to the file, so it survives a restart and clients stop reporting that
// it changed.
func (h *Handler) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if !h.posted(w, r) {
		return
	}

	var posted struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&posted); err != nil {
		http.Error(w, "the body does not say what to generate: "+err.Error(),
			http.StatusBadRequest)
		return
	}

	answer := map[string]any{}
	switch posted.Kind {
	case config.KindCertificate:
		certPEM, keyPEM, err := tlsconf.SelfSignedPEM()
		if err != nil {
			h.log.Error("the admin interface cannot generate a certificate", "error", err)
			http.Error(w, "the certificate could not be generated: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		answer["value"] = config.Encode(certPEM)
		answer["pairValue"] = config.Encode(keyPEM)
		answer["pairSummary"] = config.Describe(config.KindTLSKey, config.Encode(keyPEM))

	case config.KindSSHKey:
		key, err := config.GenerateHostKey()
		if err != nil {
			h.log.Error("the admin interface cannot generate a host key", "error", err)
			http.Error(w, "the host key could not be generated: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		answer["value"] = key

	case config.KindSessionSecret:
		key, err := config.GenerateSessionSecret()
		if err != nil {
			h.log.Error("the admin interface cannot generate a signing key", "error", err)
			http.Error(w, "the signing key could not be generated: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		answer["value"] = key

	default:
		// a private key on its own would not match any certificate
		http.Error(w, "there is nothing to generate for this setting", http.StatusBadRequest)
		return
	}

	h.log.Info("key material was generated by the admin interface",
		"kind", posted.Kind, "address", addressOf(r))
	answer["summary"] = config.Describe(posted.Kind, answer["value"].(string))
	writeJSON(w, http.StatusOK, answer)
}

// describeFile names the file in an error, so that someone who picked the wrong
// one of several sees which it was.
func describeFile(name string) string {
	if name == "" {
		return "the file"
	}
	return name
}

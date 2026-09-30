package httpd

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go-fs/internal/config"
)

// The two listeners are independent, so https can serve on its own.
func TestHTTPSListener(t *testing.T) {
	server := newServerWith(t, nil, func(https *config.HTTPS) { https.Enabled = true })
	server.write(t, "private/hello.txt", "over tls")

	if server.SecureAddr() == nil {
		t.Fatal("the tls listener is not bound")
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	port := server.SecureAddr().(*net.TCPAddr).Port
	req, _ := http.NewRequest(http.MethodGet,
		"https://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/private/hello.txt", nil)
	req.SetBasicAuth("john", "doe")

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || string(body) != "over tls" {
		t.Errorf("status %d body %q", res.StatusCode, body)
	}
}

func TestHTTPSOnlyWithoutThePlainListener(t *testing.T) {
	server := newServerWith(t, func(cfg *httpConfig) { cfg.Enabled = false },
		func(https *config.HTTPS) { https.Enabled = true })

	if addr := server.Addr(); addr != nil {
		t.Errorf("the plain listener is bound at %v, it should not exist", addr)
	}
	if server.SecureAddr() == nil {
		t.Error("the tls listener has to be bound")
	}
}

// A session cookie sent over TLS is marked Secure, which one over plain HTTP
// cannot be.
func TestSessionCookieIsSecureOverTLS(t *testing.T) {
	server := newServerWith(t, func(cfg *httpConfig) {
		cfg.Users = []config.User{fullUser("john", "doe")}
	}, func(https *config.HTTPS) { https.Enabled = true })
	server.write(t, "private/hello.txt", "x")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	port := server.SecureAddr().(*net.TCPAddr).Port
	form := url.Values{"username": {"john"}, "password": {"doe"}}
	req, _ := http.NewRequest(http.MethodPost,
		"https://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/private/?go-fs=login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	session := cookieNamed(res, sessionCookie)
	if session == nil {
		t.Fatalf("no session token was handed out: %v", res.Cookies())
	}
	if !session.Secure {
		t.Errorf("cookie = %v, want Secure over TLS", session)
	}
}

func TestNewRejectsBadConfiguration(t *testing.T) {
	base := t.TempDir()

	cfg := config.Default().HTTP
	cfg.Basefolder = base + "/nope"
	if _, err := New(cfg, config.HTTPS{}, nil, "", discardLogger()); err == nil {
		t.Error("a missing base folder has to be refused")
	}

	cfg = config.Default().HTTP
	cfg.Basefolder = base
	cfg.PathsRequireAuth = []string{"([unclosed"}
	if _, err := New(cfg, config.HTTPS{}, nil, "", discardLogger()); err == nil {
		t.Error("a broken pathsRequireAuth pattern has to be refused")
	}

	cfg = config.Default().HTTP
	cfg.Basefolder = base
	users := []config.User{{Username: "john", Password: "doe", HTTP: true, Paths: []string{"([unclosed"}}}
	if _, err := New(cfg, config.HTTPS{}, users, "", discardLogger()); err == nil {
		t.Error("a broken user path pattern has to be refused")
	}
}

func TestStartNeedsAListener(t *testing.T) {
	cfg := config.Default().HTTP
	cfg.Enabled = false
	cfg.Basefolder = t.TempDir()
	server, err := New(cfg, config.HTTPS{}, nil, "", discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err == nil {
		t.Error("starting with neither listener enabled has to fail")
	}
}

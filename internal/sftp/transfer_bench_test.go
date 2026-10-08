package sftp

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// benchSize is what one upload or download moves: large enough that the
// handshake and the open are lost in the transfer.
const benchSize = 256 << 20

// benchTransports are the ciphers a client is likely to end up with, each with
// the MAC it needs: the AEAD ciphers bring their own.
var benchTransports = []struct {
	name   string
	cipher string
	mac    string
}{
	{"aes128-gcm", ssh.CipherAES128GCM, ""},
	{"chacha20", ssh.CipherChaCha20Poly1305, ""},
	{"aes128-ctr+etm", ssh.CipherAES128CTR, ssh.HMACSHA256ETM},
}

// benchClient logs in with one cipher forced, the way a client that prefers
// it would end up with it.
func benchClient(b *testing.B, server *testServer, cipher, mac string) *sftp.Client {
	b.Helper()
	config := &ssh.ClientConfig{
		User:            "john",
		Auth:            []ssh.AuthMethod{ssh.Password("doe")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	config.Ciphers = []string{cipher}
	if mac != "" {
		config.MACs = []string{mac}
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(server.port())), config)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	client, err := sftp.NewClient(conn)
	if err != nil {
		b.Fatalf("sftp subsystem: %v", err)
	}
	b.Cleanup(func() { _ = client.Close() })
	return client
}

// zeros is a reader of nothing but zero bytes that costs nothing to read, so
// that an upload measures the transport and the server rather than a source.
type zeros struct{}

func (zeros) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

// BenchmarkTransfer moves benchSize bytes each way over loopback, once per
// cipher. Run it with -benchtime 3x: each iteration is a whole file.
func BenchmarkTransfer(b *testing.B) {
	for _, transport := range benchTransports {
		b.Run("upload/"+transport.name, func(b *testing.B) {
			server := newServer(b, nil)
			client := benchClient(b, server, transport.cipher, transport.mac)
			b.SetBytes(benchSize)
			b.ResetTimer()
			for range b.N {
				file, err := client.Create("upload.bin")
				if err != nil {
					b.Fatal(err)
				}
				written, err := file.ReadFromWithConcurrency(io.LimitReader(zeros{}, benchSize), 0)
				if closeErr := file.Close(); err == nil {
					err = closeErr
				}
				if err != nil || written != benchSize {
					b.Fatalf("upload: %d bytes, %v", written, err)
				}
			}
		})

		b.Run("download/"+transport.name, func(b *testing.B) {
			server := newServer(b, nil)
			source, err := os.Create(filepath.Join(server.base, "download.bin"))
			if err != nil {
				b.Fatal(err)
			}
			if _, err := io.Copy(source, io.LimitReader(zeros{}, benchSize)); err != nil {
				b.Fatal(err)
			}
			_ = source.Close()
			client := benchClient(b, server, transport.cipher, transport.mac)
			b.SetBytes(benchSize)
			b.ResetTimer()
			for range b.N {
				file, err := client.Open("download.bin")
				if err != nil {
					b.Fatal(err)
				}
				read, err := file.WriteTo(io.Discard)
				_ = file.Close()
				if err != nil || read != benchSize {
					b.Fatalf("download: %d bytes, %v", read, err)
				}
			}
		})
	}
}

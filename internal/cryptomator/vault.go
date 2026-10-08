// Package cryptomator reads and writes vaults of Cryptomator, format 8 with
// the cipher combination SIV_GCM: the format the Cryptomator apps create, so
// that a vault go-fs made opens in them and one they made opens in go-fs.
//
// A vault is a folder that holds two files and a tree:
//
//	vault.cryptomator      what the vault is, a JWT signed with its keys
//	masterkey.cryptomator  its keys, wrapped under a key the password derives
//	d/XX/YYYY.../          one folder per folder of the vault, flat
//
// A folder of the vault is known by an ID, the root by the empty one, and is
// kept at a path the ID hashes to. What it holds are nodes, each named by its
// cleartext name encrypted with the ID of the folder: a file is a node that
// is a file, a folder a node that is a folder holding dir.c9r, the ID of the
// folder it is. A name whose ciphertext is too long is kept shortened, in a
// node named by its hash that holds the whole name in name.c9s.
//
// The package does no I/O of its own: it turns names, paths and contents into
// what a vault keeps and back, and the caller reads and writes them wherever
// the vault is.
package cryptomator

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// The names of what a vault keeps.
const (
	// VaultFile is the file that says what the vault is.
	VaultFile = "vault.cryptomator"
	// MasterkeyFile is the file the keys of the vault are kept in.
	MasterkeyFile = "masterkey.cryptomator"
	// DataFolder is the folder the tree of the vault is kept in.
	DataFolder = "d"
	// DirFile is what a node of a folder holds: the ID of the folder.
	DirFile = "dir.c9r"
	// DirIDFile is what the folder of a folder of the vault holds besides its
	// nodes: its own ID, encrypted, so that a tree whose nodes were lost can
	// still be put back together.
	DirIDFile = "dirid.c9r"
	// ContentsFile is what a shortened node of a file holds its content in.
	ContentsFile = "contents.c9r"
	// NameFile is what a shortened node holds its whole encrypted name in.
	NameFile = "name.c9s"
	// SymlinkFile is what a node of a link holds; go-fs does not follow one.
	SymlinkFile = "symlink.c9r"
	// Suffix is what the name of a node ends in.
	Suffix = ".c9r"
	// ShortSuffix is what the name of a shortened node ends in.
	ShortSuffix = ".c9s"
)

const (
	format         = 8
	cipherCombo    = "SIV_GCM"
	masterkeyKID   = "masterkeyfile:" + MasterkeyFile
	keySize        = 32
	masterkeyVer   = 999
	scryptCost     = 1 << 15
	scryptBlock    = 8
	scryptSaltSize = 8
	// maxScryptCost and maxScryptBlock are the most a key file may ask of
	// scrypt: 1 GiB of memory, sixteen times what a vault is made with.
	maxScryptCost  = 1 << 20
	maxScryptBlock = 8
	// DefaultShorteningThreshold is the longest an encrypted name, with its
	// suffix, may be before it is kept shortened.
	DefaultShorteningThreshold = 220
)

// ErrWrongPassword is what unlocking a vault with another password than its
// own fails with.
var ErrWrongPassword = errors.New("the vault password is wrong")

// Vault is an unlocked vault: its keys, and what turns names into the
// ciphertexts it keeps.
type Vault struct {
	encKey, macKey []byte
	siv            *siv
	// threshold is how long a name may be before it is kept shortened.
	threshold int
}

// masterkeyJSON is masterkey.cryptomator.
type masterkeyJSON struct {
	Version          int    `json:"version"`
	ScryptSalt       []byte `json:"scryptSalt"`
	ScryptCostParam  int    `json:"scryptCostParam"`
	ScryptBlockSize  int    `json:"scryptBlockSize"`
	PrimaryMasterKey []byte `json:"primaryMasterKey"`
	HmacMasterKey    []byte `json:"hmacMasterKey"`
	VersionMac       []byte `json:"versionMac"`
}

// vaultClaims are what vault.cryptomator says.
type vaultClaims struct {
	Format              int    `json:"format"`
	ShorteningThreshold int    `json:"shorteningThreshold"`
	CipherCombo         string `json:"cipherCombo"`
	jwt.RegisteredClaims
}

// Create makes the keys of a new vault and what it keeps them in: the
// contents of VaultFile and MasterkeyFile, by their names, and the recovery
// key, which is the keys themselves written out (see RecoveryKey).
func Create(password string) (*Vault, map[string][]byte, string, error) {
	keys := make([]byte, 2*keySize)
	if _, err := rand.Read(keys); err != nil {
		return nil, nil, "", err
	}
	v, err := newVault(keys[:keySize], keys[keySize:], DefaultShorteningThreshold)
	if err != nil {
		return nil, nil, "", err
	}
	masterkey, err := v.masterkeyFile(password)
	if err != nil {
		return nil, nil, "", err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, vaultClaims{
		Format:              format,
		ShorteningThreshold: DefaultShorteningThreshold,
		CipherCombo:         cipherCombo,
		RegisteredClaims:    jwt.RegisteredClaims{ID: uuid(id)},
	})
	token.Header["kid"] = masterkeyKID
	signed, err := token.SignedString(v.rawKey())
	if err != nil {
		return nil, nil, "", err
	}
	files := map[string][]byte{VaultFile: []byte(signed), MasterkeyFile: masterkey}
	return v, files, v.RecoveryKey(), nil
}

// Unlock opens a vault from the contents of its VaultFile and MasterkeyFile.
func Unlock(vaultFile, masterkeyFile []byte, password string) (*Vault, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))
	unverified, _, err := parser.ParseUnverified(string(vaultFile), &vaultClaims{})
	if err != nil {
		return nil, fmt.Errorf("%s is not a vault: %w", VaultFile, err)
	}
	if kid, _ := unverified.Header["kid"].(string); kid != masterkeyKID {
		return nil, fmt.Errorf("the vault is unlocked by %q, and go-fs only unlocks one with a password", kid)
	}
	var mk masterkeyJSON
	if err := json.Unmarshal(masterkeyFile, &mk); err != nil {
		return nil, fmt.Errorf("%s is not a key file: %w", MasterkeyFile, err)
	}
	// the cost comes from the server, which could otherwise have go-fs spend
	// all its memory on one unlock
	if mk.ScryptCostParam > maxScryptCost || mk.ScryptBlockSize > maxScryptBlock {
		return nil, fmt.Errorf("%s asks for more work than go-fs spends on a password", MasterkeyFile)
	}
	kek, err := scrypt.Key([]byte(norm.NFC.String(password)), mk.ScryptSalt, mk.ScryptCostParam, mk.ScryptBlockSize, 1, keySize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", MasterkeyFile, err)
	}
	encKey, err := unwrapKey(kek, mk.PrimaryMasterKey)
	if err != nil {
		return nil, ErrWrongPassword
	}
	macKey, err := unwrapKey(kek, mk.HmacMasterKey)
	if err != nil {
		return nil, ErrWrongPassword
	}
	if !hmac.Equal(mk.VersionMac, versionMac(macKey, mk.Version)) {
		return nil, fmt.Errorf("%s was tampered with", MasterkeyFile)
	}
	raw := append(append([]byte(nil), encKey...), macKey...)
	var claims vaultClaims
	if _, err := parser.ParseWithClaims(string(vaultFile), &claims, func(*jwt.Token) (any, error) { return raw, nil }); err != nil {
		return nil, fmt.Errorf("%s is not signed by the keys of the vault: %w", VaultFile, err)
	}
	if claims.Format != format {
		return nil, fmt.Errorf("the vault is of format %d, and go-fs opens format %d", claims.Format, format)
	}
	if claims.CipherCombo != cipherCombo {
		return nil, fmt.Errorf("the vault is encrypted with %s, and go-fs opens %s", claims.CipherCombo, cipherCombo)
	}
	threshold := claims.ShorteningThreshold
	if threshold <= 0 {
		threshold = DefaultShorteningThreshold
	}
	return newVault(encKey, macKey, threshold)
}

func newVault(encKey, macKey []byte, threshold int) (*Vault, error) {
	s, err := newSIV(encKey, macKey)
	if err != nil {
		return nil, err
	}
	return &Vault{encKey: encKey, macKey: macKey, siv: s, threshold: threshold}, nil
}

// rawKey is the encryption key followed by the MAC key, what the vault file
// is signed with and what the recovery key writes out.
func (v *Vault) rawKey() []byte {
	return append(append([]byte(nil), v.encKey...), v.macKey...)
}

func (v *Vault) masterkeyFile(password string) ([]byte, error) {
	salt := make([]byte, scryptSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	kek, err := scrypt.Key([]byte(norm.NFC.String(password)), salt, scryptCost, scryptBlock, 1, keySize)
	if err != nil {
		return nil, err
	}
	primary, err := wrapKey(kek, v.encKey)
	if err != nil {
		return nil, err
	}
	hmacKey, err := wrapKey(kek, v.macKey)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(masterkeyJSON{
		Version:          masterkeyVer,
		ScryptSalt:       salt,
		ScryptCostParam:  scryptCost,
		ScryptBlockSize:  scryptBlock,
		PrimaryMasterKey: primary,
		HmacMasterKey:    hmacKey,
		VersionMac:       versionMac(v.macKey, masterkeyVer),
	}, "", "  ")
}

func versionMac(macKey []byte, version int) []byte {
	mac := hmac.New(sha256.New, macKey)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(version))
	mac.Write(b[:])
	return mac.Sum(nil)
}

// DirPath is where the folder of the vault with the ID is kept, from the top
// of the vault: d/ and the hash of the ID, split after two characters.
func (v *Vault) DirPath(dirID string) string {
	sum := sha1.Sum(v.siv.seal([]byte(dirID)))
	h := base32.StdEncoding.EncodeToString(sum[:])
	return DataFolder + "/" + h[:2] + "/" + h[2:]
}

// EncryptName is the name of the node of a file or a folder named name in
// the folder with the ID dirID, with its suffix; Shorten says whether it is
// kept under that name.
func (v *Vault) EncryptName(name, dirID string) string {
	sealed := v.siv.seal([]byte(norm.NFC.String(name)), []byte(dirID))
	return base64.URLEncoding.EncodeToString(sealed) + Suffix
}

// DecryptName is the cleartext name of a node named encrypted, its suffix
// included, in the folder with the ID dirID.
func (v *Vault) DecryptName(encrypted, dirID string) (string, error) {
	trimmed, ok := strings.CutSuffix(encrypted, Suffix)
	if !ok {
		return "", errSIV
	}
	sealed, err := base64.URLEncoding.DecodeString(trimmed)
	if err != nil {
		return "", errSIV
	}
	name, err := v.siv.open(sealed, []byte(dirID))
	if err != nil {
		return "", err
	}
	return string(name), nil
}

// Shorten is the name an encrypted name is kept under: itself while it is
// short enough, and else its hash with ShortSuffix, the node then holding the
// whole name in NameFile.
func (v *Vault) Shorten(encrypted string) (string, bool) {
	if len(encrypted) <= v.threshold {
		return encrypted, false
	}
	sum := sha1.Sum([]byte(encrypted))
	return base64.URLEncoding.EncodeToString(sum[:]) + ShortSuffix, true
}

// NewDirID is the ID of a new folder of the vault.
func NewDirID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return uuid(b), nil
}

// uuid writes 16 random bytes as a version 4 UUID.
func uuid(b []byte) string {
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

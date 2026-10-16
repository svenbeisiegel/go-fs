package fdroid

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/shogo82148/androidbinary"
)

// ErrIncomplete is an APK that is not a whole zip file, which one still being
// written is not.
var ErrIncomplete = errors.New("is not a whole APK")

// manifest is what is read of AndroidManifest.xml.
type manifest struct {
	Package     androidbinary.String `xml:"package,attr"`
	VersionCode androidbinary.Int32  `xml:"http://schemas.android.com/apk/res/android versionCode,attr"`
	VersionName androidbinary.String `xml:"http://schemas.android.com/apk/res/android versionName,attr"`
	SDK         struct {
		Min    androidbinary.Int32 `xml:"http://schemas.android.com/apk/res/android minSdkVersion,attr"`
		Target androidbinary.Int32 `xml:"http://schemas.android.com/apk/res/android targetSdkVersion,attr"`
		Max    androidbinary.Int32 `xml:"http://schemas.android.com/apk/res/android maxSdkVersion,attr"`
	} `xml:"uses-sdk"`
	Permissions      []usesPermission `xml:"uses-permission"`
	PermissionsSdk23 []usesPermission `xml:"uses-permission-sdk-23"`
	Features         []struct {
		Name androidbinary.String `xml:"http://schemas.android.com/apk/res/android name,attr"`
	} `xml:"uses-feature"`
	App struct {
		Label androidbinary.String `xml:"http://schemas.android.com/apk/res/android label,attr"`
		Icon  androidbinary.String `xml:"http://schemas.android.com/apk/res/android icon,attr"`
	} `xml:"application"`
}

type usesPermission struct {
	Name androidbinary.String `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Max  androidbinary.Int32  `xml:"http://schemas.android.com/apk/res/android maxSdkVersion,attr"`
}

// Permission is a permission an APK asks for, up to MaxSdkVersion when that
// is not 0.
type Permission struct {
	Name          string
	MaxSdkVersion int
}

// APK is what the index lists of an APK.
type APK struct {
	PackageName      string
	VersionCode      int64
	VersionName      string
	MinSdkVersion    int
	TargetSdkVersion int
	MaxSdkVersion    int
	Permissions      []Permission
	PermissionsSdk23 []Permission
	Features         []string
	// NativeCode are the ABIs the APK has native libraries for.
	NativeCode []string
	// Signer is the SHA-256 of the certificate the APK is signed with, in
	// lower case hex.
	Signer string
	// Label is the name of the app, in the default language.
	Label string
	// Icon is the launcher icon, Icon an image of the highest density the
	// APK has one of, and IconExt its extension, such as ".png"; nil when
	// the APK has none, or only one drawn from XML.
	Icon    []byte
	IconExt string
	// SHA256 is the digest of the whole file, in lower case hex, and Size
	// its size.
	SHA256 string
	Size   int64
}

// Open reads the APK at path.
func Open(path string) (*APK, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return Read(f, info.Size())
}

// Read reads an APK of size bytes from r.
func Read(r io.ReaderAt, size int64) (*APK, error) {
	z, err := zip.NewReader(r, size)
	if err != nil {
		return nil, ErrIncomplete
	}
	files := map[string]*zip.File{}
	for _, f := range z.File {
		files[f.Name] = f
	}

	raw, err := readFile(files, "AndroidManifest.xml")
	if err != nil {
		return nil, err
	}
	var table *androidbinary.TableFile
	if res, err := readFile(files, "resources.arsc"); err == nil {
		if table, err = androidbinary.NewTableFile(bytes.NewReader(res)); err != nil {
			return nil, fmt.Errorf("has a resources.arsc that cannot be read: %w", err)
		}
	}
	xmlFile, err := androidbinary.NewXMLFile(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("has an AndroidManifest.xml that cannot be read: %w", err)
	}
	var m manifest
	if err := xmlFile.Decode(&m, table, nil); err != nil {
		return nil, fmt.Errorf("has an AndroidManifest.xml that cannot be read: %w", err)
	}

	a := &APK{}
	if a.PackageName, err = m.Package.String(); err != nil || a.PackageName == "" {
		return nil, errors.New("names no package in its manifest")
	}
	code, err := m.VersionCode.Int32()
	if err != nil || code <= 0 {
		return nil, errors.New("has no versionCode in its manifest")
	}
	a.VersionCode = int64(code)
	if a.VersionName, err = m.VersionName.String(); err != nil || androidbinary.IsResID(a.VersionName) {
		a.VersionName = ""
	}
	if a.VersionName == "" {
		a.VersionName = fmt.Sprint(a.VersionCode)
	}
	a.MinSdkVersion = number(m.SDK.Min)
	if a.MinSdkVersion == 0 {
		// what Android assumes when the manifest does not say
		a.MinSdkVersion = 1
	}
	a.TargetSdkVersion = number(m.SDK.Target)
	if a.TargetSdkVersion == 0 {
		a.TargetSdkVersion = a.MinSdkVersion
	}
	a.MaxSdkVersion = number(m.SDK.Max)
	a.Permissions = permissions(m.Permissions)
	a.PermissionsSdk23 = permissions(m.PermissionsSdk23)
	for _, f := range m.Features {
		if name, err := f.Name.String(); err == nil && name != "" && !slices.Contains(a.Features, name) {
			a.Features = append(a.Features, name)
		}
	}
	a.NativeCode = nativeCode(z.File)

	if label, err := m.App.Label.String(); err == nil && !androidbinary.IsResID(label) {
		a.Label = label
	}
	a.Icon, a.IconExt = icon(m.App.Icon, files)

	if a.Signer, err = signer(r, size, z, files); err != nil {
		return nil, err
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, io.NewSectionReader(r, 0, size)); err != nil {
		return nil, err
	}
	a.SHA256 = hex.EncodeToString(sum.Sum(nil))
	a.Size = size
	return a, nil
}

func readFile(files map[string]*zip.File, name string) ([]byte, error) {
	f, ok := files[name]
	if !ok {
		return nil, fmt.Errorf("has no %s", name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("has a %s that cannot be read: %w", name, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		// a checksum that does not match is a file not yet whole
		return nil, ErrIncomplete
	}
	return data, nil
}

func number(v androidbinary.Int32) int {
	n, err := v.Int32()
	if err != nil || n < 0 {
		return 0
	}
	return int(n)
}

func permissions(in []usesPermission) []Permission {
	var out []Permission
	for _, p := range in {
		name, err := p.Name.String()
		if err != nil || name == "" {
			continue
		}
		out = append(out, Permission{Name: name, MaxSdkVersion: number(p.Max)})
	}
	return out
}

// nativeCode lists the ABIs of the native libraries in lib/<abi>/.
func nativeCode(files []*zip.File) []string {
	var abis []string
	for _, f := range files {
		rest, ok := strings.CutPrefix(f.Name, "lib/")
		if !ok {
			continue
		}
		abi, lib, ok := strings.Cut(rest, "/")
		if ok && abi != "" && lib != "" && !slices.Contains(abis, abi) {
			abis = append(abis, abi)
		}
	}
	slices.Sort(abis)
	return abis
}

// iconDensities are the densities an icon is looked for at, the highest
// first. An adaptive icon is XML from API 26 on, so it is asked for as an
// older device would, which gets an image.
var iconDensities = []uint16{640, 480, 320, 240, 160, 0}

// iconSDK is the version of Android an icon is resolved for: the last one
// before adaptive icons.
const iconSDK = 25

// icon finds the launcher icon of the APK, an image of the highest density
// there is.
func icon(ref androidbinary.String, files map[string]*zip.File) ([]byte, string) {
	for _, density := range iconDensities {
		name, err := ref.WithResTableConfig(&androidbinary.ResTableConfig{
			Density: density, SDKVersion: iconSDK,
		}).String()
		if err != nil || name == "" || androidbinary.IsResID(name) {
			continue
		}
		ext := strings.ToLower(path.Ext(name))
		if ext != ".png" && ext != ".webp" && ext != ".jpg" {
			continue
		}
		data, err := readFile(files, name)
		if err != nil {
			continue
		}
		return data, ext
	}
	return nil, ""
}

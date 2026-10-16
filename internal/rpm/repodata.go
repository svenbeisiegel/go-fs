package rpm

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// What createrepo_c writes, and zypper and dnf read: repodata/repomd.xml names
// the three files below by their checksum, and each of them lists every
// package: primary.xml what resolving dependencies needs, filelists.xml every
// path a package owns, other.xml its changelog.

const (
	// RepodataFolder is the folder of a repository its metadata is in.
	RepodataFolder = "repodata"
	// Repomd is the file a client reads first, and the signature beside it
	// and the key that made it.
	Repomd          = "repomd.xml"
	RepomdSignature = "repomd.xml.asc"
	RepomdKey       = "repomd.xml.key"

	nsCommon    = "http://linux.duke.edu/metadata/common"
	nsRPM       = "http://linux.duke.edu/metadata/rpm"
	nsFilelists = "http://linux.duke.edu/metadata/filelists"
	nsOther     = "http://linux.duke.edu/metadata/other"
	nsRepo      = "http://linux.duke.edu/metadata/repo"
)

// dataFile matches the names Write gives the files repomd.xml points at, the
// only ones in the folder it ever removes.
var dataFile = regexp.MustCompile(`^[0-9a-f]{64}-(primary|filelists|other)\.xml\.gz$`)

// primaryFile matches the paths primary.xml lists of a package, as
// createrepo_c picks them: what a dependency on a path most often names. The
// rest are only in filelists.xml.
var primaryFile = regexp.MustCompile(`^(.*bin/.*|/etc/.*|/usr/lib/sendmail)$`)

// Entry is a package as the repository lists it.
type Entry struct {
	Package
	// Href is where the package is, relative to the repository, with
	// forward slashes.
	Href string
	// Checksum is the SHA-256 of the whole file, which also identifies the
	// package in the metadata.
	Checksum string
	Size     int64
	// ModTime is the modification time of the file, in seconds.
	ModTime int64
	// HeaderStart and HeaderEnd are where the header is in the file.
	HeaderStart int64
	HeaderEnd   int64
}

// Entry reads what the metadata lists of the package, href being where it is
// in the repository. It reads the whole file for its checksum.
func (f *File) Entry(href string) (Entry, error) {
	file, err := os.Open(f.Path)
	if err != nil {
		return Entry{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Entry{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return Entry{}, err
	}
	return Entry{
		Package:     f.Package(),
		Href:        href,
		Checksum:    hex.EncodeToString(h.Sum(nil)),
		Size:        info.Size(),
		ModTime:     info.ModTime().Unix(),
		HeaderStart: f.HeaderStart,
		HeaderEnd:   f.PayloadStart,
	}, nil
}

// Repodata is the metadata a Write produced.
type Repodata struct {
	// Repomd is repomd.xml as it was written.
	Repomd []byte
}

// Sign makes the armored detached signature written beside repomd.xml.
type Sign func(repomd []byte) ([]byte, error)

// WriteRepodata writes the metadata of the packages into the repodata
// folder of folder: the three lists first, under names of their checksum so
// that none is ever replaced, then the key and the signature, then
// repomd.xml, which is the one file a client reads first, replaced at once.
// The lists of the metadata before are kept, so that a client that read the
// old repomd.xml a moment ago still finds what it names; the ones before
// those are removed.
//
// publicKey is written as repomd.xml.key and sign makes repomd.xml.asc.
func WriteRepodata(folder string, entries []Entry, publicKey []byte, sign Sign, now time.Time) (Repodata, error) {
	dir := filepath.Join(folder, RepodataFolder)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Repodata{}, err
	}
	previous := referenced(filepath.Join(dir, Repomd))

	timestamp := now.Unix()
	repomd := repomdXML{Xmlns: nsRepo, XmlnsRPM: nsRPM, Revision: strconv.FormatInt(timestamp, 10)}
	for _, kind := range []struct {
		name string
		doc  any
	}{
		{"primary", primaryXML(entries)},
		{"filelists", filelistsXML(entries)},
		{"other", otherXML(entries)},
	} {
		plain, err := document(kind.doc)
		if err != nil {
			return Repodata{}, fmt.Errorf("%s.xml: %w", kind.name, err)
		}
		var packed bytes.Buffer
		writer, _ := gzip.NewWriterLevel(&packed, gzip.BestCompression)
		writer.Write(plain)
		if err := writer.Close(); err != nil {
			return Repodata{}, err
		}
		packedSum, plainSum := sha256.Sum256(packed.Bytes()), sha256.Sum256(plain)
		name := hex.EncodeToString(packedSum[:]) + "-" + kind.name + ".xml.gz"
		if err := writeAtomic(filepath.Join(dir, name), packed.Bytes()); err != nil {
			return Repodata{}, err
		}
		repomd.Data = append(repomd.Data, repomdData{
			Type:         kind.name,
			Checksum:     checksumXML{Type: "sha256", Value: hex.EncodeToString(packedSum[:])},
			OpenChecksum: checksumXML{Type: "sha256", Value: hex.EncodeToString(plainSum[:])},
			Location:     locationXML{Href: RepodataFolder + "/" + name},
			Timestamp:    timestamp,
			Size:         int64(packed.Len()),
			OpenSize:     int64(len(plain)),
		})
	}

	content, err := document(repomd)
	if err != nil {
		return Repodata{}, err
	}
	signature, err := sign(content)
	if err != nil {
		return Repodata{}, fmt.Errorf("signing repomd.xml: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, RepomdKey), publicKey); err != nil {
		return Repodata{}, err
	}
	if err := writeAtomic(filepath.Join(dir, Repomd), content); err != nil {
		return Repodata{}, err
	}
	if err := writeAtomic(filepath.Join(dir, RepomdSignature), signature); err != nil {
		return Repodata{}, err
	}

	keep := map[string]bool{}
	for _, data := range repomd.Data {
		keep[filepath.Base(data.Location.Href)] = true
	}
	for name := range previous {
		keep[name] = true
	}
	items, err := os.ReadDir(dir)
	if err != nil {
		return Repodata{}, err
	}
	for _, item := range items {
		if dataFile.MatchString(item.Name()) && !keep[item.Name()] {
			os.Remove(filepath.Join(dir, item.Name()))
		}
	}
	return Repodata{Repomd: content}, nil
}

// referenced names the files a repomd.xml points at, none when there is no
// such file or it cannot be read.
func referenced(path string) map[string]bool {
	names := map[string]bool{}
	content, err := os.ReadFile(path)
	if err != nil {
		return names
	}
	var repomd repomdXML
	if xml.Unmarshal(content, &repomd) != nil {
		return names
	}
	for _, data := range repomd.Data {
		names[filepath.Base(data.Location.Href)] = true
	}
	return names
}

// ReadRepomd reads the repomd.xml of a repository, for tests and for a
// status: the type and location of each file it names.
func ReadRepomd(folder string) (map[string]string, error) {
	content, err := os.ReadFile(filepath.Join(folder, RepodataFolder, Repomd))
	if err != nil {
		return nil, err
	}
	var repomd repomdXML
	if err := xml.Unmarshal(content, &repomd); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, data := range repomd.Data {
		out[data.Type] = data.Location.Href
	}
	if len(out) == 0 {
		return nil, errors.New("repomd.xml names no metadata")
	}
	return out, nil
}

func document(doc any) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(xml.Header)
	encoder := xml.NewEncoder(&out)
	encoder.Indent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// writeAtomic writes a file beside path and renames it over path, so that a
// client reads either the old file or the new one, never part of one.
func writeAtomic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// The documents, as encoding/xml writes them. A prefixed name such as
// rpm:entry is written as it is; the prefix is declared on the root.

type repomdXML struct {
	XMLName  xml.Name     `xml:"repomd"`
	Xmlns    string       `xml:"xmlns,attr"`
	XmlnsRPM string       `xml:"xmlns:rpm,attr"`
	Revision string       `xml:"revision"`
	Data     []repomdData `xml:"data"`
}

type repomdData struct {
	Type         string      `xml:"type,attr"`
	Checksum     checksumXML `xml:"checksum"`
	OpenChecksum checksumXML `xml:"open-checksum"`
	Location     locationXML `xml:"location"`
	Timestamp    int64       `xml:"timestamp"`
	Size         int64       `xml:"size"`
	OpenSize     int64       `xml:"open-size"`
}

type checksumXML struct {
	Type  string `xml:"type,attr"`
	PkgID string `xml:"pkgid,attr,omitempty"`
	Value string `xml:",chardata"`
}

type locationXML struct {
	Href string `xml:"href,attr"`
}

type versionXML struct {
	Epoch   string `xml:"epoch,attr"`
	Version string `xml:"ver,attr"`
	Release string `xml:"rel,attr"`
}

func versionOf(v EVR) versionXML {
	return versionXML{Epoch: orZero(v.Epoch), Version: v.Version, Release: v.Release}
}

type primaryDoc struct {
	XMLName  xml.Name         `xml:"metadata"`
	Xmlns    string           `xml:"xmlns,attr"`
	XmlnsRPM string           `xml:"xmlns:rpm,attr"`
	Count    int              `xml:"packages,attr"`
	Packages []primaryPackage `xml:"package"`
}

type primaryPackage struct {
	Type        string      `xml:"type,attr"`
	Name        string      `xml:"name"`
	Arch        string      `xml:"arch"`
	Version     versionXML  `xml:"version"`
	Checksum    checksumXML `xml:"checksum"`
	Summary     string      `xml:"summary"`
	Description string      `xml:"description"`
	Packager    string      `xml:"packager"`
	URL         string      `xml:"url"`
	Time        struct {
		File  int64 `xml:"file,attr"`
		Build int64 `xml:"build,attr"`
	} `xml:"time"`
	Size struct {
		Package   int64 `xml:"package,attr"`
		Installed int64 `xml:"installed,attr"`
		Archive   int64 `xml:"archive,attr"`
	} `xml:"size"`
	Location locationXML `xml:"location"`
	Format   formatXML   `xml:"format"`
}

type formatXML struct {
	License     string `xml:"rpm:license"`
	Vendor      string `xml:"rpm:vendor"`
	Group       string `xml:"rpm:group"`
	BuildHost   string `xml:"rpm:buildhost"`
	SourceRPM   string `xml:"rpm:sourcerpm"`
	HeaderRange struct {
		Start int64 `xml:"start,attr"`
		End   int64 `xml:"end,attr"`
	} `xml:"rpm:header-range"`
	Provides    *entriesXML `xml:"rpm:provides,omitempty"`
	Requires    *entriesXML `xml:"rpm:requires,omitempty"`
	Conflicts   *entriesXML `xml:"rpm:conflicts,omitempty"`
	Obsoletes   *entriesXML `xml:"rpm:obsoletes,omitempty"`
	Suggests    *entriesXML `xml:"rpm:suggests,omitempty"`
	Enhances    *entriesXML `xml:"rpm:enhances,omitempty"`
	Recommends  *entriesXML `xml:"rpm:recommends,omitempty"`
	Supplements *entriesXML `xml:"rpm:supplements,omitempty"`
	Files       []fileXML   `xml:"file"`
}

type entriesXML struct {
	Entries []entryXML `xml:"rpm:entry"`
}

type entryXML struct {
	Name    string `xml:"name,attr"`
	Flags   string `xml:"flags,attr,omitempty"`
	Epoch   string `xml:"epoch,attr,omitempty"`
	Version string `xml:"ver,attr,omitempty"`
	Release string `xml:"rel,attr,omitempty"`
	Pre     string `xml:"pre,attr,omitempty"`
}

type fileXML struct {
	Type string `xml:"type,attr,omitempty"`
	Path string `xml:",chardata"`
}

func entriesOf(deps []Dependency, pre bool) *entriesXML {
	if len(deps) == 0 {
		return nil
	}
	out := &entriesXML{Entries: make([]entryXML, len(deps))}
	for i, d := range deps {
		e := entryXML{Name: d.Name, Flags: d.Flags}
		if d.Flags != "" {
			e.Epoch, e.Version, e.Release = orZero(d.Epoch), d.Version, d.Release
		}
		if pre && d.Pre {
			e.Pre = "1"
		}
		out.Entries[i] = e
	}
	return out
}

func primaryXML(entries []Entry) primaryDoc {
	doc := primaryDoc{Xmlns: nsCommon, XmlnsRPM: nsRPM, Count: len(entries)}
	for _, e := range entries {
		p := primaryPackage{
			Type:        "rpm",
			Name:        e.Name,
			Arch:        e.Arch,
			Version:     versionOf(e.EVR),
			Checksum:    checksumXML{Type: "sha256", PkgID: "YES", Value: e.Checksum},
			Summary:     e.Summary,
			Description: e.Description,
			Packager:    e.Packager,
			URL:         e.URL,
			Location:    locationXML{Href: e.Href},
		}
		p.Time.File, p.Time.Build = e.ModTime, e.BuildTime
		p.Size.Package, p.Size.Installed, p.Size.Archive = e.Size, e.InstalledSize, e.ArchiveSize
		f := &p.Format
		f.License, f.Vendor, f.Group, f.BuildHost, f.SourceRPM = e.License, e.Vendor, e.Group, e.BuildHost, e.SourceRPM
		f.HeaderRange.Start, f.HeaderRange.End = e.HeaderStart, e.HeaderEnd
		f.Provides = entriesOf(e.Provides, false)
		f.Requires = entriesOf(e.Requires, true)
		f.Conflicts = entriesOf(e.Conflicts, false)
		f.Obsoletes = entriesOf(e.Obsoletes, false)
		f.Suggests = entriesOf(e.Suggests, false)
		f.Enhances = entriesOf(e.Enhances, false)
		f.Recommends = entriesOf(e.Recommends, false)
		f.Supplements = entriesOf(e.Supplements, false)
		for _, file := range e.Files {
			if primaryFile.MatchString(file.Path) {
				f.Files = append(f.Files, fileXML{Type: file.Type, Path: file.Path})
			}
		}
		doc.Packages = append(doc.Packages, p)
	}
	return doc
}

type filelistsDoc struct {
	XMLName  xml.Name          `xml:"filelists"`
	Xmlns    string            `xml:"xmlns,attr"`
	Count    int               `xml:"packages,attr"`
	Packages []filelistPackage `xml:"package"`
}

type filelistPackage struct {
	PkgID   string     `xml:"pkgid,attr"`
	Name    string     `xml:"name,attr"`
	Arch    string     `xml:"arch,attr"`
	Version versionXML `xml:"version"`
	Files   []fileXML  `xml:"file"`
}

func filelistsXML(entries []Entry) filelistsDoc {
	doc := filelistsDoc{Xmlns: nsFilelists, Count: len(entries)}
	for _, e := range entries {
		p := filelistPackage{PkgID: e.Checksum, Name: e.Name, Arch: e.Arch, Version: versionOf(e.EVR)}
		for _, file := range e.Files {
			p.Files = append(p.Files, fileXML{Type: file.Type, Path: file.Path})
		}
		doc.Packages = append(doc.Packages, p)
	}
	return doc
}

type otherDoc struct {
	XMLName  xml.Name       `xml:"otherdata"`
	Xmlns    string         `xml:"xmlns,attr"`
	Count    int            `xml:"packages,attr"`
	Packages []otherPackage `xml:"package"`
}

type otherPackage struct {
	PkgID     string         `xml:"pkgid,attr"`
	Name      string         `xml:"name,attr"`
	Arch      string         `xml:"arch,attr"`
	Version   versionXML     `xml:"version"`
	Changelog []changelogXML `xml:"changelog"`
}

type changelogXML struct {
	Author string `xml:"author,attr"`
	Date   int64  `xml:"date,attr"`
	Text   string `xml:",chardata"`
}

func otherXML(entries []Entry) otherDoc {
	doc := otherDoc{Xmlns: nsOther, Count: len(entries)}
	for _, e := range entries {
		p := otherPackage{PkgID: e.Checksum, Name: e.Name, Arch: e.Arch, Version: versionOf(e.EVR)}
		for _, c := range e.Changelog {
			p.Changelog = append(p.Changelog, changelogXML(c))
		}
		doc.Packages = append(doc.Packages, p)
	}
	return doc
}

// PrimaryOf reads the packages a written primary.xml.gz lists, by name,
// arch and location, for tests and for a status.
func PrimaryOf(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Packages []struct {
			Location locationXML `xml:"location"`
		} `xml:"package"`
	}
	if err := xml.NewDecoder(reader).Decode(&doc); err != nil {
		return nil, err
	}
	out := make([]string, len(doc.Packages))
	for i, p := range doc.Packages {
		out[i] = p.Location.Href
	}
	return out, nil
}

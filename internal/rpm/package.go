package rpm

import (
	"strconv"
	"strings"
)

// Package is what the metadata of a repository says of one package, read
// from its header.
type Package struct {
	Name string
	Arch string
	EVR
	Summary     string
	Description string
	Packager    string
	URL         string
	License     string
	Vendor      string
	Group       string
	BuildHost   string
	SourceRPM   string
	BuildTime   int64
	// InstalledSize is what the files take once installed, ArchiveSize the
	// uncompressed payload.
	InstalledSize int64
	ArchiveSize   int64

	Provides    []Dependency
	Requires    []Dependency
	Conflicts   []Dependency
	Obsoletes   []Dependency
	Recommends  []Dependency
	Suggests    []Dependency
	Supplements []Dependency
	Enhances    []Dependency

	Files     []PackageFile
	Changelog []ChangelogEntry
}

// Dependency is one entry of a list of dependencies.
type Dependency struct {
	Name string
	// Flags is the comparison, LT, GT, EQ, LE or GE, "" for none.
	Flags string
	EVR
	// Pre marks a requirement that has to be installed before the package
	// is, for its scripts.
	Pre bool
}

// PackageFile is one path the package owns.
type PackageFile struct {
	Path string
	// Type is "dir" for a folder, "ghost" for a file the package owns but
	// does not carry, "" for any other.
	Type string
}

// ChangelogEntry is one entry of the changelog.
type ChangelogEntry struct {
	Author string
	Date   int64
	Text   string
}

// IsSource reports whether the package is a source rpm.
func (f *File) IsSource() bool {
	return f.Header.Has(tagSourcePackage) || !f.Header.Has(tagSourceRPM)
}

// Package reads what the metadata says of the package.
func (f *File) Package() Package {
	h := f.Header
	p := Package{
		Name:        h.String(tagName),
		Arch:        h.String(tagArch),
		Summary:     h.String(tagSummary),
		Description: h.String(tagDescription),
		Packager:    h.String(tagPackager),
		URL:         h.String(tagURL),
		License:     h.String(tagLicense),
		Vendor:      h.String(tagVendor),
		Group:       h.String(tagGroup),
		BuildHost:   h.String(tagBuildHost),
		SourceRPM:   h.String(tagSourceRPM),
	}
	if f.IsSource() {
		p.Arch = "src"
	}
	p.EVR = EVR{Epoch: "0", Version: h.String(tagVersion), Release: h.String(tagRelease)}
	if epoch, ok := h.Int(tagEpoch); ok {
		p.Epoch = strconv.FormatInt(epoch, 10)
	}
	p.BuildTime, _ = h.Int(tagBuildTime)
	if size, ok := h.Int(tagLongSize); ok {
		p.InstalledSize = size
	} else {
		p.InstalledSize, _ = h.Int(tagSize)
	}
	if size, ok := f.Signature.Int(sigLongPayload); ok {
		p.ArchiveSize = size
	} else if size, ok := f.Signature.Int(sigPayloadSize); ok {
		p.ArchiveSize = size
	} else {
		p.ArchiveSize, _ = h.Int(tagArchiveSize)
	}

	p.Provides = dependencies(h, tagProvideName, tagProvideFlags, tagProvideVersion)
	p.Requires = requirements(dependencies(h, tagRequireName, tagRequireFlags, tagRequireVersion))
	p.Conflicts = dependencies(h, tagConflictName, tagConflictFlags, tagConflictVersion)
	p.Obsoletes = dependencies(h, tagObsoleteName, tagObsoleteFlags, tagObsoleteVersion)
	p.Recommends = dependencies(h, tagRecommendName, tagRecommendFlags, tagRecommendVersion)
	p.Suggests = dependencies(h, tagSuggestName, tagSuggestFlags, tagSuggestVersion)
	p.Supplements = dependencies(h, tagSupplementName, tagSupplementFlags, tagSupplementVersion)
	p.Enhances = dependencies(h, tagEnhanceName, tagEnhanceFlags, tagEnhanceVersion)

	p.Files = files(h)
	p.Changelog = changelog(h)
	return p
}

// dependencies reads one list of dependencies, which the header keeps as
// three parallel arrays.
func dependencies(h *Header, nameTag, flagsTag, versionTag int32) []Dependency {
	names := h.Strings(nameTag)
	flags := h.Ints(flagsTag)
	versions := h.Strings(versionTag)
	out := make([]Dependency, 0, len(names))
	seen := map[Dependency]bool{}
	for i, name := range names {
		d := Dependency{Name: name}
		var flag int64
		if i < len(flags) {
			flag = flags[i]
		}
		if i < len(versions) && versions[i] != "" {
			d.EVR = parseEVR(versions[i])
			if d.Epoch == "" {
				d.Epoch = "0"
			}
			d.Flags = comparison(flag)
		}
		d.Pre = flag&(sensePreReq|senseScriptPre|senseScriptPost|sensePreTrans|sensePostTrans) != 0
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// requirements leaves out what rpm itself provides, rpmlib(…), which no
// repository can, as createrepo_c does.
func requirements(all []Dependency) []Dependency {
	out := all[:0]
	for _, d := range all {
		if strings.HasPrefix(d.Name, "rpmlib(") {
			continue
		}
		out = append(out, d)
	}
	return out
}

func comparison(flags int64) string {
	switch flags & (senseLess | senseGreater | senseEqual) {
	case senseLess:
		return "LT"
	case senseGreater:
		return "GT"
	case senseEqual:
		return "EQ"
	case senseLess | senseEqual:
		return "LE"
	case senseGreater | senseEqual:
		return "GE"
	}
	return ""
}

// files lists the paths the package owns, from the folder and base name
// arrays rpm keeps them in, or the whole names an old package has.
func files(h *Header) []PackageFile {
	names := h.Strings(tagOldFilenames)
	if names == nil {
		bases := h.Strings(tagBaseNames)
		dirs := h.Strings(tagDirNames)
		indexes := h.Ints(tagDirIndexes)
		for i, base := range bases {
			if i >= len(indexes) || indexes[i] < 0 || int(indexes[i]) >= len(dirs) {
				break
			}
			names = append(names, dirs[indexes[i]]+base)
		}
	}
	modes := h.Ints(tagFileModes)
	flags := h.Ints(tagFileFlags)
	out := make([]PackageFile, len(names))
	for i, name := range names {
		out[i] = PackageFile{Path: name}
		switch {
		case i < len(flags) && flags[i]&fileGhost != 0:
			out[i].Type = "ghost"
		case i < len(modes) && modes[i]&0o170000 == 0o040000:
			out[i].Type = "dir"
		}
	}
	return out
}

// changelogLimit is how many entries of the changelog the metadata carries,
// the newest, as createrepo_c keeps by default.
const changelogLimit = 10

func changelog(h *Header) []ChangelogEntry {
	times := h.Ints(tagChangelogTime)
	names := h.Strings(tagChangelogName)
	texts := h.Strings(tagChangelogText)
	n := min(len(times), len(names), len(texts), changelogLimit)
	// the header has the newest first, the metadata the oldest
	out := make([]ChangelogEntry, n)
	for i := range n {
		out[n-1-i] = ChangelogEntry{Author: names[i], Date: times[i], Text: texts[i]}
	}
	return out
}

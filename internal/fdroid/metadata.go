package fdroid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// DefaultLocale is the language what the APK says is listed in, and the one
// the client falls back to.
const DefaultLocale = "en-US"

// The texts and images an app may have beside its APKs, in
// <folder>/<packageName>/<locale>/, named as fastlane names them or as
// fdroidserver does. Each is optional.
var (
	nameFiles        = []string{"title.txt", "name.txt"}
	summaryFiles     = []string{"short_description.txt", "summary.txt"}
	descriptionFiles = []string{"full_description.txt", "description.txt"}
	videoFiles       = []string{"video.txt"}
	// graphics are the single images, by the key of the index
	graphics = map[string]string{
		"icon":           "icon",
		"featureGraphic": "featureGraphic",
		"promoGraphic":   "promoGraphic",
		"tvBanner":       "tvBanner",
	}
	// screenshotFolders are the folders of screenshots, by the key of the
	// index
	screenshotFolders = map[string]string{
		"phone":     "phoneScreenshots",
		"sevenInch": "sevenInchScreenshots",
		"tenInch":   "tenInchScreenshots",
		"tv":        "tvScreenshots",
		"wear":      "wearScreenshots",
	}
	imageExts = []string{".png", ".jpg", ".jpeg", ".webp"}
)

// metadata is what is read of the files beside the APKs of an app.
type metadata struct {
	name, summary, description, video map[string]string
	graphics                          map[string]localizedFile
	screenshots                       map[string]map[string][]fileV2
	// changelogs are by locale and then by versionCode, "default" for
	// the one of every version without its own
	changelogs map[string]map[string]string
}

// readMetadata reads the files of the app packageName in folder. An app
// without them has none.
func readMetadata(folder, packageName string) (metadata, error) {
	m := metadata{
		name: map[string]string{}, summary: map[string]string{},
		description: map[string]string{}, video: map[string]string{},
		graphics:    map[string]localizedFile{},
		screenshots: map[string]map[string][]fileV2{},
		changelogs:  map[string]map[string]string{},
	}
	dir := filepath.Join(folder, packageName)
	locales, err := os.ReadDir(dir)
	if err != nil {
		return m, nil
	}
	for _, l := range locales {
		locale := l.Name()
		if !l.IsDir() || strings.HasPrefix(locale, ".") {
			continue
		}
		base := filepath.Join(dir, locale)
		href := packageName + "/" + locale
		readText(m.name, locale, base, nameFiles)
		readText(m.summary, locale, base, summaryFiles)
		readText(m.description, locale, base, descriptionFiles)
		readText(m.video, locale, base, videoFiles)
		for key, stem := range graphics {
			for _, ext := range imageExts {
				f, err := fileOf(folder, href+"/"+stem+ext)
				if err != nil {
					continue
				}
				if m.graphics[key] == nil {
					m.graphics[key] = localizedFile{}
				}
				m.graphics[key][locale] = f
				break
			}
		}
		for key, sub := range screenshotFolders {
			shots, err := os.ReadDir(filepath.Join(base, sub))
			if err != nil {
				continue
			}
			var files []fileV2
			for _, s := range shots {
				name := s.Name()
				if s.IsDir() || strings.HasPrefix(name, ".") ||
					!slices.Contains(imageExts, strings.ToLower(path.Ext(name))) {
					continue
				}
				f, err := fileOf(folder, href+"/"+sub+"/"+name)
				if err != nil {
					return m, err
				}
				files = append(files, f)
			}
			if len(files) > 0 {
				if m.screenshots[key] == nil {
					m.screenshots[key] = map[string][]fileV2{}
				}
				m.screenshots[key][locale] = files
			}
		}
		logs, err := os.ReadDir(filepath.Join(base, "changelogs"))
		if err != nil {
			continue
		}
		for _, c := range logs {
			version, ok := strings.CutSuffix(c.Name(), ".txt")
			if c.IsDir() || !ok {
				continue
			}
			text, err := os.ReadFile(filepath.Join(base, "changelogs", c.Name()))
			if err != nil || strings.TrimSpace(string(text)) == "" {
				continue
			}
			if m.changelogs[locale] == nil {
				m.changelogs[locale] = map[string]string{}
			}
			m.changelogs[locale][version] = strings.TrimSpace(string(text))
		}
	}
	return m, nil
}

// readText reads the first of names in dir that is there, into into[locale].
func readText(into map[string]string, locale, dir string, names []string) {
	for _, name := range names {
		text, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if t := strings.TrimSpace(string(text)); t != "" {
			into[locale] = t
			return
		}
	}
}

// whatsNew is the changelog of the version code of an app, by locale.
func (m metadata) whatsNew(code int64) map[string]string {
	out := map[string]string{}
	for locale, logs := range m.changelogs {
		if text, ok := logs[fmt.Sprint(code)]; ok {
			out[locale] = text
		} else if text, ok := logs["default"]; ok {
			out[locale] = text
		}
	}
	return out
}

// fileOf is the entry the index has of the file at href in folder.
func fileOf(folder, href string) (fileV2, error) {
	data, err := os.ReadFile(filepath.Join(folder, filepath.FromSlash(href)))
	if err != nil {
		return fileV2{}, err
	}
	sum := sha256.Sum256(data)
	return fileV2{Name: "/" + href, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}, nil
}

// Inputs identifies the files beside the APKs the index is made from, the
// metadata of the apps packageNames and the icon of the repository, so that
// a change to them is noticed as one to an APK is.
func Inputs(folder string, packageNames []string, repoIcon string) string {
	var b strings.Builder
	note := func(p string) {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(folder, p)
			fmt.Fprintf(&b, "%s %d %d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano())
		}
	}
	if repoIcon != "" {
		note(filepath.Join(folder, filepath.FromSlash(repoIcon)))
	}
	names := slices.Clone(packageNames)
	slices.Sort(names)
	for _, name := range slices.Compact(names) {
		filepath.WalkDir(filepath.Join(folder, name), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				note(p)
			}
			return nil
		})
	}
	return b.String()
}

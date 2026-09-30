package httpd

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// contentType is what an extension says about a file: the media type it is
// served with and the word the directory listing shows in its Type column.
type contentType struct {
	Media string
	Kind  string
}

// contentTypes is the table of returnContentType in the Node implementation,
// kept as it was so that the listings and downloads look the same.
var contentTypes = map[string]contentType{
	// Images
	".png":  {"image/png", "Image"},
	".jpg":  {"image/jpeg", "Image"},
	".jpeg": {"image/jpeg", "Image"},
	".gif":  {"image/gif", "Image"},
	".svg":  {"image/svg+xml", "Image"},
	".webp": {"image/webp", "Image"},
	".ico":  {"image/x-icon", "Image"},

	// Audio
	".mp3": {"audio/mpeg", "Audio"},
	".wav": {"audio/wav", "Audio"},
	".ogg": {"audio/ogg", "Audio"},
	".m4a": {"audio/mp4", "Audio"},

	// Video
	".mp4":  {"video/mp4", "Video"},
	".webm": {"video/webm", "Video"},
	".avi":  {"video/x-msvideo", "Video"},
	".mov":  {"video/quicktime", "Video"},

	// Documents
	".txt":  {"text/plain", "Document"},
	".html": {"text/html", "Document"},
	".htm":  {"text/html", "Document"},
	".css":  {"text/css", "Document"},
	".js":   {"application/javascript", "Document"},
	".json": {"application/json", "Document"},
	".xml":  {"application/xml", "Document"},
	".pdf":  {"application/pdf", "Document"},

	// Archives
	".zip": {"application/zip", "Archive"},
	".rar": {"application/vnd.rar", "Archive"},
	".tar": {"application/x-tar", "Archive"},
	".gz":  {"application/gzip", "Archive"},
	".7z":  {"application/x-7z-compressed", "Archive"},

	// Fonts
	".woff":  {"font/woff", "Font"},
	".woff2": {"font/woff2", "Font"},
	".ttf":   {"font/ttf", "Font"},
	".otf":   {"font/otf", "Font"},
	".eot":   {"application/vnd.ms-fontobject", "Font"},

	// Other
	".iso": {"application/x-iso9660-image", "ISO"},
	".rpm": {"application/x-rpm", "RPM"},
}

// typeOf reports the content type of a name, falling back to a generic one.
func typeOf(name string) contentType {
	if found, ok := contentTypes[strings.ToLower(filepath.Ext(name))]; ok {
		return found
	}
	return contentType{"application/octet-stream", "Generic"}
}

// readableSize formats a size the way the listing page does. It follows the
// Node implementation, which switches units on powers of ten but divides by
// powers of two.
func readableSize(size int64) string {
	value := float64(size)
	switch {
	case size > 1000000000:
		return fmt.Sprintf("%.4g GB", roundTenth(value/1024/1024/1024))
	case size > 1000000:
		return fmt.Sprintf("%.4g MB", roundTenth(value/1024/1024))
	default:
		return fmt.Sprintf("%.4g KB", roundTenth(value/1024))
	}
}

func roundTenth(value float64) float64 {
	return float64(int64(value*10+0.5)) / 10
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}

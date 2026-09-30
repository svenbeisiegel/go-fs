// Package logging builds the logger every server writes to and holds the
// pieces of it that the rest of the program adjusts while it runs.
//
// Everything goes to standard output as one record per line, text or JSON as
// configured, so that whatever runs go-fs — a terminal, systemd, a container —
// collects the log the way it collects any other program's. Nothing is ever
// written to a file by the program itself.
package logging

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Logger is the root logger and the knob that changes its level at runtime.
type Logger struct {
	*slog.Logger
	// level is what every handler derived from this logger consults, so
	// raising it to debug reaches the per connection loggers already handed
	// out as well.
	level  *slog.LevelVar
	format string
}

// New builds the root logger for a level and a format, both already validated
// by the configuration. Output goes to stdout.
func New(level, format string) *Logger {
	return NewTo(os.Stdout, level, format)
}

// NewTo is New writing to w, for tests.
func NewTo(w io.Writer, level, format string) *Logger {
	variable := new(slog.LevelVar)
	variable.Set(ParseLevel(level))
	options := &slog.HandlerOptions{
		Level: variable,
		// a duration is written as "312ms" in JSON too, rather than as the
		// nanosecond count the JSON handler would otherwise emit, so the two
		// formats say the same thing and neither needs a calculator
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Value.Kind() == slog.KindDuration {
				return slog.String(attr.Key, attr.Value.Duration().String())
			}
			return attr
		},
	}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(w, options)
	} else {
		handler = slog.NewTextHandler(w, options)
	}
	return &Logger{Logger: slog.New(&sourced{handler}), level: variable, format: format}
}

// sourced adds where in the source a debug record was written, which is what
// tells two records with similar messages apart in a trace. Records above
// debug stay as they are: an operator reading the log at info is not helped
// by a file name. It is decided per record rather than by the handler's
// AddSource option, so that it holds for debug switched on by a reload as
// well.
type sourced struct {
	slog.Handler
}

func (s *sourced) Handle(ctx context.Context, record slog.Record) error {
	if record.Level <= slog.LevelDebug && record.PC != 0 {
		frame, _ := runtime.CallersFrames([]uintptr{record.PC}).Next()
		if frame.File != "" {
			record.AddAttrs(slog.String("source",
				fmt.Sprintf("%s:%d", filepath.Base(frame.File), frame.Line)))
		}
	}
	return s.Handler.Handle(ctx, record)
}

func (s *sourced) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &sourced{s.Handler.WithAttrs(attrs)}
}

func (s *sourced) WithGroup(name string) slog.Handler {
	return &sourced{s.Handler.WithGroup(name)}
}

// Level reports the level in effect.
func (l *Logger) Level() slog.Level {
	return l.level.Level()
}

// Format reports the output format the logger was built with, which cannot
// change while it runs.
func (l *Logger) Format() string {
	return l.format
}

// SetLevel changes the level in effect for every logger derived from this
// one, and reports whether that was a change. It is what a reload of the
// configuration file calls, so that debug output can be switched on under a
// running server to look at a problem and off again afterwards.
func (l *Logger) SetLevel(level string) bool {
	next := ParseLevel(level)
	if l.level.Level() == next {
		return false
	}
	l.level.Set(next)
	return true
}

// ParseLevel maps a configured level name onto its slog level. An unknown name
// is info, which the configuration never lets through anyway.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// HTTPErrorLog is the logger an http.Server reports its own trouble to. The
// standard library writes everything there at one level, from a client that
// failed its TLS handshake, which is ordinary, to a handler that panicked,
// which is not. The message is what tells them apart, so it decides the
// level.
func HTTPErrorLog(logger *slog.Logger, server string) *log.Logger {
	return log.New(&httpErrorWriter{log: logger.With("server", server)}, "", 0)
}

type httpErrorWriter struct {
	log *slog.Logger
}

func (w *httpErrorWriter) Write(p []byte) (int, error) {
	message := strings.TrimRight(string(p), "\n")
	switch {
	case strings.HasPrefix(message, "http: panic serving"):
		// the handler crashed; net/http recovered it and the stack trace is
		// part of the message, which is what a report of it needs
		w.log.LogAttrs(context.Background(), slog.LevelError, "a request handler panicked",
			slog.String("detail", message))
	case strings.HasPrefix(message, "http: TLS handshake error"),
		strings.Contains(message, "client sent an HTTP request to an HTTPS server"):
		// a port scan, a browser probing with the wrong scheme, a client with
		// an old TLS stack: ordinary noise that matters only in a trace
		w.log.Debug("http server reported a connection problem", "detail", message)
	default:
		w.log.Warn("http server reported a problem", "detail", message)
	}
	return len(p), nil
}

// Package logx provides the structured logger shared by every PortTransit
// component.
//
// Design notes:
//   - It is a thin wrapper over log/slog so callers can attach a component tag
//     once and then emit plain messages.
//   - Secrets never reach the log: helpers redact credentials and keys before
//     they are formatted.
//   - A ring buffer keeps the most recent records in memory so the Web GUI can
//     show a live log pane without tailing a file.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level mirrors slog.Level with friendlier names for config files.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// ParseLevel converts a config string into a slog level, defaulting to info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace", "verbose":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err", "fatal":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Entry is one captured log record, shaped for JSON transport to the Web GUI.
type Entry struct {
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// Buffer is a bounded, concurrency-safe ring of recent log entries.
type Buffer struct {
	mu      sync.RWMutex
	entries []Entry
	next    int
	filled  bool
}

// NewBuffer allocates a ring buffer holding at most size entries.
func NewBuffer(size int) *Buffer {
	if size <= 0 {
		size = 500
	}
	return &Buffer{entries: make([]Entry, size)}
}

// Add appends one entry, evicting the oldest when full.
func (b *Buffer) Add(e Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[b.next] = e
	b.next = (b.next + 1) % len(b.entries)
	if b.next == 0 {
		b.filled = true
	}
}

// Snapshot returns up to limit most-recent entries in chronological order.
// A limit <= 0 returns everything currently retained.
func (b *Buffer) Snapshot(limit int) []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	n := b.next
	if b.filled {
		n = len(b.entries)
	}
	if n == 0 {
		return nil
	}
	out := make([]Entry, 0, n)
	start := 0
	if b.filled {
		start = b.next
	}
	for i := 0; i < n; i++ {
		out = append(out, b.entries[(start+i)%len(b.entries)])
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Clear drops every retained entry.
func (b *Buffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next = 0
	b.filled = false
	for i := range b.entries {
		b.entries[i] = Entry{}
	}
}

// Options configures a Logger.
type Options struct {
	// Level is the minimum severity that is emitted.
	Level slog.Level
	// Component tags every record, e.g. "server", "client", "webui".
	Component string
	// File is an optional path for a rotating-free plain log file. The parent
	// directory is created when missing.
	File string
	// JSON selects machine-readable console output.
	JSON bool
	// Buffer optionally retains recent records for the Web GUI.
	Buffer *Buffer
	// Console forces console output even when a file is configured.
	Console bool
}

// Logger is the component-scoped logger handed to application code.
type Logger struct {
	inner *slog.Logger
	buf   *Buffer
	attrs []slog.Attr

	// closer releases the log file, when one was opened. It is shared by every
	// derived logger so a child's Close is the same Close, and it is nil when
	// the logger writes only to the console.
	closer io.Closer
}

// New builds a Logger from Options.
func New(opts Options) (*Logger, error) {
	var sinks []io.Writer
	var closer io.Closer

	if opts.Console || opts.File == "" {
		sinks = append(sinks, os.Stderr)
	}
	if opts.File != "" {
		if err := os.MkdirAll(filepath.Dir(opts.File), 0o755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(opts.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, err
		}
		closer = f
		sinks = append(sinks, f)
	}

	var w io.Writer = io.Discard
	if len(sinks) == 1 {
		w = sinks[0]
	} else if len(sinks) > 1 {
		w = io.MultiWriter(sinks...)
	}

	handlerOpts := &slog.HandlerOptions{Level: opts.Level}
	var h slog.Handler
	if opts.JSON {
		h = slog.NewJSONHandler(w, handlerOpts)
	} else {
		h = slog.NewTextHandler(w, handlerOpts)
	}

	l := &Logger{inner: slog.New(h), buf: opts.Buffer, closer: closer}
	if opts.Component != "" {
		l.attrs = append(l.attrs, slog.String("component", opts.Component))
	}
	return l, nil
}

// Close releases the log file. It is safe to call more than once and safe on a
// logger that has no file.
//
// A long-running service does not need this, but a test, a CLI invocation or a
// short-lived deployment does: without it the file stays open and the caller
// cannot delete or rename it, which on Windows makes the file impossible to
// remove until the process exits.
func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	c := l.closer
	// Clear the field so a second Close is a no-op rather than an error about
	// an already-closed file.
	l.closer = nil
	return c.Close()
}

// Discard returns a logger that emits nothing. Useful in tests.
func Discard() *Logger {
	return &Logger{inner: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// With returns a child logger carrying extra attributes.
func (l *Logger) With(args ...any) *Logger {
	if l == nil {
		return Discard()
	}
	child := &Logger{inner: l.inner.With(args...), buf: l.buf, attrs: l.attrs, closer: l.closer}
	return child
}

// Component returns a child logger whose records carry a component tag.
func (l *Logger) Component(name string) *Logger {
	if l == nil {
		return Discard()
	}
	return &Logger{
		inner:  l.inner.With("component", name),
		buf:    l.buf,
		attrs:  append(append([]slog.Attr{}, l.attrs...), slog.String("component", name)),
		closer: l.closer,
	}
}

// Buffer exposes the attached ring buffer, or nil when none was configured.
func (l *Logger) Buffer() *Buffer {
	if l == nil {
		return nil
	}
	return l.buf
}

func (l *Logger) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if l == nil {
		return
	}
	l.inner.Log(ctx, level, msg, args...)
	if l.buf == nil || !l.inner.Enabled(ctx, level) {
		return
	}
	e := Entry{
		Time:    time.Now(),
		Level:   levelString(level),
		Message: msg,
	}
	if len(args) > 0 {
		e.Attrs = make(map[string]string, len(args)/2)
		for i := 0; i+1 < len(args); i += 2 {
			k, ok := args[i].(string)
			if !ok {
				continue
			}
			e.Attrs[k] = Redact(k, sprint(args[i+1]))
		}
	}
	// The component tag is added from the logger's own attributes, so the map
	// must exist even when the call passed no arguments. Allocating it only in
	// the branch above would make every argument-less log line — which is most
	// of them — panic on a nil map assignment.
	for _, a := range l.attrs {
		if a.Key != "component" {
			continue
		}
		if e.Attrs == nil {
			e.Attrs = make(map[string]string, 1)
		}
		e.Attrs["component"] = a.Value.String()
	}
	if len(e.Attrs) == 0 {
		e.Attrs = nil
	}
	l.buf.Add(e)
}

func levelString(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "debug"
	case l < slog.LevelWarn:
		return "info"
	case l < slog.LevelError:
		return "warn"
	default:
		return "error"
	}
}

// Debug logs at debug severity.
func (l *Logger) Debug(msg string, args ...any) {
	l.log(context.Background(), slog.LevelDebug, msg, args...)
}

// Info logs at info severity.
func (l *Logger) Info(msg string, args ...any) {
	l.log(context.Background(), slog.LevelInfo, msg, args...)
}

// Warn logs at warn severity.
func (l *Logger) Warn(msg string, args ...any) {
	l.log(context.Background(), slog.LevelWarn, msg, args...)
}

// Error logs at error severity.
func (l *Logger) Error(msg string, args ...any) {
	l.log(context.Background(), slog.LevelError, msg, args...)
}

// DebugCtx logs at debug severity with a context.
func (l *Logger) DebugCtx(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelDebug, msg, args...)
}

// InfoCtx logs at info severity with a context.
func (l *Logger) InfoCtx(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelInfo, msg, args...)
}

// WarnCtx logs at warn severity with a context.
func (l *Logger) WarnCtx(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelWarn, msg, args...)
}

// ErrorCtx logs at error severity with a context.
func (l *Logger) ErrorCtx(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelError, msg, args...)
}

func sprint(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case error:
		if t == nil {
			return ""
		}
		return t.Error()
	default:
		return fmt.Sprint(v)
	}
}

// secretKeys lists attribute names whose values are always masked.
var secretKeys = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"apikey": true, "api_key": true, "private_key": true, "privatekey": true,
	"privkey": true, "psk": true, "uuid": true, "credential": true,
	"authorization": true, "cookie": true, "session": true, "passphrase": true,
}

// Redact masks a value when its key names a secret; otherwise it is returned
// unchanged.
func Redact(key, value string) string {
	if value == "" {
		return value
	}
	if secretKeys[strings.ToLower(strings.TrimSpace(key))] {
		return Mask(value)
	}
	return value
}

// Mask renders a secret as a short, non-reversible fingerprint. Short secrets
// are fully hidden so a partial reveal never leaks a usable prefix.
func Mask(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:2] + "…" + s[len(s)-2:] + "(" + itoa(len(s)) + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog.Logger for structured logging
type Logger struct {
	*slog.Logger
}

// Config holds logger configuration
type Config struct {
	Level  string // debug, info, warn, error
	Format string // text, json
}

// ArqutHandler implements slog.Handler with ARQUT format
type ArqutHandler struct {
	opts      slog.HandlerOptions
	attrs     []slog.Attr
	groups    []string
	w         io.Writer
	useColor  bool
	component string
}

// NewArqutHandler creates a new ARQUT-formatted handler
func NewArqutHandler(w io.Writer, opts *slog.HandlerOptions) *ArqutHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &ArqutHandler{
		opts:     *opts,
		w:        w,
		useColor: isTerminal(w),
	}
}

// Enabled reports whether the handler handles records at the given level
func (h *ArqutHandler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

// Handle formats and outputs the log record
// Format: 2025/10/15 21:52:15 ARQUT [INFO] [Component] message key=value
func (h *ArqutHandler) Handle(_ context.Context, r slog.Record) error {
	var buf strings.Builder

	// Timestamp (format: 2006/01/02 15:04:05)
	buf.WriteString(r.Time.Format("2006/01/02 15:04:05"))
	buf.WriteString(" ARQUT-SERVER-CE ")

	// Log level
	levelStr := levelString(r.Level)
	if h.useColor {
		levelStr = colorize(r.Level, levelStr)
	}
	buf.WriteString("[")
	buf.WriteString(levelStr)
	buf.WriteString("]")

	// Component (if present)
	component := h.component
	if component == "" {
		// Check attrs for component
		for _, attr := range h.attrs {
			if attr.Key == "component" {
				component = attr.Value.String()
				break
			}
		}
		// Check record attrs for component
		if component == "" {
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == "component" {
					component = a.Value.String()
					return false
				}
				return true
			})
		}
	}

	if component != "" {
		// Capitalize first letter
		if len(component) > 0 {
			component = strings.ToUpper(component[:1]) + component[1:]
		}
		buf.WriteString(" [")
		buf.WriteString(component)
		buf.WriteString("]")
	}

	// Message
	buf.WriteString(" ")
	buf.WriteString(r.Message)

	// Additional attributes (excluding component)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "component" {
			return true // skip component
		}
		buf.WriteString(" ")
		buf.WriteString(a.Key)
		buf.WriteString("=")
		buf.WriteString(fmt.Sprint(a.Value.Any()))
		return true
	})

	// Persisted attributes (excluding component)
	for _, attr := range h.attrs {
		if attr.Key == "component" {
			continue
		}
		buf.WriteString(" ")
		buf.WriteString(attr.Key)
		buf.WriteString("=")
		buf.WriteString(fmt.Sprint(attr.Value.Any()))
	}

	buf.WriteString("\n")
	_, err := h.w.Write([]byte(buf.String()))
	return err
}

// WithAttrs returns a new handler with the given attributes
func (h *ArqutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)

	// Extract component if present
	component := h.component
	for _, attr := range attrs {
		if attr.Key == "component" {
			component = attr.Value.String()
		} else {
			newAttrs = append(newAttrs, attr)
		}
	}

	return &ArqutHandler{
		opts:      h.opts,
		attrs:     newAttrs,
		groups:    h.groups,
		w:         h.w,
		useColor:  h.useColor,
		component: component,
	}
}

// WithGroup returns a new handler with the given group
func (h *ArqutHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	groups := make([]string, len(h.groups)+1)
	copy(groups, h.groups)
	groups[len(h.groups)] = name
	return &ArqutHandler{
		opts:      h.opts,
		attrs:     h.attrs,
		groups:    groups,
		w:         h.w,
		useColor:  h.useColor,
		component: h.component,
	}
}

// levelString returns the string representation of slog.Level
func levelString(level slog.Level) string {
	switch {
	case level < slog.LevelInfo:
		return "DEBUG"
	case level < slog.LevelWarn:
		return "INFO"
	case level < slog.LevelError:
		return "WARN"
	default:
		return "ERROR"
	}
}

// colorize adds ANSI color codes to the log level
func colorize(level slog.Level, text string) string {
	const (
		colorReset  = "\033[0m"
		colorGray   = "\033[90m"
		colorGreen  = "\033[32m"
		colorYellow = "\033[33m"
		colorRed    = "\033[31m"
	)

	switch {
	case level < slog.LevelInfo:
		return colorGray + text + colorReset
	case level < slog.LevelWarn:
		return colorGreen + text + colorReset
	case level < slog.LevelError:
		return colorYellow + text + colorReset
	default:
		return colorRed + text + colorReset
	}
}

// isTerminal checks if the writer is a terminal
func isTerminal(w io.Writer) bool {
	if w == os.Stdout || w == os.Stderr {
		// Simple heuristic: check if TERM is set
		term := os.Getenv("TERM")
		return term != "" && !strings.Contains(term, "dumb")
	}
	return false
}

// New creates a new logger instance
func New(cfg Config) *Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		// Use custom ARQUT handler for text format
		handler = NewArqutHandler(os.Stdout, opts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

// With returns a new logger with the given attributes
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		Logger: l.Logger.With(args...),
	}
}

// WithGroup returns a new logger with the given group name
func (l *Logger) WithGroup(name string) *Logger {
	return &Logger{
		Logger: l.Logger.WithGroup(name),
	}
}

// Component returns a logger with a component attribute
func (l *Logger) Component(name string) *Logger {
	return l.With("component", name)
}

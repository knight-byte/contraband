package main

import (
	"os"
	"strings"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
)

// style decorates output only as far as the destination supports it: colour
// for interactive terminals, Unicode symbols for UTF-8 locales, plain ASCII
// otherwise, so pipes, logs and limited terminals never see escape codes or
// broken glyphs.
type style struct {
	color   bool
	unicode bool
}

func styleFor(file *os.File) style {
	return style{color: supportsColor(file), unicode: supportsUnicode()}
}

func supportsColor(file *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if term := os.Getenv("TERM"); term == "" || term == "dumb" {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// supportsUnicode follows the locale precedence C libraries use.
func supportsUnicode() bool {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := os.Getenv(name); value != "" {
			value = strings.ToLower(value)
			return strings.Contains(value, "utf-8") || strings.Contains(value, "utf8")
		}
	}
	return false
}

func (out style) paint(codes, text string) string {
	if !out.color || text == "" {
		return text
	}
	return codes + text + ansiReset
}

func (out style) alert(text string) string { return out.paint(ansiBold+ansiRed, text) }
func (out style) warn(text string) string  { return out.paint(ansiBold+ansiYellow, text) }
func (out style) good(text string) string  { return out.paint(ansiGreen, text) }
func (out style) dim(text string) string   { return out.paint(ansiDim, text) }

func (out style) level(level string, text string) string {
	switch level {
	case "alert":
		return out.alert(text)
	case "warn":
		return out.warn(text)
	case "health":
		return out.warn(text)
	}
	return out.good(text)
}

func (out style) arrow() string {
	if out.unicode {
		return "→"
	}
	return "->"
}

func (out style) from() string {
	if out.unicode {
		return " ← "
	}
	return " <- "
}

func (out style) check() string {
	if out.unicode {
		return "✓"
	}
	return "ok"
}

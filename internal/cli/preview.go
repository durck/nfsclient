package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const textPreviewLimit = 256 << 10
const hexPreviewLimit = 256

var errPreviewLimit = errors.New("preview limit reached")

// Collect a bounded preview before emitting anything. Checking only the first
// block is insufficient: a later block may contain terminal control sequences.
type previewBuffer struct {
	bytes.Buffer
	limit int
}

func (b *previewBuffer) Write(p []byte) (int, error) {
	n := min(len(p), b.limit-b.Len())
	b.Buffer.Write(p[:n])
	if n < len(p) {
		return n, errPreviewLimit
	}
	return n, nil
}

func safePreview(data []byte, truncated bool) (string, error) {
	// A bounded preview may stop in the middle of an otherwise valid rune.
	if truncated {
		start := len(data) - 1
		for start >= 0 && len(data)-start < utf8.UTFMax && !utf8.RuneStart(data[start]) {
			start--
		}
		if start >= 0 && !utf8.FullRune(data[start:]) {
			data = data[:start]
		}
	}
	if !utf8.Valid(data) {
		return "", errors.New("non-UTF-8 or binary data")
	}
	for _, r := range string(data) {
		if r != '\n' && r != '\r' && r != '\t' && !unicode.IsPrint(r) {
			return "", fmt.Errorf("non-text/control character U+%04X", r)
		}
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	// Preserve a visible indication without letting a lone CR overwrite a line.
	return strings.ReplaceAll(text, "\r", `\r`), nil
}

func (s *Shell) preview(ctx context.Context, p string, binary bool) error {
	limit := textPreviewLimit
	if binary {
		limit = hexPreviewLimit
	}
	b := &previewBuffer{limit: limit}
	_, err := s.Session.Cat(ctx, p, b)
	truncated := errors.Is(err, errPreviewLimit)
	if err != nil && !truncated {
		return err
	}
	var text string
	if binary {
		text = hex.Dump(b.Bytes())
	} else {
		text, err = safePreview(b.Bytes(), truncated)
		if err != nil {
			return fmt.Errorf("cat: %w; use hex PATH for a byte preview or get PATH to download", err)
		}
	}
	if _, err := io.WriteString(s.Out, text); err != nil {
		return err
	}
	if text != "" && !strings.HasSuffix(text, "\n") {
		if _, err := io.WriteString(s.Out, "\n"); err != nil {
			return err
		}
	}
	if truncated {
		fmt.Fprintf(s.Err, "Preview limited to %s; use get to download the complete file.\n", humanSize(uint64(limit)))
	}
	return nil
}

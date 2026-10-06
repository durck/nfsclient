package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
)

func TestNoArgumentsShowsHelp(t *testing.T) {
	var out, notices bytes.Buffer
	cmd := NewCommand(strings.NewReader(""), &out, &notices)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Usage:") || !strings.Contains(out.String(), "--export") {
		t.Fatal("missing help", out.String())
	}
	if notices.Len() != 0 {
		t.Fatal("no-argument help should not be an error")
	}
}

func TestTerminalCatRejectsBinaryAndControls(t *testing.T) {
	sh, root, out := testShell(t)
	sh.Terminal = true
	for name, data := range map[string][]byte{
		"binary":          {0, 1, 2, 255},
		"charset":         []byte("text\x1b(0changed"),
		"shift":           []byte("text\x0echanged\x0f"),
		"osc":             []byte("\x1b]0;title\x07"),
		"c1":              []byte("text\u009b31m"),
		"late":            append(bytes.Repeat([]byte("a"), 40000), []byte("\x1b[31m")...),
		"incomplete-utf8": {0xe2, 0x82},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if _, err := sh.Execute(context.Background(), "cat "+name); err == nil {
				t.Fatal("unsafe terminal output accepted")
			}
			if out.Len() != 0 {
				t.Fatalf("cat emitted %d bytes before refusing unsafe data", out.Len())
			}
		})
	}
	if _, err := sh.Execute(context.Background(), "ls"); err != nil {
		t.Fatalf("session unusable after rejected cat: %v", err)
	}
}

func TestTerminalPreviewLimitsAndSessionSurvives(t *testing.T) {
	sh, root, out := testShell(t)
	sh.Terminal = true
	data := []byte(strings.Repeat("a", textPreviewLimit-1) + "Ж" + strings.Repeat("z", 40000))
	if err := os.WriteFile(filepath.Join(root, "large.txt"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(context.Background(), "cat large.txt"); err != nil {
		t.Fatal(err)
	}
	if out.String() != strings.Repeat("a", textPreviewLimit-1)+"\n" {
		t.Fatal("incorrect UTF-8 preview boundary")
	}
	if !strings.Contains(sh.Err.(*bytes.Buffer).String(), "Preview limited") {
		t.Fatal("missing truncation notice")
	}
	out.Reset()
	if _, err := sh.Execute(context.Background(), "ls"); err != nil {
		t.Fatalf("session unusable after limited preview: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "text.txt"), []byte("Привет\r\nтаб\t123\rX"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := sh.Execute(context.Background(), "cat text.txt"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Привет\nтаб\t123\\rX\n" {
		t.Fatalf("text preview = %q", out.String())
	}
}

func TestHexPreviewAndRawRedirection(t *testing.T) {
	sh, root, out := testShell(t)
	data := bytes.Repeat([]byte{0, 27, 14, 15, 255, 0xc2, 0x9b}, 100)
	if err := os.WriteFile(filepath.Join(root, "file.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	sh.Terminal = true
	if _, err := sh.Execute(context.Background(), "hex file.bin"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "00000000") || !strings.Contains(out.String(), "000000f0") || strings.Contains(out.String(), "00000100") || bytes.ContainsAny(out.Bytes(), "\x1b\x0e\x0f") {
		t.Fatal("unsafe or unbounded hex preview")
	}
	out.Reset()
	sh.Terminal = false
	if _, err := sh.Execute(context.Background(), "cat file.bin"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("redirection changed binary data")
	}
}

func TestDisplayPermissionsAndColors(t *testing.T) {
	for _, tc := range []struct {
		typ, mode uint32
		want      string
	}{
		{1, 0100777, "-rwxrwxrwx"}, {2, 040755, "drwxr-xr-x"}, {5, 0120777, "lrwxrwxrwx"},
		{1, 04755, "-rwsr-xr-x"}, {1, 02740, "-rwxr-S---"}, {2, 01777, "drwxrwxrwt"}, {2, 01776, "drwxrwxrwT"},
	} {
		if got := permissions(nfs.Attr{Type: tc.typ, Mode: tc.mode}); got != tc.want {
			t.Errorf("mode %o: %s != %s", tc.mode, got, tc.want)
		}
	}
	var plain, colored bytes.Buffer
	entries := []nfs.Entry{
		{Name: "z.txt", Node: nfs.Node{Attr: nfs.Attr{Type: 1, Mode: 0100644, Size: 1 << 30, MTime: time.Unix(0, 0)}}},
		{Name: "каталог", Node: nfs.Node{Attr: nfs.Attr{Type: 2, Mode: 040755, MTime: time.Unix(0, 0)}}},
		{Name: "bad\x1b(0name", Node: nfs.Node{Attr: nfs.Attr{Type: 5, Mode: 0120777, MTime: time.Unix(0, 0)}}},
	}
	sh := &Shell{Out: &plain}
	if err := sh.printEntries(entries); err != nil {
		t.Fatal(err)
	}
	sh.Out = &colored
	sh.Color = true
	if err := sh.printEntries(entries); err != nil {
		t.Fatal(err)
	}
	if strings.Index(plain.String(), "каталог/") > strings.Index(plain.String(), "z.txt") || !strings.Contains(plain.String(), "1.0 GiB") || strings.ContainsAny(plain.String(), "\x1b") {
		t.Fatal("invalid listing", plain.String())
	}
	stripped := colored.String()
	for _, tone := range []string{cyan, blue, green, dim, bold, muted, orange, magenta, lavender, linkTone, faint, warm, "0"} {
		stripped = strings.ReplaceAll(stripped, "\x1b["+tone+"m", "")
	}
	if stripped != plain.String() {
		t.Fatal("color changed table alignment")
	}
}

func TestColorPolicy(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if useColor("auto", true) || useColor("never", true) || !useColor("always", false) {
		t.Fatal("color policy does not honor overrides")
	}
	var out, notices bytes.Buffer
	cmd := NewCommand(strings.NewReader(""), &out, &notices)
	cmd.SetArgs([]string{"--color=always"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatal("forced color missing")
	}
	out.Reset()
	cmd = NewCommand(strings.NewReader(""), &out, &notices)
	cmd.SetArgs([]string{"--color=never"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("color disabled but ANSI emitted")
	}
}

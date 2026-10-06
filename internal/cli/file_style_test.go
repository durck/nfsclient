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
	"nfsclient/internal/session"
)

func TestFileNameHints(t *testing.T) {
	for _, tc := range []struct{ name, tone string }{
		{"README.md", muted}, {"thumbs.db", muted}, {"desktop.ini", muted}, {"image.PNG", muted},
		{".env", magenta}, {".env.production", magenta}, {"id_ed25519", magenta}, {"web.config", magenta}, {"settings.ini.bak", magenta}, {"appsettings.Production.json", magenta}, {"store.pfx", magenta},
		{"backup.tar.gz", lavender}, {"data.sqlite3", lavender}, {".bash_history", lavender}, {".db.domain.full", lavender}, {"report.xlsx", lavender},
		{"index.txt", ""}, {"credentialization.txt", ""}, {"id_ed25519.pub", ""},
	} {
		if got := fileTone(nfs.Entry{Name: tc.name, Node: nfs.Node{Attr: nfs.Attr{Type: 1, Mode: 0644}}}); got != tc.tone {
			t.Errorf("%s: %q != %q", tc.name, got, tc.tone)
		}
	}
	for _, tc := range []struct {
		kind, mode uint32
		tone       string
	}{{2, 0755, warm}, {5, 0777, linkTone}, {1, 0755, green}, {3, 0644, muted}} {
		if got := fileTone(nfs.Entry{Name: "run", Node: nfs.Node{Attr: nfs.Attr{Type: tc.kind, Mode: tc.mode}}}); got != tc.tone {
			t.Errorf("type %d: %q", tc.kind, got)
		}
	}
}

func TestCurrentYearAndLinkStyling(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.Local)
	if dateTone(now, now) != orange || dateTone(now.AddDate(-1, 0, 0), now) != muted || dateTone(now.AddDate(1, 0, 0), now) != muted {
		t.Fatal("incorrect year highlighting")
	}
	var out bytes.Buffer
	sh := &Shell{Out: &out, Color: true}
	entries := []nfs.Entry{{Name: "config", Node: nfs.Node{Attr: nfs.Attr{Type: 5, Mode: 0777, MTime: time.Now()}}}}
	if err := sh.printEntries(entries, map[string]session.LinkInfo{"config": {Target: "/etc/config", State: "missing"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), paint(true, faint, "config@ -> /etc/config [missing]")) || strings.Contains(out.String(), "\x1b["+orange+"m") {
		t.Fatal("missing link was not muted", out.String())
	}
	out.Reset()
	sh.Color = false
	if err := sh.printLegend(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "Filename hints only") {
		t.Fatal("plain legend is not useful")
	}
}

func TestListingShowsLinkTargetsAndRestoresIdentity(t *testing.T) {
	sh, root, out := testShell(t)
	if err := os.Mkdir(filepath.Join(root, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real.txt"), []byte("text"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ name, target string }{{"ok", "../real.txt"}, {"missing", "../absent"}, {"cycle", "cycle"}, {"absolute", "/real.txt"}} {
		if err := os.Symlink(link.target, filepath.Join(root, "dir", link.name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	sh.Session.AutoUID = true
	_, beforeErr := sh.Session.LS(context.Background(), "dir")
	if beforeErr != nil {
		t.Fatal(beforeErr)
	}
	identity := sh.Session.Client.Auth
	entries, links, err := sh.Session.List(context.Background(), "dir", 32)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"ok": "reachable", "missing": "missing", "cycle": "loop", "absolute": "reachable"} {
		if links[name].State != want {
			t.Errorf("%s: %+v", name, links[name])
		}
	}
	if sh.Session.Client.Auth.UID != identity.UID || sh.Session.Client.Auth.GID != identity.GID || sh.Session.CWD != "/" {
		t.Fatal("link inspection changed session state")
	}
	if err := sh.printEntries(entries, links); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ok@ -> ../real.txt") || !strings.Contains(out.String(), "[missing]") || !strings.Contains(out.String(), "[link loop]") {
		t.Fatal(out.String())
	}
	one, _, err := sh.Session.List(context.Background(), "dir/ok", 32)
	if err != nil || len(one) != 1 || one[0].Attr.Type != 5 {
		t.Fatalf("ls LINK followed final link: %+v %v", one, err)
	}
	_, links, err = sh.Session.List(context.Background(), "dir", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range links {
		if info.State != "unchecked" {
			t.Fatal("link limit ignored")
		}
	}
}

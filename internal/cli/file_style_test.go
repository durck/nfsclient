package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestFamiliarNamesAndCurrentYear(t *testing.T) {
	now := time.Now()
	var out bytes.Buffer
	sh := &Shell{Out: &out, Color: true}
	for _, tc := range []struct {
		name string
		kind uint32
		want string
	}{
		{"ProgramData", 2, muted}, {"Program Data", 2, muted},
		{"PROGRAM FILES (X86)", 2, muted}, {"Windows", 2, muted},
		{"System Volume Information", 2, muted}, {"$Recycle.Bin", 2, muted},
		{"AppData", 2, muted}, {"lost+found", 2, muted},
		{"desktop.ini", 1, muted}, {"Thumbs.db", 1, muted}, {"pagefile.sys", 1, muted},
		{"ProgramData-copy", 2, warm}, {"Windows-project", 2, warm},
		{"data", 2, warm}, {"backup", 2, lavender}, {"config", 2, warm},
		{"ProgramData", 1, ""}, {"ProgramData", 5, linkTone},
		{"desktop.ini", 2, warm}, {"secrets.yaml", 1, magenta},
		{"service.yaml", 1, blue}, {".gitconfig", 1, blue},
	} {
		e := nfs.Entry{Name: tc.name, Node: nfs.Node{Attr: nfs.Attr{Type: tc.kind, Mode: 0644, MTime: now}}}
		if got := fileTone(e); got != tc.want {
			t.Errorf("%s type %d: got %q, want %q", tc.name, tc.kind, got, tc.want)
		}
		out.Reset()
		if err := sh.printEntries([]nfs.Entry{e}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), paint(true, orange, now.Local().Format("2006-01-02 15:04"))) {
			t.Errorf("%s lost its current-year highlight", tc.name)
		}
	}
}

func TestOwnerLabelLocalDomains(t *testing.T) {
	for _, tc := range []struct{ owner, group, want string }{
		{"root@localhost", "staff@localhost", "root:staff"},
		{"root@localdomain", "staff@LOCALHOST", "root:staff"},
		{"Alice@LOCALDOMAIN", "Users@corp.example", "Alice:Users@corp.example"},
		{"Alice@corp.example", "staff@localdomain", "Alice@corp.example:staff"},
		{"root@localhost.example", "staff@localdomain.example", "root@localhost.example:staff@localdomain.example"},
		{"root", "staff", "root:staff"},
		{"@localhost", "staff", "@localhost:staff"},
		{"user@realm@localhost", "staff", "user@realm@localhost:staff"},
		{"two words@localhost", "line\n@localdomain", `"two words":"line\n"`},
		{"", "staff@localhost", `"":staff`},
		{"", "", "1000:1001"},
	} {
		a := nfs.Attr{Owner: tc.owner, Group: tc.group, UID: 1000, GID: 1001}
		if got := ownerLabel(a); got != tc.want {
			t.Errorf("%q:%q: got %q, want %q", tc.owner, tc.group, got, tc.want)
		}
	}
}

func TestDateToneLocalCalendarBoundary(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.Local)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.Local)
	end := start.AddDate(1, 0, 0)
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, muted}, {start.Add(-time.Second), muted},
		{start.UTC(), orange}, {end.Add(-time.Second).UTC(), orange}, {end, muted},
	} {
		if got := dateTone(tc.at, now); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.at, got, tc.want)
		}
	}
}

func TestListingStatusSpansKeepLayout(t *testing.T) {
	entries := []nfs.Entry{}
	links := map[string]session.LinkInfo{}
	for _, state := range []string{"reachable", "missing", "denied", "loop", "unavailable", "unchecked"} {
		name := "链接-" + state
		entries = append(entries, nfs.Entry{Name: name, Node: nfs.Node{Attr: nfs.Attr{Type: 5, Mode: 0777, MTime: time.Now()}}})
		links[name] = session.LinkInfo{State: state, Target: "target [missing]"}
	}
	var plain, colored bytes.Buffer
	for _, tc := range []struct {
		out   *bytes.Buffer
		color bool
	}{{&plain, false}, {&colored, true}} {
		sh := &Shell{Out: tc.out, Color: tc.color}
		if err := sh.printEntries(entries, links); err != nil {
			t.Fatal(err)
		}
	}
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	if strings.Contains(plain.String(), "\x1b") || ansi.ReplaceAllString(colored.String(), "") != plain.String() {
		t.Fatal("status color changed table contents or alignment")
	}
	for _, note := range []cell{{" [missing]", red}, {" [access denied]", yellow}, {" [link loop]", red}, {" [unverified]", yellow}, {" [unchecked]", muted}} {
		if !strings.Contains(colored.String(), paint(true, note.tone, note.text)) {
			t.Errorf("missing status span: %+v", note)
		}
	}
}

func TestLocalListingFamiliarDirectoryDate(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "ProgramData")
	if err := os.Mkdir(child, 0755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(child, now, now); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sh := &Shell{Out: &out, Color: true, LocalDir: dir}
	if err := sh.listLocal("."); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), paint(true, muted, "ProgramData/")) || !strings.Contains(out.String(), paint(true, orange, now.Local().Format("2006-01-02 15:04"))) {
		t.Fatal("local listing must combine a gray familiar name with a current-year date", out.String())
	}
}

func TestFileNameHints(t *testing.T) {
	for _, tc := range []struct{ name, tone string }{
		{"README.md", muted}, {"thumbs.db", muted}, {"desktop.ini", muted}, {"image.PNG", muted},
		{".env", magenta}, {".env.production", magenta}, {"id_ed25519", magenta}, {"web.config", blue}, {"settings.ini.bak", blue}, {"appsettings.Production.json", blue}, {"store.pfx", magenta},
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
	if !strings.Contains(out.String(), paint(true, linkTone, "config@ -> /etc/config")+paint(true, red, " [missing]")) || !strings.Contains(out.String(), "\x1b["+orange+"m") {
		t.Fatal("link status must not hide the link identity or current-year date", out.String())
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
		// On Windows, go-nfs/osfs may return backslash targets; skip if not portable.
		if got, err := os.Readlink(filepath.Join(root, "dir", link.name)); err != nil || strings.ContainsAny(got, "\\") {
			t.Skipf("symlink target %q reads back as %q (not portable): %v", link.target, got, err)
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
	wantState := map[string]string{"ok": "reachable", "missing": "missing", "cycle": "loop", "absolute": "reachable"}
	if runtime.GOOS == "windows" {
		// go-nfs/osfs on Windows resolves absolute NFS symlinks differently;
		// the test NFS server can't stat /real.txt within the export root.
		delete(wantState, "absolute")
	}
	for name, want := range wantState {
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

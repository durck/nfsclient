package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestCorporateAndCloudFileHints(t *testing.T) {
	for _, tc := range []struct{ name, parent, tone string }{
		{"NTDS.dit", "/backup", magenta}, {"secrets.tdb", "/samba/private", magenta},
		{"sssd.conf", "/etc/sssd", magenta}, {"cwallet.sso", "/oracle/wallet", magenta},
		{"hudson.util.Secret", "/jenkins/secrets", magenta}, {"WinSCP.ini", "/user", magenta},
		{"tnsnames.ora", "/oracle", blue}, {"applicationHost.config", "/inetsrv/config", blue},
		{"running-config", "/network", blue}, {"deploy.ps1", "/scripts", blue},
		{"Groups.xml", "/SYSVOL/domain/Policies/id/Machine/Preferences/Groups", magenta},
		{"Services.xml", "/Preferences/Services", magenta},
		{"Groups.xml", "/reports", lavender}, {"Groups.xml", "/NotPreferences/Groups", lavender},
		{"config.json", "/home/user/.docker", magenta}, {"config.json", "/home/user/not.docker", lavender},
		{"config.json", `/.docker\nested`, lavender},
		{"config", "/home/user/.kube", magenta}, {"config", "/home/user/.git", blue},
		{"config", "/home/user/project", ""}, {"config", "/home/user/.aws", blue},
		{"application_default_credentials.json", "/gcloud", magenta},
		{"kubeconfig", "/profiles", magenta}, {"admin.conf", "/etc/kubernetes", magenta},
		{"admin.conf", "/reports", blue}, {"пароли.xlsx", "/share", magenta},
		{"msal_token_cache.bin", "/user/.azure", magenta},
		{"terraform.tfstate.backup", "/infra", magenta}, {"prod.tfvars", "/infra", blue},
		{"settings.xml", "/user/.m2", magenta}, {"settings.xml", "/reports", lavender},
		{"ConsoleHost_history.txt", "/PSReadLine", lavender}, {"fish_history", "/fish", lavender},
		{".psql_history", "/home/user", lavender}, {"NTUSER.DAT", "/Users/user", lavender},
		{"mail.pst", "/archive", lavender}, {"backup.vbk", "/backups", lavender},
		{"server.qcow2", "/images", lavender}, {"database.1CD", "/1c", lavender},
		{"dump.dmp", "/dump", lavender}, {"traffic.pcapng", "/capture", lavender},
		{"id_rsa.bak.old", "/", magenta}, {"id_rsa.old.bak.orig.save~", "/", magenta},
		{"credentials.xml.tar.gz", "/", magenta}, {"config.json.old.bak", "/.docker", magenta},
		{".env.example", "/", blue}, {".env.sample.bak.old", "/", blue},
		{"id_rsa.template.zip", "/", blue}, {"secretary.txt", "/", ""},
		{"id_rsa.pub", "/.ssh", ""}, {"public.crt", "/", ""},
		{"pagefile.sys", "/", muted}, {"desktop.ini", "/.kube", muted},
	} {
		t.Run(tc.parent+"/"+tc.name, func(t *testing.T) {
			e := nfs.Entry{Name: tc.name, Node: nfs.Node{Attr: nfs.Attr{Type: 1}}}
			h := classifyFile(e, tc.parent)
			if h.tone != tc.tone || h.reason == "" {
				t.Fatalf("got %+v, want tone %q", h, tc.tone)
			}
		})
	}
}

func TestInterestingDirectoryHints(t *testing.T) {
	for _, tc := range []struct{ name, parent, tone string }{
		{".ssh", "/user", magenta}, {"SYSVOL", "/", blue},
		{"backups", "/", lavender}, {".git", "/project", blue},
		{"Credentials", "/user/AppData/Local/Microsoft", magenta},
		{"Credentials", "/reports", warm}, {"AppData", "/user", muted},
		{"ProgramData", "/", muted}, {".ssh-copy", "/user", warm},
	} {
		e := nfs.Entry{Name: tc.name, Node: nfs.Node{Attr: nfs.Attr{Type: 2}}}
		if got := fileTone(e, tc.parent); got != tc.tone {
			t.Errorf("%s/%s: got %q, want %q", tc.parent, tc.name, got, tc.tone)
		}
	}
	// Context hints must not turn symlinks into apparent credential files.
	e := nfs.Entry{Name: "config.json", Node: nfs.Node{Attr: nfs.Attr{Type: 5}}}
	if got := fileTone(e, "/.docker"); got != linkTone {
		t.Fatal(got)
	}
}

func TestContextualHintsThroughRemoteAndLocalListings(t *testing.T) {
	sh, root, out := testShell(t)
	for _, dir := range []string{".docker", "ordinary"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "config.json"), []byte("fixture only"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	sh.Color = true
	for _, command := range []string{"ls .docker", "ls .docker/config.json", "ls --offline .docker"} {
		out.Reset()
		if _, err := sh.Execute(context.Background(), command); err != nil {
			t.Fatal(command, err)
		}
		if !strings.Contains(out.String(), paint(true, magenta, "config.json")) {
			t.Fatal(command, out.String())
		}
	}
	if _, err := sh.Execute(context.Background(), "cd .docker"); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"ls", "ls ../ordinary"} {
		out.Reset()
		if _, err := sh.Execute(context.Background(), command); err != nil {
			t.Fatal(err)
		}
		tone := magenta
		if command != "ls" {
			tone = lavender
		}
		if !strings.Contains(out.String(), paint(true, tone, "config.json")) {
			t.Fatal(command, out.String())
		}
	}
	sh.LocalDir = root
	for _, p := range []string{".docker", filepath.Join(".docker", "config.json")} {
		out.Reset()
		if err := sh.listLocal(p); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), paint(true, magenta, "config.json")) {
			t.Fatal(out.String())
		}
	}
	sh.Session.AutoUID, sh.Session.AutoUIDScan = true, true
	before := sh.Session.Client.Auth
	out.Reset()
	if _, err := sh.Execute(context.Background(), "legend config.json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), ".docker/config.json") || !strings.Contains(out.String(), "contents are not inspected") {
		t.Fatal(out.String())
	}
	if !reflect.DeepEqual(before, sh.Session.Client.Auth) || !sh.Session.AutoUID || !sh.Session.AutoUIDScan {
		t.Fatal("legend changed identity policy")
	}
	for _, args := range [][]string{{"a", "b"}, {"--bad"}, {"--"}} {
		if err := (&Shell{}).explainColors(context.Background(), args); err == nil {
			t.Fatal("invalid arguments accepted", args)
		}
	}
	if completionMetadata("legend").args[0].kind != completeRemote {
		t.Fatal("legend lacks remote completion")
	}
	t.Run("resolved directory alias", func(t *testing.T) {
		if err := os.Symlink(".docker", filepath.Join(root, "alias")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		out.Reset()
		if _, err := sh.Execute(context.Background(), "ls /alias/"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), paint(true, magenta, "config.json")) {
			t.Fatal("lost resolved directory context", out.String())
		}
	})
}

func TestContextHintExportAndEscapedRoot(t *testing.T) {
	var out bytes.Buffer
	sh := &Shell{Out: &out, Color: true, Session: &session.Session{Export: "/profiles/.docker", CWD: "/"}}
	e := []nfs.Entry{{Name: "config.json", Node: nfs.Node{Attr: nfs.Attr{Type: 1}}}}
	for _, escaped := range []bool{false, true} {
		out.Reset()
		sh.Session.Escaped = escaped
		if err := sh.printEntriesAt(e, "/"); err != nil {
			t.Fatal(err)
		}
		tone := magenta
		if escaped {
			tone = lavender
		}
		if !strings.Contains(out.String(), paint(true, tone, "config.json")) {
			t.Fatal(out.String())
		}
	}
}

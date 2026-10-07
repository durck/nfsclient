package cli

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func completionResults(c *completer, input string) []string {
	line := []rune(input)
	matches, _ := c.Do(line, len(line))
	var result []string
	for _, match := range matches {
		result = append(result, string(match))
	}
	return result
}

func TestCompletionHelpFlagsAndEnumsWithoutSession(t *testing.T) {
	c := &completer{}
	for _, tc := range []struct{ input, suffix string }{
		{"qu", "it "}, {"help getp", "nfs "}, {"help tr", "ansfer "},
		{"reget --ret", "ries "}, {"getpnfs remote local --lay", "out "},
		{"getpnfs remote local --layout fl", "ex "},
		{"putrangepnfs local remote 0 --parallel ", "8 "},
		{"lock --wait 2s file r", "ead "},
		{"lock --wait-native 2s file write 0 e", "of "},
		{"auto-uid-scan of", "f "}, {"seek file 0 h", "ole "},
		{"setxattr file key cr", "eate "}, {"getacl file out da", "cl "},
		{"root v", "erify "}, {"advise file 0 1 normal,seq", "uential "},
		{"gettree --merge=f", "alse "}, {"access --json=t", "rue "},
		{"exports --rec", "ursive "},
		{"exports --paths-", "file "},
		{"ln -", "s "}, {"handle file --j", "son "}, {"mounts --j", "son "},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got := completionResults(c, tc.input)
			if !slices.Contains(got, tc.suffix) {
				t.Fatalf("%q missing from %q", tc.suffix, got)
			}
		})
	}
	for _, input := range []string{
		"help cat extra", "unknown ", "uid r", "get file --h", "root info --h",
		"getpnfs --lay", "getpnfs remote --lay", "putrangepnfs local remote --lay",
		"getpnfs remote local --layout=fl", "getpnfs remote local --read-failover=t",
		"reget file --ret", "lock file read --wa", "reconnect --discard-locks=t",
		"get --help=f", "gettree --help=f", "stat --offline=t", "exports --depth ",
		"copyfrom --source-sp", "writeadb --num", "get -- file",
		"reget --retries 2 --h", "reget --retries 2 --ret", "reget --retries 2 --fail",
		"reget --failover a,b,c --ref", "lock --wait 1s --wait", "reconnect --discard-locks --reclaim",
		"migrate --arm-failover --status", "getpnfs remote local --layout file --layout",
		"ln file -s", "ln -s -s", "ln -s literal-target another -s", "handle file extra --j",
	} {
		if got := completionResults(c, input); len(got) != 0 {
			t.Errorf("invalid or non-enumerated argument %q suggested %q", input, got)
		}
	}
	if got := completionResults(c, "reget --failover a,b,c --fail"); !reflect.DeepEqual(got, []string{"over "}) {
		t.Fatalf("repeatable recovery approval missing: %q", got)
	}
}

func TestCompletionLocalTransferRolesAndOptions(t *testing.T) {
	c := &completer{shell: &Shell{LocalDir: t.TempDir()}}
	if err := os.WriteFile(filepath.Join(c.shell.LocalDir, "local marker.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		"put lo", "putrange lo", "reput lo", "replace lo", "putpnfs lo", "putrangepnfs lo",
		"get remote lo", "getplus remote lo", "getrange remote lo", "getpnfs remote lo",
		"reget --retries 3 remote lo", "reget --referral s=a,b,c remote lo",
		"reget --failover a,b,c --failover d,e,f remote lo", "reget --reclaim-locks remote lo",
		"gettree --links --merge=false remote lo", "puttree --links lo", "puttree -- lo",
		"getacl remote lo", "setacl remote lo", "getnamedattr remote name lo",
		"lock-save lo", "offload-reconcile lo", "lls lo",
		"getpnfs remote local --block-volume lo", "putpnfs local remote --block-journal lo",
		"getpnfs remote local --block-security iscsi://server/target=lo",
		"exports --paths-file lo", "exports --paths-file=lo",
	} {
		if got := completionResults(c, input); !slices.Contains(got, `cal\ marker.txt `) {
			t.Errorf("local path %q => %q", input, got)
		}
	}
	for _, input := range []string{"put remote lo", "putrange file remote lo", "setxattr remote key lo", "lcd lo", "getnamedattr remote lo", "getpnfs remote local --ds-spn lo"} {
		if got := completionResults(c, input); len(got) != 0 {
			t.Errorf("nonlocal or directory-only argument %q => %q", input, got)
		}
	}
}

func TestCompletionQuotedUnicodeRoundTrip(t *testing.T) {
	c := &completer{shell: &Shell{LocalDir: t.TempDir()}}
	name := "документ с пробелом's.txt"
	if err := os.WriteFile(filepath.Join(c.shell.LocalDir, name), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{`put до`, `put "до`, `put 'до`, `put "документ с "`, `put документ\ с\ `} {
		line := []rune(input)
		got, length := c.Do(line, len(line))
		if len(got) != 1 {
			t.Fatalf("%q => %q", input, got)
		}
		wantLength := len(line) - len([]rune("put "))
		if length != wantLength {
			t.Errorf("readline replacement length %d, want raw rune length %d", length, wantLength)
		}
		args, err := SplitLine(input + string(got[0]))
		if err != nil || !reflect.DeepEqual(args, []string{"put", name}) {
			t.Fatalf("round trip %q + %q = %q, %v", input, string(got[0]), args, err)
		}
	}
	line := []rune(`put "документ с пробелом's.txt"`)
	if got, _ := c.Do(line, len([]rune(`put "до`))); len(got) != 0 {
		t.Fatalf("mid-token completion would duplicate the existing filename: %q", got)
	}
	for _, pos := range []int{-1, len(line) + 1} {
		if got, _ := c.Do(line, pos); len(got) != 0 {
			t.Fatal("invalid cursor accepted")
		}
	}
}

func TestCompletionEscapingMatchesSplitLine(t *testing.T) {
	for _, name := range []string{"hello world", "apostrophe's", `quote"name`, `C:\dir with spaces\file`, "документ", "nonbreaking\u00a0space", `slash\"quote`, `two\\slashes`} {
		for _, quote := range []rune{0, '\'', '"'} {
			prefix := "put "
			if quote != 0 {
				prefix += string(quote)
			}
			line := prefix + completionSuffix(name, quote, false)
			got, err := SplitLine(line)
			if err != nil || !reflect.DeepEqual(got, []string{"put", name}) {
				t.Errorf("round trip %q: %q, %v", line, got, err)
			}
		}
	}
}

func TestCompletionRemoteRolesAndDirectories(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "remote marker"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "remote directory"), 0700); err != nil {
		t.Fatal(err)
	}
	c := &completer{shell: sh}
	for _, input := range []string{
		"get re", "getplus re", "getrange re", "getpnfs re", "reget --retries 1 re", "gettree --merge=true re",
		"put local re", "putrange local re", "putpnfs local re", "putrangepnfs local re", "reput local re", "replace local re", "puttree local re",
		"mv re", "mv source re", "copyrange re", "copyrange source re", "clonerange source re", "copyasync source re",
		"copyfrom server export source re", "offload-reconcile local operation re", "chmod 600 re",
		"namedattrs re", "getnamedattr re", "setacl re", "getacl re", "setlabel re", "uid-scan re",
		"rm re", "rmdir re", "writeadb re", "ls --offline re", "stat -- re", "access --json=true re",
		"ln re", "ln source re", "ln -s ../missing re", "ln -- re", "readlink re",
		"chown 123:456 re", "chgrp group@example.test re", "handle --json re", "handle -- re",
	} {
		if got := completionResults(c, input); !slices.Contains(got, `mote\ marker `) {
			t.Errorf("remote path %q => %q", input, got)
		}
	}
	if got := completionResults(c, "cd re"); !reflect.DeepEqual(got, []string{`mote\ directory/`}) {
		t.Fatalf("cd included files or lost directories: %q", got)
	}
	if got := completionResults(c, "copyfrom server export re"); len(got) != 0 {
		t.Fatalf("source on another server was completed from current export: %q", got)
	}
	for _, input := range []string{"ln -s re", "ln -s -- re", "chown re", "chgrp re"} {
		if got := completionResults(c, input); len(got) != 0 {
			t.Errorf("literal target or identity %q completed as a path: %q", input, got)
		}
	}
}

func TestCompletionPinsWireIdentityAndSessionState(t *testing.T) {
	// This peer rejects every RPC whose AUTH_SYS UID/GID/groups differ
	// from the selected identity, including transient changes during Tab.
	sh, _, _ := legacyACLShell(t, 3, 1)
	sh.Session.AutoUID, sh.Session.AutoUIDScan, sh.Session.AutoEscape = true, true, true
	before, auth := *sh.Session, sh.Session.Client.Auth
	c := &completer{shell: sh}
	for _, input := range []string{"cat t", "ls t", "getpnfs t", "getacl t"} {
		completionResults(c, input)
	}
	if !reflect.DeepEqual(before, *sh.Session) || !reflect.DeepEqual(auth, sh.Session.Client.Auth) {
		t.Fatal("Tab changed authentication or root/session state")
	}
	inspection := c.inspection()
	if inspection.AutoUID || inspection.AutoUIDScan || inspection.AutoEscape || inspection == sh.Session {
		t.Fatal("completion inspection is not isolated and pinned")
	}
	ctx, cancel := c.timeout()
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 2*time.Second {
		t.Fatal("completion is not bounded to two seconds")
	}
	parent, stop := context.WithCancel(context.Background())
	stop()
	c.ctx = parent
	ctx, cancel = c.timeout()
	defer cancel()
	if ctx.Err() == nil {
		t.Fatal("completion ignored canceled shell context")
	}
}

func TestCompletionAfterTerminatorTreatsDashAsPath(t *testing.T) {
	c := &completer{shell: &Shell{LocalDir: t.TempDir()}}
	if err := os.WriteFile(filepath.Join(c.shell.LocalDir, "--merge"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := completionResults(c, "puttree -- --m")
	if !reflect.DeepEqual(got, []string{"erge "}) {
		t.Fatalf("flag-looking literal path: %q", got)
	}
	for _, candidate := range completionResults(c, "puttree -- ") {
		if strings.Contains(candidate, "help") {
			t.Fatal("suggested options after --")
		}
	}
}

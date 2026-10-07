package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestOffloadStateCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-state")
	for _, args := range [][]string{
		{"offload-state", "ack", path, "id"},
		{"offload-state", "ack", path, "id", "--server-quiesced"},
		{"offload-state", "ack", path, "id", "--destination-verified"},
	} {
		var out bytes.Buffer
		cmd := NewCommand(strings.NewReader(""), &out, &out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "after external verification") {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"offload-state", "inspect", path}, {"offload-state", "ack", path, "id", "--server-quiesced", "--destination-verified"}} {
		var out bytes.Buffer
		cmd := NewCommand(strings.NewReader(""), &out, &out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || strings.Contains(err.Error(), "NFS") {
			t.Fatal("offline command attempted connection", err)
		}
	}
	var out bytes.Buffer
	cmd := NewCommand(strings.NewReader(""), &out, &out)
	cmd.SetArgs([]string{"127.0.0.1", "--offload-journal", path})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--auto-uid=false and --auto-escape=false") {
		t.Fatal(err)
	}
}

func TestOffloadStateHelp(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"--help"}, []string{"offload-state", "recovery", "block-state"}},
		{[]string{"--help-all"}, []string{"--offload-journal", "--recover-offload"}},
		{[]string{"offload-state", "--help"}, []string{"nfsclient offload-state", "inspect", "ack"}},
		{[]string{"offload-state", "ack", "--help"}, []string{"ABSOLUTE_FILE OPERATION_ID", "--server-quiesced", "--destination-verified"}},
		{[]string{"block-state", "--help"}, []string{"nfsclient block-state", "inspect", "ack"}},
		{[]string{"block-state", "ack", "--help"}, []string{"ABSOLUTE_FILE OPERATION_ID", "--storage-quiesced", "--destination-verified"}},
	} {
		var out bytes.Buffer
		cmd := NewCommand(strings.NewReader(""), &out, &out)
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		for _, want := range tc.want {
			if !strings.Contains(out.String(), want) {
				t.Errorf("help for %v is missing %q: %s", tc.args, want, out.String())
			}
		}
	}
}

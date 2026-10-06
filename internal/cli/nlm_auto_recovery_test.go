package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestNLMAutoRecoveryCLIRequiresFixedIdentity(t *testing.T) {
	for _, extra := range [][]string{nil, {"--auto-uid=false"}, {"--auto-escape=false"}} {
		var out bytes.Buffer
		cmd := NewCommand(strings.NewReader(""), &out, &out)
		cmd.SetArgs(append([]string{"127.0.0.1", "--nlm-auto-recover"}, extra...))
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--auto-uid=false and --auto-escape=false") {
			t.Fatal("automatic cleanup reached connection with a variable identity", err)
		}
	}
}

func TestNLMAutoNotificationCLIProfile(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--nlm-auto-notify", "--auto-uid=false", "--auto-escape=false"}, "requires --nlm-auto-recover"},
		{[]string{"--nlm-auto-notify", "--nlm-auto-recover"}, "--auto-uid=false and --auto-escape=false"},
		{[]string{"--nlm-auto-notify", "--nlm-auto-recover", "--auto-uid=false", "--auto-escape=false", "--nfs-version", "4.2"}, "explicit NFSv2/v3"},
	} {
		var out bytes.Buffer
		cmd := NewCommand(strings.NewReader(""), &out, &out)
		cmd.SetArgs(append([]string{"127.0.0.1"}, tc.args...))
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatal("invalid automatic notification profile reached connection", err, out.String())
		}
	}
}

func TestNLMAutoNotificationReleaseCLI(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"needs-cleanup", []string{"--nlm-auto-notify", "--auto-uid=false", "--auto-escape=false"}, "requires --nlm-auto-recover"},
		{"fixed-identity", []string{"--nlm-auto-notify", "--nlm-auto-recover"}, "--auto-uid=false and --auto-escape=false"},
		{"legacy-only", []string{"--nlm-auto-notify", "--nlm-auto-recover", "--auto-uid=false", "--auto-escape=false", "--nfs-version", "4.2"}, "explicit NFSv2/v3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runKerberosCLI(t, append([]string{"127.0.0.1", "--no-banner"}, tc.args...))
			diagnostic := out
			if err != nil {
				diagnostic += err.Error()
			}
			if err == nil || !strings.Contains(diagnostic, tc.want) {
				t.Fatal("release CLI accepted unsafe notification profile", err, out)
			}
		})
	}
}

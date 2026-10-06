package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSSPICommandSelection(t *testing.T) {
	var out bytes.Buffer
	command := NewCommand(strings.NewReader(""), &out, &out)
	if command.Flags().Lookup("krb5-provider") == nil {
		t.Fatal("explicit provider option missing")
	}
	command.SetArgs([]string{"server.invalid", "--sec", "krb5p", "--krb5-provider", "sspi", "--principal", "user@EXAMPLE.TEST", "--spn", "nfs/server.test", "--ccache", "MSLSA:CURRENT", "--auto-uid=false", "--auto-escape=false", "--no-banner", "-c", "pwd"})
	err := command.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "sspi") {
		t.Fatal("unsupported provider mix reached connection", err, out.String())
	}
}

package cli

import (
	"strings"
	"testing"
)

func TestCopyFromSecurityOptions(t *testing.T) {
	for _, suffix := range []string{"", " --source-spn nfs/source.test --copy-user alice@test", " 192.0.2.3:2049 --copy-user alice@test --source-spn nfs/source.test --source-tls-name source.test"} {
		o, err := parseCopyFromOptions("192.0.2.1:2049", "192.0.2.2:2049", strings.Fields(suffix))
		if err != nil || len(o.SourceServers) != 1 {
			t.Fatal(o, err)
		}
		if suffix != "" && (o.SourceSPN != "nfs/source.test" || o.CopyUser != "alice@test") {
			t.Fatal("lost security options", o)
		}
	}
	for _, suffix := range []string{"--source-spn", "--source-spn nfs/a", "--copy-user alice@test", "--source-spn nfs/a --copy-user alice", "--source-tls-name a", "--unknown value", "--source-spn nfs/a --source-spn nfs/b --copy-user alice@test", "--source-spn nfs/a --copy-user alice@test --source-tls-name a --source-tls-name b"} {
		if _, err := parseCopyFromOptions("192.0.2.1:2049", "192.0.2.2:2049", strings.Fields(suffix)); err == nil {
			t.Fatal("invalid COPY options accepted", suffix)
		}
	}
}

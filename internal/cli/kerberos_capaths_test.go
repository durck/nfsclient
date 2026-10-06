package cli

import (
	"os"
	"strings"
	"testing"
)

func TestKerberosCAPathsDeniedCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_MULTIHOP") != "1" || os.Getenv("NFS_VIEWER_KRB5_CAPATHS") != "1" {
		t.Skip("requires explicit three-realm policy fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.2"} {
			for _, credential := range []string{"keytab", "ccache"} {
				for _, scenario := range []string{"direct", "missing", "invalid"} {
					t.Run(network+"/"+version+"/"+credential+"/"+scenario, func(t *testing.T) {
						t.Parallel()
						args := crossRealmArgs(t, network, version, "krb5p", credential, "NFS.TEST")
						var path string
						for i, v := range args {
							if v == "--krb5-config" {
								path = args[i+1]
							}
						}
						data, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						replacement := "."
						if scenario == "invalid" {
							replacement = "CLIENT.TEST"
						}
						text := strings.ReplaceAll(string(data), "NFS.TEST = MID.TEST", "NFS.TEST = "+replacement)
						if scenario == "missing" {
							text = strings.ReplaceAll(string(data), "NFS.TEST = MID.TEST", "OTHER.TEST = .")
						}
						if err = os.WriteFile(path, []byte(text), 0600); err != nil {
							t.Fatal(err)
						}
						out, err := runKerberosCLI(t, append(args, "-c", "pwd"))
						if err == nil || !strings.Contains(out+err.Error(), "capaths") || strings.Contains(out, "AUTH_SYS") {
							t.Fatalf("disallowed route accepted or silently downgraded: %v %s", err, out)
						}
					})
				}
			}
		}
	}
}

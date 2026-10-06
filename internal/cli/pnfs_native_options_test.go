package cli

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"nfs-viewer/internal/nfs"
)

// Additional disposable DSs must be explicitly selected by the fixture caller.
// Sorting keeps the API and shell mappings identical without trusting layout
// addresses as permission to contact another server.
func pnfsNativeOptions(t *testing.T, layout, advertised, target string) (nfs.PNFSOptions, string) {
	t.Helper()
	o := nfs.PNFSOptions{Layout: layout, DataServers: map[string]string{advertised: target}}
	for _, entry := range strings.Fields(os.Getenv("NFS_VIEWER_PNFS_EXTRA_DS")) {
		from, to, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatal("extra fixture DS must be ADVERTISED=TARGET")
		}
		for _, value := range []string{from, to} {
			addr, err := netip.ParseAddrPort(value)
			if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() {
				t.Fatal("invalid extra fixture DS endpoint")
			}
		}
		if _, exists := o.DataServers[from]; exists {
			t.Fatal("duplicate fixture DS")
		}
		o.DataServers[from] = to
	}
	if len(o.DataServers) > 64 {
		t.Fatal("too many fixture DSs")
	}
	var args []string
	for from, to := range o.DataServers {
		args = append(args, from+"="+to)
	}
	slices.Sort(args)
	if layout == "flex" && len(o.DataServers) > 1 {
		o.Parallelism = 2
		args = append(args, "--parallel", "2")
	}
	return o, strings.Join(args, " ")
}

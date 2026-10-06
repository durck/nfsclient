package scan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestExpandTarget(t *testing.T) {
	tests := []struct {
		input   string
		want    []string
		wantErr bool
	}{
		{"192.168.1.1", []string{"192.168.1.1"}, false},
		{"10.0.0.1-10.0.0.3", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, false},
		{"10.0.0.1-3", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, false},
		{"192.168.1.0/30", []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}, false},
		// end before start
		{"10.0.0.5-3", nil, true},
		// valid hostname
		{"myserver", []string{"myserver"}, false},
		// invalid chars
		{"not an ip!", nil, true},
	}

	for _, tc := range tests {
		got, err := expandTarget(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("expandTarget(%q): expected error, got %v", tc.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("expandTarget(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("expandTarget(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseTargets_dedup(t *testing.T) {
	hosts, err := ParseTargets([]string{"10.0.0.1", "10.0.0.1-2", "10.0.0.0/30"}, "")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, h := range hosts {
		seen[h]++
	}
	for ip, count := range seen {
		if count > 1 {
			t.Errorf("duplicate IP %s (count=%d)", ip, count)
		}
	}
}

func TestParseTargets_file(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "hosts.txt")
	content := "# comment\n10.0.0.1\n10.0.0.2\n\n# another comment\n10.0.0.3\n"
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := ParseTargets(nil, f)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if !slices.Equal(hosts, want) {
		t.Errorf("got %v, want %v", hosts, want)
	}
}

func TestExpandCIDR_size(t *testing.T) {
	// /24 = 256 hosts
	hosts, err := expandCIDR("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 256 {
		t.Errorf("got %d hosts for /24, want 256", len(hosts))
	}
	if hosts[0] != "192.168.0.0" || hosts[255] != "192.168.0.255" {
		t.Errorf("unexpected first/last: %s ... %s", hosts[0], hosts[255])
	}
}

package nfs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

// This peer accepts only PUTFH/GETATTR. Any content read, OPEN or mutation is
// rejected by the independent operation dispatcher in peer4.
func inspectionPeer(t *testing.T, supported []uint32, variant string) (*Client, *int) {
	t.Helper()
	calls := 0
	v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		if code != 9 {
			return nil, 0, fmt.Errorf("inspection sent operation %d", code)
		}
		calls++
		bits := readBitmap4(d)
		if len(bits) != 1 {
			return nil, 0, fmt.Errorf("unexpected requested attributes: %v", bits)
		}
		bit := bits[0]
		if bit != 0 && !hasAttribute(supported, bit) {
			return nil, 0, fmt.Errorf("unadvertised attribute %d requested", bit)
		}
		if variant == "discovery-unsupported" || bit == 83 && variant == "unsupported" {
			return nil, 10032, nil
		}
		var e, a encoder
		if variant == "discovery-omitted" || bit == 83 && variant == "omitted" {
			bitmap4(&e)
			e.opaque(nil)
			return e, 0, nil
		}
		bitmap4(&e, bit)
		switch bit {
		case 0:
			// Encode independently of bitmap4's three-word request limit.
			words := make([]uint32, 5)
			for _, b := range supported {
				words[b/32] |= 1 << (b % 32)
			}
			a.u32(uint32(len(words)))
			for _, word := range words {
				a.u32(word)
			}
		case 82:
			if variant == "xattrs-false" {
				a.u32(0)
			} else {
				a.u32(1)
			}
		case 83:
			switch variant {
			case "online":
				a.u32(0)
			case "malformed":
				a.u32(2)
			case "truncated":
			default:
				a.u32(1)
			}
		case 62, 64:
			a.u32(2)
			a.u32(1)
			a.u32(4)
		default:
			return nil, 0, fmt.Errorf("unexpected GETATTR %d", bit)
		}
		e.opaque(a)
		return e, 0, nil
	})
	return v.c, &calls
}

func TestOfflineMetadataSupportAware(t *testing.T) {
	for _, tt := range []struct {
		name  string
		bits  []uint32
		state OfflineState
		calls int
		bad   bool
	}{
		{"offline", []uint32{0, 83}, OfflineOffline, 2, false},
		{"online", []uint32{0, 83}, OfflineOnline, 2, false},
		{"absent", []uint32{0, 130}, OfflineUnknown, 1, false},
		{"unsupported", []uint32{0, 83}, OfflineUnknown, 2, false},
		{"omitted", []uint32{0, 83}, OfflineUnknown, 2, false},
		{"discovery-unsupported", []uint32{0, 83}, OfflineUnknown, 1, false},
		{"discovery-omitted", []uint32{0, 83}, OfflineUnknown, 1, false},
		{"malformed", []uint32{0, 83}, OfflineUnknown, 2, true},
		{"truncated", []uint32{0, 83}, OfflineUnknown, 2, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, calls := inspectionPeer(t, tt.bits, tt.name)
			state, err := c.OfflineMetadata(context.Background(), []byte("file"))
			if state != tt.state || (err != nil) != tt.bad || *calls != tt.calls {
				t.Fatalf("state=%s err=%v calls=%d", state, err, *calls)
			}
		})
	}
}

func TestCapabilitiesDistinguishImplementationAndAdvertisement(t *testing.T) {
	c, calls := inspectionPeer(t, []uint32{0, 7, 12, 64, 77, 82, 83, 130}, "offline")
	r, err := c.Capabilities(context.Background(), []byte("file"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.SupportedAttrsKnown || !hasAttribute(r.SupportedAttrs, 130) || r.Offline != OfflineOffline || *calls != 4 || !reflect.DeepEqual(r.LayoutTypes, []uint32{1, 4}) {
		t.Fatalf("%+v calls=%d", r, *calls)
	}
	for _, f := range r.Features {
		want := "advertised"
		if f.Name == "copy" || f.Name == "clone" || f.Name == "sparse" || f.Name == "named_attributes" {
			want = "unknown"
		}
		if !f.Implemented || f.Server != want {
			t.Fatalf("misleading capability: %+v", f)
		}
	}
}

func TestCapabilitiesMissingAndFalse(t *testing.T) {
	for _, variant := range []string{"absent", "xattrs-false", "discovery-omitted"} {
		t.Run(variant, func(t *testing.T) {
			bits := []uint32{0}
			if variant == "xattrs-false" {
				bits = append(bits, 82)
			}
			c, _ := inspectionPeer(t, bits, variant)
			r, err := c.Capabilities(context.Background(), []byte("file"))
			if err != nil {
				t.Fatal(err)
			}
			want := "unsupported"
			if variant == "discovery-omitted" {
				want = "unknown"
			}
			if r.Features[1].Server != want || r.Offline != OfflineUnknown {
				t.Fatalf("%+v", r)
			}
		})
	}
	legacy := &Client{version: "3"}
	r, err := legacy.Capabilities(context.Background(), []byte("file"))
	if err != nil || r.SupportedAttrsKnown {
		t.Fatalf("legacy: %+v %v", r, err)
	}
	for _, f := range r.Features {
		if f.Server != "unknown" {
			t.Fatalf("legacy inferred support: %+v", f)
		}
	}
	if state, err := legacy.OfflineMetadata(context.Background(), nil); state != OfflineUnknown || err != nil {
		t.Fatal(state, err)
	}
}

func TestCapabilitiesPerObjectNoCache(t *testing.T) {
	current := ""
	v := peer4WithHandle(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		if code != 9 {
			return nil, 0, fmt.Errorf("unexpected op %d", code)
		}
		bits := readBitmap4(d)
		var e, a encoder
		if reflect.DeepEqual(bits, []uint32{0}) {
			bitmap4(&e, 0)
			if current == "cold" {
				bitmap4(&a, 0, 83)
			} else {
				bitmap4(&a, 0)
			}
		} else if current == "cold" && reflect.DeepEqual(bits, []uint32{83}) {
			bitmap4(&e, 83)
			a.u32(1)
		} else {
			return nil, 0, fmt.Errorf("cross-object capability leak")
		}
		e.opaque(a)
		return e, 0, nil
	}, func(fh []byte) error { current = string(fh); return nil })
	for _, p := range []string{"cold", "hot", "cold"} {
		state, err := v.c.OfflineMetadata(context.Background(), []byte(p))
		want := OfflineUnknown
		if p == "cold" {
			want = OfflineOffline
		}
		if err != nil || state != want {
			t.Fatal(p, state, err)
		}
	}
}

func TestConnectionInfoObservedPeerAndNoSecrets(t *testing.T) {
	c := &Client{version: "4.2", security: "krb5p", principal: "alice@EXAMPLE.TEST", config: &Config{Host: "nas.example.test", TLS: TLSConfig{InsecureSkipVerify: true, KeyFile: "secret-key-file"}, Kerberos: KerberosConfig{Password: "secret-password"}}, nfs: &rpcClient{conn: serverInfoConn{peer: &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 2050}}}}
	c.v4 = &v4Client{implementationClaims: []ServerImplementation{{Name: "claim"}}}
	r := c.ConnectionInfo(context.Background())
	if r.Hostname != "nas.example.test" || r.Peer != "192.0.2.9:2050" || r.Security != "krb5p" || r.Principal != c.principal || r.TLS || r.TLSVerified || !r.TLSInsecureRequested || len(r.ImplementationClaims) != 1 {
		t.Fatalf("%+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), "secret-") {
		t.Fatal(string(b), err)
	}
	r.ImplementationClaims[0].Name = "changed"
	if c.v4.implementationClaims[0].Name != "claim" {
		t.Fatal("mutable internal claims escaped")
	}
}

func TestCapabilitiesFilesystemLayoutAdvertisement(t *testing.T) {
	c, _ := inspectionPeer(t, []uint32{0, 58, 62}, "offline")
	r, err := c.Capabilities(context.Background(), []byte("file"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Features[0].Server != "advertised" || r.Features[7].Server != "advertised" || len(r.LayoutTypes) != 0 || !reflect.DeepEqual(r.FSLayoutTypes, []uint32{1, 4}) {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Features[7].Evidence, "eligibility unknown") {
		t.Fatal(r.Features[7])
	}
}

func TestConnectionInfoExchangeImplementationClaim(t *testing.T) {
	for _, nanos := range []uint32{123, 1000000000} {
		t.Run(fmt.Sprint(nanos), func(t *testing.T) {
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 42:
					d.take(8)
					d.str()
					d.take(12)
					e.u64(123)
					e.u32(1)
					e.u32(0x40000)
					e.u32(0)
					e.u64(1)
					e.str("owner")
					e.str("scope")
					e.u32(1)
					e.str("example.test")
					e.str("server claim")
					e.u64(42)
					e.u32(nanos)
				case 43:
					d.u64()
					seq := d.u32()
					d.take(68)
					e = createSequenceReply(seq)
				default:
					return nil, 0, fmt.Errorf("unexpected initialization op %d", code)
				}
				return e, 0, nil
			})
			v.exchangeRole = 0x40000
			err := v.initialize(context.Background())
			if nanos >= 1e9 {
				if err == nil {
					t.Fatal("invalid implementation timestamp accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			claims := v.c.ConnectionInfo(context.Background()).ImplementationClaims
			if len(claims) != 1 || claims[0].Name != "server claim" || claims[0].Domain != "example.test" || claims[0].DateNanos != nanos {
				t.Fatal(claims)
			}
		})
	}
}

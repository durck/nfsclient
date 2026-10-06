package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync/atomic"
	"time"

	"nfsclient/internal/resolve"
)

const (
	nfsProgram   = 100003
	mountProgram = 100005
)

type Status uint32

func (s Status) Error() string {
	if s == 10010 {
		return "NFS 10010: conflicting file lock (NFS4ERR_DENIED)"
	}
	v4Names := map[Status]string{10011: "NFSv4 lease expired; reconnect", 10013: "server grace period; retry shortly", 10016: "requested security flavor not allowed; select --sec explicitly", 10018: "resource unavailable", 10019: "filesystem moved; an approved namespace/state migration profile is required", 10021: "NFSv4 minor version not supported", 10022: "stale NFSv4 client ID; reconnect", 10023: "stale NFSv4 state ID; reconnect", 10025: "invalid NFSv4 state ID; reconnect", 10026: "invalid NFSv4 sequence ID; reconnect", 10052: "NFSv4 session expired; reconnect", 10046: "file is open", 10032: "attribute not supported", 10095: "extended attribute not found", 10096: "extended attribute too large", 10055: "connection is not bound to the NFSv4 session; reconnect", 10078: "NFSv4 session is dead; reconnect"}
	if n, ok := v4Names[s]; ok {
		return fmt.Sprintf("NFS %d: %s", s, n)
	}
	names := map[Status]string{1: "not owner", 2: "not found", 5: "I/O error", 13: "permission denied", 17: "already exists", 18: "cross-device operation", 20: "not a directory", 21: "is a directory", 22: "invalid argument", 28: "no space", 30: "read-only filesystem", 63: "name too long", 66: "directory not empty", 70: "stale file handle", 10001: "bad handle", 10003: "bad directory cookie", 10004: "not supported", 10005: "reply too small", 10008: "server busy"}
	if n, ok := names[s]; ok {
		return fmt.Sprintf("NFS %d: %s", s, n)
	}
	return fmt.Sprintf("NFS status %d", s)
}

type Config struct {
	Host                                  string
	Transport                             string
	UDPSize                               uint32 // zero selects the 4096-byte default
	Version                               string
	PortmapPort, MountPort, NFSPort       int
	NLMPort                               int    // zero discovers NLM on the connected NFS peer
	NLMClientIP, NLMListenIP, NLMStateDir string // explicit embedded NSM profile
	NLMReclaim                            bool   // Explicit server-enforced grace profile; never infer from a granted reply.
	NLMAutoRecover                        bool   // Clean confirmed pre-crash owners before the first new legacy lock.
	NLMAutoNotify                         bool   // Emit crash notification after cleanup; possible delivery keeps new locks quarantined.
	Timeout                               time.Duration
	ReservedPort                          bool
	Auth                                  Auth
	Security                              string
	Kerberos                              KerberosConfig
	DNS                                   resolve.Config
	TLS                                   TLSConfig
	PNFS                                  bool   // Explicit FILE-layout profile: v4.1/4.2 over TCP.
	Offload                               bool   // Explicit v4.2 TCP callback profile.
	OffloadJournal                        string // Optional absolute crash-evidence journal path.
	OffloadReconcile                      bool   // Record bounded synchronous whole-file COPY/CLONE reconciliation evidence.
	OffloadSessionRecovery                bool   // Persist original-session requests and completion evidence before slot reuse.
}
type Client struct {
	config              *Config
	mount, nfs          *rpcClient
	Auth                Auth
	mounted             map[string]bool
	ReadSize, WriteSize uint32
	basicReadDir        bool
	version             string
	v4                  *v4Client
	nlm                 *nlmClient
	security, principal string
	closeKerberos       func()
	cancelKerberos      atomic.Pointer[kerberosCancellation]
}
type Export struct {
	Path      string   `json:"path"`
	Clients   []string `json:"advertised_clients"`
	Namespace bool     `json:"namespace_root,omitempty"`
}
type Attr struct {
	HasNLink  bool      `json:"-"`
	NLink     uint32    `json:"-"`
	HasSize   bool      `json:"-"`
	HasMTime  bool      `json:"-"`
	HasCTime  bool      `json:"-"`
	HasChange bool      `json:"-"`
	CTime     time.Time `json:"-"`
	Change    uint64    `json:"-"`
	HasFSID   bool      `json:"-"`
	HasFileID bool      `json:"-"`
	Owner     string    `json:"owner,omitempty"`
	Group     string    `json:"group,omitempty"`
	FSIDMinor uint64    `json:"fsid_minor,omitempty"`
	Type      uint32    `json:"type"`
	Mode      uint32    `json:"mode"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Size      uint64    `json:"size"`
	FSID      uint64    `json:"fsid"`
	FileID    uint64    `json:"file_id"`
	MTime     time.Time `json:"mtime"`
}
type Node struct {
	Handle []byte `json:"-"`
	Attr   Attr   `json:"attributes"`
}
type Entry struct {
	Name string `json:"name"`
	Node
}

func readAttr(d *decoder) Attr {
	a := Attr{Type: d.u32(), Mode: d.u32()}
	a.NLink, a.HasNLink = d.u32(), true
	a.UID = d.u32()
	a.GID = d.u32()
	a.Size = d.u64()
	d.u64()
	d.u32()
	d.u32()
	a.FSID = d.u64()
	a.FileID = d.u64()
	a.HasFSID, a.HasFileID = true, true
	d.take(8)
	sec, nsec := d.u32(), d.u32()
	a.MTime = time.Unix(int64(sec), int64(nsec))
	if nsec >= 1e9 {
		d.err = errors.New("invalid NFSv3 modification timestamp")
	}
	sec, nsec = d.u32(), d.u32()
	if nsec >= 1e9 {
		d.err = errors.New("invalid NFSv3 metadata timestamp")
	}
	a.CTime = time.Unix(int64(sec), int64(nsec))
	a.HasSize, a.HasMTime, a.HasCTime = true, true, true
	return a
}
func postAttr(d *decoder) (Attr, bool) {
	if d.boolean() {
		return readAttr(d), true
	}
	return Attr{}, false
}
func wcc(d *decoder) {
	if d.boolean() {
		d.take(24)
	}
	postAttr(d)
}

func connectLegacy(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if len(cfg.Auth.Groups) > 16 {
		return nil, errors.New("AUTH_SYS supports at most 16 supplementary groups")
	}
	c := &Client{version: cfg.Version, Auth: cfg.Auth, mounted: make(map[string]bool), ReadSize: 32768, WriteSize: 32768}
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	if c.Version() == "2" {
		c.ReadSize = 8192
		c.WriteSize = 8192
	}
	if cfg.MountPort == 0 || cfg.NFSPort == 0 {
		pmConfig := cfg
		pmConfig.ReservedPort = false
		pm, err := dialConfiguredRPC(ctx, pmConfig, cfg.PortmapPort, 100000, 2)
		if err != nil {
			return nil, err
		}
		defer pm.conn.Close()
		getport := func(prog uint32) (int, error) {
			var e encoder
			e.u32(prog)
			version := c.nfsVersion()
			if prog == mountProgram {
				version = c.mountVersion()
			}
			e.u32(version)
			protocol := uint32(6)
			if cfg.Transport == "udp" {
				protocol = 17
			}
			e.u32(protocol)
			e.u32(0)
			d, err := pm.call(ctx, 100000, 2, 3, nil, e)
			if err != nil {
				return 0, err
			}
			p := d.u32()
			if d.err != nil {
				return 0, d.err
			}
			if p == 0 || p > 65535 {
				return 0, fmt.Errorf("RPC program %d v%d/%s unavailable; specify service ports or check protocol support", prog, version, cfg.Transport)
			}
			return int(p), nil
		}
		if cfg.MountPort == 0 {
			p, err := getport(mountProgram)
			if err != nil {
				return nil, err
			}
			cfg.MountPort = p
		}
		if cfg.NFSPort == 0 {
			p, err := getport(nfsProgram)
			if err != nil {
				return nil, err
			}
			cfg.NFSPort = p
		}
	}
	var err error
	c.mount, err = dialConfiguredRPC(ctx, cfg, cfg.MountPort, mountProgram, c.mountVersion())
	if err != nil {
		return nil, err
	}
	c.nfs, err = dialConfiguredRPC(ctx, cfg, cfg.NFSPort, nfsProgram, c.nfsVersion())
	if err != nil {
		c.mount.conn.Close()
		return nil, err
	}
	if cfg.Transport == "udp" {
		limit := uint32(udpTransferMax)
		if cfg.UDPSize != 0 {
			limit = cfg.UDPSize
		}
		c.ReadSize, c.WriteSize = limit, limit
	}
	if err = c.authenticateKerberos(ctx, cfg); err != nil {
		c.Close()
		return nil, err
	}
	if _, err = c.nfs.call(ctx, nfsProgram, c.nfsVersion(), 0, &c.Auth, nil); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) Close() {
	// Foreground GSS replacement may hold nfs.mu while renewing a FILE TGT.
	// Interrupt its KDC work before any RPC mutex wait; keys remain live until
	// the RPC has unwound and closeKerberos performs final destruction below.
	if owner := c.cancelKerberos.Load(); owner != nil {
		owner.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c.nlm != nil {
		c.nlm.close(ctx)
		c.nlm = nil
	}
	// Cancel the lease's KDC work before waiting for the RPC mutex it holds.
	if c.v4 != nil && c.v4.stop != nil {
		c.v4.stop()
	}
	if c.nfs != nil {
		c.nfs.mu.Lock()
		c.nfs.closing = true
		c.nfs.mu.Unlock()
	}
	if c.v4 != nil {
		c.v4.close(ctx)
	}
	for p := range c.mounted {
		c.Unmount(ctx, p)
	}
	if c.mount != nil {
		c.mount.conn.Close()
	}
	if c.nfs != nil {
		c.nfs.destroyKerberos(ctx)
		c.nfs.conn.Close()
		if c.nfs.duplex != nil {
			<-c.nfs.duplex.done
		}
		if c.nfs.backchannel != nil {
			c.nfs.backchannel.close()
		}
	}
	if c.closeKerberos != nil {
		c.closeKerberos()
		c.closeKerberos = nil
		c.cancelKerberos.Store(nil)
	}
}
func (c *Client) call(ctx context.Context, proc uint32, e encoder) (*decoder, error) {
	if scope, _ := ctx.Value(nlmRangeKey{}).(*nlmRangeScope); scope != nil {
		if err := scope.request(c, proc, e); err != nil {
			return nil, err
		}
	}
	guarded := c.nlm != nil && len(c.nlm.locks) > 0
	if guarded {
		if err := c.nlm.beforeRPC(ctx, proc, e); err != nil {
			return nil, err
		}
	}
	d, err := c.nfs.call(ctx, nfsProgram, c.nfsVersion(), proc, &c.Auth, e)
	if err != nil {
		if guarded {
			c.nlm.monitor.invalidate()
		}
		return nil, err
	}
	if guarded {
		if err := c.nlm.guard(ctx); err != nil {
			return nil, err
		}
	}
	s := d.u32()
	if d.err != nil {
		return nil, d.err
	}
	if s != 0 {
		return nil, Status(s)
	}
	return d, nil
}
func (c *Client) Exports(ctx context.Context) ([]Export, error) {
	if c.v4 != nil {
		return []Export{{Path: "/", Clients: []string{}, Namespace: true}}, nil
	}
	d, err := c.mount.call(ctx, mountProgram, c.mountVersion(), 5, &c.Auth, nil)
	if err != nil {
		return nil, err
	}
	out := []Export{}
	for d.boolean() && d.err == nil {
		e := Export{Path: d.str(), Clients: []string{}}
		for d.boolean() && d.err == nil {
			e.Clients = append(e.Clients, d.str())
		}
		out = append(out, e)
	}
	return out, d.err
}
func (c *Client) Mount(ctx context.Context, p string) (Node, error) {
	if c.v4 != nil {
		return c.v4.mount(ctx, p)
	}
	var e encoder
	e.str(p)
	d, err := c.mount.call(ctx, mountProgram, c.mountVersion(), 1, &c.Auth, e)
	if err != nil {
		return Node{}, err
	}
	s := d.u32()
	if d.err != nil {
		return Node{}, d.err
	}
	if s != 0 {
		return Node{}, Status(s)
	}
	if c.Version() == "2" {
		fh := append([]byte(nil), d.take(32)...)
		if d.err != nil {
			return Node{}, d.err
		}
		c.mounted[p] = true
		a, err := c.GetAttr(ctx, fh)
		return Node{Handle: fh, Attr: a}, err
	}
	fh := d.opaque(64)
	count := d.u32()
	if count > 128 {
		return Node{}, errors.New("invalid mount auth flavor count")
	}
	wanted := uint32(1)
	if c.Security() == "krb5" {
		wanted = 390003
	}
	if c.Security() == "krb5i" {
		wanted = 390004
	}
	if c.Security() == "krb5p" {
		wanted = 390005
	}
	allowed := count == 0 && wanted == 1
	for i := uint32(0); i < count; i++ {
		if d.u32() == wanted {
			allowed = true
		}
	}
	if d.err != nil {
		return Node{}, d.err
	}
	c.mounted[p] = true
	if !allowed {
		if wanted == 1 {
			return Node{}, errors.New("export does not allow AUTH_SYS; select an explicitly supported security mode")
		}
		return Node{}, fmt.Errorf("export does not allow requested security %s; refusing authentication downgrade", c.Security())
	}
	a, err := c.GetAttr(ctx, fh)
	return Node{Handle: fh, Attr: a}, err
}
func (c *Client) Unmount(ctx context.Context, p string) error {
	if c.v4 != nil {
		return nil
	}
	var e encoder
	e.str(p)
	_, err := c.mount.call(ctx, mountProgram, c.mountVersion(), 3, &c.Auth, e)
	if err == nil {
		delete(c.mounted, p)
	}
	return err
}
func (c *Client) GetAttr(ctx context.Context, fh []byte) (Attr, error) {
	if c.Version() == "2" {
		return c.getAttr2(ctx, fh)
	}
	if c.v4 != nil {
		return c.v4.getAttr(ctx, fh)
	}
	var e encoder
	e.opaque(fh)
	d, err := c.call(ctx, 1, e)
	if err != nil {
		return Attr{}, err
	}
	a := readAttr(d)
	return a, d.err
}

// GetNFSv4Root returns the NFSv4 pseudo-root node obtained via PUTROOTFH+GETFH+GETATTR.
// Returns an error if the connection is not NFSv4 or the root handle is not yet set.
func (c *Client) GetNFSv4Root(ctx context.Context) (Node, error) {
	if c.v4 == nil || len(c.v4.root) == 0 {
		return Node{}, errors.New("not connected via NFSv4")
	}
	fh := append([]byte(nil), c.v4.root...)
	a, err := c.v4.getAttr(ctx, fh)
	return Node{Handle: fh, Attr: a}, err
}
func (c *Client) Lookup(ctx context.Context, dir []byte, name string) (Node, error) {
	if c.Version() == "2" {
		return c.lookup2(ctx, dir, name)
	}
	if c.v4 != nil {
		return c.v4.lookup(ctx, dir, name)
	}
	var e encoder
	e.opaque(dir)
	e.str(name)
	d, err := c.call(ctx, 3, e)
	if err != nil {
		return Node{}, err
	}
	fh := d.opaque(64)
	a, ok := postAttr(d)
	postAttr(d)
	if d.err != nil {
		return Node{}, d.err
	}
	if !ok {
		a, err = c.GetAttr(ctx, fh)
	}
	return Node{Handle: fh, Attr: a}, err
}
func (c *Client) Access(ctx context.Context, fh []byte) (uint32, error) {
	if c.Version() == "2" {
		return 0, errors.New("NFSv2 does not support ACCESS; link access is unverified")
	}
	if c.v4 != nil {
		return c.v4.access(ctx, fh)
	}
	var e encoder
	e.opaque(fh)
	e.u32(63)
	d, err := c.call(ctx, 4, e)
	if err != nil {
		return 0, err
	}
	postAttr(d)
	v := d.u32()
	return v, d.err
}
func (c *Client) Readlink(ctx context.Context, fh []byte) (string, error) {
	if c.Version() == "2" {
		return c.readlink2(ctx, fh)
	}
	if c.v4 != nil {
		return c.v4.readlink(ctx, fh)
	}
	var e encoder
	e.opaque(fh)
	d, err := c.call(ctx, 5, e)
	if err != nil {
		return "", err
	}
	postAttr(d)
	s := d.str()
	return s, d.err
}

// Tune transfers to the server's advertised maxima. A failure is explicit.
func (c *Client) Tune(ctx context.Context, fh []byte) error {
	if c.Version() == "2" {
		return c.tune2(ctx, fh)
	}
	if c.v4 != nil {
		return c.v4.tune(ctx, fh)
	}
	var e encoder
	e.opaque(fh)
	d, err := c.call(ctx, 19, e)
	if err != nil {
		return err
	}
	postAttr(d)
	r := d.u32()
	d.u32()
	d.u32()
	w := d.u32()
	d.take(32)
	if d.err != nil {
		return d.err
	}
	if r == 0 || w == 0 {
		return errors.New("server returned zero transfer maximum")
	}
	c.ReadSize = min(r, 32768)
	c.WriteSize = min(w, 32768)
	if c.Transport() == "udp" {
		c.ReadSize = min(c.ReadSize, c.udpSize())
		c.WriteSize = min(c.WriteSize, c.udpSize())
	}
	return nil
}
func (c *Client) ReadDir(ctx context.Context, fh []byte) ([]Entry, error) {
	if c.Version() == "2" {
		return c.readdir2(ctx, fh)
	}
	if c.v4 != nil {
		return c.v4.readdir(ctx, fh)
	}
	entries, err := c.readDir(ctx, fh, !c.basicReadDir)
	if !c.basicReadDir && unsupported(err) {
		c.basicReadDir = true
		return c.readDir(ctx, fh, false)
	}
	return entries, err
}

var errDirectoryChanged = errors.New("directory changed while listing")

func (c *Client) readDir(ctx context.Context, fh []byte, plus bool) ([]Entry, error) {
	// Restart only this read-only traversal, once, discarding every old entry and
	// cookie. Repeated change is explicit; a listing is not an atomic snapshot.
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := c.readDirOnce(ctx, fh, plus)
		if !errors.Is(err, errDirectoryChanged) && !errors.Is(err, Status(10003)) {
			return entries, err
		}
		if attempt == 1 {
			return nil, fmt.Errorf("directory changed while listing; retry when activity settles: %w", err)
		}
	}
}

func (c *Client) readDirOnce(ctx context.Context, fh []byte, plus bool) ([]Entry, error) {
	entries := []Entry{}
	var cookie uint64
	var verifier [8]byte
	seen := map[uint64]bool{}
	names := map[string]bool{}
	for {
		var e encoder
		e.opaque(fh)
		e.u64(cookie)
		e = append(e, verifier[:]...)
		dirCount := uint32(4096)
		if c.Transport() == "udp" {
			dirCount = min(dirCount, c.udpSize())
		}
		e.u32(dirCount)
		proc := uint32(16)
		if plus {
			maxCount := uint32(32768)
			if c.Transport() == "udp" {
				maxCount = c.udpSize()
			}
			e.u32(maxCount)
			proc = 17
		}
		d, err := c.call(ctx, proc, e)
		if err != nil {
			return nil, err
		}
		postAttr(d)
		var nextVerifier [8]byte
		copy(nextVerifier[:], d.take(8))
		if d.err != nil {
			return nil, d.err
		}
		if cookie != 0 && nextVerifier != verifier {
			return nil, fmt.Errorf("%w: cookie verifier changed", errDirectoryChanged)
		}
		verifier = nextVerifier
		old := cookie
		for d.boolean() && d.err == nil {
			d.u64()
			name := d.str()
			cookie = d.u64()
			var a Attr
			var ok bool
			var handle []byte
			if plus {
				a, ok = postAttr(d)
				if d.boolean() {
					handle = d.opaque(64)
				}
			}
			if d.err != nil {
				return nil, d.err
			}
			if name == "." || name == ".." {
				continue
			}
			// Some servers restart silently with new cookies and a zero verifier.
			// A name can appear only once, even when several names share a fileid.
			if names[name] {
				return nil, fmt.Errorf("%w: repeated name %q", errDirectoryChanged, name)
			}
			names[name] = true
			n := Node{Handle: handle, Attr: a}
			if !ok || len(handle) == 0 {
				n, err = c.Lookup(ctx, fh, name)
				if err != nil {
					return nil, fmt.Errorf("attributes for %q: %w", name, err)
				}
			}
			entries = append(entries, Entry{Name: name, Node: n})
			if len(entries) > 1000000 {
				return nil, errors.New("directory exceeds one million entries")
			}
		}
		eof := d.boolean()
		if d.err != nil {
			return nil, d.err
		}
		if eof {
			break
		}
		if cookie == old || seen[cookie] {
			return nil, errors.New("directory listing made no progress")
		}
		seen[cookie] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}
func (c *Client) ReadTo(ctx context.Context, fh []byte, w io.Writer) (int64, error) {
	return c.ReadToProgress(ctx, fh, w, nil)
}

// ReadToProgress reports bytes accepted by the destination writer.
func (c *Client) ReadToProgress(ctx context.Context, fh []byte, w io.Writer, progress func(uint64)) (int64, error) {
	if c.Version() == "2" {
		return c.read2(ctx, fh, w, progress)
	}
	if c.v4 != nil {
		return c.v4.read(ctx, fh, w, progress)
	}
	var offset uint64
	for {
		var e encoder
		e.opaque(fh)
		e.u64(offset)
		e.u32(c.ReadSize)
		d, err := c.call(ctx, 6, e)
		if err != nil {
			return int64(offset), err
		}
		postAttr(d)
		count := d.u32()
		eof := d.boolean()
		data := d.opaque(c.ReadSize)
		if d.err != nil {
			return int64(offset), d.err
		}
		if count != uint32(len(data)) {
			return int64(offset), errors.New("READ count mismatch")
		}
		n, err := w.Write(data)
		offset += uint64(n)
		if progress != nil {
			progress(offset)
		}
		if err != nil {
			return int64(offset), err
		}
		if n != len(data) {
			return int64(offset), io.ErrShortWrite
		}
		if eof {
			return int64(offset), nil
		}
		if count == 0 {
			return int64(offset), io.ErrNoProgress
		}
	}
}

func sattr(e *encoder, mode *uint32, size *uint64) {
	if mode == nil {
		e.u32(0)
	} else {
		e.u32(1)
		e.u32(*mode)
	}
	e.u32(0)
	e.u32(0)
	if size == nil {
		e.u32(0)
	} else {
		e.u32(1)
		e.u64(*size)
	}
	e.u32(0)
	e.u32(0)
}
func (c *Client) Chmod(ctx context.Context, fh []byte, mode uint32) error {
	if c.Version() == "2" {
		return c.chmod2(ctx, fh, mode)
	}
	if c.v4 != nil {
		return c.v4.chmod(ctx, fh, mode)
	}
	var e encoder
	e.opaque(fh)
	sattr(&e, &mode, nil)
	e.u32(0)
	d, err := c.call(ctx, 2, e)
	if err != nil {
		return err
	}
	wcc(d)
	return d.err
}
func (c *Client) Create(ctx context.Context, dir []byte, name string, mode uint32, directory bool) (Node, error) {
	if c.Version() == "2" {
		return c.create2(ctx, dir, name, mode, directory)
	}
	if c.v4 != nil {
		return c.v4.create(ctx, dir, name, mode, directory)
	}
	var e encoder
	e.opaque(dir)
	e.str(name)
	proc := uint32(8)
	if directory {
		proc = 9
	} else {
		e.u32(1)
	} // GUARDED: never truncate an existing file.
	sattr(&e, &mode, nil)
	d, err := c.call(ctx, proc, e)
	if err != nil {
		return Node{}, err
	}
	var fh []byte
	if d.boolean() {
		fh = d.opaque(64)
	}
	a, ok := postAttr(d)
	wcc(d)
	if d.err != nil {
		return Node{}, d.err
	}
	if len(fh) == 0 || !ok {
		return c.Lookup(ctx, dir, name)
	}
	return Node{Handle: fh, Attr: a}, nil
}

// Remove unlinks a named non-directory entry, including unpublished uploads.
func (c *Client) Remove(ctx context.Context, dir []byte, name string) error {
	if c.Version() == "2" {
		return c.remove2(ctx, dir, name)
	}
	if c.v4 != nil {
		return c.v4.remove(ctx, dir, name)
	}
	var e encoder
	e.opaque(dir)
	e.str(name)
	d, err := c.call(ctx, 12, e)
	if err != nil {
		return err
	}
	wcc(d)
	return d.err
}

// Rmdir removes one empty directory; it never walks or recursively removes it.
func (c *Client) Rmdir(ctx context.Context, dir []byte, name string) error {
	if c.v4 != nil {
		return c.v4.remove(ctx, dir, name)
	}
	var e encoder
	if c.Version() == "2" {
		var err error
		e, err = handle2(dir)
		if err != nil {
			return err
		}
		e.str(name)
		_, err = c.call(ctx, 15, e)
		return err
	}
	e.opaque(dir)
	e.str(name)
	d, err := c.call(ctx, 13, e)
	if err != nil {
		return err
	}
	wcc(d)
	return d.err
}

// Rename atomically moves a name within a filesystem, replacing the target
// according to server RENAME semantics. It has no no-replace guarantee.
func (c *Client) Rename(ctx context.Context, fromDir []byte, from string, toDir []byte, to string) error {
	if c.Version() == "2" {
		return c.rename2(ctx, fromDir, from, toDir, to)
	}
	if c.v4 != nil {
		return c.v4.rename(ctx, fromDir, from, toDir, to)
	}
	var e encoder
	e.opaque(fromDir)
	e.str(from)
	e.opaque(toDir)
	e.str(to)
	d, err := c.call(ctx, 14, e)
	if err != nil {
		return err
	}
	wcc(d)
	wcc(d)
	return d.err
}

func (c *Client) WriteFrom(ctx context.Context, fh []byte, r io.Reader) (int64, error) {
	return c.WriteFromProgress(ctx, fh, r, nil)
}

// WriteFromProgress reports only server-confirmed, stable bytes, including
// COMMIT verification when the server returns an unstable WRITE reply.
func (c *Client) WriteFromProgress(ctx context.Context, fh []byte, r io.Reader, progress func(uint64)) (int64, error) {
	if c.Version() == "2" {
		return c.write2(ctx, fh, r, progress)
	}
	if c.v4 != nil {
		return c.v4.write(ctx, fh, r, progress)
	}
	return c.write3At(ctx, fh, r, progress, 0)
}

func (c *Client) write3At(ctx context.Context, fh []byte, r io.Reader, progress func(uint64), start uint64) (int64, error) {
	if start > 1<<63-1 || c.WriteSize == 0 {
		return 0, errors.New("unsupported NFSv3 write offset or zero write size")
	}
	buf := make([]byte, c.WriteSize)
	offset := start
	for {
		if err := ctx.Err(); err != nil {
			return int64(offset - start), err
		}
		n, readErr := r.Read(buf)
		if n < 0 || n > len(buf) {
			return int64(offset - start), errors.New("invalid reader count")
		}
		if uint64(n) > uint64(1<<63-1)-offset {
			return int64(offset - start), errors.New("NFSv3 write exceeds supported signed 64-bit size")
		}
		if n == 0 && readErr == nil {
			return int64(offset - start), io.ErrNoProgress
		}
		for data := buf[:n]; len(data) > 0; {
			if err := ctx.Err(); err != nil {
				return int64(offset - start), err
			}
			var e encoder
			e.opaque(fh)
			e.u64(offset)
			e.u32(uint32(len(data)))
			e.u32(2)
			e.opaque(data)
			d, err := c.call(ctx, 7, e)
			if err != nil {
				var status Status
				if !errors.As(err, &status) {
					err = c.uncertainLegacyWrite(err)
				}
				return int64(offset - start), err
			}
			wcc(d)
			count := d.u32()
			stable := d.u32()
			verifier := append([]byte(nil), d.take(8)...)
			if d.err != nil {
				return int64(offset - start), c.uncertainLegacyWrite(d.err)
			}
			if len(d.b) != 0 || count == 0 || count > uint32(len(data)) {
				return int64(offset - start), c.uncertainLegacyWrite(errors.New("invalid WRITE count"))
			}
			if stable > 2 {
				return int64(offset - start), c.uncertainLegacyWrite(errors.New("invalid WRITE stability"))
			}
			if stable != 2 {
				var commit encoder
				commit.opaque(fh)
				commit.u64(offset)
				commit.u32(count)
				reply, err := c.call(ctx, 21, commit)
				if err != nil {
					return int64(offset - start), c.uncertainLegacyWrite(err)
				}
				wcc(reply)
				v := reply.take(8)
				if reply.err != nil {
					return int64(offset - start), c.uncertainLegacyWrite(reply.err)
				}
				if len(reply.b) != 0 || string(v) != string(verifier) {
					return int64(offset - start), c.uncertainLegacyWrite(errors.New("server rebooted during upload; write verifier changed"))
				}
			}
			offset += uint64(count)
			if progress != nil {
				progress(offset - start)
			}
			data = data[count:]
		}
		if readErr == io.EOF {
			return int64(offset - start), nil
		}
		if readErr != nil {
			return int64(offset - start), readErr
		}
	}
}

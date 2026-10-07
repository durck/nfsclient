package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"nfsclient/internal/iscsi"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/chzyer/readline"
	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

var commands = []string{"exports", "use", "reconnect", "migrate", "lock-save", "offload-reconcile", "lock", "locktest", "nlmrecover", "locks", "unlock", "pwd", "cd", "ls", "stat", "acl", "getacl", "setacl", "label", "setlabel", "xattrs", "getxattr", "setxattr", "removexattr", "cat", "hex", "get", "getplus", "getpnfs", "putrangepnfs", "putpnfs", "getrange", "putrange", "reget", "reput", "replace", "gettree", "puttree", "put", "chmod", "mkdir", "rm", "rmdir", "mv", "copyrange", "clonerange", "copyasync", "copyfrom", "writesame", "writeadb", "advise", "seek", "allocate", "deallocate", "id", "uid", "uid-scan", "auto-uid", "auto-uid-scan", "escape", "root", "auto-escape", "squash", "lpwd", "lcd", "lls", "help", "legend", "exit", "quit"}

func parseLockRange(args []string) (uint64, uint64, error) {
	if len(args) == 0 {
		return 0, nfs.LockToEOF, nil
	}
	if len(args) != 2 {
		return 0, 0, errors.New("usage: lock PATH read|write [OFFSET LENGTH|eof]")
	}
	offset, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return 0, 0, errors.New("lock offset must be a decimal uint64")
	}
	length := nfs.LockToEOF
	if args[1] != "eof" {
		length, err = strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return 0, 0, errors.New("lock length must be a decimal uint64 or eof")
		}
	}
	if err := nfs.ValidateLockRange(offset, length); err != nil {
		return 0, 0, err
	}
	return offset, length, nil
}

func lockLengthLabel(length uint64) string {
	if length == nfs.LockToEOF {
		return "eof"
	}
	return strconv.FormatUint(length, 10)
}

func parseCopyFromOptions(source, destination string, args []string) (nfs.CopyFromOptions, error) {
	o := nfs.CopyFromOptions{Destination: destination}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			o.SourceServers = append(o.SourceServers, arg)
			continue
		}
		if seen[arg] || i+1 == len(args) || strings.HasPrefix(args[i+1], "--") {
			return o, errors.New("COPY security options need one value and must not repeat")
		}
		seen[arg] = true
		i++
		switch arg {
		case "--source-spn":
			o.SourceSPN = args[i]
		case "--copy-user":
			o.CopyUser = args[i]
		case "--source-tls-name":
			o.SourceTLSName = args[i]
		default:
			return o, fmt.Errorf("unknown COPY option %s", arg)
		}
	}
	if len(o.SourceServers) == 0 {
		o.SourceServers = []string{source}
	}
	return o, nfs.ValidateCopyFromOptions(o)
}

func parseADB(args []string) (b nfs.ApplicationDataBlock, wait time.Duration, err error) {
	if len(args) < 4 || len(args) > 10 {
		return b, 0, errors.New("usage: writeadb PATH OFFSET BLOCK_SIZE BLOCK_COUNT WAIT [--number OFFSET FIRST] [--pattern OFFSET HEX]")
	}
	for i, field := range []*uint64{&b.Offset, &b.BlockSize, &b.BlockCount} {
		*field, err = strconv.ParseUint(args[i], 10, 64)
		if err != nil {
			return b, 0, errors.New("ADB offset, size and count must be decimal uint64 values")
		}
	}
	wait, err = time.ParseDuration(args[3])
	if err != nil {
		return b, 0, err
	}
	if err = nfs.ValidateOffloadWait(wait); err != nil {
		return b, 0, err
	}
	seen := map[string]bool{}
	for i := 4; i < len(args); i += 3 {
		flag := args[i]
		if i+2 >= len(args) || seen[flag] || flag != "--number" && flag != "--pattern" {
			return b, 0, errors.New("ADB options need one offset/value pair per --number or --pattern")
		}
		seen[flag] = true
		offset, parseErr := strconv.ParseUint(args[i+1], 10, 64)
		if parseErr != nil {
			return b, 0, errors.New("ADB field offset must be a decimal uint64")
		}
		if flag == "--number" {
			value, parseErr := strconv.ParseUint(args[i+2], 10, 32)
			if parseErr != nil {
				return b, 0, errors.New("ADB first number must be a decimal uint32")
			}
			first := uint32(value)
			b.FirstNumber = &first
			b.NumberOffset = offset
		} else {
			if len(args[i+2]) == 0 || len(args[i+2]) > 8192 {
				return b, 0, errors.New("ADB hex pattern must contain 1..4096 bytes")
			}
			b.Pattern, err = hex.DecodeString(args[i+2])
			if err != nil {
				return b, 0, err
			}
			b.PatternOffset = offset
		}
	}
	_, err = nfs.ValidateApplicationDataBlock(b)
	return
}

type Shell struct {
	Session         *session.Session
	Out, Err        io.Writer
	LocalDir        string
	Terminal        bool
	Color, ErrColor bool
	ErrTerminal     bool
	ProgressMode    string
	Ask             func(string) (string, error)
	AskChoice       func(string, string) (string, error)
	promptClient    *nfs.Client
	promptHost      string
	promptServer    string
}

func (s *Shell) local(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.LocalDir, p)
}

func (s *Shell) Execute(ctx context.Context, line string) (bool, error) {
	a, err := SplitLine(line)
	if err != nil {
		return false, err
	}
	if len(a) == 0 {
		return false, nil
	}
	retries := 0
	reclaim := false
	var failover []nfs.ReadReplica
	var referrals []session.ReferralTarget
	if a[0] == "reget" && len(a) > 1 && a[1] == "--referral" {
		i := 1
		for i < len(a) && a[i] == "--referral" {
			if i+1 >= len(a) || len(referrals) >= 8 {
				return false, errors.New("usage: reget --referral SERVER=HOST:PORT,SPN,TLS_NAME [--referral ...] REMOTE [LOCAL]")
			}
			server, value, ok := strings.Cut(a[i+1], "=")
			fields := strings.Split(value, ",")
			if !ok || server == "" || len(fields) != 3 {
				return false, errors.New("referral approval requires SERVER=HOST:PORT,SPN,TLS_NAME")
			}
			referrals = append(referrals, session.ReferralTarget{Server: server, Target: nfs.ReadReplica{Address: fields[0], SPN: fields[1], TLSName: fields[2]}})
			i += 2
		}
		if i >= len(a) || strings.HasPrefix(a[i], "--") {
			return false, errors.New("reget recovery modes cannot be combined")
		}
		a = append([]string{a[0]}, a[i:]...)
	}
	if a[0] == "reget" && len(a) > 1 && a[1] == "--failover" {
		i := 1
		for i < len(a) && a[i] == "--failover" {
			if i+1 >= len(a) || len(failover) >= 8 {
				return false, errors.New("usage: reget --failover HOST:PORT,SPN,TLS_NAME [--failover ...] REMOTE [LOCAL]")
			}
			fields := strings.Split(a[i+1], ",")
			if len(fields) != 3 {
				return false, errors.New("failover target must contain HOST:PORT,SPN,TLS_NAME; use empty unused identities")
			}
			failover = append(failover, nfs.ReadReplica{Address: fields[0], SPN: fields[1], TLSName: fields[2]})
			i += 2
		}
		if i >= len(a) || strings.HasPrefix(a[i], "--") {
			return false, errors.New("reget recovery modes cannot be combined")
		}
		a = append([]string{a[0]}, a[i:]...)
	}
	if a[0] == "reget" && len(a) > 1 && a[1] == "--reclaim-locks" {
		reclaim = true
		a = append([]string{a[0]}, a[2:]...)
		if len(a) < 2 || strings.HasPrefix(a[1], "--") {
			return false, errors.New("usage: reget --reclaim-locks REMOTE [LOCAL] (one reclaim; cannot combine with --retries)")
		}
	}
	if a[0] == "reget" && len(a) > 1 && a[1] == "--retries" {
		if len(a) < 4 {
			return false, errors.New("usage: reget [--retries 0..30] REMOTE [LOCAL]")
		}
		retries, err = strconv.Atoi(a[2])
		if err != nil || retries < 0 || retries > 30 {
			return false, errors.New("resume retries must be between 0 and 30")
		}
		a = append([]string{a[0]}, a[3:]...)
		if strings.HasPrefix(a[1], "--") {
			return false, errors.New("reget recovery modes cannot be combined or repeated")
		}
	}
	argc := len(a) - 1
	check := func(min, max int, usage string) error {
		if argc < min || argc > max {
			return fmt.Errorf("usage: %s", usage)
		}
		return nil
	}
	optional := func() string {
		if argc == 0 {
			return "."
		}
		return a[1]
	}
	sess := s.Session
	switch a[0] {
	case "exit", "quit":
		return true, check(0, 0, a[0])
	case "help":
		if err := check(0, 0, "help"); err != nil {
			return false, err
		}
		err = s.printHelp()
	case "legend":
		if err := check(0, 0, "legend"); err != nil {
			return false, err
		}
		err = s.printLegend()
	case "exports":
		err = s.discoverExports(ctx, a[1:])
	case "use":
		if err := check(1, 1, "use EXPORT"); err != nil {
			return false, err
		}
		err = sess.Use(ctx, a[1])
		if err == nil {
			err = s.printReady(s.Err, s.ErrColor)
		}
	case "migrate":
		if argc == 1 && a[1] == "--status" {
			status := sess.Client.StatefulFailoverStatus()
			fmt.Fprintf(s.Out, "Automatic stateful failover: armed=%t consumed=%t target=%s\n", status.Armed, status.Consumed, status.Target.Address)
			return false, nil
		}
		if err := check(1, 2, "migrate [--source-unavailable|--arm-failover] SERVER=HOST:PORT,SPN,TLS_NAME"); err != nil {
			return false, err
		}
		failover := argc == 2 && a[1] == "--source-unavailable"
		arm := argc == 2 && a[1] == "--arm-failover"
		if argc == 2 && !failover && !arm {
			return false, errors.New("usage: migrate [--source-unavailable|--arm-failover] SERVER=HOST:PORT,SPN,TLS_NAME")
		}
		server, value, ok := strings.Cut(a[len(a)-1], "=")
		fields := strings.Split(value, ",")
		if !ok || server == "" || len(fields) != 3 {
			return false, errors.New("migration requires SERVER=HOST:PORT,SPN,TLS_NAME")
		}
		approval := session.ReferralTarget{Server: server, Target: nfs.ReadReplica{Address: fields[0], SPN: fields[1], TLSName: fields[2]}}
		if arm {
			err = sess.ArmStatefulFailover(approval)
		} else if failover {
			err = sess.FailoverLocks(ctx, approval)
		} else {
			err = sess.Migrate(ctx, approval)
		}
		if err == nil {
			if arm {
				fmt.Fprintln(s.Err, "One automatic same-session failover armed; only the exact cached request may be replayed.")
			} else {
				fmt.Fprintln(s.Err, "Transferred OPEN/LOCK state and paths verified; interrupted operations were not replayed.")
			}
		}
	case "lock-save":
		if err := check(1, 1, "lock-save ABSOLUTE_JOURNAL"); err != nil {
			return false, err
		}
		err = sess.SaveLocks(a[1])
		if err == nil {
			fmt.Fprintln(s.Err, "Confirmed lock state saved or empty namespace armed; planned lock phases and cached mutations are recorded durably.")
		}
	case "offload-reconcile":
		if err := check(3, 3, "offload-reconcile ABSOLUTE_JOURNAL OPERATION_ID DESTINATION"); err != nil {
			return false, err
		}
		err = sess.ReconcileOffload(ctx, a[1], a[2], a[3])
		if err == nil {
			fmt.Fprintln(s.Err, "Server completion receipt and complete destination bytes verified; no offload or data write replayed.")
		}
	case "reconnect":
		if err := check(0, 1, "reconnect [--discard-locks|--reclaim-locks]"); err != nil {
			return false, err
		}
		if argc == 1 && a[1] == "--reclaim-locks" {
			err = sess.Reclaim(ctx)
			if err == nil {
				fmt.Fprintln(s.Err, "Previous locks reclaimed and paths verified; interrupted file operations were not replayed.")
			}
		} else {
			if argc == 1 {
				if a[1] != "--discard-locks" {
					return false, errors.New("usage: reconnect [--discard-locks|--reclaim-locks]")
				}
				if sess.Escaped {
					return false, errors.New("reset the discovered root before discarding state")
				}
				sess.Client.DiscardLocks()
				clear(sess.LockPaths)
				fmt.Fprintln(s.Err, "Old lock state abandoned; server release is not guaranteed until lease expiry. Locks will not be restored.")
			}
			err = sess.Reconnect(ctx)
		}
		if err == nil {
			err = s.printReady(s.Err, s.ErrColor)
		}
	case "locktest":
		if err := check(2, 4, "locktest PATH read|write [OFFSET LENGTH|eof]"); err != nil {
			return false, err
		}
		if a[2] != "read" && a[2] != "write" {
			return false, errors.New("lock type must be read or write")
		}
		offset, length, parseErr := parseLockRange(a[3:])
		if parseErr != nil {
			return false, fmt.Errorf("locktest range: %w", parseErr)
		}
		var conflict *nfs.LockConflict
		conflict, err = sess.TestLock(ctx, a[1], a[2] == "write", offset, length)
		if err == nil {
			if conflict == nil {
				fmt.Fprintln(s.Out, "No conflict reported at this instant; no lock acquired.")
			} else {
				kind := "read"
				if conflict.Write {
					kind = "write"
				}
				fmt.Fprintf(s.Out, "Conflict: %s lock, offset=%d length=%s svid=%d; no lock acquired.\n", kind, conflict.Offset, lockLengthLabel(conflict.Length), conflict.SVID)
			}
		}
	case "lock":
		var wait time.Duration
		native := argc > 0 && a[1] == "--wait-native"
		if argc > 0 && (a[1] == "--wait" || native) {
			if argc < 4 {
				return false, errors.New("usage: lock [--wait|--wait-native] DURATION PATH read|write [OFFSET LENGTH|eof]")
			}
			var parseErr error
			wait, parseErr = time.ParseDuration(a[2])
			if parseErr != nil || wait <= 0 || wait > 24*time.Hour {
				return false, errors.New("lock wait must be a positive duration at most 24h")
			}
			a = append([]string{a[0]}, a[3:]...)
			argc = len(a) - 1
		}
		if err := check(2, 4, "lock PATH read|write [OFFSET LENGTH|eof]"); err != nil {
			return false, err
		}
		if a[2] != "read" && a[2] != "write" {
			return false, errors.New("lock type must be read or write")
		}
		offset, length, parseErr := parseLockRange(a[3:])
		if parseErr != nil {
			return false, parseErr
		}
		var id uint64
		if native {
			id, err = sess.LockNativeWait(ctx, a[1], a[2] == "write", offset, length, wait)
		} else if wait > 0 {
			id, err = sess.LockWait(ctx, a[1], a[2] == "write", offset, length, wait)
		} else {
			id, err = sess.LockRange(ctx, a[1], a[2] == "write", offset, length)
		}
		if err == nil {
			fmt.Fprintf(s.Out, "Lock %d: %s %s (offset=%d length=%s, advisory)\n", id, a[2], label(sess.LockPaths[id]), offset, lockLengthLabel(length))
		}
	case "nlmrecover":
		if err := check(0, 0, "nlmrecover"); err != nil {
			return false, err
		}
		if sess.AutoUID || sess.AutoEscape || sess.Escaped {
			return false, errors.New("nlmrecover requires a fixed identity and selected export")
		}
		var count int
		count, err = sess.Client.RecoverNLMLocks(ctx)
		if err == nil {
			fmt.Fprintf(s.Out, "Released %d recorded NLM locks; no file operations replayed.\n", count)
		}
	case "locks":
		if err := check(0, 0, "locks"); err != nil {
			return false, err
		}
		locks := sess.Client.Locks()
		if len(locks) == 0 {
			fmt.Fprintln(s.Out, "No file locks.")
		}
		for _, l := range locks {
			kind, state := "read", "held"
			if l.Write {
				kind = "write"
			}
			if l.Uncertain {
				state = "uncertain"
			}
			fmt.Fprintf(s.Out, "%d\t%s\t%s\toffset=%d length=%s\t%s\n", l.ID, kind, state, l.Offset, lockLengthLabel(l.Length), label(sess.LockPaths[l.ID]))
		}
	case "unlock":
		if err := check(1, 1, "unlock ID"); err != nil {
			return false, err
		}
		var id uint64
		id, err = strconv.ParseUint(a[1], 10, 64)
		if err == nil {
			err = sess.Client.Unlock(ctx, id)
			retained := false
			for _, l := range sess.Client.Locks() {
				retained = retained || l.ID == id
			}
			if !retained {
				delete(sess.LockPaths, id)
			}
		}
	case "pwd":
		if err := check(0, 0, "pwd"); err != nil {
			return false, err
		}
		fmt.Fprintln(s.Out, label(sess.CWD))
	case "cd":
		if err := check(0, 1, "cd [PATH]"); err != nil {
			return false, err
		}
		p := "/"
		if argc == 1 {
			p = a[1]
		}
		err = sess.CD(ctx, p)
	case "ls":
		if err := check(0, 1, "ls [PATH]"); err != nil {
			return false, err
		}
		var entries []nfs.Entry
		var links map[string]session.LinkInfo
		entries, links, err = sess.List(ctx, optional(), 32)
		if entries != nil {
			if printErr := s.printEntries(entries, links); printErr != nil {
				return false, printErr
			}
		}
	case "stat":
		if err := check(1, 1, "stat PATH"); err != nil {
			return false, err
		}
		var n nfs.Node
		n, _, err = sess.Resolve(ctx, a[1], false)
		if err == nil {
			enc := json.NewEncoder(s.Out)
			enc.SetIndent("", "  ")
			err = enc.Encode(n.Attr)
		}
	case "acl":
		if err := check(1, 1, "acl PATH"); err != nil {
			return false, err
		}
		err = s.inspectACL(ctx, a[1])
	case "getacl":
		if err := check(2, 3, "getacl PATH LOCAL [acl|dacl|sacl]"); err != nil {
			return false, err
		}
		attribute := "acl"
		if len(a) == 4 {
			attribute = a[3]
		}
		err = s.exportACL(ctx, a[1], a[2], attribute)
	case "setacl":
		if err := check(2, 2, "setacl PATH LOCAL"); err != nil {
			return false, err
		}
		err = s.setACL(ctx, a[1], a[2])
	case "copyrange", "clonerange", "copyasync":
		args, usage := 5, a[0]+" SOURCE DESTINATION SOURCE_OFFSET DESTINATION_OFFSET LENGTH"
		if a[0] == "copyasync" {
			args = 6
			usage += " WAIT"
		}
		if err := check(args, args, usage); err != nil {
			return false, err
		}
		sourceOffset, first := strconv.ParseUint(a[3], 10, 64)
		destinationOffset, second := strconv.ParseUint(a[4], 10, 64)
		length, third := strconv.ParseUint(a[5], 10, 64)
		if first != nil || second != nil || third != nil {
			return false, errors.New("copy offsets and length must be decimal uint64 values")
		}
		if err := nfs.ValidateCopyRange(sourceOffset, destinationOffset, length); err != nil {
			return false, err
		}
		var copied uint64
		if a[0] == "copyasync" {
			wait, parseErr := time.ParseDuration(a[6])
			if parseErr != nil {
				return false, parseErr
			}
			if err := nfs.ValidateOffloadWait(wait); err != nil {
				return false, err
			}
			copied, err = sess.CopyRangeAsync(ctx, a[1], a[2], sourceOffset, destinationOffset, length, wait)
		} else {
			copied, err = sess.CopyRange(ctx, a[1], a[2], sourceOffset, destinationOffset, length, a[0] == "clonerange")
		}
		if err == nil {
			err = json.NewEncoder(s.Out).Encode(struct {
				Copied uint64 `json:"copied"`
			}{copied})
		}
	case "copyfrom":
		if err := check(9, 79, "copyfrom SOURCE_IP:PORT EXPORT SOURCE DESTINATION SOURCE_OFFSET DESTINATION_OFFSET LENGTH WAIT DESTINATION_IP:PORT [APPROVED_SOURCE_IP:PORT ...] [--source-spn nfs/HOST --copy-user USER@DOMAIN] [--source-tls-name HOST]"); err != nil {
			return false, err
		}
		sourceOffset, first := strconv.ParseUint(a[5], 10, 64)
		destinationOffset, second := strconv.ParseUint(a[6], 10, 64)
		length, third := strconv.ParseUint(a[7], 10, 64)
		if first != nil || second != nil || third != nil {
			return false, errors.New("copy offsets and length must be decimal uint64 values")
		}
		if err := nfs.ValidateCopyRange(sourceOffset, destinationOffset, length); err != nil {
			return false, err
		}
		wait, err := time.ParseDuration(a[8])
		if err != nil {
			return false, err
		}
		if err := nfs.ValidateOffloadWait(wait); err != nil {
			return false, err
		}
		options, err := parseCopyFromOptions(a[1], a[9], a[10:])
		if err != nil {
			return false, err
		}
		copied, err := sess.CopyFrom(ctx, a[1], a[2], a[3], a[4], sourceOffset, destinationOffset, length, wait, options)
		if err != nil {
			return false, err
		}
		return false, json.NewEncoder(s.Out).Encode(struct {
			Copied uint64 `json:"copied"`
		}{copied})
	case "writeadb":
		if err := check(5, 11, "writeadb PATH OFFSET BLOCK_SIZE BLOCK_COUNT WAIT [--number OFFSET FIRST] [--pattern OFFSET HEX]"); err != nil {
			return false, err
		}
		block, wait, err := parseADB(a[2:])
		if err != nil {
			return false, err
		}
		written, err := sess.WriteApplicationDataBlocks(ctx, a[1], block, wait)
		if err != nil {
			return false, err
		}
		return false, json.NewEncoder(s.Out).Encode(struct {
			Written uint64 `json:"written"`
		}{written})
	case "writesame":
		if err := check(5, 5, "writesame PATH OFFSET REPEAT_COUNT HEX_PATTERN WAIT"); err != nil {
			return false, err
		}
		offset, first := strconv.ParseUint(a[2], 10, 64)
		count, second := strconv.ParseUint(a[3], 10, 64)
		if first != nil || second != nil {
			return false, errors.New("WRITE_SAME offset and count must be decimal uint64 values")
		}
		if len(a[4]) > 8192 {
			return false, errors.New("WRITE_SAME pattern exceeds 4096 bytes")
		}
		pattern, err := hex.DecodeString(a[4])
		if err != nil {
			return false, err
		}
		wait, err := time.ParseDuration(a[5])
		if err != nil {
			return false, err
		}
		if _, err := nfs.ValidateWriteSame(offset, count, pattern); err != nil {
			return false, err
		}
		if err := nfs.ValidateOffloadWait(wait); err != nil {
			return false, err
		}
		n, err := sess.WriteSame(ctx, a[1], offset, count, pattern, wait)
		if err != nil {
			return false, err
		}
		return false, json.NewEncoder(s.Out).Encode(struct {
			Written uint64 `json:"written"`
		}{n})
	case "xattrs":
		if err := check(1, 1, "xattrs PATH"); err != nil {
			return false, err
		}
		var names []string
		names, err = sess.ListXattrs(ctx, a[1])
		if err == nil {
			err = json.NewEncoder(s.Out).Encode(names)
		}
	case "getxattr":
		if err := check(2, 2, "getxattr PATH KEY"); err != nil {
			return false, err
		}
		var value []byte
		value, err = sess.GetXattr(ctx, a[1], a[2])
		if err == nil {
			err = json.NewEncoder(s.Out).Encode(struct {
				Key string `json:"key"`
				Hex string `json:"hex"`
			}{a[2], hex.EncodeToString(value)})
		}
	case "setxattr":
		if err := check(4, 4, "setxattr PATH KEY create|replace|either HEX"); err != nil {
			return false, err
		}
		options := map[string]uint32{"either": 0, "create": 1, "replace": 2}
		option, ok := options[a[3]]
		if !ok {
			return false, errors.New("xattr option must be create, replace or either")
		}
		if len(a[4]) > 2*nfs.MaxXattrValue {
			return false, errors.New("xattr value exceeds 65536 bytes")
		}
		var value []byte
		value, err = hex.DecodeString(a[4])
		if err == nil {
			err = sess.SetXattr(ctx, a[1], a[2], value, option)
		}
	case "removexattr":
		if err := check(2, 2, "removexattr PATH KEY"); err != nil {
			return false, err
		}
		err = sess.RemoveXattr(ctx, a[1], a[2])
	case "label":
		if err := check(1, 1, "label PATH"); err != nil {
			return false, err
		}
		var label nfs.SecurityLabel
		label, err = sess.GetSecurityLabel(ctx, a[1])
		if err == nil {
			err = json.NewEncoder(s.Out).Encode(struct {
				Format uint32 `json:"format"`
				Policy uint32 `json:"policy"`
				Hex    string `json:"hex"`
			}{label.Format, label.Policy, hex.EncodeToString(label.Data)})
		}
	case "setlabel":
		if err := check(4, 4, "setlabel PATH FORMAT POLICY HEX"); err != nil {
			return false, err
		}
		format, first := strconv.ParseUint(a[2], 10, 32)
		policy, second := strconv.ParseUint(a[3], 10, 32)
		if first != nil || second != nil {
			return false, errors.New("label format and policy must be decimal uint32 values")
		}
		if len(a[4]) > 2*nfs.MaxSecurityLabel {
			return false, errors.New("security label exceeds 4096 bytes")
		}
		var data []byte
		data, err = hex.DecodeString(a[4])
		if err == nil {
			err = sess.SetSecurityLabel(ctx, a[1], nfs.SecurityLabel{Format: uint32(format), Policy: uint32(policy), Data: data})
		}
	case "advise":
		if err := check(4, 4, "advise PATH OFFSET LENGTH HINT[,HINT...]"); err != nil {
			return false, err
		}
		offset, first := strconv.ParseUint(a[2], 10, 64)
		length, second := strconv.ParseUint(a[3], 10, 64)
		if first != nil || second != nil {
			return false, errors.New("advice offset and length must be decimal uint64 values")
		}
		hints, parseErr := nfs.ParseAdvice(a[4])
		if parseErr != nil {
			return false, parseErr
		}
		if err := nfs.ValidateAdvice(offset, length, hints); err != nil {
			return false, err
		}
		var result nfs.AdviceResult
		result, err = sess.Advise(ctx, a[1], offset, length, hints)
		if err == nil {
			err = json.NewEncoder(s.Out).Encode(result)
		}
	case "seek":
		if err := check(3, 3, "seek PATH OFFSET data|hole"); err != nil {
			return false, err
		}
		offset, parseErr := strconv.ParseUint(a[2], 10, 64)
		if parseErr != nil || (a[3] != "data" && a[3] != "hole") {
			return false, errors.New("seek requires a decimal uint64 offset and data or hole")
		}
		var result nfs.SeekResult
		result, err = sess.Seek(ctx, a[1], offset, a[3] == "hole")
		if err == nil {
			err = json.NewEncoder(s.Out).Encode(result)
		}
	case "allocate", "deallocate":
		if err := check(3, 3, a[0]+" PATH OFFSET LENGTH"); err != nil {
			return false, err
		}
		offset, first := strconv.ParseUint(a[2], 10, 64)
		length, second := strconv.ParseUint(a[3], 10, 64)
		if first != nil || second != nil {
			return false, errors.New("space offset and length must be decimal uint64 values")
		}
		if a[0] == "allocate" {
			err = sess.Allocate(ctx, a[1], offset, length)
		} else {
			err = sess.Deallocate(ctx, a[1], offset, length)
		}
	case "cat", "hex":
		if err := check(1, 1, a[0]+" PATH"); err != nil {
			return false, err
		}
		if a[0] == "hex" || s.Terminal {
			err = s.preview(ctx, a[1], a[0] == "hex")
		} else {
			_, err = sess.Cat(ctx, a[1], s.Out)
		}
	case "replace":
		if err := check(2, 2, "replace LOCAL REMOTE"); err != nil {
			return false, err
		}
		p := newProgress(s.Err, "replace", s.local(a[1]), a[2], s.ProgressMode, s.ErrTerminal, s.ErrColor)
		var count int64
		count, err = sess.Replace(ctx, s.local(a[1]), a[2], p.Update)
		p.Finish(count, err)
	case "getrange", "putrange":
		usage, countArgs := "putrange LOCAL REMOTE OFFSET", 3
		if a[0] == "getrange" {
			usage, countArgs = "getrange REMOTE LOCAL OFFSET LENGTH", 4
		}
		if err := check(countArgs, countArgs, usage); err != nil {
			return false, err
		}
		offset, parseErr := strconv.ParseUint(a[3], 10, 64)
		if parseErr != nil {
			return false, errors.New("range offset must be a decimal uint64")
		}
		var count int64
		p := newProgress(s.Err, a[0], a[1], a[2], s.ProgressMode, s.ErrTerminal, s.ErrColor)
		if a[0] == "getrange" {
			length, parseErr := strconv.ParseUint(a[4], 10, 64)
			if parseErr != nil {
				return false, errors.New("range length must be a decimal uint64")
			}
			count, err = sess.GetRange(ctx, a[1], s.local(a[2]), offset, length, p.Update)
		} else {
			count, err = sess.PutRange(ctx, s.local(a[1]), a[2], offset, p.Update)
		}
		p.Finish(count, err)
	case "reput":
		if err := check(2, 2, "reput LOCAL REMOTE"); err != nil {
			return false, err
		}
		p := newProgress(s.Err, "reput", s.local(a[1]), a[2], s.ProgressMode, s.ErrTerminal, s.ErrColor)
		var count int64
		count, err = sess.PutResume(ctx, s.local(a[1]), a[2], p.Update)
		p.Finish(count, err)
	case "getpnfs", "putrangepnfs", "putpnfs":
		start, minimum, maximum := 3, 3, 200
		usage := "getpnfs REMOTE LOCAL [--layout file|flex|block|object] [--osd-target iscsi://IP:PORT/IQN/LUN ... --osd-initiator IQN] [--block-volume LOCAL_IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN] [--read-failover|--mirror-failover|--refresh-devices|--session-trunking] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] ADVERTISED_IP:PORT=APPROVED_IP:PORT[@TLS_NAME] [...]"
		if a[0] == "putrangepnfs" {
			start, minimum, maximum = 4, 4, 200
			usage = "putrangepnfs LOCAL REMOTE OFFSET [--layout file|flex|block] [--block-write --block-volume LOCAL_IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN] [--extend] [--block-journal STATE] [--block-resume] [--write-failover] [--refresh-devices] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] ADVERTISED_IP:PORT=APPROVED_IP:PORT[@TLS_NAME] [...]"
		} else if a[0] == "putpnfs" {
			maximum = 198
			usage = "putpnfs LOCAL REMOTE [--layout file|flex|block] [--block-journal STATE] [--block-write --block-volume IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] ADVERTISED_IP:PORT=APPROVED_IP:PORT[@TLS_NAME] [...]"
		}
		if err := check(minimum, maximum, usage); err != nil {
			return false, err
		}
		var offset uint64
		if a[0] == "putrangepnfs" {
			offset, err = strconv.ParseUint(a[3], 10, 64)
			if err != nil {
				return false, errors.New("range offset must be a decimal uint64")
			}
		}
		options := nfs.PNFSOptions{DataServers: map[string]string{}, TLSNames: map[string]string{}, SPNs: map[string]string{}}
		for i := start; i < len(a); i++ {
			mapping := a[i]
			if mapping == "--object-write" {
				if a[0] != "putrangepnfs" || options.ObjectWrite {
					return false, errors.New("--object-write is accepted once for putrangepnfs")
				}
				options.ObjectWrite = true
				continue
			}
			if mapping == "--block-write" {
				if a[0] == "getpnfs" || options.BlockWrite {
					return false, errors.New("--block-write is accepted once for putpnfs/putrangepnfs")
				}
				options.BlockWrite = true
				continue
			}
			if mapping == "--block-journal" {
				if a[0] == "getpnfs" || i+1 >= len(a) || options.BlockJournal != "" || strings.HasPrefix(a[i+1], "--") {
					return false, errors.New("--block-journal requires one local state file for block writes")
				}
				i++
				options.BlockJournal = s.local(a[i])
				continue
			}
			if mapping == "--block-resume" {
				if a[0] != "putrangepnfs" || options.BlockResume {
					return false, errors.New("--block-resume is accepted once for putrangepnfs with a fresh whole-file lock")
				}
				options.BlockResume = true
				continue
			}
			if mapping == "--osd-secure" {
				if options.OSDRequireSecure {
					return false, errors.New("--osd-secure may be selected once")
				}
				options.OSDRequireSecure = true
				continue
			}
			if mapping == "--block-security" || mapping == "--osd-security" {
				if i+1 >= len(a) || strings.HasPrefix(a[i+1], "--") || mapping == "--osd-security" && a[0] != "getpnfs" && a[0] != "putrangepnfs" {
					return false, errors.New("storage security requires TARGET_URL=PROFILE_FILE")
				}
				i++
				target, path, ok := strings.Cut(a[i], "=")
				if !ok || target == "" || path == "" {
					return false, errors.New("storage security requires TARGET_URL=PROFILE_FILE")
				}
				policy, err := iscsi.LoadSecurity(s.local(path))
				if err != nil {
					return false, err
				}
				policies := &options.BlockSecurity
				if mapping == "--osd-security" {
					policies = &options.OSDSecurity
				}
				if *policies == nil {
					*policies = map[string]iscsi.Security{}
				}
				if _, ok := (*policies)[target]; ok || len(*policies) >= 64 {
					return false, errors.New("duplicate or excessive storage security policy")
				}
				(*policies)[target] = policy
				continue
			}
			if mapping == "--block-alternate" {
				if a[0] != "getpnfs" || i+1 >= len(a) {
					return false, errors.New("--block-alternate requires PRIMARY_URL=ALTERNATE_URL for getpnfs")
				}
				i++
				primary, alternate, ok := strings.Cut(a[i], "=")
				if !ok {
					return false, errors.New("--block-alternate requires PRIMARY_URL=ALTERNATE_URL")
				}
				if _, err := iscsi.ParseTarget(primary); err != nil {
					return false, err
				}
				if _, err := iscsi.ParseTarget(alternate); err != nil {
					return false, err
				}
				if options.BlockReadAlternates == nil {
					options.BlockReadAlternates = map[string][]string{}
				}
				if len(options.BlockReadAlternates) >= 64 || len(options.BlockReadAlternates[primary]) >= 8 {
					return false, errors.New("too many approved block read portals")
				}
				options.BlockReadAlternates[primary] = append(options.BlockReadAlternates[primary], alternate)
				continue
			}
			if mapping == "--block-target" {
				if i+1 >= len(a) || strings.HasPrefix(a[i+1], "--") || len(options.BlockTargets) == 64 {
					return false, errors.New("--block-target requires iscsi://IP:PORT/IQN/LUN (up to 64 approvals)")
				}
				i++
				options.BlockTargets = append(options.BlockTargets, a[i])
				continue
			}
			if mapping == "--osd-target" {
				if a[0] != "getpnfs" && a[0] != "putrangepnfs" || i+1 >= len(a) || strings.HasPrefix(a[i+1], "--") || len(options.OSDTargets) == 64 {
					return false, errors.New("--osd-target requires an explicit OSD iSCSI URL for getpnfs/putrangepnfs")
				}
				i++
				options.OSDTargets = append(options.OSDTargets, a[i])
				continue
			}
			if mapping == "--osd-initiator" {
				if a[0] != "getpnfs" && a[0] != "putrangepnfs" || i+1 >= len(a) || options.OSDInitiator != "" || strings.HasPrefix(a[i+1], "--") {
					return false, errors.New("--osd-initiator requires one explicit IQN for getpnfs/putrangepnfs")
				}
				i++
				options.OSDInitiator = a[i]
				continue
			}
			if mapping == "--block-initiator" {
				if i+1 >= len(a) || options.BlockInitiator != "" || strings.HasPrefix(a[i+1], "--") {
					return false, errors.New("--block-initiator requires one explicit IQN")
				}
				i++
				options.BlockInitiator = a[i]
				continue
			}
			if mapping == "--block-volume" {
				if i+1 >= len(a) || strings.HasPrefix(a[i+1], "--") || len(options.BlockVolumes) == 64 {
					return false, errors.New("pNFS commands accept up to 64 --block-volume LOCAL_IMAGE options")
				}
				i++
				options.BlockVolumes = append(options.BlockVolumes, s.local(a[i]))
				continue
			}
			if mapping == "--session-trunking" {
				if a[0] != "getpnfs" || options.SessionTrunking {
					return false, errors.New("--session-trunking is accepted once for getpnfs")
				}
				options.SessionTrunking = true
				continue
			}
			if mapping == "--refresh-devices" {
				if options.RefreshDevices {
					return false, errors.New("--refresh-devices is accepted once")
				}
				options.RefreshDevices = true
				continue
			}
			if mapping == "--write-failover" {
				if a[0] == "getpnfs" || options.WriteFailover {
					return false, errors.New("--write-failover is accepted once for putpnfs or putrangepnfs")
				}
				options.WriteFailover = true
				continue
			}
			if mapping == "--layout" {
				if options.Layout != "" || i+1 >= len(a) {
					return false, errors.New("pNFS commands accept one --layout file|flex|block|object")
				}
				i++
				if a[i] != "file" && a[i] != "flex" && a[i] != "block" && a[i] != "object" {
					return false, errors.New("pNFS layout must be file, flex, block or object")
				}
				options.Layout = a[i]
				continue
			}
			if mapping == "--mirror-failover" {
				if a[0] != "getpnfs" || options.MirrorFailover {
					return false, errors.New("--mirror-failover is accepted once for getpnfs")
				}
				options.MirrorFailover = true
				continue
			}
			if mapping == "--read-failover" {
				if a[0] != "getpnfs" || options.ReadFailover {
					return false, errors.New("--read-failover is accepted once for getpnfs")
				}
				options.ReadFailover = true
				continue
			}
			if mapping == "--ds-spn" {
				if i+1 >= len(a) {
					return false, errors.New("--ds-spn requires TARGET=nfs/HOST")
				}
				i++
				target, spn, ok := strings.Cut(a[i], "=")
				if !ok || target == "" || spn == "" || options.SPNs[target] != "" {
					return false, errors.New("invalid or duplicate pNFS DS SPN")
				}
				options.SPNs[target] = spn
				continue
			}
			if mapping == "--extend" {
				if a[0] != "putrangepnfs" || options.Extend {
					return false, errors.New("--extend is accepted once for putrangepnfs")
				}
				options.Extend = true
				continue
			}
			if mapping == "--parallel" {
				if options.Parallelism != 0 || i+1 >= len(a) {
					return false, errors.New("pNFS needs one --parallel value in 1..8")
				}
				i++
				value, parseErr := strconv.Atoi(a[i])
				if parseErr != nil || value < 1 || value > 8 {
					return false, errors.New("pNFS parallelism must be 1..8")
				}
				options.Parallelism = value
				continue
			}
			from, to, ok := strings.Cut(mapping, "=")
			if !ok || options.DataServers[from] != "" {
				return false, errors.New("invalid or duplicate pNFS mapping")
			}
			to, name, hasName := strings.Cut(to, "@")
			if hasName {
				if name == "" || options.TLSNames[to] != "" && options.TLSNames[to] != name {
					return false, errors.New("empty or conflicting pNFS TLS name")
				}
				options.TLSNames[to] = name
			}
			options.DataServers[from] = to
		}
		if options.Layout == "object" {
			if a[0] != "getpnfs" && (a[0] != "putrangepnfs" || !options.ObjectWrite) || options.Extend {
				return false, errors.New("object writes require putrangepnfs --object-write without --extend")
			}
		} else if options.ObjectWrite || options.OSDRequireSecure || len(options.OSDSecurity) != 0 || len(options.OSDTargets) != 0 || options.OSDInitiator != "" {
			return false, errors.New("OSD options require --layout object")
		} else if options.Layout == "block" {
			if options.BlockResume && options.BlockJournal == "" {
				return false, errors.New("--block-resume requires --block-journal")
			}
			if a[0] != "getpnfs" && !options.BlockWrite {
				return false, errors.New("block writes require --block-write")
			}
			if options.ReadFailover && (a[0] != "getpnfs" || len(options.BlockTargets) == 0) || len(options.BlockReadAlternates) != 0 && !options.ReadFailover {
				return false, errors.New("block read failover requires getpnfs and approved iSCSI targets")
			}
			if len(options.BlockVolumes)+len(options.BlockTargets) == 0 || len(options.BlockVolumes)+len(options.BlockTargets) > 64 || len(options.DataServers) != 0 || len(options.SPNs) != 0 || len(options.TLSNames) != 0 || options.WriteFailover || options.MirrorFailover || options.RefreshDevices || options.SessionTrunking || options.Parallelism > 1 {
				return false, errors.New("block I/O needs 1..64 approved images/targets without DS, parallel or recovery options")
			}
		} else if len(options.BlockReadAlternates) != 0 || len(options.BlockSecurity) != 0 || len(options.BlockVolumes) != 0 || len(options.BlockTargets) != 0 || options.BlockInitiator != "" || options.BlockWrite || options.BlockJournal != "" || options.BlockResume {
			return false, errors.New("block volumes require --layout block")
		} else if len(options.DataServers) == 0 {
			return false, errors.New("pNFS requires explicit DS endpoint mappings")
		}
		p := newProgress(s.Err, "getpnfs", a[1], s.local(a[2]), s.ProgressMode, s.ErrTerminal, s.ErrColor)
		var count int64
		if a[0] == "putrangepnfs" {
			p = newProgress(s.Err, a[0], s.local(a[1]), a[2], s.ProgressMode, s.ErrTerminal, s.ErrColor)
			count, err = sess.PutPNFSRange(ctx, s.local(a[1]), a[2], offset, options, p.Update)
		} else if a[0] == "putpnfs" {
			p = newProgress(s.Err, a[0], s.local(a[1]), a[2], s.ProgressMode, s.ErrTerminal, s.ErrColor)
			count, err = sess.PutPNFS(ctx, s.local(a[1]), a[2], options, p.Update)
		} else {
			count, err = sess.GetPNFS(ctx, a[1], s.local(a[2]), options, p.Update)
		}
		p.Finish(count, err)
	case "getplus":
		if err := check(2, 2, "getplus REMOTE LOCAL"); err != nil {
			return false, err
		}
		p := newProgress(s.Err, "getplus", a[1], s.local(a[2]), s.ProgressMode, s.ErrTerminal, s.ErrColor)
		var count int64
		count, err = sess.GetPlus(ctx, a[1], s.local(a[2]), p.Update)
		p.Finish(count, err)
	case "gettree", "puttree":
		options := session.TreeOptions{}
		args := a[1:]
		for len(args) > 0 && strings.HasPrefix(args[0], "--") {
			switch args[0] {
			case "--merge":
				options.Merge = true
			case "--links":
				options.Links = true
			case "--hardlinks":
				options.Hardlinks = true
			case "--preserve-mode":
				options.Mode = true
			case "--preserve-mtime":
				options.MTime = true
			default:
				return false, fmt.Errorf("unknown tree option %q", args[0])
			}
			args = args[1:]
		}
		if len(args) != 2 || strings.HasPrefix(args[0], "--") {
			return false, fmt.Errorf("usage: %s [--merge] [--links] [--hardlinks] [--preserve-mode] [--preserve-mtime] SOURCE DESTINATION", a[0])
		}
		var count int64
		if a[0] == "gettree" {
			count, err = sess.GetTreeWithOptions(ctx, args[0], s.local(args[1]), options, nil)
		} else {
			count, err = sess.PutTreeWithOptions(ctx, s.local(args[0]), args[1], options, nil)
		}
		if err == nil {
			fmt.Fprintf(s.Err, "Transferred tree: %d file bytes.\n", count)
		}
	case "get", "put", "reget":
		if err := check(1, 2, a[0]+" SOURCE [DESTINATION]"); err != nil {
			return false, err
		}
		if a[0] == "get" || a[0] == "reget" {
			local := path.Base(a[1])
			if argc == 2 {
				local = a[2]
			}
			// A remote basename must not become a Windows drive or path.
			if argc == 1 && (strings.ContainsAny(local, "\\:") || local == "." || local == ".." || local == "/") {
				return false, errors.New("specify an explicit local filename")
			}
			if a[0] == "reget" {
				p := newProgress(s.Err, "reget", a[1], s.local(local), s.ProgressMode, s.ErrTerminal, s.ErrColor)
				var count int64
				if len(referrals) != 0 {
					func() {
						notice := sess.Notice
						sess.Notice = s.Err
						defer func() { sess.Notice = notice }()
						count, err = sess.GetResumeReferrals(ctx, a[1], s.local(local), referrals, p.Update)
					}()
				} else if len(failover) != 0 {
					func() {
						notice := sess.Notice
						sess.Notice = s.Err
						defer func() { sess.Notice = notice }()
						count, err = sess.GetResumeFailover(ctx, a[1], s.local(local), failover, p.Update)
					}()
				} else if reclaim {
					count, err = sess.GetResumeReclaim(ctx, a[1], s.local(local), p.Update)
				} else {
					count, err = sess.GetResumeRetry(ctx, a[1], s.local(local), retries, p.Update)
				}
				p.Finish(count, err)
			} else {
				err = s.transfer(ctx, "get", a[1], s.local(local))
			}
		} else {
			remote := filepath.Base(a[1])
			if argc == 2 {
				remote = a[2]
			}
			err = s.transfer(ctx, "put", s.local(a[1]), remote)
		}
	case "chmod":
		if err := check(2, 2, "chmod OCTAL PATH"); err != nil {
			return false, err
		}
		var mode uint32
		mode, err = parseMode(a[1])
		if err == nil {
			err = sess.Chmod(ctx, a[2], mode)
		}
	case "mkdir":
		if err := check(1, 1, "mkdir PATH"); err != nil {
			return false, err
		}
		err = sess.Mkdir(ctx, a[1])
	case "rm", "rmdir":
		if err := check(1, 1, a[0]+" PATH"); err != nil {
			return false, err
		}
		if a[0] == "rm" {
			err = sess.Remove(ctx, a[1])
		} else {
			err = sess.Rmdir(ctx, a[1])
		}
	case "mv":
		if err := check(2, 2, "mv SOURCE DESTINATION (exact name; may replace destination)"); err != nil {
			return false, err
		}
		err = sess.RenameReplace(ctx, a[1], a[2])
	case "id":
		if err := check(0, 0, "id"); err != nil {
			return false, err
		}
		err = s.printSession(s.Out, s.Color)
	case "uid":
		if len(sess.Client.Locks()) != 0 {
			return false, nfs.ErrLocksHeld
		}
		if sess.Client.Security() != "sys" {
			return false, errors.New("kerberos identity is fixed for this connection; reconnect with --principal")
		}
		if err := check(1, 3, "uid UID [GID [G1,G2,...]]"); err != nil {
			return false, err
		}
		auth := sess.BaseAuth
		n, parseErr := strconv.ParseUint(a[1], 10, 32)
		if parseErr != nil {
			return false, errors.New("UID must be an unsigned 32-bit integer")
		}
		auth.UID = uint32(n)
		if argc >= 2 {
			n, parseErr = strconv.ParseUint(a[2], 10, 32)
			if parseErr != nil {
				return false, errors.New("GID must be an unsigned 32-bit integer")
			}
			auth.GID = uint32(n)
		}
		if argc == 3 {
			auth.Groups, err = parseGroups(a[3])
			if err != nil {
				return false, err
			}
		}
		sess.BaseAuth, sess.Client.Auth, sess.AutoUID = auth, auth, false
	case "uid-scan":
		if err := check(1, 3, "uid-scan PATH [START END]"); err != nil {
			return false, err
		}
		var start, end uint32
		if argc >= 2 {
			n, parseErr := strconv.ParseUint(a[2], 10, 32)
			if parseErr != nil {
				return false, errors.New("START must be an unsigned 32-bit integer")
			}
			start = uint32(n)
		}
		if argc == 3 {
			n, parseErr := strconv.ParseUint(a[3], 10, 32)
			if parseErr != nil {
				return false, errors.New("END must be an unsigned 32-bit integer")
			}
			end = uint32(n)
		} else if argc < 2 {
			end = 65535
		} else {
			end = 65535
		}
		if end < start {
			return false, errors.New("END must be >= START")
		}
		target := a[1]
		n, _, resolveErr := sess.Resolve(ctx, target, false)
		if resolveErr != nil {
			return false, resolveErr
		}
		const maxHits = 20
		found, scanErr := sess.UIDScan(ctx, n.Handle, start, end, maxHits)
		if scanErr != nil {
			return false, scanErr
		}
		if len(found) == 0 {
			fmt.Fprintln(s.Out, "No UID with read access found in the scanned range.")
		} else {
			for _, uid := range found {
				fmt.Fprintf(s.Out, "UID %d has read access\n", uid)
			}
			if len(found) == maxHits {
				fmt.Fprintf(s.Out, "(stopped after %d hits)\n", maxHits)
			}
		}
	case "auto-uid-scan":
		if err := check(1, 1, "auto-uid-scan on|off"); err != nil {
			return false, err
		}
		if a[1] != "on" && a[1] != "off" {
			return false, errors.New("expected on or off")
		}
		if a[1] == "on" && sess.Client.Security() != "sys" {
			return false, errors.New("auto-uid-scan requires AUTH_SYS")
		}
		sess.AutoUIDScan = a[1] == "on"
	case "auto-uid", "auto-escape":
		if err := check(1, 1, a[0]+" on|off"); err != nil {
			return false, err
		}
		if a[1] != "on" && a[1] != "off" {
			return false, errors.New("expected on or off")
		}
		if a[0] == "auto-uid" {
			if a[1] == "on" && sess.Client.Version() != "3" {
				return false, errors.New("auto-uid is only available with NFSv3; use uid for an explicit identity")
			}
			if a[1] == "on" && sess.Client.Security() != "sys" {
				return false, errors.New("automatic UID selection requires AUTH_SYS; Kerberos identity is server-mapped")
			}
			sess.AutoUID = a[1] == "on"
			if !sess.AutoUID {
				sess.Client.Auth = sess.BaseAuth
			}
		} else {
			v := sess.Client.Version()
			if a[1] == "on" && v != "2" && v != "3" && !strings.HasPrefix(v, "4") {
				return false, errors.New("auto-escape requires NFSv2, NFSv3, or NFSv4")
			}
			sess.AutoEscape = a[1] == "on"
		}
	case "root":
		if err := check(0, 1, "root [info|verify|reset|discovered|probe]"); err != nil {
			return false, err
		}
		action := "info"
		if argc == 1 {
			action = a[1]
		}
		err = s.rootCommand(ctx, action)
	case "escape":
		if err := check(0, 0, "escape"); err != nil {
			return false, err
		}
		var ok bool
		ok, err = sess.Escape(ctx)
		sess.ProbeError = err
		if err == nil && !ok {
			fmt.Fprintln(s.Err, "No accessible filesystem-root candidate found.")
		}
		if err == nil {
			err = s.printReady(s.Err, s.ErrColor)
		}
	case "squash":
		if err := check(0, 0, "squash"); err != nil {
			return false, err
		}
		var noSquash bool
		noSquash, err = sess.ProbeSquash(ctx)
		if err == nil {
			if noSquash {
				fmt.Fprintln(s.Out, "no_root_squash active: UID 0 was preserved by the server.")
			} else {
				fmt.Fprintln(s.Out, "root_squash active: UID 0 was remapped by the server.")
			}
		}
	case "lls":
		if err := check(0, 1, "lls [PATH]"); err != nil {
			return false, err
		}
		err = s.listLocal(optional())
	case "lpwd":
		if err := check(0, 0, "lpwd"); err != nil {
			return false, err
		}
		fmt.Fprintln(s.Out, label(s.LocalDir))
	case "lcd":
		if err := check(1, 1, "lcd PATH"); err != nil {
			return false, err
		}
		p := s.local(a[1])
		var info os.FileInfo
		info, err = os.Stat(p)
		if err == nil {
			if !info.IsDir() {
				return false, errors.New("not a local directory")
			}
			s.LocalDir = p
		}
	default:
		return false, fmt.Errorf("unknown command %q; type help", a[0])
	}
	return false, err
}

// RunBatch stops at the first failure and emits no prompts or terminal controls.
func (s *Shell) RunBatch(ctx context.Context, in io.Reader) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		exit, err := s.Execute(ctx, scanner.Text())
		if err != nil {
			return err
		}
		if exit {
			return nil
		}
	}
	return scanner.Err()
}

func (s *Shell) RunInteractive(ctx context.Context, history string) error {
	return s.runInteractive(ctx, history, nil)
}

func (s *Shell) runInteractive(parent context.Context, history string, configure func(*readline.Config)) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	interrupts := &interruptState{quit: cancel}
	cfg := &readline.Config{Prompt: "nfs> ", HistoryFile: history, HistoryLimit: 500, DisableAutoSaveHistory: true, AutoComplete: &completer{shell: s, ctx: ctx}, Stdout: s.Out, Stderr: s.Err, InterruptPrompt: "^C", EOFPrompt: "exit", FuncFilterInputRune: interrupts.filter}
	if configure != nil {
		configure(cfg)
	}
	if cfg.Stdin == nil {
		cfg.Stdin = readline.NewCancelableStdin(readline.Stdin)
	}
	input := &choiceInput{ReadCloser: cfg.Stdin}
	cfg.Stdin = input
	rl, err := readline.NewEx(cfg)
	if err != nil {
		return err
	}
	defer rl.Close()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-signals:
				interrupts.press()
			case <-ctx.Done():
				_ = rl.Close()
				return
			case <-done:
				return
			}
		}
	}()
	defer func() { close(done); <-stopped }()
	hint := func() { fmt.Fprintln(s.Err, "  Ctrl+C again to exit; any other key continues.") }
	previousAsk := s.Ask
	s.Ask = func(prompt string) (string, error) {
		rl.SetPrompt(prompt)
		defer func() { rl.SetPrompt(s.prompt(ctx)) }()
		return rl.Readline()
	}
	defer func() { s.Ask = previousAsk }()
	previousChoice := s.AskChoice
	s.AskChoice = func(prompt, keys string) (string, error) {
		input.choices(keys)
		defer input.choices("")
		return s.Ask(prompt)
	}
	defer func() { s.AskChoice = previousChoice }()
	for {
		rl.SetPrompt(s.prompt(ctx))
		line, err := rl.Readline()
		if _, exiting := interrupts.status(); exiting {
			return nil
		}
		if parent.Err() != nil {
			return parent.Err()
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, readline.ErrInterrupt) {
			hint()
			continue
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) != "" {
			_ = rl.SaveHistory(line)
		}
		operation, finish := interrupts.begin(ctx)
		exit, err := s.Execute(operation, line)
		finish()
		if _, exiting := interrupts.status(); exiting {
			return nil
		}
		if err != nil {
			fmt.Fprintf(s.Err, "%s %v\n", paint(s.ErrColor, red, "Error:"), err)
		} else if exit {
			return nil
		}
		if armed, _ := interrupts.status(); armed {
			hint()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

type completer struct {
	shell *Shell
	ctx   context.Context
}

func (c *completer) Do(line []rune, pos int) ([][]rune, int) {
	if pos < 0 || pos > len(line) {
		return nil, 0
	}
	text := string(line[:pos])
	a, err := SplitLine(text)
	if err != nil {
		return nil, 0
	}
	if pos == 0 || unicode.IsSpace(line[pos-1]) {
		a = append(a, "")
	}
	if len(a) == 0 {
		return nil, 0
	}
	prefix := a[len(a)-1]
	var values []string
	if len(a) == 1 {
		values = commands
	} else {
		ctx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
		defer cancel()
		if a[0] == "root" && len(a) == 2 {
			values = []string{"info", "verify", "reset", "discovered", "probe"}
		} else if (a[0] == "lock" || a[0] == "locktest") && len(a) == 3 {
			values = []string{"read", "write"}
		} else if (a[0] == "lock" || a[0] == "locktest") && len(a) == 5 {
			values = []string{"eof"}
		} else if a[0] == "unlock" && len(a) == 2 {
			for _, l := range c.shell.Session.Client.Locks() {
				values = append(values, strconv.FormatUint(l.ID, 10))
			}
		} else if a[0] == "reconnect" && len(a) == 2 {
			values = []string{"--discard-locks", "--reclaim-locks"}
		} else if a[0] == "use" && len(a) == 2 {
			exports, err := c.shell.Session.Client.Exports(ctx)
			if err != nil {
				return nil, 0
			}
			for _, e := range exports {
				values = append(values, e.Path)
			}
		} else {
			local := a[0] == "put" && len(a) == 2 || (a[0] == "get" || a[0] == "getacl" || a[0] == "setacl") && len(a) == 3 || (a[0] == "lcd" || a[0] == "lls") && len(a) == 2
			remote := (a[0] == "lock" || a[0] == "locktest" || a[0] == "cd" || a[0] == "ls" || a[0] == "stat" || a[0] == "acl" || a[0] == "getacl" || a[0] == "setacl" || a[0] == "label" || a[0] == "setlabel" || a[0] == "xattrs" || a[0] == "getxattr" || a[0] == "setxattr" || a[0] == "removexattr" || a[0] == "cat" || a[0] == "hex" || a[0] == "get" || a[0] == "mkdir") && len(a) == 2 || (a[0] == "chmod" || a[0] == "put") && len(a) == 3
			if !local && !remote {
				return nil, 0
			}
			if local {
				dir, _ := filepath.Split(prefix)
				entries, err := os.ReadDir(c.shell.local(dir))
				if err != nil {
					return nil, 0
				}
				for _, e := range entries {
					if a[0] == "lcd" && !e.IsDir() {
						continue
					}
					name := dir + e.Name()
					if e.IsDir() {
						name += string(filepath.Separator)
					}
					values = append(values, name)
				}
			} else {
				dir, _ := path.Split(prefix)
				if dir == "" {
					dir = "."
				}
				old := c.shell.Session.Client.Auth
				inspection := *c.shell.Session
				if a[0] == "acl" || a[0] == "getacl" || a[0] == "setacl" {
					inspection.AutoUID = false
				}
				entries, err := inspection.LS(ctx, dir)
				c.shell.Session.Client.Auth = old
				if err != nil {
					return nil, 0
				}
				base, _ := path.Split(prefix)
				for _, e := range entries {
					if a[0] == "cd" && e.Attr.Type != 2 {
						continue
					}
					name := base + e.Name
					if e.Attr.Type == 2 {
						name += "/"
					}
					values = append(values, name)
				}
			}
		}
	}
	var out [][]rune
	for _, value := range values {
		if !strings.HasPrefix(value, prefix) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			continue
		}
		suffix := strings.TrimPrefix(value, prefix)
		suffix = strings.NewReplacer(" ", "\\ ", "'", "\\'", "\"", "\\\"").Replace(suffix)
		if !strings.HasSuffix(value, "/") && !strings.HasSuffix(value, "\\") {
			suffix += " "
		}
		out = append(out, []rune(suffix))
	}
	return out, len([]rune(prefix))
}

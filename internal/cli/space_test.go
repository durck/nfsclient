package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestSpaceCommandValidation(t *testing.T) {
	sh := &Shell{Out: io.Discard, Err: io.Discard}
	for _, command := range []string{"seek", "seek file -1 hole", "seek file 0 what", "seek file 18446744073709551616 data", "allocate file 0", "allocate file -1 1", "allocate file 0 0", "deallocate file 0 eof", "deallocate file 18446744073709551615 1"} {
		if _, err := sh.Execute(context.Background(), command); err == nil {
			t.Fatal("invalid syntax accepted", command)
		}
	}
}

func TestAdviceCommandValidation(t *testing.T) {
	sh := &Shell{Out: io.Discard, Err: io.Discard}
	for _, command := range []string{"advise", "advise file 0 0", "advise file -1 1 normal", "advise file 0 eof read", "advise file 0 0 unknown", "advise file 18446744073709551615 1 sequential"} {
		if _, err := sh.Execute(context.Background(), command); err == nil {
			t.Fatal("invalid advice syntax accepted", command)
		}
	}
}

func TestCopyCommandValidation(t *testing.T) {
	sh := &Shell{Out: io.Discard, Err: io.Discard}
	for _, command := range []string{"copyrange", "clonerange a b 0 0", "copyrange a b -1 0 1", "copyrange a b 0 0 0", "clonerange a b 18446744073709551615 0 1", "copyrange a b 0 18446744073709551615 1"} {
		if _, err := sh.Execute(context.Background(), command); err == nil {
			t.Fatal("invalid copy syntax accepted", command)
		}
	}
}

func TestOffloadCommandValidation(t *testing.T) {
	sh := &Shell{Out: io.Discard, Err: io.Discard}
	for _, command := range []string{
		"writeadb", "writeadb a 0 0 1 1s", "writeadb a -1 4096 1 1s", "writeadb a 0 4096 0 1s",
		"writeadb a 0 4096 1 0s", "writeadb a 0 4096 1 1s --number 0 4294967296",
		"writeadb a 0 4096 1 1s --number 0 1 --number 8 2",
		"writeadb a 0 4096 1 1s --number 0 1 --pattern 7 ff",
		"writeadb a 0 4096 1 1s --pattern 0 zz", "writeadb a 0 4096 1 1s --pattern 0",
		"writeadb a 0 4096 1 1s --unknown 0 1",
		"copyfrom", "copyfrom 192.0.2.1:2049 / a b 0 0 0 1s 192.0.2.2:2049",
		"copyfrom 192.0.2.1:2049 / a b -1 0 1 1s 192.0.2.2:2049",
		"copyfrom 192.0.2.1:2049 / a b 0 0 1 0s 192.0.2.2:2049",
		"copyfrom 192.0.2.1:2049 / a b 0 0 1 1s hostname:2049",
		"copyfrom hostname:2049 / a b 0 0 1 1s 192.0.2.2:2049",
		"copyfrom 192.0.2.1:2049 / a b 0 0 1 1s 192.0.2.2:2049 192.0.2.1:2049 192.0.2.1:2049",
		"copyasync a b 0 0 1", "copyasync a b 0 0 1 0s", "copyasync a b 0 0 1 25h",
		"writesame", "writesame a -1 1 ff 1s", "writesame a 0 0 ff 1s",
		"writesame a 0 1 zz 1s", "writesame a 0 1 f 1s", "writesame a 0 1 ff never",
		"writesame a 0 1 ff -1s", "writesame a 18446744073709551615 1 ff 1s",
		"writesame a 0 18446744073709551615 ffff 1s",
	} {
		if _, err := sh.Execute(context.Background(), command); err == nil {
			t.Fatal("invalid syntax accepted", command)
		}
	}
}

func TestADBArgumentParsing(t *testing.T) {
	for _, suffix := range []string{"", " --number 0 17 --pattern 8 cafe", " --pattern 8 cafe --number 0 17"} {
		b, wait, err := parseADB(strings.Fields("16 4096 3 2s" + suffix))
		if err != nil || b.Offset != 16 || b.BlockSize != 4096 || b.BlockCount != 3 || wait.Seconds() != 2 {
			t.Fatal(b, wait, err)
		}
		if suffix == "" {
			if b.FirstNumber != nil || len(b.Pattern) != 0 {
				t.Fatal("zeroing defaults", b)
			}
		} else if b.FirstNumber == nil || *b.FirstNumber != 17 || b.NumberOffset != 0 || b.PatternOffset != 8 || !bytes.Equal(b.Pattern, []byte{0xca, 0xfe}) {
			t.Fatal("ADB fields", b)
		}
	}
}

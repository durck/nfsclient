//go:build linux

package gssapi

import (
	stdcontext "context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

func nativeASPlatform() error { return nil }

func privateNativeFile(path string, executable bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || !executable && info.Mode().Perm()&0077 != 0 || executable && info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("native AS files must be regular, root/current-user owned and protected; helper must be executable")
	}
	return info, nil
}

func readNativeFile(path string) ([]byte, error) {
	before, err := privateNativeFile(path, false)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("native AS credential file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCCacheSize+1))
	if err != nil {
		clear(b)
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || len(b) > maxCCacheSize {
		clear(b)
		return nil, errors.New("native AS credential file changed or exceeds 4 MiB")
	}
	return b, nil
}

type nativeHelperOutput struct {
	b        [64]byte
	n        int
	overflow bool
}

func (o *nativeHelperOutput) Write(b []byte) (int, error) {
	n := len(b)
	if n > len(o.b)-o.n {
		o.overflow = true
	}
	o.n += copy(o.b[o.n:], b)
	return n, nil
}

func runRequiredFAST(ctx stdcontext.Context, helper, armor, keytab, principal, configuration string) (*credentials.CCache, error) {
	if err := ValidateNativeAS(helper, armor, true); err != nil {
		return nil, err
	}
	armor = strings.TrimPrefix(armor, "FILE:")
	armorBytes, err := readNativeFile(armor)
	if err != nil {
		return nil, err
	}
	defer clear(armorBytes)
	cache, err := parseCCache(armorBytes)
	if err != nil {
		return nil, err
	}
	defer clearNativeCache(cache)
	// Validate the armor TGT using the same strict cache profile, then discard
	// parsed secret copies. Only a private raw copy reaches native libkrb5.
	_, realm, _ := strings.Cut(principal, "@")
	if cache.DefaultPrincipal.Realm != realm {
		return nil, errors.New("FAST armor requires a valid TGT in the selected canonical home realm")
	}
	if err := validateArmorTGT(cache); err != nil {
		return nil, err
	}
	return runNativeAS(ctx, helper, principal, configuration, "fast", "fast-required", []nativeASInput{{"keytab", keytab, nil}, {"armor", armor, armorBytes}})
}

type nativeASInput struct {
	flag, path string
	validated  []byte
}

func runPKINIT(ctx stdcontext.Context, helper, principal, configuration string, p PKINITFiles) (*credentials.CCache, error) {
	if err := ValidatePKINIT(helper, p); err != nil {
		return nil, err
	}
	inputs := []nativeASInput{{"cert", p.Cert, nil}, {"key", p.Key, nil}, {"anchors", p.CA, nil}}
	if p.CRL != "" {
		inputs = append(inputs, nativeASInput{"revoke", p.CRL, nil})
	}
	return runNativeAS(ctx, helper, principal, configuration, "pkinit", "pkinit-required", inputs)
}

func runNativeAS(ctx stdcontext.Context, helper, principal, configuration, mode, record string, inputs []nativeASInput) (*credentials.CCache, error) {
	before, err := privateNativeFile(helper, true)
	if err != nil {
		return nil, err
	}
	helperFile, err := os.Open(helper)
	if err != nil {
		return nil, err
	}
	defer helperFile.Close()
	opened, err := helperFile.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("native AS helper changed while opening")
	}
	dir, err := os.MkdirTemp("", "nfs-viewer-as-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if strings.ContainsAny(dir, ",\r\n\x00") {
		return nil, errors.New("native AS temporary directory has unsafe path syntax")
	}
	configPath, outPath := filepath.Join(dir, "krb5.conf"), filepath.Join(dir, "result")
	args := []string{"--protocol", "1", "--mode", mode, "--principal", principal}
	for _, input := range inputs {
		b := input.validated
		if b == nil {
			b, err = readNativeFile(input.path)
			if err != nil {
				return nil, err
			}
		}
		path := filepath.Join(dir, input.flag)
		err = os.WriteFile(path, b, 0600)
		clear(b)
		if err != nil {
			return nil, err
		}
		args = append(args, "--"+input.flag, "FILE:"+path)
		if input.flag == "revoke" {
			configuration += "[libdefaults]\n pkinit_revoke = " + strconv.Quote("FILE:"+path) + "\n pkinit_require_crl_checking = true\n"
		}
	}
	if mode == "pkinit" && len(inputs) == 3 {
		args = append(args, "--revoke", "-")
	}
	args = append(args, "--output", "FILE:"+outPath)
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = stdcontext.Background()
	}
	ctx, cancel := stdcontext.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, args...)
	// Execute the validated inode, not a pathname that can be replaced between
	// validation and exec. Linux /proc/self/fd resolves the inherited descriptor.
	cmd.Path = "/proc/self/fd/3"
	cmd.ExtraFiles = []*os.File{helperFile}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=" + dir, "TMPDIR=" + dir, "KRB5_CONFIG=" + configPath, "KRB5CCNAME=FILE:" + outPath}
	cmd.Dir = dir
	var output nativeHelperOutput
	defer clear(output.b[:])
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("native AS helper failed; no credential fallback: %w", err)
	}
	after, err := os.Lstat(helper)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("native AS helper changed during execution")
	}
	if output.overflow || string(output.b[:output.n]) != "nfs-viewer-as-helper/1 "+record+"\n" {
		return nil, errors.New("native AS helper did not confirm the required authentication protocol")
	}
	b, err := readNativeFile(outPath)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	result, err := parseCCache(b)
	if err != nil {
		return nil, err
	}
	name, realm, ok := strings.Cut(principal, "@")
	if !ok || result.DefaultPrincipal.Realm != realm || result.DefaultPrincipal.PrincipalName.PrincipalNameString() != name {
		clearNativeCache(result)
		return nil, errors.New("native AS cache differs from selected canonical principal")
	}
	return result, nil
}

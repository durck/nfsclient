package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func (s *Shell) destination(ctx context.Context, operation, name string) (exists, regular bool, err error) {
	if operation == "get" {
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return false, false, nil
		}
		if err != nil {
			return false, false, err
		}
		return true, info.Mode().IsRegular(), nil
	}
	n, _, err := s.Session.Resolve(ctx, name, false)
	var status nfs.Status
	if errors.As(err, &status) && status == 2 {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, n.Attr.Type == 1, nil
}

func (s *Shell) transfer(ctx context.Context, operation, source, destination string) error {
	overwrite := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		exists, regular, err := s.destination(ctx, operation, destination)
		if err != nil {
			return err
		}
		if !exists {
			break
		}
		legacyUpload := operation == "put" && (s.Session.Client.Version() == "2" || s.Session.Client.Version() == "3")
		if s.Ask == nil && s.AskChoice == nil {
			if legacyUpload && regular {
				return fmt.Errorf("%w: %s (choose another destination; NFSv2/v3 upload replacement cannot preserve ACLs)", session.ErrDestinationExists, label(destination))
			}
			return fmt.Errorf("%w: %s (choose another destination; interactive mode offers overwrite or rename)", session.ErrDestinationExists, label(destination))
		}
		fmt.Fprintf(s.Err, "\n  %s %s\n", paint(s.ErrColor, orange, "EXISTS"), label(destination))
		choices, keys := "[o] overwrite  [r] rename  [c] cancel (Enter): ", "orc"
		if !regular {
			choices, keys = "[r] rename  [c] cancel (not a regular file): ", "rc"
		} else if legacyUpload {
			fmt.Fprintln(s.Err, "  Overwrite unavailable: NFSv2/v3 upload replacement cannot preserve ACLs.")
			choices, keys = "[r] rename  [c] cancel (Enter): ", "rc"
		}
		var answer string
		if s.AskChoice != nil {
			answer, err = s.AskChoice("  "+choices, keys)
		} else {
			answer, err = s.Ask("  " + choices)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, readline.ErrInterrupt) {
			answer, err = "c", nil
		}
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "", "c", "cancel":
			fmt.Fprintln(s.Err, "  Cancelled; destination unchanged.")
			return nil
		case "o", "overwrite":
			if legacyUpload && regular {
				fmt.Fprintln(s.Err, "  Choose a new name or use NFSv4 for ACL-preserving replacement.")
				continue
			}
			if !regular {
				fmt.Fprintln(s.Err, "  Only regular files can be overwritten.")
				continue
			}
			overwrite = true
		case "r", "rename":
			name, err := s.Ask("  New filename or path (no quotes; empty cancels): ")
			if errors.Is(err, io.EOF) || errors.Is(err, readline.ErrInterrupt) {
				name, err = "", nil
			}
			if err != nil {
				return err
			}
			if strings.TrimSpace(name) == "" {
				fmt.Fprintln(s.Err, "  Cancelled; destination unchanged.")
				return nil
			}
			if operation == "get" {
				if filepath.Base(name) == name {
					destination = filepath.Join(filepath.Dir(destination), name)
				} else {
					destination = s.local(name)
				}
			} else {
				if !strings.Contains(name, "/") {
					destination = destination[:strings.LastIndex(destination, "/")+1] + name
				} else {
					destination = name
				}
			}
			continue
		default:
			if keys == "rc" {
				fmt.Fprintln(s.Err, "  Choose r or c.")
			} else {
				fmt.Fprintln(s.Err, "  Choose o, r or c.")
			}
			continue
		}
		break
	}
	progress := newProgress(s.Err, operation, source, destination, s.ProgressMode, s.ErrTerminal, s.ErrColor)
	options := session.TransferOptions{Overwrite: overwrite, Progress: progress.Update}
	var count int64
	var err error
	if operation == "get" {
		count, err = s.Session.GetWithOptions(ctx, source, destination, options)
	} else {
		count, err = s.Session.PutWithOptions(ctx, source, destination, options)
	}
	progress.Finish(count, err)
	return err
}

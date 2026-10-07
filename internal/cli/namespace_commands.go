package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

func parseOwnership(value string) (owner, group *string, err error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 || parts[0] == "" || len(parts) == 2 && parts[1] == "" {
		return nil, nil, errors.New("expected OWNER or OWNER:GROUP with nonempty values")
	}
	owner = &parts[0]
	if len(parts) == 2 {
		group = &parts[1]
	}
	return owner, group, nil
}

func parseLinkArgs(args []string) (symbolic bool, source, destination string, err error) {
	if len(args) > 0 && args[0] == "-s" {
		symbolic = true
		args = args[1:]
	}
	terminated := len(args) > 0 && args[0] == "--"
	if terminated {
		args = args[1:]
	}
	if len(args) != 2 || !terminated && strings.HasPrefix(args[0], "-") {
		return false, "", "", errors.New("usage: ln [-s] [--] SOURCE DESTINATION")
	}
	return symbolic, args[0], args[1], nil
}

func (s *Shell) runNamespaceCommand(ctx context.Context, name string, args []string) error {
	switch name {
	case "ln":
		symbolic, source, destination, err := parseLinkArgs(args)
		if err != nil {
			return err
		}
		if symbolic {
			return s.Session.Symlink(ctx, source, destination)
		}
		return s.Session.Link(ctx, source, destination)
	case "readlink":
		if len(args) != 1 {
			return errors.New("usage: readlink PATH")
		}
		target, err := s.Session.Readlink(ctx, args[0])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(s.Out, label(target))
		return err
	case "chown":
		if len(args) != 2 {
			return errors.New("usage: chown OWNER[:GROUP] PATH")
		}
		owner, group, err := parseOwnership(args[0])
		if err != nil {
			return err
		}
		return s.Session.Chown(ctx, args[1], owner, group)
	case "chgrp":
		if len(args) != 2 {
			return errors.New("usage: chgrp GROUP PATH")
		}
		return s.Session.Chown(ctx, args[1], nil, &args[0])
	}
	return fmt.Errorf("unknown namespace command %q", name)
}

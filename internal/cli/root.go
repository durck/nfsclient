package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"nfsclient/internal/session"
)

func (s *Shell) rootCommand(ctx context.Context, action string) error {
	switch action {
	case "", "info":
		return s.printRootInfo()
	case "verify":
		_, err := s.Session.VerifyRoot(ctx)
		return errors.Join(err, s.printRootInfo())
	case "reset", "discovered":
		if err := s.Session.SelectRoot(ctx, action == "discovered"); err != nil {
			return err
		}
		return s.printReady(s.Err, s.ErrColor)
	case "probe":
		ok, err := s.Session.Escape(ctx)
		s.Session.ProbeError = err
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(s.Err, "No accessible candidate found; root unchanged.")
		}
		return s.printRootInfo()
	default:
		return errors.New("usage: root [info|verify|reset|discovered|probe]")
	}
}

func (s *Shell) printRootInfo() error {
	state := s.Session
	if state.Export == "" {
		return errors.New("select an export with use first")
	}
	section(s.Out, "ROOT", s.Color)
	selected, method := "Original export", "server-returned export handle"
	if strings.HasPrefix(state.Client.Version(), "4") {
		method = "NFSv4 namespace path"
	}
	if state.Escaped {
		selected = "Discovered directory"
		if strings.HasPrefix(state.Client.Version(), "4") {
			method = "NFSv4 pseudo-root (PUTROOTFH)"
		} else {
			method = "Linux knfsd handle heuristic"
		}
	}
	rows := [][]cell{
		{{"Selected", dim}, {selected, warm}},
		{{"Export", dim}, {label(state.Export), ""}},
		{{"Method", dim}, {method, ""}},
		{{"Object", dim}, {session.RootObjectID(state.Root), ""}},
		{{"Remote cwd", dim}, {label(state.CWD), ""}},
		{{"Host /", dim}, {"Unverified; requires independent server-side confirmation", yellow}},
	}
	if len(state.ExportRoot.Handle) > 0 {
		rows = append(rows, []cell{{"Export object", dim}, {session.RootObjectID(state.ExportRoot), ""}})
	}
	if state.DiscoveredRoot != nil {
		rows = append(rows, []cell{{"Saved discovery", dim}, {session.RootObjectID(*state.DiscoveredRoot), ""}})
	}
	if state.DiscoveryAttempts > 0 {
		rows = append(rows, []cell{{"Probe attempts", dim}, {fmt.Sprint(state.DiscoveryAttempts), ""}})
	}
	if state.ProbeError != nil {
		rows = append(rows, []cell{{"Probe result", dim}, {label(state.ProbeError.Error()), yellow}})
	}
	if report := state.RootVerification; report != nil {
		identity := fmt.Sprintf("UID %d / GID %d / groups %v", report.Auth.UID, report.Auth.GID, report.Auth.Groups)
		if strings.Contains(report.Identity, "(krb5)") || strings.Contains(report.Identity, "(krb5i)") || strings.Contains(report.Identity, "(krb5p)") {
			identity = report.Identity
		}
		rows = append(rows, []cell{{"Checked", dim}, {report.CheckedAt.Format("2006-01-02 15:04:05 MST"), ""}}, []cell{{"Check identity", dim}, {label(identity), ""}})
		for _, check := range report.Checks {
			rows = append(rows, []cell{{check.Name, dim}, {label(check.Result), ""}})
		}
	} else {
		rows = append(rows, []cell{{"Verification", dim}, {"Not run for this selection; root verify", muted}})
	}
	if err := table(s.Out, rows, s.Color); err != nil {
		return err
	}
	_, err := fmt.Fprint(s.Out, "\n  root reset  /  root discovered  /  root verify\n  Paths are relative to the selected root; verification does not change it.\n\n")
	return err
}

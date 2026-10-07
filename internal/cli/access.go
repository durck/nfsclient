package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/pflag"
	"nfsclient/internal/nfs"
)

func (s *Shell) access(ctx context.Context, args []string) error {
	f := pflag.NewFlagSet("access", pflag.ContinueOnError)
	f.SetOutput(io.Discard)
	var asJSON bool
	f.BoolVar(&asJSON, "json", false, "Print the server access observation as JSON")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return fmt.Errorf("usage: access PATH [--json]")
	}
	n, resolved, report, checkErr := s.Session.AccessPath(ctx, f.Arg(0))
	actions := []string{"read", "lookup", "modify", "extend", "delete", "execute"}
	if n.Attr.Type == 2 {
		actions[0] = "list"
		actions[1] = "traverse"
	}
	decisions := map[string]string{}
	for i, name := range actions {
		decisions[name] = report.Decision(1 << i)
	}
	executeRead := strings.HasPrefix(s.Session.Client.Version(), "4") && n.Attr.Type == 1 && report.Decision(32) == "allowed" && report.Decision(1) != "allowed"
	if asJSON {
		if err := json.NewEncoder(s.Out).Encode(struct {
			Path string `json:"path"`
			nfs.AccessReport
			Actions               map[string]string `json:"actions"`
			ExecuteAuthorizesRead bool              `json:"execute_authorizes_read,omitempty"`
		}{resolved, report, decisions, executeRead}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(s.Out, "Access: %s\n  Identity: %s\n", label(resolved), label(report.Identity))
		for _, name := range actions {
			fmt.Fprintf(s.Out, "  %s: %s\n", name, decisions[name])
		}
		if executeRead {
			fmt.Fprintln(s.Out, "  NFSv4 EXECUTE authorizes OPEN/READ; content was not read.")
		}
		fmt.Fprintln(s.Out, "  Server observation only; later operations may fail. No content read or write probe.")
	}
	return checkErr
}

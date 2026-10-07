package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/pflag"
	"nfsclient/internal/nfs"
)

func discoveryFlags(f *pflag.FlagSet, o *nfs.DiscoveryOptions, recursive *bool) {
	f.BoolVar(recursive, "recursive", false, "Explore NFSv4 directories to depth 3 (override with --depth)")
	f.IntVar(&o.MaxDepth, "depth", o.MaxDepth, "Maximum NFSv4 discovery depth from the server root")
	f.IntVar(&o.MaxEntries, "max-entries", o.MaxEntries, "Maximum discovery entries examined, including files")
	f.DurationVar(&o.Timeout, "discovery-timeout", o.Timeout, "Total discovery time budget")
}

func (s *Shell) discoverExports(ctx context.Context, args []string) error {
	o := nfs.DefaultDiscoveryOptions()
	var recursive, asJSON bool
	f := pflag.NewFlagSet("exports", pflag.ContinueOnError)
	f.SetOutput(io.Discard)
	discoveryFlags(f, &o, &recursive)
	f.BoolVar(&asJSON, "json", false, "Print discovery report as JSON")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("usage: exports [--recursive] [--depth N] [--max-entries N] [--discovery-timeout D] [--json]")
	}
	if recursive && !f.Changed("depth") {
		o.MaxDepth = 3
	}
	r, err := s.Session.Client.Discover(ctx, o)
	if err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(s.Out).Encode(r)
	}
	section(s.Out, "RESOURCES / NFS "+r.Version, s.Color)
	fmt.Fprintln(s.Out, "  Identity: "+label(r.Identity))
	permission := func(b *bool) string {
		if b == nil {
			return "?"
		}
		if *b {
			return "yes"
		}
		return "no"
	}
	for _, e := range r.Entries {
		fmt.Fprintf(s.Out, "  %s  [%s]  %s  list=%s traverse=%s\n", paint(s.Color, warm, label(e.Path)), e.Source, e.Access, permission(e.CanList), permission(e.CanTraverse))
		if e.FilesystemBoundary {
			fmt.Fprintln(s.Out, "    Filesystem boundary (not necessarily an export boundary)")
		}
		for _, rule := range e.Clients {
			fmt.Fprintln(s.Out, "    Advertised client: "+label(rule))
		}
		if e.Traversal != "" {
			fmt.Fprintln(s.Out, "    Traversal: "+e.Traversal)
		}
		if e.Error != "" {
			fmt.Fprintln(s.Out, "    "+label(e.Error))
		}
	}
	if r.Complete {
		fmt.Fprintln(s.Out, "  Discovery complete for the visible namespace / advertised exports.")
	} else {
		fmt.Fprintln(s.Out, "  Partial discovery:")
	}
	for _, issue := range r.Issues {
		fmt.Fprintln(s.Out, "    "+label(issue))
	}
	_, err = fmt.Fprintln(s.Out, "  Hidden paths may still be accessible by name. Access reflects the current identity.")
	return err
}

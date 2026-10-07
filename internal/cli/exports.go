package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"nfsclient/internal/nfs"
)

func discoveryFlags(f *pflag.FlagSet, o *nfs.DiscoveryOptions, recursive *bool) {
	f.StringArrayVar(&o.Paths, "path", o.Paths, "Check an absolute known path even when its parent cannot be listed (repeatable)")
	f.StringVar(new(string), "paths-file", "", "File of absolute server paths to probe (one per line, # comments)")
	f.BoolVar(recursive, "recursive", false, "Explore NFSv4 directories to depth 3 (override with --depth)")
	f.IntVar(&o.MaxDepth, "depth", o.MaxDepth, "Maximum NFSv4 discovery depth from the server root")
	f.IntVar(&o.MaxEntries, "max-entries", o.MaxEntries, "Maximum discovery entries examined, including files")
	f.DurationVar(&o.Timeout, "discovery-timeout", o.Timeout, "Total discovery time budget")
}

const maxPathsFileBytes = 16 * 1024 * 1024

// loadPathsFile reads an absolute-path wordlist (one per line, # comments).
// Entries are trimmed, validated and counted before committing the whole list.
// Byte and scanner line limits also bound files containing only comments or blanks.
func loadPathsFile(file string, o *nfs.DiscoveryOptions) error {
	if file == "" {
		return nil
	}
	if err := o.Validate(); err != nil {
		return fmt.Errorf("paths-file %s: %w", file, err)
	}
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open paths-file %s: %w", file, err)
	}
	defer f.Close()
	input := &io.LimitedReader{R: f, N: maxPathsFileBytes + 1}
	sc := bufio.NewScanner(input)
	var paths []string
	lineNumber := 0
	for sc.Scan() {
		lineNumber++
		if input.N == 0 {
			return fmt.Errorf("paths-file %s: line %d: exceeds %d byte limit", file, lineNumber, maxPathsFileBytes)
		}
		line := sc.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(o.Paths)+len(paths) >= o.MaxEntries {
			return fmt.Errorf("paths-file %s: line %d: known paths exceed discovery max-entries (%d)", file, lineNumber, o.MaxEntries)
		}
		candidate := *o
		candidate.Paths = []string{line}
		if err := candidate.Validate(); err != nil {
			return fmt.Errorf("paths-file %s: line %d: %w", file, lineNumber, err)
		}
		paths = append(paths, line)
	}
	if input.N == 0 {
		return fmt.Errorf("paths-file %s: line %d: exceeds %d byte limit", file, lineNumber+1, maxPathsFileBytes)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("paths-file %s: line %d: %w", file, lineNumber+1, err)
	}
	o.Paths = append(o.Paths, paths...)
	return nil
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
		return fmt.Errorf("usage: exports [--path /known/path] [--paths-file FILE] [--recursive] [--depth N] [--max-entries N] [--discovery-timeout D] [--json]")
	}
	if pf, _ := f.GetString("paths-file"); pf != "" {
		if err := loadPathsFile(s.local(pf), &o); err != nil {
			return err
		}
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
		fmt.Fprintf(s.Out, "  %s  [%s]  %s  list=%s traverse=%s\n", paint(s.Color, warm, label(e.Path)), strings.Join(e.Sources, ", "), e.Access, permission(e.CanList), permission(e.CanTraverse))
		if len(e.AdvertisedSecurity) > 0 {
			fmt.Fprintln(s.Out, "    Advertised security: "+label(strings.Join(e.AdvertisedSecurity, ", ")))
		}
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

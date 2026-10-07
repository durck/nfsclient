package cli

import (
	"fmt"
	"io"

	"github.com/spf13/pflag"
	"nfsclient/internal/session"
)

func parseTreeOptions(command string, args []string) (session.TreeOptions, []string, error) {
	var options session.TreeOptions
	f := pflag.NewFlagSet(command, pflag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.BoolVar(&options.Merge, "merge", false, "Merge into an existing directory")
	f.BoolVar(&options.Links, "links", false, "Preserve symbolic links")
	f.BoolVar(&options.Hardlinks, "hardlinks", false, "Preserve hard links")
	f.BoolVar(&options.Mode, "preserve-mode", false, "Preserve permission bits")
	f.BoolVar(&options.MTime, "preserve-mtime", false, "Preserve modification times")
	if command == "gettree" {
		f.BoolVar(&options.SkipOffline, "skip-offline", false, "Skip files known to require archive recall")
	}
	if err := f.Parse(args); err != nil {
		return options, nil, fmt.Errorf("%s: %w; use help %s", command, err, command)
	}
	if f.NArg() != 2 {
		return options, nil, fmt.Errorf("usage: %s [OPTIONS] SOURCE DESTINATION; use help %s", command, command)
	}
	return options, f.Args(), nil
}

package cli

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"io"
	"nfsclient/internal/nfs"
)

func newLockStateCommand(out io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "lock-state", Short: "Inspect durable lock evidence offline"}
	root.AddCommand(&cobra.Command{Use: "inspect ABSOLUTE_FILE", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		r, err := nfs.InspectLockJournal(args[0])
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(r)
	}})
	return root
}

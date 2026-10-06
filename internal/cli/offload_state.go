package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"nfs-viewer/internal/nfs"
)

func newOffloadStateCommand(out io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "offload-state", Short: "Inspect or acknowledge local offload crash evidence without contacting NFS"}
	inspect := &cobra.Command{Use: "inspect ABSOLUTE_FILE", Short: "Read the complete validated journal and print its latest record", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, err := nfs.InspectOffloadJournal(args[0])
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(r)
	}}
	var quiesced, verified bool
	ack := &cobra.Command{Use: "ack ABSOLUTE_FILE OPERATION_ID --server-quiesced --destination-verified", Short: "Record external verification; keep the unknown outcome, never replay or certify a copy", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		if !quiesced || !verified {
			return errors.New("ack requires --server-quiesced and --destination-verified after external verification/repair; it does not stop server work")
		}
		if err := nfs.AcknowledgeOffloadJournal(args[0], args[1]); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Unknown outcome acknowledged locally. No server operation was sent; no copy success is claimed.")
		return err
	}}
	ack.Flags().BoolVar(&quiesced, "server-quiesced", false, "Confirm the server can no longer modify the recorded destination")
	ack.Flags().BoolVar(&verified, "destination-verified", false, "Confirm the destination has been independently verified or repaired")
	root.AddCommand(inspect, ack)
	return root
}

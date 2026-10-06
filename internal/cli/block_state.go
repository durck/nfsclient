package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"nfs-viewer/internal/nfs"
)

func newBlockStateCommand(out io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "block-state", Short: "Inspect block crash evidence without contacting NFS or storage"}
	inspect := &cobra.Command{Use: "inspect ABSOLUTE_FILE", Args: cobra.ExactArgs(1), Short: "Print validated state without cached block contents", RunE: func(cmd *cobra.Command, args []string) error {
		r, err := nfs.InspectBlockJournal(args[0])
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(r)
	}}
	var quiesced, verified bool
	ack := &cobra.Command{Use: "ack ABSOLUTE_FILE OPERATION_ID --storage-quiesced --destination-verified", Args: cobra.ExactArgs(2), Short: "Record external quiescence/repair; never replay or certify success", RunE: func(cmd *cobra.Command, args []string) error {
		if !quiesced || !verified {
			return errors.New("ack requires --storage-quiesced and --destination-verified after external verification/repair")
		}
		if err := nfs.AcknowledgeBlockJournal(args[0], args[1]); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Unknown block outcome acknowledged locally. No NFS/storage request was sent; success is not certified.")
		return err
	}}
	ack.Flags().BoolVar(&quiesced, "storage-quiesced", false, "Confirm original storage/server requests can no longer change data")
	ack.Flags().BoolVar(&verified, "destination-verified", false, "Confirm the destination was independently verified or repaired")
	root.AddCommand(inspect, ack)
	return root
}

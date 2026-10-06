package main

import (
	"context"
	"fmt"
	"os"

	"nfsclient/internal/cli"
)

func main() {
	if err := cli.NewCommand(os.Stdin, os.Stdout, os.Stderr).ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

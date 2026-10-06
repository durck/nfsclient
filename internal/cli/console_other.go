//go:build !windows

package cli

import "io"

func enableANSI(w io.Writer) (bool, func()) { return isTerminal(w), func() {} }

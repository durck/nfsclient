//go:build windows

package cli

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func enableANSI(w io.Writer) (bool, func()) {
	f, ok := w.(*os.File)
	if !ok {
		return false, func() {}
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return false, func() {}
	}
	if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		return false, func() {}
	}
	return true, func() { windows.SetConsoleMode(h, mode) }
}

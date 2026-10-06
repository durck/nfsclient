package session

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func treeFileID(f *os.File) (string, error) {
	var st windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &st); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d:%d", st.VolumeSerialNumber, st.FileIndexHigh, st.FileIndexLow), nil
}

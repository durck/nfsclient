package session

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func treeFileID(f *os.File) (string, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}

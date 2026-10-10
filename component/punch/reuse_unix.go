//go:build unix

package punch

import "syscall"

// SO_REUSEPORT is 0x0F on Linux/Android; the syscall package does not export it for all targets.
const soReusePort = 0x0F

func setReuse(fd int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1)
}

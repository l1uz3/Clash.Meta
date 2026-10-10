//go:build unix

package punch

import "golang.org/x/sys/unix"

// unix.SO_REUSEPORT resolves per OS (0x0F on Linux/Android, 0x200 on macOS). A hard-coded
// Linux value would silently set a different option on macOS and break punching there.
func setReuse(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}

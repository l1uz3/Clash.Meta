//go:build windows

package punch

import "golang.org/x/sys/windows"

// Windows has no SO_REUSEPORT. SO_REUSEADDR lets several sockets bind the same local port,
// which is what simultaneous open needs to reuse a port the NAT has already mapped.
func setReuse(fd int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
}

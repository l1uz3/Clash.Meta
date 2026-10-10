//go:build !unix && !windows

package punch

// Simultaneous-open punching needs port reuse; on other platforms the dial proceeds without it
// and the punch rounds will usually fail rather than misbehave.
func setReuse(int) error { return nil }

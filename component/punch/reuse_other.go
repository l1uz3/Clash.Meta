//go:build !unix

package punch

// Simultaneous-open punching needs SO_REUSEPORT; on other platforms the dial simply proceeds
// without it and the cone/predict rounds will usually fail rather than misbehave.
func setReuse(int) error { return nil }

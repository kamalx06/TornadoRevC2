//go:build !windows

package evasion

// ApplyWindowsEvasion is a no-op on non-Windows platforms. The stub
// keeps main.go free of build-tagged branches; the return type
// matches the Windows implementation.
func ApplyWindowsEvasion(amsi, etw bool) error { return nil }
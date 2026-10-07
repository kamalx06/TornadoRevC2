//go:build !windows

package evasion

import "errors"

// PPIDSpoof is a Windows-only feature. The stub keeps main.go's
// `if runtime.GOOS == "windows"` branch free of build-tagged code:
// the runtime check makes the call a no-op, and the compiler still
// needs the symbol to exist on every platform.
func PPIDSpoof() (bool, error) {
	return false, errors.New("ppid spoof not supported on this platform")
}
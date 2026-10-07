//go:build linux

package evasion

import (
	"fmt"
)

// EncryptSelf is the platform implementation of the sleep mask. On
// Linux no mask is implemented: there is no equivalent of
// VirtualProtect that changes page permissions on a live mapping from
// the same process, and /proc/self/maps would show .text as readable
// regardless. A realistic implementation would use mprotect plus a
// trampoline in an anonymous mapping, or an eBPF page-fault handler.
// The signature accepts the algorithm name for parity with Windows.
func EncryptSelf(maskType string) ([]byte, error) {
	switch maskType {
	case "", "none":
		return nil, nil
	case "rc4", "aes-ctr", "ekko":
		return nil, fmt.Errorf(
			"sleep mask %q not implemented on linux", maskType)
	default:
		return nil, fmt.Errorf("unknown sleep mask %q", maskType)
	}
}

// DecryptSelf is a no-op because EncryptSelf never encrypts anything.
func DecryptSelf(key []byte) error { return nil }
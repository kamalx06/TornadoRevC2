//go:build windows

package evasion

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	smKernel32 = syscall.NewLazyDLL("kernel32.dll")
	smProcGetModuleHandleW = smKernel32.NewProc("GetModuleHandleW")
)

// EncryptSelf is the platform implementation of the sleep mask. On
// Windows the mask is currently disabled: encrypting .text while
// executing from .text requires a trampoline in a region outside the
// encrypted range — a VirtualAlloc'd executable page, or a
// timer-queue callback that returns via NtContinue. Neither is
// implemented here. The function accepts and ignores the build-time
// algorithm name so main.go can call it with SleepMaskType without
// platform-specific branches.
//
// Recognised maskType values: "none", "rc4", "aes-ctr", "ekko".
// All of them currently return an error so the caller falls through
// to a plain sleep rather than leaving .text in an inconsistent
// state.
func EncryptSelf(maskType string) ([]byte, error) {
	switch maskType {
	case "", "none":
		return nil, nil
	case "rc4", "aes-ctr", "ekko":
		return nil, fmt.Errorf(
			"sleep mask %q disabled on windows: trampoline not implemented",
			maskType)
	default:
		return nil, fmt.Errorf("unknown sleep mask %q", maskType)
	}
}

func DecryptSelf(key []byte) error { return nil }

// TextSection returns the base address and length of the main module's
// .text section. It is a reference implementation for the eventual
// sleep mask — the correct PE32+ parsing is the hard part, and it is
// done here so that a future mask implementation has a correct
// starting point.
//
// PE32+ has a 240-byte optional header (0xF0), not 224 bytes (0xE0,
// PE32 only). Reading SizeOfOptionalHeader from the COFF header is
// the only correct way to locate the section table on both
// architectures without branching on the magic number.
func TextSection() (uintptr, uintptr, error) {
	base, _, _ := smProcGetModuleHandleW.Call(0)
	if base == 0 {
		return 0, 0, syscall.EINVAL
	}

	eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	peHeader := base + uintptr(eLfanew)

	numSections := *(*uint16)(unsafe.Pointer(peHeader + 6))
	sizeOfOptHdr := *(*uint16)(unsafe.Pointer(peHeader + 20))
	sectionTable := peHeader + 24 + uintptr(sizeOfOptHdr)

	for i := uintptr(0); i < uintptr(numSections); i++ {
		sect := sectionTable + i*40
		nameBytes := (*[8]byte)(unsafe.Pointer(sect))
		var name string
		for _, b := range nameBytes {
			if b == 0 {
				break
			}
			name += string(b)
		}
		if name != ".text" {
			continue
		}
		virtualSize := *(*uint32)(unsafe.Pointer(sect + 8))
		virtualAddr := *(*uint32)(unsafe.Pointer(sect + 12))
		return base + uintptr(virtualAddr), uintptr(virtualSize), nil
	}
	return 0, 0, syscall.EINVAL
}
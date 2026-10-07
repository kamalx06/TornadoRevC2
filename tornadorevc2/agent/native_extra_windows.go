//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// nativeStatExtra on Windows returns nothing — the FileInfo struct
// already exposes everything useful, and Windows does not have POSIX
// uid/gid in the sense Unix does.
func nativeStatExtra(_ string) string { return "" }

// nativeDF reports disk usage via GetDiskFreeSpaceExW.
//
// Usage: df [path]     (path must be a drive root like C:\)
func nativeDF(args []string) (string, error) {
	path := "C:\\"
	if len(args) > 0 {
		path = args[0]
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var freeAvail, total, totalFree uint64
	r, _, errno := proc.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return "", errno
	}
	used := total - totalFree
	usePct := 0.0
	if total > 0 {
		usePct = float64(used) * 100 / float64(total)
	}
	return fmt.Sprintf(
		"Path       : %s\n"+
			"Total      : %d bytes (%.1f GiB)\n"+
			"Used       : %d bytes (%.1f GiB)\n"+
			"Available  : %d bytes (%.1f GiB)\n"+
			"Use%%       : %.1f%%\n",
		path,
		total, float64(total)/(1<<30),
		used, float64(used)/(1<<30),
		freeAvail, float64(freeAvail)/(1<<30),
		usePct,
	), nil
}

// nativeUptime uses GetTickCount64.
//
// NOTE: on 386 and arm (32-bit) builds, uintptr is 4 bytes and the
// upper half of the ULONGLONG return is discarded. Uptime past
// ~49.7 days wraps on those platforms. Windows 32-bit beacons are
// rare enough that this trade-off is acceptable.
func nativeUptime() (string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetTickCount64")
	r, _, _ := proc.Call()
	// r is milliseconds since boot
	secs := r / 1000
	days := int(secs) / 86400
	hours := (int(secs) % 86400) / 3600
	mins := (int(secs) % 3600) / 60
	return fmt.Sprintf("up %d day(s), %d hour(s), %d minute(s) (%d seconds)\n",
		days, hours, mins, int(secs)), nil
}
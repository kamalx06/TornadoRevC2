//go:build linux

package evasion

import (
	"os"
	"strconv"
	"strings"
)

// DebuggerDetected returns true if the process is being traced.
//
// Reads /proc/self/status and checks TracerPid. Zero means no tracer.
// This is equivalent to what ptrace(PTRACE_TRACEME) would tell you,
// without the side effect of attaching the process to itself.
func DebuggerDetected() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
		pid, err := strconv.Atoi(val)
		if err != nil {
			return false
		}
		return pid != 0
	}
	return false
}
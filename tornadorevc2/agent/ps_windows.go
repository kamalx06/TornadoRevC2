//go:build windows
// +build windows

package main

import (
	"os/exec"
	"strings"
)

// nativePS uses `tasklist /FO CSV /NH` on Windows.
//
// OPSEC trade-off: this spawns one child process, unlike the Linux
// path. There is no in-process alternative without pulling in
// golang.org/x/sys/windows and writing ~80 lines of Toolhelp32
// marshalling. For most engagements the tasklist call is acceptable —
// `tasklist.exe` is a signed Microsoft binary and a defender seeing
// it in the process tree learns nothing. If your target has EDR that
// flags any process-creation event, port this to Toolhelp32.
func nativePS() (string, error) {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return "", err
	}
	// Reformat CSV rows into the same columnar text the Linux path
	// produces: PID on the left, image name (and any args) on the right.
	var sb strings.Builder
	sb.WriteString("PID      COMMAND\n")
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// CSV: "ImageName","PID","SessionName","Session#","MemUsage"
		parts := strings.Split(line, "\",\"")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimPrefix(parts[0], "\"")
		pid := parts[1]
		sb.WriteString(name)
		// Pad the name to 8+ chars; PID goes on the right.
		if len(name) < 8 {
			sb.WriteString(strings.Repeat(" ", 8-len(name)))
		}
		sb.WriteString(" ")
		sb.WriteString(pid)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}
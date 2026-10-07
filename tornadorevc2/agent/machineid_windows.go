//go:build windows

package main

import (
	"os/exec"
	"strings"
)

func machineID() string {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`,
		"/v", "MachineGuid").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.Contains(l, "MachineGuid") {
			fields := strings.Fields(l)
			if len(fields) >= 3 {
				return fields[len(fields)-1]
			}
		}
	}
	return ""
}
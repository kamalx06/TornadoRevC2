//go:build linux

package main

import (
	"os"
	"strings"
)

func machineID() string {
	for _, p := range []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	} {
		if data, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}
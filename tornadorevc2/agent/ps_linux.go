//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// nativePS walks /proc to build a process list. No subprocess.
// PID and COMMAND columns are pipe-separated internally for easy
// parsing by the console; the output format matches `ps auxww | head`
// closely enough that a plugin expecting columnar text will accept it.
func nativePS() (string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	type proc struct {
		pid  int
		comm string
		cmd  string
	}
	var procs []proc

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		cmdline, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))

		p := proc{
			pid:  pid,
			comm: strings.TrimSpace(string(comm)),
		}
		// cmdline is NUL-separated; replace NULs with spaces.
		if len(cmdline) > 0 {
			p.cmd = strings.ReplaceAll(
				strings.TrimRight(string(cmdline), "\x00"), "\x00", " ")
		}
		if p.cmd == "" {
			p.cmd = p.comm
		}
		procs = append(procs, p)
	}

	sort.Slice(procs, func(i, j int) bool {
		return procs[i].pid < procs[j].pid
	})

	var sb strings.Builder
	sb.WriteString("PID      COMMAND\n")
	for _, p := range procs {
		// Truncate to keep output bounded on chatty systems.
		cmd := p.cmd
		if len(cmd) > 200 {
			cmd = cmd[:197] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-8d %s\n", p.pid, cmd))
	}
	return sb.String(), nil
}
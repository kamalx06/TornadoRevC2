//go:build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// nativeStatExtra appends uid/gid/mode to the stat output on Linux.
func nativeStatExtra(path string) string {
	var sb strings.Builder
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		fmt.Fprintf(&sb, "Uid      : %d\n", sys.Uid)
		fmt.Fprintf(&sb, "Gid      : %d\n", sys.Gid)
		if u, err := user.LookupId(strconv.FormatUint(uint64(sys.Uid), 10)); err == nil {
			fmt.Fprintf(&sb, "User     : %s\n", u.Username)
		}
		if g, err := user.LookupGroupId(strconv.FormatUint(uint64(sys.Gid), 10)); err == nil {
			fmt.Fprintf(&sb, "Group    : %s\n", g.Name)
		}
	}
	return sb.String()
}

// nativeDF reports filesystem usage for the filesystem containing path
// (default: /).
//
// Usage: df [path]
func nativeDF(args []string) (string, error) {
	path := "/"
	if len(args) > 0 {
		path = args[0]
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return "", err
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	free := st.Bfree * bsize
	avail := st.Bavail * bsize
	used := total - free
	// Guard against a zero-size filesystem (empty tmpfs, bind mount
	// of an empty directory). Without this the percentage is NaN.
	usePct := 0.0
	if total > 0 {
		usePct = float64(used) * 100 / float64(total)
	}
	return fmt.Sprintf(
		"Path       : %s\n"+
			"Block size : %d\n"+
			"Total      : %d bytes (%.1f GiB)\n"+
			"Used       : %d bytes (%.1f GiB)\n"+
			"Available  : %d bytes (%.1f GiB)\n"+
			"Use%%       : %.1f%%\n",
		path, bsize,
		total, float64(total)/(1<<30),
		used, float64(used)/(1<<30),
		avail, float64(avail)/(1<<30),
		usePct,
	), nil
}

// nativeUptime reads /proc/uptime.
func nativeUptime() (string, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return "", fmt.Errorf("malformed /proc/uptime")
	}
	secs, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return "", err
	}
	days := int(secs) / 86400
	hours := (int(secs) % 86400) / 3600
	mins := (int(secs) % 3600) / 60
	return fmt.Sprintf("up %d day(s), %d hour(s), %d minute(s) (%d seconds)\n",
		days, hours, mins, int(secs)), nil
}
//go:build linux
// +build linux

package main

import (
	"fmt"
	"os/user"
	"strconv"
	"syscall"
)

func nativeID() (string, error) {
	u, err := user.Current()
	if err != nil {
		// Fall back to raw syscalls even if user.Current() failed.
		uid := syscall.Getuid()
		gid := syscall.Getgid()
		return fmt.Sprintf("uid=%d gid=%d\n", uid, gid), nil
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	// Supplementary groups — same info `id` prints by default.
	groups, _ := syscall.Getgroups()
	groupStr := ""
	for i, g := range groups {
		if i > 0 {
			groupStr += ","
		}
		groupStr += strconv.Itoa(g)
	}

	return fmt.Sprintf(
		"uid=%d(%s) gid=%d(%s) groups=%s\n",
		uid, u.Username, gid, u.Name, groupStr,
	), nil
}
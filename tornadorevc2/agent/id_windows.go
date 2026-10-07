//go:build windows
// +build windows

package main

import (
	"fmt"
	"os/user"
)

// nativeID returns the current Windows identity. The username is
// DOMAIN\user; there is no uid/gid concept, so the output uses the
// same KEY=VALUE shape as the Linux path for parser consistency.
func nativeID() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"username=%s uid=%s gid=%s\n",
		u.Username, u.Uid, u.Gid,
	), nil
}
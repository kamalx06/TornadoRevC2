//go:build !windows

package main

import (
	"context"
	"errors"
)

// BOFs are Windows COFF objects. Non-Windows targets have no loader.
func execBOF(_ context.Context, _ []byte,
	_ string, _ []byte) (string, int, error) {
	return "", -1, errors.New("BOF execution requires a Windows target")
}
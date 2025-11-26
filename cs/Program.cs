using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    // ---------- Win32 constants ----------

    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    const ushort PROCESSOR_ARCHITECTURE_AMD64 = 9;
    const ushort PROCESSOR_ARCHITECTURE_ARM64 = 12;

    const ushort IMAGE_FILE_MACHINE_UNKNOWN = 0;
    const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

    const uint CP_UTF8 = 65001;

    // PEB / RTL_USER_PROCESS_PARAMETERS offsets
    const ulong OFF_PEB_ProcessParameters_32 = 0x10;
    const ulong OFF_PEB_ProcessParameters_64 = 0x20;
    const ulong OFF_RTLUPP_Environment_32 = 0x48;
    const ulong OFF_RTLUPP_Environment_64 = 0x80;

    // ---------- Enums / structs ----------

    enum PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0,
        // ...
        ProcessWow64Information = 26
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION_T
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION64
    {
        public ulong Reserved1;
        public ulong PebBaseAddress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public ulong[] Reserved2;
        public ulong UniqueProcessId;
        public ulong Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    class ArchInfo
    {
        public bool IsTarget64;
        public bool IsSelf64 = (IntPtr.Size == 8);
        public bool IsError;
    }

    // ---------- Delegates for NT functions ----------

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate int NtQueryInformationProcessDelegate(
        IntPtr ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        IntPtr ProcessInformation,
        uint ProcessInformationLength,
        out uint ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate int NtWow64QueryInformationProcess64Delegate(
        IntPtr ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        IntPtr ProcessInformation,
        uint ProcessInformationLength,
        out uint ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate int NtWow64ReadVirtualMemory64Delegate(
        IntPtr ProcessHandle,
        ulong BaseAddress,
        IntPtr Buffer,
        ulong Size,
        out ulong NumberOfBytesRead);

    class NtApi
    {
        public NtQueryInformationProcessDelegate NtQueryInformationProcess;
        public NtWow64QueryInformationProcess64Delegate NtWow64QueryInfo64;
        public NtWow64ReadVirtualMemory64Delegate NtWow64ReadMem64;

        public bool Ok => NtQueryInformationProcess != null;
    }

    // ---------- P/Invoke declarations ----------

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        IntPtr nSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleOutputCP(uint wCodePageID);

    // This may not exist on older systems; we'll call it in a try/catch
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsWow64Process2(
        IntPtr hProcess,
        out ushort processMachine,
        out ushort nativeMachine);

    // ---------- Helper methods ----------

    static bool NT_SUCCESS(int status) => status >= 0;

    static void PrintLastError(string what)
    {
        int err = Marshal.GetLastWin32Error();
        string msg = new Win32Exception(err).Message;
        Console.Error.WriteLine($"[!] {what} failed with error {err}: {msg}");
    }

    static bool EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var hToken))
            return false;

        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
                return false;

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[1]
            };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;

            int err = Marshal.GetLastWin32Error();
            return err == 0;
        }
        finally
        {
            CloseHandle(hToken);
        }
    }

    static ArchInfo DetectArch(IntPtr hProcess)
    {
        var ai = new ArchInfo();

        // Try IsWow64Process2 (Windows 10+)
        try
        {
            if (IsWow64Process2(hProcess, out ushort processMachine, out ushort nativeMachine))
            {
                bool osIs64bit = (nativeMachine == IMAGE_FILE_MACHINE_AMD64 || nativeMachine == IMAGE_FILE_MACHINE_ARM64);
                ai.IsTarget64 = (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) && osIs64bit;
                return ai;
            }
        }
        catch (EntryPointNotFoundException)
        {
            // Not available; fall back
        }

        // Fallback: IsWow64Process + GetNativeSystemInfo
        bool isWow64 = false;
        bool haveIsWow64 = false;
        try
        {
            haveIsWow64 = IsWow64Process(hProcess, out isWow64);
        }
        catch (EntryPointNotFoundException)
        {
            haveIsWow64 = false;
        }

        GetNativeSystemInfo(out var si);
        bool osIs64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                       si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);

        if (haveIsWow64)
        {
            ai.IsTarget64 = (!isWow64 && osIs64);
        }
        else
        {
            ai.IsTarget64 = osIs64 && ai.IsSelf64;
        }
        return ai;
    }

    static NtApi LoadNtApi()
    {
        var api = new NtApi();
        IntPtr hNt = GetModuleHandle("ntdll.dll");
        if (hNt == IntPtr.Zero)
            return api;

        IntPtr fp;

        fp = GetProcAddress(hNt, "NtQueryInformationProcess");
        if (fp != IntPtr.Zero)
            api.NtQueryInformationProcess = (NtQueryInformationProcessDelegate)
                Marshal.GetDelegateForFunctionPointer(fp, typeof(NtQueryInformationProcessDelegate));

        fp = GetProcAddress(hNt, "NtWow64QueryInformationProcess64");
        if (fp != IntPtr.Zero)
            api.NtWow64QueryInfo64 = (NtWow64QueryInformationProcess64Delegate)
                Marshal.GetDelegateForFunctionPointer(fp, typeof(NtWow64QueryInformationProcess64Delegate));

        fp = GetProcAddress(hNt, "NtWow64ReadVirtualMemory64");
        if (fp != IntPtr.Zero)
            api.NtWow64ReadMem64 = (NtWow64ReadVirtualMemory64Delegate)
                Marshal.GetDelegateForFunctionPointer(fp, typeof(NtWow64ReadVirtualMemory64Delegate));

        return api;
    }

    static bool ReadRemote(
        IntPtr hProcess,
        ulong addr,
        byte[] buffer,
        int bytes,
        bool useWow64Read,
        NtApi api,
        out int outRead)
    {
        outRead = 0;

        if (useWow64Read)
        {
            if (api.NtWow64ReadMem64 == null)
                return false;

            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                IntPtr bufPtr = handle.AddrOfPinnedObject();
                ulong read;
                int status = api.NtWow64ReadMem64(hProcess, addr, bufPtr, (ulong)bytes, out read);
                outRead = (int)read;
                return NT_SUCCESS(status) && read > 0;
            }
            finally
            {
                handle.Free();
            }
        }
        else
        {
            IntPtr bytesReadPtr;
            bool ok = ReadProcessMemory(
                hProcess,
                new IntPtr(unchecked((long)addr)), // only used when pointer width matches
                buffer,
                new IntPtr(bytes),
                out bytesReadPtr);

            outRead = bytesReadPtr.ToInt32();
            return ok && outRead > 0;
        }
    }

    static bool ReadPtr(
        IntPtr hProcess,
        ulong addr,
        bool ptr64,
        bool useWow64Read,
        NtApi api,
        out ulong value)
    {
        value = 0;
        int size = ptr64 ? 8 : 4;
        var buf = new byte[size];
        if (!ReadRemote(hProcess, addr, buf, size, useWow64Read, api, out int read) || read < size)
            return false;

        if (ptr64)
            value = BitConverter.ToUInt64(buf, 0);
        else
            value = BitConverter.ToUInt32(buf, 0);

        return true;
    }

    static byte[] ReadRemoteEnvironmentBlock(
        IntPtr hProcess,
        ulong envAddr,
        bool target64,
        bool useWow64Read,
        NtApi api)
    {
        const int CHUNK = 64 * 1024;
        const int MAX_BYTES = 4 * 1024 * 1024;

        var bytes = new List<byte>(CHUNK);
        ulong cur = envAddr;
        int total = 0;
        bool foundTerminator = false;
        int bytesKeep = 0;

        while (total < MAX_BYTES && !foundTerminator)
        {
            int toRead = CHUNK;
            var buf = new byte[toRead];
            if (!ReadRemote(hProcess, cur, buf, toRead, useWow64Read, api, out int actually) || actually == 0)
            {
                bool progressed = false;
                for (int sz = 16 * 1024; sz >= 512; sz /= 2)
                {
                    buf = new byte[sz];
                    if (ReadRemote(hProcess, cur, buf, sz, useWow64Read, api, out actually) && actually > 0)
                    {
                        toRead = sz;
                        progressed = true;
                        break;
                    }
                }
                if (!progressed)
                    break;
            }

            // Append what we actually got
            for (int i = 0; i < actually; i++)
                bytes.Add(buf[i]);

            total += actually;
            cur += (ulong)actually;

            // Look for UTF-16 double-NUL terminator
            if (total >= 4)
            {
                int charCount = (total / 2);
                var chars = new char[charCount];
                Buffer.BlockCopy(bytes.ToArray(), 0, chars, 0, charCount * 2);
                for (int i = 1; i < charCount; i++)
                {
                    if (chars[i - 1] == '\0' && chars[i] == '\0')
                    {
                        foundTerminator = true;
                        bytesKeep = (i + 1) * 2; // bytes to keep
                        break;
                    }
                }
            }
        }

        if (bytes.Count == 0)
            return Array.Empty<byte>();

        if (foundTerminator && bytesKeep > 0 && bytesKeep < bytes.Count)
        {
            return bytes.GetRange(0, bytesKeep).ToArray();
        }

        // Align to even number of bytes
        int aligned = bytes.Count & ~1;
        return bytes.GetRange(0, aligned).ToArray();
    }

    // ---------- Main logic ----------

    static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: envpid <PID>");
            return 1;
        }

        if (!uint.TryParse(args[0], out uint pid))
        {
            Console.Error.WriteLine("Invalid PID.");
            return 1;
        }

        // Best-effort SeDebugPrivilege
        EnablePrivilege("SeDebugPrivilege");

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            // Fallback for older Windows
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        }

        if (hProcess == IntPtr.Zero)
        {
            PrintLastError("OpenProcess");
            return 2;
        }

        try
        {
            var arch = DetectArch(hProcess);

            NtApi nt = LoadNtApi();
            if (!nt.Ok)
            {
                Console.Error.WriteLine("Failed to resolve NtQueryInformationProcess from ntdll.");
                return 3;
            }

            ulong pebAddr = 0;

            if (arch.IsTarget64)
            {
                if (arch.IsSelf64)
                {
                    // 64-bit self -> 64-bit target
                    int sizePbi = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION_T));
                    IntPtr pbiPtr = Marshal.AllocHGlobal(sizePbi);
                    try
                    {
                        uint retLen;
                        int status = nt.NtQueryInformationProcess(
                            hProcess,
                            PROCESSINFOCLASS.ProcessBasicInformation,
                            pbiPtr,
                            (uint)sizePbi,
                            out retLen);

                        if (!NT_SUCCESS(status))
                        {
                            Console.Error.WriteLine("NtQueryInformationProcess(ProcessBasicInformation) failed (target 64-bit).");
                            return 4;
                        }

                        var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION_T>(pbiPtr);
                        pebAddr = (ulong)pbi.PebBaseAddress.ToInt64();
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pbiPtr);
                    }
                }
                else
                {
                    // 32-bit self -> 64-bit target
                    if (nt.NtWow64QueryInfo64 == null)
                    {
                        Console.Error.WriteLine("NtWow64QueryInformationProcess64 not available; rebuild as x64 or run on newer OS.");
                        return 5;
                    }

                    int sizePbi64 = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION64));
                    IntPtr pbi64Ptr = Marshal.AllocHGlobal(sizePbi64);
                    try
                    {
                        uint retLen;
                        int status = nt.NtWow64QueryInfo64(
                            hProcess,
                            PROCESSINFOCLASS.ProcessBasicInformation,
                            pbi64Ptr,
                            (uint)sizePbi64,
                            out retLen);

                        if (!NT_SUCCESS(status))
                        {
                            Console.Error.WriteLine("NtWow64QueryInformationProcess64 failed (target 64-bit).");
                            return 6;
                        }

                        var pbi64 = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION64>(pbi64Ptr);
                        pebAddr = pbi64.PebBaseAddress;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pbi64Ptr);
                    }
                }
            }
            else
            {
                // Target is 32-bit
                if (arch.IsSelf64)
                {
                    // 64-bit self -> WOW64 target: get WOW64 PEB
                    IntPtr wow64PebPtr = Marshal.AllocHGlobal(IntPtr.Size);
                    try
                    {
                        Marshal.WriteIntPtr(wow64PebPtr, IntPtr.Zero);
                        uint retLen;
                        int status = nt.NtQueryInformationProcess(
                            hProcess,
                            PROCESSINFOCLASS.ProcessWow64Information,
                            wow64PebPtr,
                            (uint)IntPtr.Size,
                            out retLen);

                        if (!NT_SUCCESS(status))
                        {
                            Console.Error.WriteLine("NtQueryInformationProcess(ProcessWow64Information) failed (target 32-bit under WOW64).");
                            return 7;
                        }

                        IntPtr wow64Peb = Marshal.ReadIntPtr(wow64PebPtr);
                        if (wow64Peb == IntPtr.Zero)
                        {
                            Console.Error.WriteLine("NtQueryInformationProcess(ProcessWow64Information) returned null PEB (target 32-bit under WOW64).");
                            return 7;
                        }

                        pebAddr = (ulong)wow64Peb.ToInt64();
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(wow64PebPtr);
                    }
                }
                else
                {
                    // 32-bit self -> 32-bit target
                    int sizePbi = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION_T));
                    IntPtr pbiPtr = Marshal.AllocHGlobal(sizePbi);
                    try
                    {
                        uint retLen;
                        int status = nt.NtQueryInformationProcess(
                            hProcess,
                            PROCESSINFOCLASS.ProcessBasicInformation,
                            pbiPtr,
                            (uint)sizePbi,
                            out retLen);

                        if (!NT_SUCCESS(status))
                        {
                            Console.Error.WriteLine("NtQueryInformationProcess(ProcessBasicInformation) failed (target 32-bit).");
                            return 8;
                        }

                        var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION_T>(pbiPtr);
                        pebAddr = (ulong)pbi.PebBaseAddress.ToInt64();
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pbiPtr);
                    }
                }
            }

            bool useWow64Read = (!arch.IsSelf64 && arch.IsTarget64); // only 32->64 uses NtWow64ReadVirtualMemory64

            // Read ProcessParameters pointer from PEB
            ulong procParams;
            ulong procParamsOffset = arch.IsTarget64 ? OFF_PEB_ProcessParameters_64 : OFF_PEB_ProcessParameters_32;

            if (!ReadPtr(
                    hProcess,
                    pebAddr + procParamsOffset,
                    arch.IsTarget64,
                    useWow64Read,
                    nt,
                    out procParams))
            {
                Console.Error.WriteLine("Failed to read ProcessParameters pointer from remote PEB.");
                return 9;
            }

            if (procParams == 0)
            {
                Console.Error.WriteLine("ProcessParameters is null. (Process may be exiting.)");
                return 10;
            }

            // Read Environment pointer from RTL_USER_PROCESS_PARAMETERS
            ulong envPtr;
            ulong envOffset = arch.IsTarget64 ? OFF_RTLUPP_Environment_64 : OFF_RTLUPP_Environment_32;

            if (!ReadPtr(
                    hProcess,
                    procParams + envOffset,
                    arch.IsTarget64,
                    useWow64Read,
                    nt,
                    out envPtr))
            {
                Console.Error.WriteLine("Failed to read Environment pointer from remote RTL_USER_PROCESS_PARAMETERS.");
                return 11;
            }

            if (envPtr == 0)
            {
                Console.Error.WriteLine("Environment pointer is null (no environment or process is tearing down).");
                return 12;
            }

            // Read environment block (UTF-16, double-NUL terminated)
            byte[] envBytes = ReadRemoteEnvironmentBlock(hProcess, envPtr, arch.IsTarget64, useWow64Read, nt);

            if (envBytes == null || envBytes.Length == 0)
            {
                Console.Error.WriteLine("Couldn't read environment block.");
                return 13;
            }

            // Console as UTF-8
            SetConsoleOutputCP(CP_UTF8);
            Console.OutputEncoding = Encoding.UTF8;

            // Convert bytes (UTF-16-LE) to string and split
            int charCount2 = envBytes.Length / 2;
            var chars2 = new char[charCount2];
            Buffer.BlockCopy(envBytes, 0, chars2, 0, envBytes.Length);
            string envBlock = new string(chars2);
            string[] entries = envBlock.Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);

            Console.WriteLine($"PID {pid} environment ({entries.Length} entries):");
            foreach (var entry in entries)
            {
                Console.WriteLine(entry);
            }

            return 0;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }
}

// Build: cl /nologo /W4 /EHsc /DUNICODE /D_UNICODE envpid.cpp
//   x64 build recommended (handles both 32-bit & 64-bit targets).
//   For a 32-bit build reading a 64-bit target, this uses NtWow64* APIs.

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>   // for PROCESSINFOCLASS enum if available (we define fallbacks below)
#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")

// PBI (native pointer width)
typedef struct _PROCESS_BASIC_INFORMATION_T {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_T;

// PBI for 64-bit target when caller is 32-bit (explicit 64-bit layout)
typedef struct _PROCESS_BASIC_INFORMATION64 {
    ULONGLONG Reserved1;
    ULONGLONG PebBaseAddress;
    ULONGLONG Reserved2[2];
    ULONGLONG UniqueProcessId;
    ULONGLONG Reserved3;
} PROCESS_BASIC_INFORMATION64;

// Function pointer typedefs (resolved dynamically from ntdll/kernel32).
using pNtQueryInformationProcess = NTSTATUS(NTAPI*)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

using pNtWow64QueryInformationProcess64 = NTSTATUS(NTAPI*)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

using pNtWow64ReadVirtualMemory64 = NTSTATUS(NTAPI*)(
    HANDLE, ULONGLONG /*BaseAddress*/, PVOID /*Buffer*/, ULONGLONG /*BufferSize*/, PULONGLONG /*BytesRead*/);

using pIsWow64Process = BOOL(WINAPI*)(HANDLE, PBOOL);
using pIsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

// ---------- Privilege helper ----------
static bool EnablePrivilege(LPCWSTR name) {
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

static std::string WideToUtf8(const wchar_t* w, int len = -1) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, (LPSTR)s.data(), n, nullptr, nullptr);
    return s;
}

static void PrintLastError(const char* what) {
    DWORD err = GetLastError();
    LPWSTR msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, 0, (LPWSTR)&msg, 0, nullptr);

    std::string utf8Msg = msg ? WideToUtf8(msg) : "Unknown";
    if (msg) LocalFree(msg);

    // Optional: ensure console uses UTF-8 if you want proper glyphs
    // SetConsoleOutputCP(CP_UTF8);

    std::cerr << "[!] " << what
        << " failed with error " << err << ": "
        << utf8Msg << std::endl;
}

// ---------- Architecture detection ----------
struct ArchInfo {
    bool isTarget64 = false;
    bool isSelf64 = (sizeof(void*) == 8);
    bool isError = false;

};

static ArchInfo DetectArch(HANDLE hProcess) {
    ArchInfo ai{};
    // Prefer IsWow64Process2 if available (Windows 10+), else fall back.
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");

    auto pIsWow64Process2Fn = (pIsWow64Process2)GetProcAddress(hKernel, "IsWow64Process2");
    auto pIsWow64ProcessFn = (pIsWow64Process)GetProcAddress(hKernel, "IsWow64Process");

    USHORT processMachine = 0, nativeMachine = 0;
    if (pIsWow64Process2Fn && pIsWow64Process2Fn(hProcess, &processMachine, &nativeMachine)) {
        // If processMachine != IMAGE_FILE_MACHINE_UNKNOWN, target is WOW64 (i.e., 32-bit).
        // Otherwise target is native; it's 64-bit if nativeMachine is a 64-bit arch.
        // 0x8664 = AMD64, 0xAA64 = ARM64
        bool osIs64 = (nativeMachine == 0x8664 || nativeMachine == 0xAA64);
        ai.isTarget64 = (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) && osIs64;
        return ai;
    }

    // Fallback: IsWow64Process + OS arch
    BOOL isWow64 = FALSE;
    bool haveIsWow64 = pIsWow64ProcessFn && pIsWow64ProcessFn(hProcess, &isWow64);
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    bool osIs64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
    if (haveIsWow64) {
        ai.isTarget64 = (!isWow64 && osIs64); // not WOW64 on a 64-bit OS => 64-bit process
    }
    else {
        // On older systems: assume 32-bit target unless OS is clearly 64-bit and process not WOW64 (unknown here).
        ai.isTarget64 = osIs64 && ai.isSelf64; // best-effort
    }
    return ai;
}

// ---------- NTDLL resolution ----------
struct NtApi {
    pNtQueryInformationProcess NtQueryInformationProcess = nullptr;
    pNtWow64QueryInformationProcess64 NtWow64QueryInfo64 = nullptr;
    pNtWow64ReadVirtualMemory64 NtWow64ReadMem64 = nullptr;
    bool ok() const { return NtQueryInformationProcess != nullptr; }
};

static NtApi LoadNtApi() {
    NtApi api{};
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return api;
    api.NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(hNt, "NtQueryInformationProcess");
    api.NtWow64QueryInfo64 = (pNtWow64QueryInformationProcess64)
        GetProcAddress(hNt, "NtWow64QueryInformationProcess64");
    api.NtWow64ReadMem64 = (pNtWow64ReadVirtualMemory64)
        GetProcAddress(hNt, "NtWow64ReadVirtualMemory64");
    return api;
}

// ---------- Remote memory reading helpers ----------
static bool ReadRemote(HANDLE hProcess, ULONGLONG addr, void* buf, SIZE_T bytes,
    bool useWow64Read, const NtApi& api, SIZE_T* outRead = nullptr)
{
    if (useWow64Read) {
        if (!api.NtWow64ReadMem64) return false;
        ULONGLONG read = 0;
        NTSTATUS st = api.NtWow64ReadMem64(hProcess, addr, buf, (ULONGLONG)bytes, &read);
        if (outRead) *outRead = (SIZE_T)read;
        return NT_SUCCESS(st) && read > 0;
    }
    else {
        SIZE_T read = 0;
        BOOL ok = ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)addr, buf, bytes, &read);
        if (outRead) *outRead = read;
        return ok && read > 0;
    }
}

static bool ReadPtr(HANDLE hProcess, ULONGLONG addr, bool ptr64, ULONGLONG& out,
    bool useWow64Read, const NtApi& api)
{
    if (ptr64) {
        ULONGLONG tmp = 0;
        if (!ReadRemote(hProcess, addr, &tmp, sizeof(tmp), useWow64Read, api)) return false;
        out = tmp;
        return true;
    }
    else {
        uint32_t tmp = 0;
        if (!ReadRemote(hProcess, addr, &tmp, sizeof(tmp), useWow64Read, api)) return false;
        out = (ULONGLONG)tmp;
        return true;
    }
}

// Read remote environment (UTF-16) until double-NUL. Returns a vector of wchar_t (includes trailing NUL).
static std::vector<wchar_t> ReadRemoteEnvironmentBlock(HANDLE hProcess, ULONGLONG envAddr,
    bool target64, bool useWow64Read, const NtApi& api)
{
    const SIZE_T CHUNK = 64ull * 1024;           // 64KB
    const SIZE_T MAX_BYTES = 4ull * 1024 * 1024; // 4MB sanity cap
    std::vector<char> bytes; bytes.reserve(CHUNK);
    ULONGLONG cur = envAddr;
    SIZE_T total = 0;

    while (total < MAX_BYTES) {
        SIZE_T toRead = CHUNK;
        bytes.resize(total + toRead);
        SIZE_T actually = 0;
        if (!ReadRemote(hProcess, cur, bytes.data() + total, toRead, useWow64Read, api, &actually) || actually == 0) {
            // Try smaller reads when crossing region boundaries.
            bool progressed = false;
            for (SIZE_T sz = 16ull * 1024; sz >= 512; sz /= 2) {
                SIZE_T tryRead = sz;
                if (total + tryRead > bytes.size()) bytes.resize(total + tryRead);
                SIZE_T got = 0;
                if (ReadRemote(hProcess, cur, bytes.data() + total, tryRead, useWow64Read, api, &got) && got > 0) {
                    actually = got; progressed = true; break;
                }
            }
            if (!progressed) break;
        }
        total += actually;
        cur += actually;

        // Look for UTF-16 double-NUL terminator.
        if (total >= 4) {
            // Interpret as wchar_t (little-endian). Ensure alignment on 2-byte boundary:
            SIZE_T aligned = total & ~((SIZE_T)1);
            const wchar_t* w = (const wchar_t*)bytes.data();
            SIZE_T wcCount = aligned / sizeof(wchar_t);
            for (SIZE_T i = 1; i < wcCount; ++i) {
                if (w[i - 1] == L'\0' && w[i] == L'\0') {
                    // Found end; truncate.
                    SIZE_T bytesKeep = (i + 1) * sizeof(wchar_t);
                    bytes.resize(bytesKeep);
                    total = bytesKeep;
                    goto done;
                }
            }
        }
    }
done:
    // Convert raw bytes to wchar_t vector
    std::vector<wchar_t> out;
    SIZE_T aligned = total & ~((SIZE_T)1);
    out.resize(aligned / sizeof(wchar_t));
    memcpy(out.data(), bytes.data(), aligned);
    return out;
}

// ---------- Core logic ----------
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::wcerr << L"Usage: envpid <PID>\n";
        return 1;
    }

    DWORD pid = 0;
    try {
        pid = std::stoul(argv[1]);
    }
    catch (...) {
        std::wcerr << L"Invalid PID.\n";
        return 1;
    }

    // Try to enable SeDebugPrivilege (best-effort).
    EnablePrivilege(SE_DEBUG_NAME);

    // Open target process.
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        // Fallback for older Windows
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    }
    if (!hProcess) {
        PrintLastError("OpenProcess");
        return 2;
    }

    // Determine architectures.
    ArchInfo arch = DetectArch(hProcess);

    // Load NT API.
    NtApi nt = LoadNtApi();
    if (!nt.ok()) {
        std::wcerr << L"Failed to resolve NtQueryInformationProcess from ntdll.\n";
        CloseHandle(hProcess);
        return 3;
    }

    // Get PEB base address of target process.
    ULONGLONG pebAddr = 0;

    if (arch.isTarget64) {
        if (arch.isSelf64) {
            PROCESS_BASIC_INFORMATION_T pbi{};
            ULONG retLen = 0;
            NTSTATUS st = nt.NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
            if (!NT_SUCCESS(st)) {
                std::wcerr << L"NtQueryInformationProcess(ProcessBasicInformation) failed (target 64-bit).\n";
                CloseHandle(hProcess);
                return 4;
            }
            pebAddr = (ULONGLONG)(uintptr_t)pbi.PebBaseAddress;
        }
        else {
            if (!nt.NtWow64QueryInfo64) {
                std::wcerr << L"NtWow64QueryInformationProcess64 not available; rebuild as x64 or run on newer OS.\n";
                CloseHandle(hProcess);
                return 5;
            }
            PROCESS_BASIC_INFORMATION64 pbi64{};
            ULONG retLen = 0;
            NTSTATUS st = nt.NtWow64QueryInfo64(hProcess, ProcessBasicInformation, &pbi64, sizeof(pbi64), &retLen);
            if (!NT_SUCCESS(st)) {
                std::wcerr << L"NtWow64QueryInformationProcess64 failed (target 64-bit).\n";
                CloseHandle(hProcess);
                return 6;
            }
            pebAddr = pbi64.PebBaseAddress;
        }
    }
    else { // target is 32-bit
        if (arch.isSelf64) {
            // Query the WOW64 (32-bit) PEB address via ProcessWow64Information.
            PVOID wow64Peb = nullptr;
            ULONG retLen = 0;
            NTSTATUS st = nt.NtQueryInformationProcess(hProcess, ProcessWow64Information, &wow64Peb, sizeof(wow64Peb), &retLen);
            if (!NT_SUCCESS(st) || wow64Peb == nullptr) {
                std::wcerr << L"NtQueryInformationProcess(ProcessWow64Information) failed (target 32-bit under WOW64).\n";
                CloseHandle(hProcess);
                return 7;
            }
            pebAddr = (ULONGLONG)(uintptr_t)wow64Peb;
        }
        else {
            PROCESS_BASIC_INFORMATION_T pbi{};
            ULONG retLen = 0;
            NTSTATUS st = nt.NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
            if (!NT_SUCCESS(st)) {
                std::wcerr << L"NtQueryInformationProcess(ProcessBasicInformation) failed (target 32-bit).\n";
                CloseHandle(hProcess);
                return 8;
            }
            pebAddr = (ULONGLONG)(uintptr_t)pbi.PebBaseAddress;
        }
    }

    // Read ProcessParameters pointer from PEB.
    // Offsets are well-known: 0x10 (32-bit), 0x20 (64-bit)
    const ULONGLONG OFF_PEB_ProcessParameters_32 = 0x10;
    const ULONGLONG OFF_PEB_ProcessParameters_64 = 0x20;
    ULONGLONG procParams = 0;
    bool useWow64Read = (!arch.isSelf64 && arch.isTarget64); // only 32->64 needs NtWow64ReadVirtualMemory64

    if (!ReadPtr(hProcess,
        pebAddr + (arch.isTarget64 ? OFF_PEB_ProcessParameters_64 : OFF_PEB_ProcessParameters_32),
        arch.isTarget64,
        procParams, useWow64Read, nt)) {
        std::wcerr << L"Failed to read ProcessParameters pointer from remote PEB.\n";
        CloseHandle(hProcess);
        return 9;
    }
    if (procParams == 0) {
        std::wcerr << L"ProcessParameters is null. (Process may be exiting.)\n";
        CloseHandle(hProcess);
        return 10;
    }

    // Read Environment pointer from RTL_USER_PROCESS_PARAMETERS.
    // Offsets are well-known: 0x48 (32-bit), 0x80 (64-bit)
    const ULONGLONG OFF_RTLUPP_Environment_32 = 0x48;
    const ULONGLONG OFF_RTLUPP_Environment_64 = 0x80;

    ULONGLONG envPtr = 0;
    if (!ReadPtr(hProcess,
        procParams + (arch.isTarget64 ? OFF_RTLUPP_Environment_64 : OFF_RTLUPP_Environment_32),
        arch.isTarget64,
        envPtr, useWow64Read, nt)) {
        std::wcerr << L"Failed to read Environment pointer from remote RTL_USER_PROCESS_PARAMETERS.\n";
        CloseHandle(hProcess);
        return 11;
    }
    if (envPtr == 0) {
        std::wcerr << L"Environment pointer is null (no environment or process is tearing down).\n";
        CloseHandle(hProcess);
        return 12;
    }

    // Read environment block (UTF-16, double-NUL terminated)
    auto envW = ReadRemoteEnvironmentBlock(hProcess, envPtr, arch.isTarget64, useWow64Read, nt);
    CloseHandle(hProcess);

    if (envW.empty()) {
        std::wcerr << L"Couldn't read environment block.\n";
        return 13;
    }

    // Prepare console for UTF-8 output (so non-ASCII values show up correctly).
    SetConsoleOutputCP(CP_UTF8);

    // Parse and print each "NAME=VALUE" string until the terminating empty string.
    const wchar_t* p = envW.data();
    size_t count = 0;
    std::vector<std::wstring> lines;
    while (*p) {
        std::wstring entry = p;
        lines.push_back(std::move(entry));
        p += lines.back().size() + 1; // move past this string + NUL
        ++count;
    }

    std::cout << "PID " << pid << " environment (" << count << " entries):\n";
    for (const auto& w : lines) {
        // Print exactly as stored (may include entries beginning with '=' like "=C:=C:\\Windows")
        std::string utf8 = WideToUtf8(w.c_str());
        std::cout << utf8 << "\n";
    }
    return 0;
}

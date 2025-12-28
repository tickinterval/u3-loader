#pragma once

#include <windows.h>
#include <intrin.h>

namespace loader {
namespace anti_debug {

using NTSTATUS = LONG;

// ================== BASIC CHECKS ==================

// Проверка IsDebuggerPresent
inline bool CheckDebuggerPresent() {
    return IsDebuggerPresent() != FALSE;
}

// Alias для совместимости
inline bool IsDebuggerPresent_Check() {
    return CheckDebuggerPresent();
}

// Проверка через NtQueryInformationProcess
inline bool CheckRemoteDebugger() {
    BOOL is_debugged = FALSE;
    typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    
    if (NtQueryInformationProcess) {
        // ProcessDebugPort = 7
        NtQueryInformationProcess(GetCurrentProcess(), 7, &is_debugged, sizeof(BOOL), nullptr);
        return is_debugged != FALSE;
    }
    return false;
}

// Проверка через CheckRemoteDebuggerPresent
inline bool CheckRemoteDebuggerPresent() {
    BOOL is_debugged = FALSE;
    ::CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_debugged);
    return is_debugged != FALSE;
}

// Проверка через PEB.BeingDebugged
inline bool CheckPEB() {
#ifdef _WIN64
    BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
#else
    BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
#endif
    // Offset BeingDebugged в PEB = 0x2
    return peb && peb[2] != 0;
}

// Проверка на аппаратные breakpoint'ы
inline bool CheckHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
    }
    return false;
}

// ================== ADVANCED CHECKS ==================

// Проверка NtGlobalFlag в PEB (отладчик устанавливает флаги кучи)
inline bool CheckNtGlobalFlag() {
#ifdef _WIN64
    BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(peb + 0xBC);
#else
    BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(peb + 0x68);
#endif
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    const DWORD debugFlags = 0x70;
    return (ntGlobalFlag & debugFlags) != 0;
}

// Проверка HeapFlags (отладчик модифицирует кучу)
inline bool CheckHeapFlags() {
#ifdef _WIN64
    BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
    void** processHeap = reinterpret_cast<void**>(peb + 0x30);
    DWORD flags = *reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(*processHeap) + 0x70);
    DWORD forceFlags = *reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(*processHeap) + 0x74);
#else
    BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
    void** processHeap = reinterpret_cast<void**>(peb + 0x18);
    DWORD flags = *reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(*processHeap) + 0x40);
    DWORD forceFlags = *reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(*processHeap) + 0x44);
#endif
    // HEAP_GROWABLE = 2 - нормальный флаг, остальные подозрительны
    if (flags != 2) return true;
    if (forceFlags != 0) return true;
    return false;
}

// Timing check через RDTSC (отладка замедляет выполнение)
inline bool CheckRDTSC() {
    unsigned __int64 start, end;
    
    start = __rdtsc();
    
    // Фиктивные операции
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy += i;
    }
    
    end = __rdtsc();
    
    // Если дельта слишком большая - отладка или VM
    // Порог подобран эмпирически (обычно < 10000 циклов)
    return (end - start) > 100000;
}

// Проверка ProcessDebugFlags через NtQueryInformationProcess
inline bool CheckDebugFlags() {
    typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    
    if (NtQueryInformationProcess) {
        DWORD debugFlags = 0;
        // ProcessDebugFlags = 0x1F
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(DWORD), nullptr);
        if (status >= 0 && debugFlags == 0) {
            return true; // NoDebugInherit отключён = отладка
        }
    }
    return false;
}

// Проверка ProcessDebugObjectHandle
inline bool CheckDebugObjectHandle() {
    typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    
    if (NtQueryInformationProcess) {
        HANDLE debugObject = nullptr;
        // ProcessDebugObjectHandle = 0x1E
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0x1E, &debugObject, sizeof(HANDLE), nullptr);
        if (status >= 0 && debugObject != nullptr) {
            return true;
        }
    }
    return false;
}

// Проверка через OutputDebugString (SetLastError trick)
inline bool CheckOutputDebugString() {
    SetLastError(0);
    OutputDebugStringA("Anti-Debug Check");
    return GetLastError() != 0;
}

// Проверка CloseHandle с невалидным handle (вызывает исключение при отладке)
inline bool CheckCloseHandle() {
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(0xDEADBEEF));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true; // Исключение = отладчик
    }
    return false;
}

// Проверка INT 2D (отладчики часто перехватывают)
inline bool CheckInt2D() {
    __try {
#ifdef _WIN64
        // INT 2D не работает напрямую в x64, используем альтернативу
        __nop();
        return false;
#else
        __asm {
            int 0x2D
            nop
        }
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false; // Нормально - исключение словлено
    }
    return true; // Отладчик проглотил INT 2D
}

// Проверка NtSetInformationThread (скрытие от отладчика)
inline bool CheckThreadHideFromDebugger() {
    typedef NTSTATUS(WINAPI* NtSetInformationThread_t)(HANDLE, DWORD, PVOID, ULONG);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto NtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(
        GetProcAddress(ntdll, "NtSetInformationThread"));
    
    if (NtSetInformationThread) {
        // ThreadHideFromDebugger = 0x11
        NTSTATUS status = NtSetInformationThread(GetCurrentThread(), 0x11, nullptr, 0);
        // Если успешно - отладчик не сможет получать debug events
        return false; // Это не детекция, а активная защита
    }
    return false;
}

// ================== DETECTOR CHECKS ==================

// Проверка загруженных DLL отладчиков
inline bool CheckDebuggerDlls() {
    const wchar_t* debuggerDlls[] = {
        L"dbghelp.dll",
        L"api_ms_win_core_debug",
        L"vehdebug",
        L"SbieDll.dll",      // Sandboxie
        L"snxhk.dll",        // Avast sandbox
        L"cmdvrt32.dll",     // Comodo
        L"pstorec.dll",      // Некоторые отладчики
    };
    
    for (const auto& dll : debuggerDlls) {
        if (GetModuleHandleW(dll) != nullptr) {
            return true;
        }
    }
    return false;
}

// Проверка родительского процесса (не explorer.exe = подозрительно)
inline bool CheckParentProcess() {
    typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    
    if (!NtQueryInformationProcess) return false;
    
    struct PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } pbi = {};
    
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), nullptr);
    if (status < 0) return false;
    
    DWORD parentPid = static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
    
    // Открываем родительский процесс
    HANDLE parentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!parentProcess) return true; // Не можем открыть = подозрительно
    
    wchar_t parentPath[MAX_PATH] = {};
    DWORD pathLen = MAX_PATH;
    
    typedef BOOL(WINAPI* QueryFullProcessImageNameW_t)(HANDLE, DWORD, LPWSTR, PDWORD);
    auto QueryFullProcessImageNameW_fn = reinterpret_cast<QueryFullProcessImageNameW_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueryFullProcessImageNameW"));
    
    bool suspicious = false;
    if (QueryFullProcessImageNameW_fn && QueryFullProcessImageNameW_fn(parentProcess, 0, parentPath, &pathLen)) {
        // Конвертируем в нижний регистр
        _wcslwr_s(parentPath, MAX_PATH);
        
        // Проверяем на подозрительные родители
        const wchar_t* suspiciousParents[] = {
            L"x64dbg.exe",
            L"x32dbg.exe",
            L"ollydbg.exe",
            L"ida.exe",
            L"ida64.exe",
            L"idaq.exe",
            L"idaq64.exe",
            L"windbg.exe",
            L"dbgview.exe",
            L"processhacker.exe",
            L"procmon.exe",
            L"procexp.exe",
            L"pestudio.exe",
            L"fiddler.exe",
            L"charles.exe",
            L"wireshark.exe",
            L"dnspy.exe",
            L"de4dot.exe",
            L"cheatengine",
            L"httpanalyzer",
        };
        
        for (const auto& parent : suspiciousParents) {
            if (wcsstr(parentPath, parent) != nullptr) {
                suspicious = true;
                break;
            }
        }
    }
    
    CloseHandle(parentProcess);
    return suspicious;
}

// ================== DETECTOR CHECKS (declared in cpp) ==================

// Проверка запущенных процессов на подозрительные
bool CheckSuspiciousProcesses();

// Проверка подозрительных окон
bool CheckSuspiciousWindows();

// Проверка на хуки в критических функциях
bool CheckApiHooks();

// ================== COMBINED CHECKS ==================

// Базовая комплексная проверка (быстрая)
inline bool IsDebuggerDetected() {
    return CheckDebuggerPresent() ||
           CheckRemoteDebugger() ||
           CheckRemoteDebuggerPresent() ||
           CheckPEB() ||
           CheckHardwareBreakpoints();
}

// Расширенная комплексная проверка (более тщательная)
inline bool IsDebuggerDetectedAdvanced() {
    // Базовые проверки
    if (IsDebuggerDetected()) return true;
    
    // Продвинутые проверки
    if (CheckNtGlobalFlag()) return true;
    if (CheckDebugFlags()) return true;
    if (CheckDebugObjectHandle()) return true;
    if (CheckOutputDebugString()) return true;
    if (CheckDebuggerDlls()) return true;
    
    return false;
}

// Полная проверка (включая timing и parent process)
inline bool IsDebuggerDetectedFull() {
    if (IsDebuggerDetectedAdvanced()) return true;
    
    // Тяжёлые проверки
    if (CheckRDTSC()) return true;
    if (CheckParentProcess()) return true;
    if (CheckCloseHandle()) return true;
    
    return false;
}

// Активировать скрытие от отладчика
inline void HideFromDebugger() {
    CheckThreadHideFromDebugger();
}

// ================== WATCHDOG ==================

// Поток-сторож для постоянной проверки
DWORD WINAPI AntiDebugWatchdog(LPVOID param);

// Запуск watchdog потока
void StartWatchdog();

// Остановка watchdog потока
void StopWatchdog();

} // namespace anti_debug
} // namespace loader

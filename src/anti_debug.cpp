#include "anti_debug.h"
#include "anti_crack.h"
#include <atomic>
#include <tlhelp32.h>

namespace loader {
namespace anti_debug {

static std::atomic<bool> g_watchdog_running(true);
static HANDLE g_watchdog_thread = nullptr;

// Список подозрительных процессов (отладчики, анализаторы, сниферы)
static const wchar_t* g_suspicious_processes[] = {
    // Отладчики
    L"x64dbg.exe",
    L"x32dbg.exe",
    L"ollydbg.exe",
    L"ida.exe",
    L"ida64.exe",
    L"idaq.exe",
    L"idaq64.exe",
    L"windbg.exe",
    L"devenv.exe",       // Visual Studio (может отлаживать)
    L"radare2.exe",
    L"r2.exe",
    L"immunity debugger.exe",
    
    // Дизассемблеры и анализаторы
    L"ghidra.exe",
    L"cutter.exe",
    L"binaryninja.exe",
    L"hopper.exe",
    L"pestudio.exe",
    L"die.exe",          // Detect It Easy
    L"exeinfope.exe",
    L"lordpe.exe",
    L"pe-bear.exe",
    
    // Мониторы процессов
    L"processhacker.exe",
    L"procmon.exe",
    L"procmon64.exe",
    L"procexp.exe",
    L"procexp64.exe",
    L"apimonitor.exe",
    L"apimonitor-x64.exe",
    
    // Сетевые анализаторы
    L"wireshark.exe",
    L"fiddler.exe",
    L"charles.exe",
    L"httpanalyzer",
    L"httpdebuggerpro.exe",
    L"telerik.httpproxy.exe",
    
    // .NET анализаторы
    L"dnspy.exe",
    L"de4dot.exe",
    L"ilspy.exe",
    L"dotpeek.exe",
    L"justdecompile.exe",
    
    // Читы и инжекторы
    L"cheatengine-x86_64.exe",
    L"cheatengine-i386.exe",
    L"cheatengine.exe",
    L"ce.exe",
    L"artmoney.exe",
    L"extremeinjector.exe",
    
    // Снифферы и прокси
    L"mitmproxy.exe",
    L"burp.exe",
    L"zaproxy.exe",
    
    // Виртуальные машины (tools)
    L"vmtoolsd.exe",
    L"vmwaretray.exe",
    L"vboxservice.exe",
    L"vboxtray.exe",
    
    // Дамперы памяти
    L"scylla.exe",
    L"scylla_x64.exe",
    L"scylla_x86.exe",
    L"importrec.exe",
    L"imprec.exe",
    
    // Sandbox
    L"sandboxiedcomlaunch.exe",
    L"sandboxierpcss.exe",
    
    // Другие
    L"resourcehacker.exe",
    L"regmon.exe",
    L"filemon.exe",
    L"autoruns.exe",
    L"tcpview.exe",
};

// Список подозрительных заголовков окон
static const wchar_t* g_suspicious_windows[] = {
    L"x64dbg",
    L"x32dbg",
    L"OllyDbg",
    L"IDA",
    L"Ghidra",
    L"WinDbg",
    L"Cheat Engine",
    L"Process Hacker",
    L"Process Monitor",
    L"Process Explorer",
    L"Wireshark",
    L"Fiddler",
    L"HTTP Debugger",
    L"dnSpy",
    L"PE Explorer",
    L"PE-bear",
    L"Scylla",
    L"Import Reconstructor",
    L"Resource Hacker",
    L"API Monitor",
};

// Проверка запущенных процессов на подозрительные
bool CheckSuspiciousProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    
    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            // Конвертируем имя процесса в нижний регистр для сравнения
            wchar_t procName[MAX_PATH];
            wcscpy_s(procName, entry.szExeFile);
            _wcslwr_s(procName);
            
            for (const auto& suspicious : g_suspicious_processes) {
                wchar_t suspLower[MAX_PATH];
                wcscpy_s(suspLower, suspicious);
                _wcslwr_s(suspLower);
                
                if (wcsstr(procName, suspLower) != nullptr) {
                    found = true;
                    break;
                }
            }
            
            if (found) break;
        } while (Process32NextW(snapshot, &entry));
    }
    
    CloseHandle(snapshot);
    return found;
}

// Callback для проверки окон
static bool g_suspicious_window_found = false;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    wchar_t title[256] = {};
    GetWindowTextW(hwnd, title, 256);
    
    if (wcslen(title) == 0) {
        return TRUE; // Продолжаем
    }
    
    // Конвертируем в нижний регистр
    _wcslwr_s(title);
    
    for (const auto& suspicious : g_suspicious_windows) {
        wchar_t suspLower[256];
        wcscpy_s(suspLower, suspicious);
        _wcslwr_s(suspLower);
        
        if (wcsstr(title, suspLower) != nullptr) {
            g_suspicious_window_found = true;
            return FALSE; // Прекращаем перечисление
        }
    }
    
    return TRUE;
}

// Проверка подозрительных окон
bool CheckSuspiciousWindows() {
    g_suspicious_window_found = false;
    EnumWindows(EnumWindowsProc, 0);
    return g_suspicious_window_found;
}

// Проверка на хуки в критических функциях
bool CheckApiHooks() {
    // Проверяем начало функций на наличие JMP инструкций
    auto CheckForHook = [](void* func) -> bool {
        if (!func) return false;
        
        BYTE* bytes = static_cast<BYTE*>(func);
        
        // Проверяем на JMP (E9), CALL (E8), или push+ret комбинации
        if (bytes[0] == 0xE9 || bytes[0] == 0xE8) return true;
        if (bytes[0] == 0x68 && bytes[5] == 0xC3) return true; // push + ret
        if (bytes[0] == 0xFF && bytes[1] == 0x25) return true; // jmp [addr]
        if (bytes[0] == 0x48 && bytes[1] == 0xB8) return true; // mov rax, addr (x64)
        
        return false;
    };
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    
    if (!ntdll || !kernel32) return false;
    
    // Критические функции для проверки
    if (CheckForHook(GetProcAddress(ntdll, "NtQueryInformationProcess"))) return true;
    if (CheckForHook(GetProcAddress(ntdll, "NtSetInformationThread"))) return true;
    if (CheckForHook(GetProcAddress(ntdll, "NtQuerySystemInformation"))) return true;
    if (CheckForHook(GetProcAddress(kernel32, "IsDebuggerPresent"))) return true;
    if (CheckForHook(GetProcAddress(kernel32, "CheckRemoteDebuggerPresent"))) return true;
    
    return false;
}

// Усиленный watchdog с рандомными интервалами
DWORD WINAPI AntiDebugWatchdog(LPVOID param) {
    // Сразу скрываем этот поток от отладчика
    HideFromDebugger();
    
    // Начальная задержка (рандомная)
    Sleep(500 + (GetTickCount() % 500));
    
    DWORD check_counter = 0;
    
    while (g_watchdog_running) {
        // Каждую итерацию делаем разные проверки
        bool detected = false;
        
        switch (check_counter % 8) {
            case 0:
                detected = IsDebuggerDetected();
                break;
            case 1:
                detected = CheckNtGlobalFlag();
                break;
            case 2:
                detected = CheckDebugFlags();
                break;
            case 3:
                detected = CheckDebugObjectHandle();
                break;
            case 4:
                detected = CheckSuspiciousProcesses();
                break;
            case 5:
                detected = CheckSuspiciousWindows();
                break;
            case 6:
                detected = CheckApiHooks();
                break;
            case 7:
                // Полная проверка раз в 8 итераций
                detected = IsDebuggerDetectedAdvanced();
                break;
        }
        
        if (detected) {
            ANTI_CRACK_RANDOM();
        }
        
        check_counter++;
        
        // Рандомный интервал 600-1400мс для усложнения анализа
        DWORD sleep_time = 600 + (GetTickCount() % 800);
        Sleep(sleep_time);
    }
    
    return 0;
}

void StartWatchdog() {
    g_watchdog_running = true;
    g_watchdog_thread = CreateThread(nullptr, 0, AntiDebugWatchdog, nullptr, 0, nullptr);
    
    // Устанавливаем приоритет выше среднего
    if (g_watchdog_thread) {
        SetThreadPriority(g_watchdog_thread, THREAD_PRIORITY_ABOVE_NORMAL);
    }
}

void StopWatchdog() {
    g_watchdog_running = false;
    
    if (g_watchdog_thread) {
        WaitForSingleObject(g_watchdog_thread, 2000);
        CloseHandle(g_watchdog_thread);
        g_watchdog_thread = nullptr;
    }
}

} // namespace anti_debug
} // namespace loader

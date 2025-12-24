#include "app.h"
#include "anti_debug.h"
#include "protection.h"
#include "anti_crack.h"

static void CenterWindowOnMonitor(HWND hwnd) {
    RECT rc = {};
    if (!GetWindowRect(hwnd, &rc)) {
        return;
    }
    HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = {};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(monitor, &mi)) {
        return;
    }
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    int x = mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - width) / 2;
    int y = mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - height) / 2;
    SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    // ============ ЗАЩИТА ОТ КРЯКИНГА ============
    // ПРИМЕЧАНИЕ: Для тестирования некоторые проверки временно отключены
    // Включи их обратно перед production!
    
    // 0. Скрываем основной поток от отладчика
    loader::anti_debug::HideFromDebugger();
    
    // 1. Базовая анти-отладка (без агрессивных проверок)
    if (loader::anti_debug::IsDebuggerPresent_Check()) {
        ANTI_CRACK_RANDOM();
        return 0;
    }
    
    // 2-4. Проверки процессов/окон/хуков (временно отключены для тестирования)
    // ANTI_CRACK_CHECK(loader::anti_debug::CheckSuspiciousProcesses());
    // ANTI_CRACK_CHECK(loader::anti_debug::CheckSuspiciousWindows());
    // ANTI_CRACK_CHECK(loader::anti_debug::CheckApiHooks());
    
    // 5. Запуск watchdog потока для постоянной проверки (ВРЕМЕННО ОТКЛЮЧЕН)
    // loader::anti_debug::StartWatchdog();
    
    // 6-7. VM/Sandbox проверки (временно отключены - слишком много false positives)
    // if (loader::protection::IsRunningInVM()) {
    //     ANTI_CRACK_RANDOM();
    //     return 0;
    // }
    // if (loader::protection::IsRunningSandbox()) {
    //     ANTI_CRACK_RANDOM();
    //     return 0;
    // }
    
    // 8. Проверка целостности (отключена для разработки)
    // ВАЖНО: Для production используйте VMProtect/Themida с опцией "Integrity Check"
    if (!loader::protection::VerifyIntegrity()) {
        ANTI_CRACK_EXIT();
        return 0;
    }
    
    // ============================================
    
    auto set_dpi_context = reinterpret_cast<BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT)>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDpiAwarenessContext"));
    if (set_dpi_context) {
        set_dpi_context(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    } else {
        SetProcessDPIAware();
    }

    InitializeCriticalSection(&loader::g_status_lock);
    InitializeCriticalSection(&loader::g_programs_lock);

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    if (!loader::LoadConfig(&loader::g_config)) {
        MessageBoxW(nullptr, L"Configuration error", L"u3ware", MB_OK | MB_ICONERROR);
        return 0;
    }

    if (loader::CheckForUpdateSilent()) {
        return 0;
    }

    loader::LoadSavedKey(&loader::g_cached_key);

    const wchar_t* kClassName = L"LoaderAppWindow";
    const wchar_t* kStatusClassName = L"LoaderStatusWindow";
    WNDCLASSW wc = {};
    wc.lpfnWndProc = loader::WndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = kClassName;
    RegisterClassW(&wc);
    wc.lpszClassName = kStatusClassName;
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, kClassName, L"u3ware", WS_POPUP | WS_SYSMENU | WS_MINIMIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT, 480, 320, nullptr, nullptr, instance, nullptr);
    if (!hwnd) {
        return 0;
    }

    CenterWindowOnMonitor(hwnd);
    loader::g_hwnd = hwnd;
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    loader::SetStage(loader::g_stage);
    if (!loader::g_cached_key.empty()) {
        PostMessageW(hwnd, loader::kMsgAutoValidate, 0, 0);
    }

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    DeleteCriticalSection(&loader::g_status_lock);
    DeleteCriticalSection(&loader::g_programs_lock);
    return 0;
}

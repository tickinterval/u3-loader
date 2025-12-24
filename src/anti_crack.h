#pragma once

#include <windows.h>

namespace loader {
namespace anti_crack {

// Безопасное завершение процесса без явного вызова ExitProcess
// Использует различные методы для крашинга приложения
inline void SecureExit() {
    // Метод 1: Access Violation
    __try {
        *(volatile int*)0 = 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Метод 2: Terminate через handle
        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
    }
    
    // Метод 3: Если всё ещё живы - бесконечный цикл с крашем
    while (true) {
        *(volatile int*)nullptr = 0;
    }
}

// Варианты краша для обфускации
inline void CrashMethod1() {
    // Division by zero в inline assembly (сложнее детектить)
    volatile int x = 0;
    volatile int y = 1 / x;
    (void)y;
}

inline void CrashMethod2() {
    // Stack overflow
    volatile char buffer[1024*1024*10]; // 10MB на стеке
    memset((void*)buffer, 0xFF, sizeof(buffer));
}

inline void CrashMethod3() {
    // Access violation через NULL pointer
    __try {
        void(*crash_func)() = nullptr;
        crash_func(); // Вызов NULL указателя
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        *(int*)0 = 0;
    }
}

// Выбирает случайный метод краша для усложнения анализа
inline void RandomCrash() {
    DWORD tick = GetTickCount();
    switch (tick % 3) {
        case 0: CrashMethod1(); break;
        case 1: CrashMethod2(); break;
        case 2: CrashMethod3(); break;
    }
    // Если ничего не сработало
    SecureExit();
}

} // namespace anti_crack
} // namespace loader

// Макросы для использования в коде
#define ANTI_CRACK_EXIT() loader::anti_crack::SecureExit()
#define ANTI_CRACK_RANDOM() loader::anti_crack::RandomCrash()

// Условный краш с обфускацией
#define ANTI_CRACK_CHECK(condition) \
    do { \
        if (condition) { \
            volatile int _dummy = GetTickCount() % 2; \
            if (_dummy == 0 || _dummy == 1) { \
                ANTI_CRACK_RANDOM(); \
            } \
        } \
    } while(0)


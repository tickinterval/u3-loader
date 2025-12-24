#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace loader {
namespace injector {

// Результат инжекта
struct InjectionResult {
    bool success;
    std::wstring error;
    DWORD target_pid;  // PID целевого процесса (для shared memory)
};

// Manual mapping injection в целевой процесс
InjectionResult InjectDll(const std::wstring& target_process_name, const std::vector<char>& dll_bytes);

// Инжект по PID (если процесс уже найден)
InjectionResult InjectDllByPid(DWORD target_pid, const std::vector<char>& dll_bytes);

// Поиск процесса по имени
DWORD FindProcessId(const std::wstring& process_name);

// Ожидание появления процесса
DWORD WaitForProcessId(const std::wstring& process_name);

// Проверка архитектуры процесса (x86/x64)
bool IsProcess32Bit(DWORD process_id);

} // namespace injector
} // namespace loader

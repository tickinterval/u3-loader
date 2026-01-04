#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace loader {
namespace process_info {

// Информация о модуле процесса
struct ModuleInfo {
    std::wstring name;           // Имя модуля (например, "wotblitz.exe")
    uintptr_t base_address;      // Базовый адрес модуля
    size_t size;                 // Размер модуля
    std::wstring path;           // Полный путь к модулю
};

// Информация о функции в модуле
struct FunctionInfo {
    std::string module_name;     // Имя модуля (ANSI для GetProcAddress)
    std::string function_name;   // Имя функции
    uintptr_t address;           // Адрес функции (если удалось получить)
};

// Полная информация о процессе для защиты
struct ProcessInfo {
    DWORD process_id;                    // PID процесса
    std::vector<ModuleInfo> modules;      // Список модулей
    std::vector<FunctionInfo> functions;  // Список функций для проверки
    uint64_t timestamp;                  // Timestamp сбора информации
};

// Сбор информации о процессе
// Возвращает true если успешно собрана информация
bool CollectProcessInfo(DWORD process_id, ProcessInfo* info);

// Преобразование ProcessInfo в JSON для отправки на сервер
std::string ProcessInfoToJson(const ProcessInfo& info);

// Получение CPUID (для проверки в DLL)
uint32_t GetCPUID();

} // namespace process_info
} // namespace loader










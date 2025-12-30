#pragma once

#include <windows.h>
#include <string>

namespace loader {
namespace shared_config {

// Имя shared memory (с рандомным суффиксом для уникальности)
#define SHARED_CONFIG_NAME_PREFIX L"Local\\U3W_CFG_"

// Магическое число для проверки валидности
#define SHARED_CONFIG_MAGIC 0x55335743  // "U3WC"

// Максимальные размеры строк
#define MAX_URL_LENGTH 256
#define MAX_THUMBPRINT_LENGTH 128
#define MAX_PRODUCT_LENGTH 32
#define MAX_TOKEN_LENGTH 512

// Структура конфигурации в shared memory
#pragma pack(push, 1)
struct SharedConfig {
    DWORD magic;                            // Магическое число для проверки
    DWORD version;                          // Версия структуры
    wchar_t server_url[MAX_URL_LENGTH];     // TCP server URL (tcps://host:port)
    wchar_t server_thumbprint[MAX_THUMBPRINT_LENGTH]; // TLS certificate pin (hex)
    wchar_t product_code[MAX_PRODUCT_LENGTH]; // Код продукта
    char event_token[MAX_TOKEN_LENGTH];     // Токен для событий
    DWORD heartbeat_interval_ms;            // Интервал heartbeat в мс
    DWORD flags;                            // Дополнительные флаги
};
#pragma pack(pop)

// Флаги
#define CONFIG_FLAG_HEARTBEAT_ENABLED   0x0001
#define CONFIG_FLAG_PROTECTION_ENABLED  0x0002

// Генерация уникального имени shared memory
inline std::wstring GenerateSharedName() {
    wchar_t name[64];
    // Используем PID целевого процесса как часть имени
    swprintf_s(name, L"%s%08X", SHARED_CONFIG_NAME_PREFIX, GetCurrentProcessId());
    return name;
}

// Генерация имени для целевого процесса
inline std::wstring GenerateSharedNameForProcess(DWORD targetPid) {
    wchar_t name[64];
    swprintf_s(name, L"%s%08X", SHARED_CONFIG_NAME_PREFIX, targetPid);
    return name;
}

// Запись конфигурации в shared memory (вызывается лоадером)
inline HANDLE WriteConfig(DWORD targetPid, const SharedConfig& config) {
    std::wstring name = GenerateSharedNameForProcess(targetPid);
    
    // Создаём shared memory
    HANDLE mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        sizeof(SharedConfig),
        name.c_str()
    );
    
    if (!mapping) {
        return nullptr;
    }
    
    // Мапим в наше адресное пространство
    SharedConfig* shared = reinterpret_cast<SharedConfig*>(
        MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(SharedConfig))
    );
    
    if (!shared) {
        CloseHandle(mapping);
        return nullptr;
    }
    
    // Копируем данные
    memcpy(shared, &config, sizeof(SharedConfig));
    
    // Отмапливаем (данные остаются в shared memory)
    UnmapViewOfFile(shared);
    
    // Возвращаем handle (нужно держать открытым пока DLL не прочитает)
    return mapping;
}

// Чтение конфигурации из shared memory (вызывается DLL)
inline bool ReadConfig(SharedConfig* config) {
    // Пробуем несколько вариантов имени (для разных PID)
    DWORD currentPid = GetCurrentProcessId();
    
    std::wstring name = GenerateSharedNameForProcess(currentPid);
    
    HANDLE mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, name.c_str());
    if (!mapping) {
        return false;
    }
    
    SharedConfig* shared = reinterpret_cast<SharedConfig*>(
        MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(SharedConfig))
    );
    
    if (!shared) {
        CloseHandle(mapping);
        return false;
    }
    
    // Проверяем магическое число
    if (shared->magic != SHARED_CONFIG_MAGIC) {
        UnmapViewOfFile(shared);
        CloseHandle(mapping);
        return false;
    }
    
    // Копируем данные
    memcpy(config, shared, sizeof(SharedConfig));
    
    // Очищаем (затираем данные в shared memory)
    volatile char* p = reinterpret_cast<volatile char*>(shared);
    for (size_t i = 0; i < sizeof(SharedConfig); i++) {
        p[i] = 0;
    }
    
    UnmapViewOfFile(shared);
    CloseHandle(mapping);
    
    return true;
}

// Очистка shared memory (вызывается лоадером после инжекта)
inline void CleanupConfig(HANDLE mapping) {
    if (mapping) {
        CloseHandle(mapping);
    }
}

} // namespace shared_config
} // namespace loader

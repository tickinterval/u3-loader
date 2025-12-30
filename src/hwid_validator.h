#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace loader {
namespace hwid_validator {

// Результат валидации HWID
struct ValidationResult {
    bool is_valid;
    int suspicion_score;  // 0-100, где 100 = точно spoof
    std::vector<std::string> flags;  // Список подозрительных признаков
};

// Основная валидация HWID
ValidationResult ValidateHWID();

// Проверка на известные HWID спуферы
bool DetectKnownSpoofers();

// Проверка консистентности компонентов
bool CheckComponentConsistency();

// Детект виртуальных компонентов
bool DetectVirtualComponents();

// Проверка SMBIOS на валидность
bool ValidateSMBIOS();

// Детект известных дефолтных значений
bool DetectDefaultValues();

// Получение списка подозрительных процессов
std::vector<std::string> GetSuspiciousProcesses();

} // namespace hwid_validator
} // namespace loader






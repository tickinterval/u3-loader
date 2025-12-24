#include "hwid_validator.h"
#include "app.h"
#include <tlhelp32.h>
#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "setupapi.lib")

namespace loader {
namespace hwid_validator {

// Известные HWID спуферы
static const wchar_t* KNOWN_SPOOFERS[] = {
    L"hwid.exe",
    L"hwidspoofer.exe", 
    L"hwidchanger.exe",
    L"macchanger.exe",
    L"volumeidchanger.exe",
    L"serialchanger.exe",
    L"temperhwid.exe",
    L"eacspoofer.exe",
    L"beспуфер.exe",
    L"valorantspoofer.exe",
    L"apexspoofer.exe",
    L"fnspoofер.exe",
    L"hwchanger.exe",
    L"diskspoofer.exe",
    L"guidspoofer.exe",
    L"pcispoofer.exe",
    L"usbspoofer.exe",
    L"nicspoofer.exe",
    L"bioseditor.exe",
    L"dmiedit.exe",
};

// Дефолтные/подозрительные значения SMBIOS
static const wchar_t* SUSPICIOUS_SMBIOS[] = {
    L"To Be Filled By O.E.M.",
    L"To be filled by O.E.M.",
    L"System Product Name",
    L"System Version",
    L"Default string",
    L"OEM",
    L"INVALID",
    L"None",
    L"Not Specified",
    L"N/A",
    L"Unknown",
    L"",
    L"1234567890",
    L"0123456789",
    L"12345678-1234-1234-1234-123456789012",
    L"00000000-0000-0000-0000-000000000000",
    L"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
};

// Виртуальные диски/компоненты
static const wchar_t* VIRTUAL_DISK_MODELS[] = {
    L"DADY HARDDISK",
    L"QEMU HARDDISK",
    L"VBOX HARDDISK",
    L"Virtual HD",
    L"Virtual Disk",
    L"VMware Virtual",
    L"Msft Virtual Disk",
};

std::wstring ToLowerW(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

bool ContainsSubstringI(const std::wstring& haystack, const std::wstring& needle) {
    return ToLowerW(haystack).find(ToLowerW(needle)) != std::wstring::npos;
}

std::vector<std::string> GetSuspiciousProcesses() {
    std::vector<std::string> suspicious;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return suspicious;
    }
    
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring exe_name = entry.szExeFile;
            std::wstring exe_lower = ToLowerW(exe_name);
            
            for (const wchar_t* spoofer : KNOWN_SPOOFERS) {
                if (exe_lower == ToLowerW(spoofer)) {
                    char name_utf8[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, exe_name.c_str(), -1, name_utf8, MAX_PATH, nullptr, nullptr);
                    suspicious.push_back(name_utf8);
                }
            }
            
            // Детект по паттернам в имени
            if (ContainsSubstringI(exe_name, L"spoof") ||
                ContainsSubstringI(exe_name, L"changer") ||
                ContainsSubstringI(exe_name, L"hwid") ||
                ContainsSubstringI(exe_name, L"serial") ||
                ContainsSubstringI(exe_name, L"volume") ||
                ContainsSubstringI(exe_name, L"disk") && ContainsSubstringI(exe_name, L"edit")) {
                char name_utf8[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, exe_name.c_str(), -1, name_utf8, MAX_PATH, nullptr, nullptr);
                // Избегаем дубликатов
                if (std::find(suspicious.begin(), suspicious.end(), name_utf8) == suspicious.end()) {
                    suspicious.push_back(name_utf8);
                }
            }
            
        } while (Process32NextW(snapshot, &entry));
    }
    
    CloseHandle(snapshot);
    return suspicious;
}

bool DetectKnownSpoofers() {
    return !GetSuspiciousProcesses().empty();
}

bool DetectDefaultValues() {
    int suspicious_count = 0;
    
    // Проверяем SMBIOS UUID
    std::wstring uuid = loader::GetSmbiosUuid();
    for (const wchar_t* suspicious : SUSPICIOUS_SMBIOS) {
        if (uuid == suspicious) {
            suspicious_count++;
            break;
        }
    }
    
    // Проверяем BIOS Serial
    std::wstring bios_serial = loader::GetBiosSerial();
    for (const wchar_t* suspicious : SUSPICIOUS_SMBIOS) {
        if (bios_serial == suspicious) {
            suspicious_count++;
            break;
        }
    }
    
    // Проверяем Baseboard Serial
    std::wstring baseboard_serial = loader::GetBaseBoardSerial();
    for (const wchar_t* suspicious : SUSPICIOUS_SMBIOS) {
        if (baseboard_serial == suspicious) {
            suspicious_count++;
            break;
        }
    }
    
    // Проверяем на пустые или слишком короткие серийники
    if (bios_serial.empty() || bios_serial.length() < 4) {
        suspicious_count++;
    }
    if (baseboard_serial.empty() || baseboard_serial.length() < 4) {
        suspicious_count++;
    }
    
    // Если 2+ компонента подозрительны - возвращаем true
    return suspicious_count >= 2;
}

bool DetectVirtualComponents() {
    // Проверяем диски через WMI/API
    HDEVINFO device_info = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISKDRIVE, nullptr, nullptr, DIGCF_PRESENT);
    if (device_info == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    bool is_virtual = false;
    SP_DEVINFO_DATA device_data = {};
    device_data.cbSize = sizeof(device_data);
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(device_info, i, &device_data); i++) {
        wchar_t model[256] = {};
        if (SetupDiGetDeviceRegistryPropertyW(device_info, &device_data, SPDRP_FRIENDLYNAME,
                                              nullptr, reinterpret_cast<PBYTE>(model),
                                              sizeof(model), nullptr)) {
            for (const wchar_t* virtual_model : VIRTUAL_DISK_MODELS) {
                if (ContainsSubstringI(model, virtual_model)) {
                    is_virtual = true;
                    break;
                }
            }
        }
        if (is_virtual) break;
    }
    
    SetupDiDestroyDeviceInfoList(device_info);
    return is_virtual;
}

bool ValidateSMBIOS() {
    std::wstring uuid = loader::GetSmbiosUuid();
    
    // UUID не должен быть пустым
    if (uuid.empty() || uuid.length() < 32) {
        return false;
    }
    
    // UUID не должен быть заполнен одним символом
    bool all_same = true;
    wchar_t first_char = uuid[0];
    for (wchar_t c : uuid) {
        if (c != first_char && c != L'-') {
            all_same = false;
            break;
        }
    }
    if (all_same) {
        return false;
    }
    
    // Проверка на подозрительные паттерны
    for (const wchar_t* suspicious : SUSPICIOUS_SMBIOS) {
        if (ContainsSubstringI(uuid, suspicious)) {
            return false;
        }
    }
    
    return true;
}

bool CheckComponentConsistency() {
    // Проверяем что у нас есть базовая информация о системе
    std::wstring machine_guid = loader::GetMachineGuid();
    std::wstring volume_serial = loader::GetVolumeSerial();
    std::wstring cpu = loader::GetCpuName();
    std::wstring gpu = loader::GetGpuName();
    
    int empty_count = 0;
    if (machine_guid.empty()) empty_count++;
    if (volume_serial.empty()) empty_count++;
    if (cpu.empty()) empty_count++;
    if (gpu.empty()) empty_count++;
    
    // Если больше 2 компонентов пусты - подозрительно
    if (empty_count > 2) {
        return false;
    }
    
    // MachineGuid и VolumeSerial не должны быть одинаковыми
    if (!machine_guid.empty() && !volume_serial.empty() && machine_guid == volume_serial) {
        return false;
    }
    
    return true;
}

ValidationResult ValidateHWID() {
    ValidationResult result;
    result.is_valid = true;
    result.suspicion_score = 0;
    
    // 1. Проверка на известные спуферы (+40 баллов)
    if (DetectKnownSpoofers()) {
        result.suspicion_score += 40;
        result.flags.push_back("known_spoofer_detected");
    }
    
    // 2. Проверка на дефолтные значения (+30 баллов)
    if (DetectDefaultValues()) {
        result.suspicion_score += 30;
        result.flags.push_back("default_smbios_values");
    }
    
    // 3. Проверка на виртуальные компоненты (+20 баллов)
    if (DetectVirtualComponents()) {
        result.suspicion_score += 20;
        result.flags.push_back("virtual_components");
    }
    
    // 4. Валидация SMBIOS (+15 баллов)
    if (!ValidateSMBIOS()) {
        result.suspicion_score += 15;
        result.flags.push_back("invalid_smbios");
    }
    
    // 5. Проверка консистентности (+25 баллов)
    if (!CheckComponentConsistency()) {
        result.suspicion_score += 25;
        result.flags.push_back("inconsistent_components");
    }
    
    // Получаем список подозрительных процессов
    std::vector<std::string> suspicious_procs = GetSuspiciousProcesses();
    for (const auto& proc : suspicious_procs) {
        result.flags.push_back("process:" + proc);
    }
    
    // Порог: 50+ баллов = подозрительный HWID
    if (result.suspicion_score >= 50) {
        result.is_valid = false;
    }
    
    return result;
}

} // namespace hwid_validator
} // namespace loader


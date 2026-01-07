#include "process_info.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

namespace loader {
namespace process_info {

// Получение CPUID через встроенные функции
uint32_t GetCPUID() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1); // EAX=1 для получения CPUID
    
    // Используем комбинацию EAX, EBX, ECX, EDX для создания уникального идентификатора
    // XOR всех регистров для получения 32-битного значения
    // Mask APIC ID bits (per-core) for a stable fingerprint.
    cpuInfo[1] &= 0x00FFFFFF;
    return static_cast<uint32_t>(cpuInfo[0] ^ cpuInfo[1] ^ cpuInfo[2] ^ cpuInfo[3]);
}

// Получение списка модулей процесса
static bool GetProcessModules(DWORD process_id, std::vector<ModuleInfo>& modules) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (!process) {
        return false;
    }
    
    HMODULE module_handles[1024];
    DWORD needed = 0;
    
    if (!EnumProcessModules(process, module_handles, sizeof(module_handles), &needed)) {
        CloseHandle(process);
        return false;
    }
    
    DWORD module_count = needed / sizeof(HMODULE);
    modules.reserve(module_count);
    
    for (DWORD i = 0; i < module_count && i < 1024; i++) {
        MODULEINFO mod_info = {};
        if (!GetModuleInformation(process, module_handles[i], &mod_info, sizeof(mod_info))) {
            continue;
        }
        
        wchar_t module_name[MAX_PATH] = {};
        wchar_t module_path[MAX_PATH] = {};
        
        if (GetModuleBaseNameW(process, module_handles[i], module_name, MAX_PATH) &&
            GetModuleFileNameExW(process, module_handles[i], module_path, MAX_PATH)) {
            
            ModuleInfo info = {};
            info.name = module_name;
            info.base_address = reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll);
            info.size = mod_info.SizeOfImage;
            info.path = module_path;
            
            modules.push_back(info);
        }
    }
    
    CloseHandle(process);
    return true;
}

// Получение адресов критических функций
static bool GetCriticalFunctions(DWORD process_id, const std::vector<ModuleInfo>& modules, 
                                  std::vector<FunctionInfo>& functions) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (!process) {
        return false;
    }
    
    // Список критических модулей и функций для проверки
    struct CriticalFunction {
        const char* module;
        const char* function;
    };
    
    static const CriticalFunction critical_funcs[] = {
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "GetProcAddress"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "VirtualProtect"},
        {"ntdll.dll", "NtCreateThreadEx"},
        {"ntdll.dll", "NtQueryInformationProcess"},
    };
    
    for (const auto& crit_func : critical_funcs) {
        // Ищем модуль в списке
        HMODULE target_module = nullptr;
        for (const auto& mod : modules) {
            std::string mod_name_ansi;
            int size = WideCharToMultiByte(CP_ACP, 0, mod.name.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (size > 0) {
                mod_name_ansi.resize(size - 1);
                WideCharToMultiByte(CP_ACP, 0, mod.name.c_str(), -1, &mod_name_ansi[0], size, nullptr, nullptr);
            }
            
            if (_stricmp(mod_name_ansi.c_str(), crit_func.module) == 0) {
                target_module = reinterpret_cast<HMODULE>(mod.base_address);
                break;
            }
        }
        
        if (!target_module) {
            // Пытаемся загрузить модуль локально для получения адреса
            HMODULE local_mod = GetModuleHandleA(crit_func.module);
            if (local_mod) {
                // Адрес функции в нашем процессе (будет отличаться в целевом, но структура та же)
                FARPROC func_addr = GetProcAddress(local_mod, crit_func.function);
                if (func_addr) {
                    FunctionInfo info = {};
                    info.module_name = crit_func.module;
                    info.function_name = crit_func.function;
                    info.address = reinterpret_cast<uintptr_t>(func_addr);
                    functions.push_back(info);
                }
            }
            continue;
        }
        
        // Пытаемся получить адрес функции в целевом процессе
        // Это сложно, так как нужно читать память процесса
        // Пока сохраняем информацию о модуле и функции
        FunctionInfo info = {};
        info.module_name = crit_func.module;
        info.function_name = crit_func.function;
        info.address = 0; // Будет заполнено сервером или позже
        functions.push_back(info);
    }
    
    CloseHandle(process);
    return true;
}

bool CollectProcessInfo(DWORD process_id, ProcessInfo* info) {
    if (!info) {
        return false;
    }
    
    info->process_id = process_id;
    info->timestamp = static_cast<uint64_t>(GetTickCount64());
    
    // Собираем модули
    if (!GetProcessModules(process_id, info->modules)) {
        return false;
    }
    
    // Собираем функции
    GetCriticalFunctions(process_id, info->modules, info->functions);
    
    return true;
}

// JSON escape для строк
static std::string JsonEscape(const std::string& str) {
    std::ostringstream o;
    for (char c : str) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') 
                      << static_cast<int>(static_cast<unsigned char>(c));
                } else {
                    o << c;
                }
                break;
        }
    }
    return o.str();
}

// Преобразование wide string в UTF-8
static std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

std::string ProcessInfoToJson(const ProcessInfo& info) {
    std::ostringstream json;
    json << "{";
    
    // PID
    json << "\"process_id\":" << info.process_id << ",";
    
    // Timestamp
    json << "\"timestamp\":" << info.timestamp << ",";
    
    // CPUID
    json << "\"cpuid\":" << GetCPUID() << ",";
    
    // Модули
    json << "\"modules\":[";
    for (size_t i = 0; i < info.modules.size(); i++) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"name\":\"" << JsonEscape(WideToUtf8(info.modules[i].name)) << "\",";
        json << "\"base_address\":\"" << std::hex << "0x" << info.modules[i].base_address << std::dec << "\",";
        json << "\"size\":" << info.modules[i].size << ",";
        json << "\"path\":\"" << JsonEscape(WideToUtf8(info.modules[i].path)) << "\"";
        json << "}";
    }
    json << "],";
    
    // Функции
    json << "\"functions\":[";
    for (size_t i = 0; i < info.functions.size(); i++) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"module\":\"" << JsonEscape(info.functions[i].module_name) << "\",";
        json << "\"function\":\"" << JsonEscape(info.functions[i].function_name) << "\",";
        json << "\"address\":\"" << std::hex << "0x" << info.functions[i].address << std::dec << "\"";
        json << "}";
    }
    json << "]";
    
    json << "}";
    return json.str();
}

} // namespace process_info
} // namespace loader












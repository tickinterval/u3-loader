#include "protection.h"
#include <fstream>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "crypt32.lib")

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace loader {
namespace protection {

// XOR ключ для шифрования (генерируется рандомно для каждой сборки)
constexpr char XOR_KEY = 0x7E;
constexpr size_t kIntegrityHashLen = 64;
constexpr char kIntegrityTag[] =
    "U3HASH-V1:"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000";
constexpr size_t kIntegrityMarkerLen = sizeof(kIntegrityTag) - 1 - kIntegrityHashLen;

// Зашифрованный публичный ключ RSA (auto-generated)
static const unsigned char ENCRYPTED_PUBLIC_KEY[] = {
    0x53, 0x53, 0x53, 0x53, 0x53, 0x3C, 0x3B, 0x39, 0x37, 0x30, 0x5E, 0x2E, 0x2B, 0x3C, 0x32, 0x37,
    0x3D, 0x5E, 0x35, 0x3B, 0x27, 0x53, 0x53, 0x53, 0x53, 0x53, 0x74, 0x33, 0x37, 0x37, 0x3C, 0x37,
    0x14, 0x3F, 0x30, 0x3C, 0x19, 0x15, 0x0F, 0x16, 0x15, 0x17, 0x39, 0x47, 0x09, 0x4E, 0x3C, 0x3F,
    0x2F, 0x3B, 0x38, 0x3F, 0x3F, 0x31, 0x3D, 0x3F, 0x2F, 0x46, 0x3F, 0x33, 0x37, 0x37, 0x3C, 0x3D,
    0x19, 0x35, 0x3D, 0x3F, 0x2F, 0x3B, 0x3F, 0x47, 0x0C, 0x30, 0x33, 0x39, 0x2F, 0x31, 0x28, 0x29,
    0x4B, 0x12, 0x18, 0x36, 0x2A, 0x3A, 0x24, 0x13, 0x0B, 0x14, 0x35, 0x74, 0x16, 0x2B, 0x1C, 0x4D,
    0x11, 0x4E, 0x4A, 0x3C, 0x3C, 0x09, 0x51, 0x29, 0x12, 0x2F, 0x28, 0x04, 0x1C, 0x4A, 0x17, 0x0B,
    0x24, 0x46, 0x39, 0x3F, 0x06, 0x36, 0x0D, 0x2A, 0x10, 0x49, 0x2A, 0x12, 0x0E, 0x24, 0x3F, 0x4C,
    0x4A, 0x4F, 0x2A, 0x1A, 0x1A, 0x51, 0x51, 0x55, 0x24, 0x3B, 0x3C, 0x08, 0x3C, 0x28, 0x0C, 0x2B,
    0x12, 0x0F, 0x1A, 0x07, 0x32, 0x2E, 0x47, 0x30, 0x4E, 0x04, 0x4E, 0x47, 0x74, 0x10, 0x1C, 0x2D,
    0x15, 0x14, 0x32, 0x11, 0x12, 0x2C, 0x11, 0x1B, 0x1B, 0x07, 0x3F, 0x48, 0x0D, 0x4C, 0x3D, 0x35,
    0x0D, 0x15, 0x51, 0x34, 0x1B, 0x2F, 0x47, 0x4B, 0x4F, 0x12, 0x12, 0x2B, 0x3B, 0x31, 0x4F, 0x49,
    0x49, 0x2B, 0x14, 0x11, 0x4D, 0x1C, 0x04, 0x4F, 0x4E, 0x1D, 0x31, 0x1C, 0x38, 0x4C, 0x2C, 0x28,
    0x51, 0x2B, 0x1A, 0x4C, 0x0C, 0x13, 0x51, 0x0D, 0x2B, 0x3A, 0x3D, 0x48, 0x06, 0x74, 0x32, 0x2F,
    0x0C, 0x32, 0x31, 0x14, 0x2E, 0x09, 0x0F, 0x1C, 0x39, 0x16, 0x15, 0x0B, 0x47, 0x49, 0x30, 0x08,
    0x3F, 0x48, 0x14, 0x15, 0x1F, 0x34, 0x2E, 0x0C, 0x11, 0x34, 0x0E, 0x06, 0x3D, 0x17, 0x2A, 0x27,
    0x27, 0x2F, 0x34, 0x06, 0x0D, 0x18, 0x2D, 0x33, 0x0F, 0x10, 0x2A, 0x4D, 0x2C, 0x24, 0x08, 0x0F,
    0x3D, 0x38, 0x4F, 0x06, 0x0B, 0x13, 0x31, 0x1B, 0x3D, 0x0A, 0x26, 0x38, 0x35, 0x15, 0x74, 0x36,
    0x2B, 0x17, 0x2D, 0x3B, 0x19, 0x33, 0x0C, 0x06, 0x48, 0x10, 0x4D, 0x17, 0x06, 0x2F, 0x07, 0x3A,
    0x0A, 0x3F, 0x3B, 0x4C, 0x13, 0x3F, 0x28, 0x24, 0x4E, 0x1A, 0x31, 0x1A, 0x34, 0x11, 0x34, 0x47,
    0x37, 0x38, 0x14, 0x38, 0x0A, 0x19, 0x0B, 0x47, 0x0A, 0x48, 0x14, 0x2D, 0x1C, 0x17, 0x48, 0x4E,
    0x13, 0x33, 0x55, 0x4F, 0x33, 0x4B, 0x15, 0x2C, 0x4E, 0x55, 0x31, 0x11, 0x10, 0x28, 0x3D, 0x74,
    0x4E, 0x1C, 0x19, 0x4B, 0x19, 0x34, 0x3D, 0x46, 0x2B, 0x4E, 0x19, 0x34, 0x10, 0x1C, 0x47, 0x2D,
    0x35, 0x1D, 0x11, 0x2F, 0x4C, 0x1B, 0x38, 0x36, 0x3D, 0x15, 0x30, 0x13, 0x0D, 0x27, 0x3F, 0x39,
    0x55, 0x32, 0x06, 0x36, 0x34, 0x28, 0x11, 0x2D, 0x13, 0x51, 0x12, 0x36, 0x18, 0x1F, 0x0A, 0x46,
    0x3D, 0x0B, 0x29, 0x1F, 0x28, 0x3B, 0x32, 0x16, 0x3F, 0x24, 0x46, 0x4A, 0x1A, 0x3F, 0x1A, 0x0B,
    0x74, 0x26, 0x2F, 0x37, 0x3A, 0x3F, 0x2F, 0x3F, 0x3C, 0x74, 0x53, 0x53, 0x53, 0x53, 0x53, 0x3B,
    0x30, 0x3A, 0x5E, 0x2E, 0x2B, 0x3C, 0x32, 0x37, 0x3D, 0x5E, 0x35, 0x3B, 0x27, 0x53, 0x53, 0x53,
    0x53, 0x53, 0x74,
};

std::string GetPublicKey() {
    // Расшифровываем публичный ключ в runtime
    std::string key;
    key.reserve(sizeof(ENCRYPTED_PUBLIC_KEY));
    
    for (size_t i = 0; i < sizeof(ENCRYPTED_PUBLIC_KEY); i++) {
        key.push_back(ENCRYPTED_PUBLIC_KEY[i] ^ XOR_KEY);
    }
    
    return key;
}

bool IsHexChar(char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

bool ExtractExpectedHash(std::string* out) {
    if (!out) {
        return false;
    }
    const char* start = kIntegrityTag + kIntegrityMarkerLen;
    for (size_t i = 0; i < kIntegrityHashLen; i++) {
        if (!IsHexChar(start[i])) {
            return false;
        }
    }
    out->assign(start, kIntegrityHashLen);
    for (char& ch : *out) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return true;
}

bool MaskIntegrityTag(std::vector<BYTE>* buffer) {
    if (!buffer || buffer->empty()) {
        return false;
    }
    const BYTE* marker = reinterpret_cast<const BYTE*>(kIntegrityTag);
    auto it = buffer->begin();
    while (true) {
        it = std::search(it, buffer->end(), marker, marker + kIntegrityMarkerLen);
        if (it == buffer->end()) {
            return false;
        }
        size_t offset = static_cast<size_t>(it - buffer->begin());
        size_t hashOffset = offset + kIntegrityMarkerLen;
        if (hashOffset + kIntegrityHashLen <= buffer->size()) {
            bool looks_hex = true;
            for (size_t i = 0; i < kIntegrityHashLen; i++) {
                if (!IsHexChar(static_cast<char>((*buffer)[hashOffset + i]))) {
                    looks_hex = false;
                    break;
                }
            }
            if (looks_hex) {
                std::fill(buffer->begin() + hashOffset,
                          buffer->begin() + hashOffset + kIntegrityHashLen,
                          static_cast<BYTE>('0'));
                return true;
            }
        }
        ++it;
    }
}

std::string ComputeFileHash(const std::wstring& file_path) {
    HANDLE file = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (file == INVALID_HANDLE_VALUE) {
        return {};
    }

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > static_cast<LONGLONG>(SIZE_MAX)) {
        CloseHandle(file);
        return {};
    }

    std::vector<BYTE> buffer(static_cast<size_t>(size.QuadPart));
    size_t offset = 0;
    const size_t total = buffer.size();
    const size_t chunkSize = 1024 * 1024;

    while (offset < total) {
        DWORD toRead = static_cast<DWORD>(std::min(chunkSize, total - offset));
        DWORD bytesRead = 0;
        if (!ReadFile(file, buffer.data() + offset, toRead, &bytesRead, nullptr) || bytesRead == 0) {
            CloseHandle(file);
            return {};
        }
        offset += bytesRead;
    }

    CloseHandle(file);

    if (!MaskIntegrityTag(&buffer)) {
        return {};
    }

    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    HCRYPTHASH hash = 0;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(provider, 0);
        return {};
    }

    size_t hashed = 0;
    while (hashed < buffer.size()) {
        DWORD chunk = static_cast<DWORD>(std::min(chunkSize, buffer.size() - hashed));
        if (!CryptHashData(hash, buffer.data() + hashed, chunk, 0)) {
            CryptDestroyHash(hash);
            CryptReleaseContext(provider, 0);
            return {};
        }
        hashed += chunk;
    }

    DWORD hash_len = 32;
    BYTE hash_value[32];
    if (!CryptGetHashParam(hash, HP_HASHVAL, hash_value, &hash_len, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return {};
    }

    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);

    static const char hex[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(hash_len * 2);
    for (DWORD i = 0; i < hash_len; i++) {
        result.push_back(hex[hash_value[i] >> 4]);
        result.push_back(hex[hash_value[i] & 0x0F]);
    }

    return result;
}

std::string GetExeHash() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return ComputeFileHash(path);
}

bool VerifyIntegrity() {
    std::string expected_hash;
    if (!ExtractExpectedHash(&expected_hash)) {
        return false;
    }

    std::string current_hash = GetExeHash();
    if (current_hash.empty()) {
        return false;
    }

    return _stricmp(current_hash.c_str(), expected_hash.c_str()) == 0;
}

// ================== ADVANCED VM DETECTION ==================

// Проверка CPUID на hypervisor bit и vendor ID
bool CheckCPUID() {
    int cpuInfo[4] = {};
    
    // CPUID с EAX=1: проверка hypervisor bit (bit 31 в ECX)
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        return true; // Hypervisor present
    }
    
    // CPUID с EAX=0x40000000: получаем hypervisor vendor ID
    __cpuid(cpuInfo, 0x40000000);
    
    // Собираем vendor string из EBX, ECX, EDX
    char vendor[13] = {};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    vendor[12] = '\0';
    
    // Известные hypervisor vendor IDs
    const char* vmVendors[] = {
        "VMwareVMware",  // VMware
        "Microsoft Hv",  // Hyper-V
        "KVMKVMKVM",     // KVM
        "XenVMMXenVMM",  // Xen
        "prl hyperv  ",  // Parallels
        "VBoxVBoxVBox",  // VirtualBox
        " lrpepyh vr",   // Parallels variant
        "bhyve bhyve ",  // bhyve
        "QNXQVMBSQG",    // QNX
        "TCGTCGTCGTCG",  // QEMU TCG
        "ACRNACRNACRN",  // ACRN
    };
    
    for (const auto& vmVendor : vmVendors) {
        if (strncmp(vendor, vmVendor, 12) == 0) {
            return true;
        }
    }
    
    return false;
}

// Проверка MAC адресов на VM
bool CheckMacAddress() {
    // Известные OUI (первые 3 байта MAC) виртуальных машин
    // Формат: первые 6 символов MAC адреса в верхнем регистре
    const char* vmMacPrefixes[] = {
        "000C29",  // VMware
        "001C14",  // VMware
        "005056",  // VMware
        "000569",  // VMware
        "080027",  // VirtualBox
        "0A0027",  // VirtualBox
        "001C42",  // Parallels
        "00155D",  // Hyper-V
        "000F4B",  // Virtual Iron
        "00163E",  // Xen
        "001E4F",  // Hyper-V
        "00505F",  // VMware ESX
    };
    
    // Получаем информацию о сетевых адаптерах
    typedef struct _IP_ADAPTER_INFO {
        struct _IP_ADAPTER_INFO* Next;
        DWORD ComboIndex;
        char AdapterName[260];
        char Description[132];
        UINT AddressLength;
        BYTE Address[8];
        DWORD Index;
        UINT Type;
        UINT DhcpEnabled;
        void* CurrentIpAddress;
        // ... остальные поля не нужны
    } IP_ADAPTER_INFO;
    
    typedef ULONG (WINAPI *GetAdaptersInfo_t)(IP_ADAPTER_INFO*, PULONG);
    
    HMODULE iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (!iphlpapi) return false;
    
    auto GetAdaptersInfo_fn = reinterpret_cast<GetAdaptersInfo_t>(
        GetProcAddress(iphlpapi, "GetAdaptersInfo"));
    
    if (!GetAdaptersInfo_fn) {
        FreeLibrary(iphlpapi);
        return false;
    }
    
    ULONG bufferSize = 0;
    GetAdaptersInfo_fn(nullptr, &bufferSize);
    
    if (bufferSize == 0) {
        FreeLibrary(iphlpapi);
        return false;
    }
    
    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_INFO* adapter = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
    
    if (GetAdaptersInfo_fn(adapter, &bufferSize) != ERROR_SUCCESS) {
        FreeLibrary(iphlpapi);
        return false;
    }
    
    bool detected = false;
    
    while (adapter) {
        if (adapter->AddressLength >= 3) {
            char macPrefix[7];
            sprintf_s(macPrefix, "%02X%02X%02X",
                adapter->Address[0],
                adapter->Address[1],
                adapter->Address[2]);
            
            for (const auto& vmPrefix : vmMacPrefixes) {
                if (strcmp(macPrefix, vmPrefix) == 0) {
                    detected = true;
                    break;
                }
            }
        }
        
        if (detected) break;
        adapter = adapter->Next;
    }
    
    FreeLibrary(iphlpapi);
    return detected;
}

// Проверка реестра на VM ключи
bool CheckRegistryVM() {
    // Ключи реестра, специфичные для VM
    struct RegCheck {
        HKEY root;
        const wchar_t* path;
        const wchar_t* valueName;
        const wchar_t* valueContent;  // nullptr = просто проверяем существование ключа
    };
    
    const RegCheck vmRegKeys[] = {
        // VMware
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Workstation", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmci", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmmouse", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmusbmouse", nullptr, nullptr },
        
        // VirtualBox
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxService", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF", nullptr, nullptr },
        
        // Hyper-V
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmicshutdown", nullptr, nullptr },
        
        // Parallels
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\prl_fs", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\prl_memdev", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\prl_mouf", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\prl_pv32", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\prl_strg", nullptr, nullptr },
        
        // QEMU
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\QEMU", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"QEMU" },
    };
    
    for (const auto& check : vmRegKeys) {
        HKEY key;
        if (RegOpenKeyExW(check.root, check.path, 0, KEY_READ, &key) == ERROR_SUCCESS) {
            if (check.valueName == nullptr) {
                RegCloseKey(key);
                return true; // Ключ существует
            }
            
            wchar_t buffer[256] = {};
            DWORD size = sizeof(buffer);
            if (RegQueryValueExW(key, check.valueName, nullptr, nullptr, 
                reinterpret_cast<BYTE*>(buffer), &size) == ERROR_SUCCESS) {
                if (check.valueContent == nullptr || wcsstr(buffer, check.valueContent) != nullptr) {
                    RegCloseKey(key);
                    return true;
                }
            }
            RegCloseKey(key);
        }
    }
    
    return false;
}

// Проверка на известные VM файлы
bool CheckVMFiles() {
    const wchar_t* vmFiles[] = {
        // VMware
        L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
        L"C:\\Windows\\System32\\drivers\\vmrawdsk.sys",
        L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
        L"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
        L"C:\\Windows\\System32\\drivers\\vmci.sys",
        L"C:\\Windows\\System32\\drivers\\vmnet.sys",
        
        // VirtualBox
        L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        L"C:\\Windows\\System32\\VBoxControl.exe",
        L"C:\\Windows\\System32\\VBoxService.exe",
        L"C:\\Windows\\System32\\VBoxTray.exe",
        
        // Parallels
        L"C:\\Windows\\System32\\drivers\\prl_fs.sys",
        L"C:\\Windows\\System32\\drivers\\prl_pv32.sys",
        L"C:\\Windows\\System32\\drivers\\prl_boot.sys",
    };
    
    for (const auto& file : vmFiles) {
        DWORD attrs = GetFileAttributesW(file);
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    
    return false;
}

// Проверка на VM драйверы через SetupAPI
bool CheckVMDevices() {
    // Подозрительные имена устройств
    const wchar_t* vmDevices[] = {
        L"vmware",
        L"vbox",
        L"virtualbox",
        L"qemu",
        L"xen",
        L"virtual hd",
        L"vmbus",
        L"vmhba",
    };
    
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum", 
        0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }
    
    // Проверяем диски
    HKEY diskKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        0, KEY_READ, &diskKey) == ERROR_SUCCESS) {
        
        wchar_t buffer[512] = {};
        DWORD size = sizeof(buffer);
        
        if (RegQueryValueExW(diskKey, L"0", nullptr, nullptr, 
            reinterpret_cast<BYTE*>(buffer), &size) == ERROR_SUCCESS) {
            
            _wcslwr_s(buffer);
            
            for (const auto& device : vmDevices) {
                if (wcsstr(buffer, device) != nullptr) {
                    RegCloseKey(diskKey);
                    RegCloseKey(key);
                    return true;
                }
            }
        }
        RegCloseKey(diskKey);
    }
    
    RegCloseKey(key);
    return false;
}

bool IsRunningInVM() {
    // 1. CPUID проверка (наиболее надёжная)
    if (CheckCPUID()) {
        return true;
    }
    
    // 2. MAC адреса
    if (CheckMacAddress()) {
        return true;
    }
    
    // 3. Реестр
    if (CheckRegistryVM()) {
        return true;
    }
    
    // 4. Известные VM файлы
    if (CheckVMFiles()) {
        return true;
    }
    
    // 5. VM устройства
    if (CheckVMDevices()) {
        return true;
    }
    
    // 6. Проверка ресурсов (старая логика)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 1) {
        return true; // Очень подозрительно - только 1 ядро
    }
    
    MEMORYSTATUSEX mem_status = {};
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status);
    if (mem_status.ullTotalPhys <= 2ULL * 1024 * 1024 * 1024) {
        return true; // Меньше 2GB RAM - очень подозрительно
    }
    
    return false;
}

bool IsRunningSandbox() {
    // 1. Проверка на слишком быстрое выполнение (sandbox skip)
    DWORD start = GetTickCount();
    Sleep(100);
    DWORD elapsed = GetTickCount() - start;
    
    if (elapsed < 80) {
        return true; // Sandbox ускорил время
    }
    
    // 2. Проверка на sandbox DLL
    const wchar_t* sandboxDlls[] = {
        L"sbiedll.dll",      // Sandboxie
        L"dbghelp.dll",      // Debug help (может быть легитимной)
        L"api_ms_win_core_synch_l1_2_0.dll",  // Cuckoo
        L"dir_watch.dll",    // iDefense
        L"pstorec.dll",      // SunBelt
        L"vmcheck.dll",      // Virtual PC
        L"wpespy.dll",       // WPE Pro
        L"cmdvrt32.dll",     // Comodo
        L"cmdvrt64.dll",     // Comodo x64
        L"snxhk.dll",        // Avast sandbox
        L"snxhk64.dll",      // Avast sandbox x64
        L"sxin.dll",         // 360 sandbox
    };
    
    for (const auto& dll : sandboxDlls) {
        if (GetModuleHandleW(dll) != nullptr) {
            return true;
        }
    }
    
    // 3. Проверка количества процессов (в sandbox обычно мало)
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        
        int count = 0;
        if (Process32FirstW(snapshot, &entry)) {
            do {
                count++;
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        
        if (count < 25) {
            return true; // Слишком мало процессов
        }
    }
    
    // 4. Проверка переменных среды sandbox
    wchar_t buffer[256] = {};
    if (GetEnvironmentVariableW(L"SANDBOX", buffer, 256) > 0) {
        return true;
    }
    if (GetEnvironmentVariableW(L"CUCKOO", buffer, 256) > 0) {
        return true;
    }
    
    // 5. Проверка имени пользователя
    wchar_t username[256] = {};
    DWORD usernameLen = 256;
    if (GetUserNameW(username, &usernameLen)) {
        _wcslwr_s(username);
        
        const wchar_t* suspiciousUsers[] = {
            L"sandbox",
            L"virus",
            L"malware",
            L"sample",
            L"test",
            L"user",
            L"currentuser",
            L"admin",
        };
        
        for (const auto& user : suspiciousUsers) {
            if (wcscmp(username, user) == 0) {
                return true;
            }
        }
    }
    
    // 6. Проверка имени компьютера
    wchar_t compName[256] = {};
    DWORD compNameLen = 256;
    if (GetComputerNameW(compName, &compNameLen)) {
        _wcslwr_s(compName);
        
        const wchar_t* suspiciousComputers[] = {
            L"sandbox",
            L"virus",
            L"malware",
            L"analysis",
            L"cuckoo",
            L"joe",
            L"vmware",
            L"virtual",
        };
        
        for (const auto& comp : suspiciousComputers) {
            if (wcsstr(compName, comp) != nullptr) {
                return true;
            }
        }
    }
    
    return false;
}

} // namespace protection
} // namespace loader



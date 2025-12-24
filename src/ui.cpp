#include "app.h"
#include "injector.h"
#include "anti_debug.h"
#include "protection.h"
#include "anti_crack.h"
#include "shared_config.h"
#include "hwid_validator.h"
#include <winhttp.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <windowsx.h>
#include <shlobj.h>
#include <gdiplus.h>

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <unordered_map>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "gdiplus.lib")

namespace loader {
std::wstring ToLowerString(const std::wstring& value);
COLORREF GetStatusColor(const std::wstring& status);
int GetAvatarIndex(const std::wstring& code);
std::string EscapeSigField(const std::string& value);
bool JsonGetBoolTopLevel(const std::string& json, const std::string& key, bool* value);
bool JsonGetStringTopLevel(const std::string& json, const std::string& key, std::string* value);
bool JsonGetInt64TopLevel(const std::string& json, const std::string& key, int64_t* value);
bool VerifyResponseSignature(const std::string& payload, const std::string& signature_b64, std::wstring* error);
std::wstring BytesToHexUpper(const BYTE* bytes, DWORD size);
bool VerifyServerCertificatePin(HINTERNET request, const std::wstring& expected_thumbprint, std::wstring* error);
bool HttpGetBinary(const std::wstring& url, std::vector<char>* out, std::wstring* error);
bool WriteFileBinary(const std::wstring& path, const std::vector<char>& data);
std::string Sha256HexBytes(const std::vector<char>& data);
std::wstring SanitizeToken(const std::wstring& value);

static std::unordered_map<std::wstring, int> g_avatar_index;
static std::vector<HBITMAP> g_avatar_bitmaps;
static bool g_gdiplus_started = false;
static ULONG_PTR g_gdiplus_token = 0;

constexpr UINT kUiTimerId = 1;
constexpr BYTE kFadeStep = 18;
static bool g_fade_active = false;
static BYTE g_fade_alpha = 0;
static std::wstring g_status_base;
static int g_status_anim_tick = 0;

struct WindowState {
    bool is_status = false;
    RECT card = {};
};

std::wstring GetExeDir() {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring full(path);
    size_t pos = full.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return L".";
    }
    return full.substr(0, pos);
}

std::wstring GetExePath() {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::wstring(path);
}

std::wstring GetTempAvatarPath(const std::wstring& code) {
    wchar_t temp_path[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_path);
    std::wstring name = L"u3ware_avatar_";
    name += SanitizeToken(code.empty() ? L"unknown" : code);
    name += L".png";
    return std::wstring(temp_path) + name;
}

void StartGdiPlus() {
    if (g_gdiplus_started) {
        return;
    }
    Gdiplus::GdiplusStartupInput input;
    if (Gdiplus::GdiplusStartup(&g_gdiplus_token, &input, nullptr) == Gdiplus::Ok) {
        g_gdiplus_started = true;
    }
}

void StopGdiPlus() {
    if (g_gdiplus_started) {
        Gdiplus::GdiplusShutdown(g_gdiplus_token);
        g_gdiplus_started = false;
        g_gdiplus_token = 0;
    }
}

HBITMAP LoadAvatarBitmap(const std::wstring& path, int size) {
    StartGdiPlus();
    if (!g_gdiplus_started) {
        return nullptr;
    }
    Gdiplus::Bitmap bitmap(path.c_str(), FALSE);
    if (bitmap.GetLastStatus() != Gdiplus::Ok) {
        return nullptr;
    }
    Gdiplus::Bitmap scaled(size, size, PixelFormat32bppARGB);
    Gdiplus::Graphics gfx(&scaled);
    gfx.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
    gfx.DrawImage(&bitmap, Gdiplus::Rect(0, 0, size, size));
    HBITMAP out = nullptr;
    if (scaled.GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &out) != Gdiplus::Ok) {
        return nullptr;
    }
    return out;
}

std::wstring GetStorageDir() {
    PWSTR path = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path))) {
        out = path;
        CoTaskMemFree(path);
    }
    if (out.empty()) {
        return GetExeDir();
    }
    out += L"\\u3ware";
    CreateDirectoryW(out.c_str(), nullptr);
    return out;
}

std::wstring GetKeyPath() {
    return GetStorageDir() + L"\\license.dat";
}

// Конфигурация захардкожена в app_state.cpp - ReadIniValue больше не нужен

std::wstring NormalizeThumbprint(const std::wstring& input) {
    std::wstring out;
    out.reserve(input.size());
    for (wchar_t ch : input) {
        if (ch == L' ' || ch == L':') {
            continue;
        }
        if (ch >= L'a' && ch <= L'f') {
            out.push_back(static_cast<wchar_t>(ch - L'a' + L'A'));
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

int CompareVersions(const std::string& left, const std::string& right) {
    auto parse = [](const std::string& value) {
        std::vector<int> parts;
        size_t start = 0;
        while (start < value.size()) {
            size_t end = value.find('.', start);
            if (end == std::string::npos) {
                end = value.size();
            }
            int number = 0;
            size_t i = start;
            while (i < end && value[i] >= '0' && value[i] <= '9') {
                number = number * 10 + (value[i] - '0');
                i++;
            }
            parts.push_back(number);
            start = end + 1;
        }
        return parts;
    };

    std::vector<int> a = parse(left);
    std::vector<int> b = parse(right);
    size_t size = a.size() > b.size() ? a.size() : b.size();
    for (size_t i = 0; i < size; ++i) {
        int av = i < a.size() ? a[i] : 0;
        int bv = i < b.size() ? b[i] : 0;
        if (av > bv) return 1;
        if (av < bv) return -1;
    }
    return 0;
}

std::string BuildUpdateSigPayload(bool ok,
                                  int64_t ts,
                                  const std::string& nonce,
                                  const std::string& error,
                                  const std::string& version,
                                  const std::string& url,
                                  const std::string& sha256) {
    std::string out = "ok=" + std::string(ok ? "1" : "0") + "\nts=" + std::to_string(ts) + "\nnonce=" + nonce;
    if (!error.empty()) {
        out += "\nerror=" + EscapeSigField(error);
    }
    if (!version.empty()) {
        out += "\nversion=" + EscapeSigField(version);
    }
    if (!url.empty()) {
        out += "\nurl=" + EscapeSigField(url);
    }
    if (!sha256.empty()) {
        out += "\nsha256=" + EscapeSigField(sha256);
    }
    return out;
}

bool LoadConfig(Config* config) {
    // Все настройки захардкожены - никакого ini файла
    config->server_url = kDefaultServerUrl;
    config->expected_thumbprint = NormalizeThumbprint(kDefaultExpectedThumbprint);
    config->user_agent = kDefaultUserAgent;
    config->target_process = kDefaultTargetProcess;
    return true;
}

int Scale(int value) {
    return MulDiv(value, static_cast<int>(g_dpi), 96);
}

int GetFontHeight(HWND hwnd, HFONT font) {
    HDC dc = GetDC(hwnd);
    HFONT old = reinterpret_cast<HFONT>(SelectObject(dc, font));
    TEXTMETRIC tm = {};
    GetTextMetrics(dc, &tm);
    SelectObject(dc, old);
    ReleaseDC(hwnd, dc);
    return tm.tmHeight;
}

void DestroyFonts() {
    if (g_title_font) {
        DeleteObject(g_title_font);
        g_title_font = nullptr;
    }
    if (g_subtitle_font) {
        DeleteObject(g_subtitle_font);
        g_subtitle_font = nullptr;
    }
    if (g_body_font) {
        DeleteObject(g_body_font);
        g_body_font = nullptr;
    }
    if (g_small_font) {
        DeleteObject(g_small_font);
        g_small_font = nullptr;
    }
    if (g_avatar_font) {
        DeleteObject(g_avatar_font);
        g_avatar_font = nullptr;
    }
}

void CreateFonts() {
    DestroyFonts();
    g_title_font = CreateFontW(-Scale(30), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                               OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_subtitle_font = CreateFontW(-Scale(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                  OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_body_font = CreateFontW(-Scale(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_small_font = CreateFontW(-Scale(12), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                               OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_avatar_font = CreateFontW(-Scale(12), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
}

void ApplyFonts() {
    if (g_title) {
        SendMessageW(g_title, WM_SETFONT, reinterpret_cast<WPARAM>(g_title_font), TRUE);
    }
    if (g_subtitle) {
        SendMessageW(g_subtitle, WM_SETFONT, reinterpret_cast<WPARAM>(g_subtitle_font), TRUE);
    }
    if (g_label_key) {
        SendMessageW(g_label_key, WM_SETFONT, reinterpret_cast<WPARAM>(g_small_font), TRUE);
    }
    if (g_edit) {
        SendMessageW(g_edit, WM_SETFONT, reinterpret_cast<WPARAM>(g_body_font), TRUE);
    }
    if (g_button) {
        SendMessageW(g_button, WM_SETFONT, reinterpret_cast<WPARAM>(g_body_font), TRUE);
    }
    if (g_status) {
        SendMessageW(g_status, WM_SETFONT, reinterpret_cast<WPARAM>(g_small_font), TRUE);
    }
    if (g_label_programs) {
        SendMessageW(g_label_programs, WM_SETFONT, reinterpret_cast<WPARAM>(g_body_font), TRUE);
    }
    if (g_label_col_program) {
        SendMessageW(g_label_col_program, WM_SETFONT, reinterpret_cast<WPARAM>(g_small_font), TRUE);
    }
    if (g_label_col_updated) {
        SendMessageW(g_label_col_updated, WM_SETFONT, reinterpret_cast<WPARAM>(g_small_font), TRUE);
    }
    if (g_label_col_expires) {
        SendMessageW(g_label_col_expires, WM_SETFONT, reinterpret_cast<WPARAM>(g_small_font), TRUE);
    }
    if (g_list) {
        SendMessageW(g_list, WM_SETFONT, reinterpret_cast<WPARAM>(g_body_font), TRUE);
    }
}

std::string WideToUtf8(const std::wstring& input) {
    if (input.empty()) {
        return {};
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), out.data(), len, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    int len = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0);
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), out.data(), len);
    return out;
}

std::string JsonEscape(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char ch : input) {
        switch (ch) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += ch;
                break;
        }
    }
    return out;
}

std::wstring GetMachineGuid() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return L"";
    }

    wchar_t buffer[256] = {};
    DWORD size = sizeof(buffer);
    if (RegQueryValueExW(key, L"MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &size) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return L"";
    }
    RegCloseKey(key);
    return std::wstring(buffer);
}

std::wstring ReadRegistryString(HKEY root, const wchar_t* subkey, const wchar_t* value_name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return L"";
    }
    wchar_t buffer[512] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    std::wstring result;
    if (RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            result.assign(buffer);
        }
    }
    RegCloseKey(key);
    return result;
}

std::wstring GetVolumeSerial() {
    wchar_t system_path[MAX_PATH] = {};
    GetSystemDirectoryW(system_path, MAX_PATH);
    wchar_t root_path[MAX_PATH] = {system_path[0], system_path[1], L'\\', L'\0'};

    DWORD serial = 0;
    if (!GetVolumeInformationW(root_path, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        return L"";
    }
    wchar_t buffer[16] = {};
    swprintf_s(buffer, L"%08X", serial);
    return std::wstring(buffer);
}

std::wstring GetCpuName() {
    return ReadRegistryString(HKEY_LOCAL_MACHINE,
                              L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                              L"ProcessorNameString");
}

std::wstring GetWindowsBuild() {
    std::wstring build = ReadRegistryString(HKEY_LOCAL_MACHINE,
                                           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                           L"CurrentBuildNumber");
    if (build.empty()) {
        build = ReadRegistryString(HKEY_LOCAL_MACHINE,
                                   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                   L"CurrentBuild");
    }
    return build;
}

std::wstring GetGpuName() {
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Video", 0, KEY_READ | KEY_WOW64_64KEY, &root) != ERROR_SUCCESS) {
        return L"";
    }
    wchar_t name[256] = {};
    DWORD name_len = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
    std::wstring result;
    for (DWORD index = 0; ; index++) {
        name_len = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
        LONG status = RegEnumKeyExW(root, index, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (status != ERROR_SUCCESS) {
            break;
        }
        std::wstring subkey = std::wstring(L"SYSTEM\\CurrentControlSet\\Control\\Video\\") + name + L"\\0000";
        result = ReadRegistryString(HKEY_LOCAL_MACHINE, subkey.c_str(), L"DriverDesc");
        if (result.empty()) {
            result = ReadRegistryString(HKEY_LOCAL_MACHINE, subkey.c_str(), L"Device Description");
        }
        if (!result.empty()) {
            break;
        }
    }
    RegCloseKey(root);
    return result;
}

std::wstring GetOsVersion() {
    std::wstring product = ReadRegistryString(HKEY_LOCAL_MACHINE,
                                              L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                              L"ProductName");
    std::wstring release = ReadRegistryString(HKEY_LOCAL_MACHINE,
                                              L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                              L"DisplayVersion");
    if (release.empty()) {
        release = ReadRegistryString(HKEY_LOCAL_MACHINE,
                                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                     L"ReleaseId");
    }
    std::wstring os = product;
    if (!release.empty()) {
        if (!os.empty()) {
            os += L" ";
        }
        os += release;
    }
    return os;
}

std::wstring GetComputerNameSafe() {
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
    if (GetComputerNameW(name, &size)) {
        return std::wstring(name);
    }
    return L"";
}

std::string Sha256Hex(const std::string& data) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(provider, 0);
        return {};
    }
    CryptHashData(hash, reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size()), 0);

    DWORD hash_len = 0;
    DWORD len_size = sizeof(hash_len);
    CryptGetHashParam(hash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hash_len), &len_size, 0);

    std::vector<BYTE> buffer(hash_len);
    CryptGetHashParam(hash, HP_HASHVAL, buffer.data(), &hash_len, 0);

    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);

    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(buffer.size() * 2);
    for (BYTE b : buffer) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

// ================== SMBIOS UUID ==================

// Структуры для SMBIOS
#pragma pack(push, 1)
struct RawSMBIOSData {
    BYTE Used20CallingMethod;
    BYTE SMBIOSMajorVersion;
    BYTE SMBIOSMinorVersion;
    BYTE DmiRevision;
    DWORD Length;
    BYTE SMBIOSTableData[];
};

struct SMBIOSHeader {
    BYTE Type;
    BYTE Length;
    WORD Handle;
};

struct SMBIOSSystemInfo {
    SMBIOSHeader Header;
    BYTE Manufacturer;
    BYTE ProductName;
    BYTE Version;
    BYTE SerialNumber;
    BYTE UUID[16];
    BYTE WakeUpType;
    BYTE SKUNumber;
    BYTE Family;
};
#pragma pack(pop)

std::wstring GetSmbiosUuid() {
    // Получаем размер SMBIOS данных
    DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0) {
        return L"";
    }
    
    std::vector<BYTE> buffer(size);
    if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), size) != size) {
        return L"";
    }
    
    RawSMBIOSData* smbios = reinterpret_cast<RawSMBIOSData*>(buffer.data());
    BYTE* data = smbios->SMBIOSTableData;
    BYTE* end = data + smbios->Length;
    
    while (data < end) {
        SMBIOSHeader* header = reinterpret_cast<SMBIOSHeader*>(data);
        
        if (header->Type == 1 && header->Length >= sizeof(SMBIOSSystemInfo)) {
            // System Information (Type 1)
            SMBIOSSystemInfo* sysInfo = reinterpret_cast<SMBIOSSystemInfo*>(data);
            
            // Проверяем что UUID не пустой (все нули или все FF)
            bool allZero = true;
            bool allFF = true;
            for (int i = 0; i < 16; i++) {
                if (sysInfo->UUID[i] != 0x00) allZero = false;
                if (sysInfo->UUID[i] != 0xFF) allFF = false;
            }
            
            if (!allZero && !allFF) {
                // Форматируем UUID как строку
                // UUID формат: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
                // SMBIOS хранит в little-endian для первых 3 полей
                wchar_t uuidStr[40];
                swprintf_s(uuidStr, L"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    sysInfo->UUID[3], sysInfo->UUID[2], sysInfo->UUID[1], sysInfo->UUID[0],  // time_low (LE)
                    sysInfo->UUID[5], sysInfo->UUID[4],  // time_mid (LE)
                    sysInfo->UUID[7], sysInfo->UUID[6],  // time_hi_and_version (LE)
                    sysInfo->UUID[8], sysInfo->UUID[9],  // clock_seq
                    sysInfo->UUID[10], sysInfo->UUID[11], sysInfo->UUID[12],
                    sysInfo->UUID[13], sysInfo->UUID[14], sysInfo->UUID[15]  // node
                );
                return std::wstring(uuidStr);
            }
        }
        
        // Пропускаем к следующей структуре
        data += header->Length;
        
        // Пропускаем строки (заканчиваются двойным нулём)
        while (data < end - 1 && !(data[0] == 0 && data[1] == 0)) {
            data++;
        }
        data += 2;
    }
    
    return L"";
}

// Получение серийного номера BIOS
std::wstring GetBiosSerial() {
    DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0) {
        return L"";
    }
    
    std::vector<BYTE> buffer(size);
    if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), size) != size) {
        return L"";
    }
    
    RawSMBIOSData* smbios = reinterpret_cast<RawSMBIOSData*>(buffer.data());
    BYTE* data = smbios->SMBIOSTableData;
    BYTE* end = data + smbios->Length;
    
    while (data < end) {
        SMBIOSHeader* header = reinterpret_cast<SMBIOSHeader*>(data);
        
        if (header->Type == 1) {
            // System Information (Type 1)
            SMBIOSSystemInfo* sysInfo = reinterpret_cast<SMBIOSSystemInfo*>(data);
            BYTE serialIndex = sysInfo->SerialNumber;
            
            if (serialIndex > 0) {
                // Получаем строку по индексу
                BYTE* strData = data + header->Length;
                BYTE currentIndex = 1;
                
                while (strData < end && *strData != 0) {
                    if (currentIndex == serialIndex) {
                        // Нашли строку
                        std::string serial(reinterpret_cast<char*>(strData));
                        // Проверяем что не placeholder
                        if (serial != "To Be Filled By O.E.M." &&
                            serial != "Default string" &&
                            serial != "System Serial Number" &&
                            serial.length() > 3) {
                            return std::wstring(serial.begin(), serial.end());
                        }
                        break;
                    }
                    
                    // Пропускаем к следующей строке
                    while (strData < end && *strData != 0) {
                        strData++;
                    }
                    strData++;
                    currentIndex++;
                }
            }
            break;
        }
        
        // Пропускаем к следующей структуре
        data += header->Length;
        while (data < end - 1 && !(data[0] == 0 && data[1] == 0)) {
            data++;
        }
        data += 2;
    }
    
    return L"";
}

// Получение серийного номера материнской платы
std::wstring GetBaseBoardSerial() {
    DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0) {
        return L"";
    }
    
    std::vector<BYTE> buffer(size);
    if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), size) != size) {
        return L"";
    }
    
    RawSMBIOSData* smbios = reinterpret_cast<RawSMBIOSData*>(buffer.data());
    BYTE* data = smbios->SMBIOSTableData;
    BYTE* end = data + smbios->Length;
    
    while (data < end) {
        SMBIOSHeader* header = reinterpret_cast<SMBIOSHeader*>(data);
        
        if (header->Type == 2 && header->Length >= 8) {
            // Baseboard Information (Type 2)
            // Серийный номер - это 4-й байт после заголовка (индекс строки)
            BYTE serialIndex = data[7];
            
            if (serialIndex > 0) {
                BYTE* strData = data + header->Length;
                BYTE currentIndex = 1;
                
                while (strData < end && *strData != 0) {
                    if (currentIndex == serialIndex) {
                        std::string serial(reinterpret_cast<char*>(strData));
                        if (serial != "To Be Filled By O.E.M." &&
                            serial != "Default string" &&
                            serial.length() > 3) {
                            return std::wstring(serial.begin(), serial.end());
                        }
                        break;
                    }
                    
                    while (strData < end && *strData != 0) {
                        strData++;
                    }
                    strData++;
                    currentIndex++;
                }
            }
            break;
        }
        
        data += header->Length;
        while (data < end - 1 && !(data[0] == 0 && data[1] == 0)) {
            data++;
        }
        data += 2;
    }
    
    return L"";
}

// ================== IMPROVED HWID ==================

std::string BuildHwid() {
    // Основные компоненты
    std::wstring machineGuid = GetMachineGuid();
    std::wstring volumeSerial = GetVolumeSerial();
    std::wstring cpu = GetCpuName();
    std::wstring gpu = GetGpuName();
    std::wstring build = GetWindowsBuild();
    
    // SMBIOS компоненты (сложнее спуфить)
    std::wstring smbiosUuid = GetSmbiosUuid();
    std::wstring biosSerial = GetBiosSerial();
    std::wstring boardSerial = GetBaseBoardSerial();
    
    // Комбинируем все компоненты
    std::wstring combined = machineGuid + L"|" + 
                           volumeSerial + L"|" + 
                           cpu + L"|" + 
                           gpu + L"|" + 
                           build + L"|" +
                           smbiosUuid + L"|" +
                           biosSerial + L"|" +
                           boardSerial;
    
    std::string combined_utf8 = WideToUtf8(combined);
    return Sha256Hex(combined_utf8);
}

std::string Sha256HexBytes(const std::vector<char>& data) {
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }
    HCRYPTHASH hash = 0;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(provider, 0);
        return {};
    }
    if (!data.empty()) {
        CryptHashData(hash, reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size()), 0);
    }

    DWORD hash_len = 0;
    DWORD len_size = sizeof(hash_len);
    CryptGetHashParam(hash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hash_len), &len_size, 0);
    std::vector<BYTE> buffer(hash_len);
    CryptGetHashParam(hash, HP_HASHVAL, buffer.data(), &hash_len, 0);

    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);

    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(buffer.size() * 2);
    for (BYTE b : buffer) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

struct UrlParts {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port;
    bool secure;
};

bool CrackUrl(const std::wstring& url, UrlParts* out, std::wstring* error) {
    URL_COMPONENTS components = {};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);

    std::wstring url_copy = url;
    if (!WinHttpCrackUrl(url_copy.data(), static_cast<DWORD>(url_copy.size()), 0, &components)) {
        if (error) {
            *error = L"Failed to parse URL";
        }
        return false;
    }

    out->secure = components.nScheme == INTERNET_SCHEME_HTTPS;
    out->port = components.nPort;
    out->host.assign(components.lpszHostName, components.dwHostNameLength);
    out->path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    if (components.dwExtraInfoLength > 0) {
        out->path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    if (out->path.empty()) {
        out->path = L"/";
    }
    return true;
}

bool VerifyServerCertificatePin(HINTERNET request, const std::wstring& expected_thumbprint, std::wstring* error) {
    // Если thumbprint пустой - пропускаем проверку (для тестирования)
    if (expected_thumbprint.empty()) {
        return true;
    }

    PCCERT_CONTEXT cert = nullptr;
    DWORD cert_size = sizeof(cert);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &cert_size) || !cert) {
        if (error) {
            *error = L"Failed to read server certificate";
        }
        return false;
    }

    BYTE hash[20] = {};
    DWORD hash_size = sizeof(hash);
    if (!CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash, &hash_size)) {
        CertFreeCertificateContext(cert);
        if (error) {
            *error = L"Failed to read certificate hash";
        }
        return false;
    }
    CertFreeCertificateContext(cert);

    std::wstring actual = BytesToHexUpper(hash, hash_size);
    std::wstring expected = NormalizeThumbprint(expected_thumbprint);
    if (actual != expected) {
        if (error) {
            *error = L"Certificate thumbprint mismatch";
        }
        return false;
    }
    return true;
}

bool HttpRequest(const std::wstring& method, const std::wstring& url, const std::string& body, std::string* response, std::wstring* error) {
    UrlParts parts = {};
    if (!CrackUrl(url, &parts, error)) {
        return false;
    }

    HINTERNET session = WinHttpOpen(g_config.user_agent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        if (error) {
            DWORD win_error = GetLastError();
            wchar_t buf[256];
            swprintf_s(buf, L"Failed to open WinHTTP (err: %lu)", win_error);
            *error = buf;
        }
        return false;
    }

    HINTERNET connect = WinHttpConnect(session, parts.host.c_str(), parts.port, 0);
    if (!connect) {
        DWORD win_error = GetLastError();
        WinHttpCloseHandle(session);
        if (error) {
            wchar_t buf[256];
            swprintf_s(buf, L"Failed to connect to %s:%d (err: %lu)", parts.host.c_str(), parts.port, win_error);
            *error = buf;
        }
        return false;
    }

    DWORD flags = parts.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, method.c_str(), parts.path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        DWORD win_error = GetLastError();
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        if (error) {
            wchar_t buf[256];
            swprintf_s(buf, L"Failed to open request (err: %lu)", win_error);
            *error = buf;
        }
        return false;
    }

    if (parts.secure) {
        DWORD secure_flags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURE_PROTOCOLS, &secure_flags, sizeof(secure_flags));
    }

    std::wstring headers;
    if (!body.empty()) {
        headers = L"Content-Type: application/json\r\n";
    }

    BOOL sent = WinHttpSendRequest(request,
        headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        headers.empty() ? 0 : static_cast<DWORD>(headers.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);

    if (!sent) {
        DWORD win_error = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        if (error) {
            wchar_t buf[256];
            swprintf_s(buf, L"Send failed (err: %lu)", win_error);
            *error = buf;
        }
        return false;
    }

    if (!WinHttpReceiveResponse(request, nullptr)) {
        DWORD win_error = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        if (error) {
            wchar_t buf[256];
            swprintf_s(buf, L"Receive failed (err: %lu)", win_error);
            *error = buf;
        }
        return false;
    }

    if (parts.secure) {
        std::wstring pin_error;
        if (!VerifyServerCertificatePin(request, g_config.expected_thumbprint, &pin_error)) {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            if (error) {
                *error = pin_error.empty() ? L"Certificate pin failed" : pin_error;
            }
            return false;
        }
    }

    std::string out;
    DWORD available = 0;
    do {
        if (!WinHttpQueryDataAvailable(request, &available)) {
            break;
        }
        if (available == 0) {
            break;
        }
        std::vector<char> buffer(available);
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer.data(), available, &read)) {
            break;
        }
        out.append(buffer.data(), read);
    } while (available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if (response) {
        *response = out;
    }
    return true;
}

bool CheckForUpdateSilent() {
    std::string response;
    std::wstring error;
    if (!HttpRequest(L"GET", g_config.server_url + L"/update/latest", {}, &response, &error)) {
        return false;
    }

    bool ok = false;
    if (!JsonGetBoolTopLevel(response, "ok", &ok)) {
        return false;
    }
    std::string sig;
    std::string nonce;
    int64_t ts = 0;
    if (!JsonGetStringTopLevel(response, "sig", &sig) || !JsonGetStringTopLevel(response, "nonce", &nonce) || !JsonGetInt64TopLevel(response, "ts", &ts)) {
        return false;
    }
    std::string error_code;
    std::string version;
    std::string url;
    std::string sha256;
    JsonGetStringTopLevel(response, "error", &error_code);
    JsonGetStringTopLevel(response, "version", &version);
    JsonGetStringTopLevel(response, "url", &url);
    JsonGetStringTopLevel(response, "sha256", &sha256);

    std::string sig_payload = BuildUpdateSigPayload(ok, ts, nonce, error_code, version, url, sha256);
    std::wstring sig_error;
    if (!VerifyResponseSignature(sig_payload, sig, &sig_error)) {
        return false;
    }

    if (!ok || version.empty() || url.empty() || sha256.empty()) {
        return false;
    }
    if (CompareVersions(version, kLoaderVersion) <= 0) {
        return false;
    }

    std::vector<char> exe_bytes;
    if (!HttpGetBinary(Utf8ToWide(url), &exe_bytes, &error)) {
        return false;
    }

    std::string actual_hash = Sha256HexBytes(exe_bytes);
    if (_stricmp(actual_hash.c_str(), sha256.c_str()) != 0) {
        return false;
    }

    std::wstring exe_path = GetExePath();
    std::wstring new_path = exe_path + L".new";
    if (!WriteFileBinary(new_path, exe_bytes)) {
        return false;
    }

    wchar_t temp_path[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_path);
    wchar_t temp_file[MAX_PATH] = {};
    if (!GetTempFileNameW(temp_path, L"u3w", 0, temp_file)) {
        return false;
    }
    std::wstring script_path = temp_file;
    size_t dot = script_path.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        script_path.replace(dot, std::wstring::npos, L".cmd");
    } else {
        script_path += L".cmd";
    }
    DeleteFileW(temp_file);
    std::string cmd = "@echo off\r\n";
    cmd += "set \"OLD=" + WideToUtf8(exe_path) + "\"\r\n";
    cmd += "set \"NEW=" + WideToUtf8(new_path) + "\"\r\n";
    cmd += "set \"PID=" + std::to_string(GetCurrentProcessId()) + "\"\r\n";
    cmd += ":wait\r\n";
    cmd += "tasklist /FI \"PID eq %PID%\" | find \"%PID%\" > nul\r\n";
    cmd += "if not errorlevel 1 (timeout /t 1 > nul\r\n";
    cmd += "goto wait)\r\n";
    cmd += "move /y \"%NEW%\" \"%OLD%\" > nul\r\n";
    cmd += "start \"\" \"%OLD%\"\r\n";
    cmd += "del \"%~f0\"\r\n";

    std::vector<char> script_bytes(cmd.begin(), cmd.end());
    if (!WriteFileBinary(script_path, script_bytes)) {
        return false;
    }

    std::wstring command_line = L"cmd.exe /C \"" + script_path + L"\"";
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

void SendEvent(const std::wstring& server_url,
               const std::wstring& key,
               const std::string& hwid,
               const std::wstring& product_code,
               const std::string& event_type,
               const std::string& detail) {
    std::string key_utf8 = WideToUtf8(key);
    std::string code_utf8 = WideToUtf8(product_code);
    std::string cpu = WideToUtf8(GetCpuName());
    std::string gpu = WideToUtf8(GetGpuName());
    std::string build = WideToUtf8(GetWindowsBuild());
    std::string os = WideToUtf8(GetOsVersion());
    std::string name = WideToUtf8(GetComputerNameSafe());
    if (g_event_token.empty()) {
        return;
    }
    std::string body = "{\"key\":\"" + JsonEscape(key_utf8) + "\",\"hwid\":\"" + JsonEscape(hwid) +
        "\",\"type\":\"" + JsonEscape(event_type) + "\",\"product_code\":\"" + JsonEscape(code_utf8) +
        "\",\"detail\":\"" + JsonEscape(detail) + "\",\"token\":\"" + JsonEscape(g_event_token) +
        "\",\"device_cpu\":\"" + JsonEscape(cpu) +
        "\",\"device_gpu\":\"" + JsonEscape(gpu) +
        "\",\"device_build\":\"" + JsonEscape(build) +
        "\",\"device_os\":\"" + JsonEscape(os) +
        "\",\"device_name\":\"" + JsonEscape(name) + "\"}";
    std::string response;
    std::wstring error;
    HttpRequest(L"POST", server_url + L"/event", body, &response, &error);
}

bool JsonGetBool(const std::string& json, const std::string& key, bool* value) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return false;
    }
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }
    if (json.compare(pos, 4, "true") == 0) {
        *value = true;
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        *value = false;
        return true;
    }
    return false;
}

bool JsonGetInt64(const std::string& json, const std::string& key, int64_t* value) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return false;
    }
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }
    size_t end = pos;
    while (end < json.size() && (json[end] == '-' || (json[end] >= '0' && json[end] <= '9'))) {
        end++;
    }
    if (end == pos) {
        return false;
    }
    try {
        *value = std::stoll(json.substr(pos, end - pos));
    } catch (...) {
        return false;
    }
    return true;
}

bool JsonGetString(const std::string& json, const std::string& key, std::string* value) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return false;
    }
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }
    if (pos >= json.size() || json[pos] != '"') {
        return false;
    }
    pos++;
    size_t end = json.find('"', pos);
    if (end == std::string::npos) {
        return false;
    }
    *value = json.substr(pos, end - pos);
    return true;
}

bool FindTopLevelValue(const std::string& json, const std::string& key, size_t* value_pos) {
    int depth = 0;
    bool in_string = false;
    bool escape = false;

    for (size_t i = 0; i < json.size(); ++i) {
        char ch = json[i];
        if (in_string) {
            if (escape) {
                escape = false;
                continue;
            }
            if (ch == '\\') {
                escape = true;
                continue;
            }
            if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            size_t start = i + 1;
            size_t end = start;
            bool esc = false;
            while (end < json.size()) {
                char c = json[end];
                if (esc) {
                    esc = false;
                } else if (c == '\\') {
                    esc = true;
                } else if (c == '"') {
                    break;
                }
                ++end;
            }
            if (end >= json.size()) {
                return false;
            }
            if (depth == 1 && json.compare(start, end - start, key) == 0) {
                size_t pos = end + 1;
                while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) {
                    ++pos;
                }
                if (pos >= json.size() || json[pos] != ':') {
                    return false;
                }
                ++pos;
                while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) {
                    ++pos;
                }
                *value_pos = pos;
                return true;
            }
            i = end;
            continue;
        }

        if (ch == '{' || ch == '[') {
            depth++;
        } else if (ch == '}' || ch == ']') {
            depth--;
        }
    }
    return false;
}

bool JsonGetStringTopLevel(const std::string& json, const std::string& key, std::string* value) {
    size_t pos = 0;
    if (!FindTopLevelValue(json, key, &pos)) {
        return false;
    }
    if (pos >= json.size() || json[pos] != '"') {
        return false;
    }
    pos++;
    size_t end = pos;
    bool escape = false;
    while (end < json.size()) {
        char ch = json[end];
        if (escape) {
            escape = false;
        } else if (ch == '\\') {
            escape = true;
        } else if (ch == '"') {
            break;
        }
        ++end;
    }
    if (end >= json.size()) {
        return false;
    }
    *value = json.substr(pos, end - pos);
    return true;
}

bool JsonGetBoolTopLevel(const std::string& json, const std::string& key, bool* value) {
    size_t pos = 0;
    if (!FindTopLevelValue(json, key, &pos)) {
        return false;
    }
    if (json.compare(pos, 4, "true") == 0) {
        *value = true;
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        *value = false;
        return true;
    }
    return false;
}

bool JsonGetInt64TopLevel(const std::string& json, const std::string& key, int64_t* value) {
    size_t pos = 0;
    if (!FindTopLevelValue(json, key, &pos)) {
        return false;
    }
    size_t end = pos;
    while (end < json.size() && (json[end] == '-' || (json[end] >= '0' && json[end] <= '9'))) {
        ++end;
    }
    if (end == pos) {
        return false;
    }
    try {
        *value = std::stoll(json.substr(pos, end - pos));
    } catch (...) {
        return false;
    }
    return true;
}

bool ExtractJsonArray(const std::string& json, const std::string& key, std::string* out) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find('[', pos);
    if (pos == std::string::npos) {
        return false;
    }

    int depth = 0;
    bool in_string = false;
    for (size_t i = pos; i < json.size(); ++i) {
        char ch = json[i];
        if (ch == '"' && (i == 0 || json[i - 1] != '\\')) {
            in_string = !in_string;
        }
        if (in_string) {
            continue;
        }
        if (ch == '[') {
            depth++;
        } else if (ch == ']') {
            depth--;
            if (depth == 0) {
                *out = json.substr(pos, i - pos + 1);
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string> ExtractJsonObjects(const std::string& array_json) {
    std::vector<std::string> objects;
    int depth = 0;
    bool in_string = false;
    size_t start = 0;

    for (size_t i = 0; i < array_json.size(); ++i) {
        char ch = array_json[i];
        if (ch == '"' && (i == 0 || array_json[i - 1] != '\\')) {
            in_string = !in_string;
        }
        if (in_string) {
            continue;
        }
        if (ch == '{') {
            if (depth == 0) {
                start = i;
            }
            depth++;
        } else if (ch == '}') {
            depth--;
            if (depth == 0 && i > start) {
                objects.push_back(array_json.substr(start, i - start + 1));
            }
        }
    }
    return objects;
}

std::string EscapeSigField(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        switch (ch) {
            case '\\':
                out.append("\\\\");
                break;
            case '|':
                out.append("\\|");
                break;
            case '\n':
                out.append("\\n");
                break;
            case '\r':
                out.append("\\r");
                break;
            default:
                out.push_back(ch);
                break;
        }
    }
    return out;
}

std::string BuildSigPayload(bool ok,
                            int64_t ts,
                            const std::string& nonce,
                            const std::string& error,
                            const std::string& min_version,
                            const std::string& update_url,
                            const std::string& expires_at,
                            const std::string& dll_url,
                            const std::string& dll_sha256,
                            const std::string& event_token,
                            const std::vector<ProgramInfo>& programs) {
    std::string out = "ok=" + std::string(ok ? "1" : "0");
    out += "\nts=" + std::to_string(ts);
    out += "\nnonce=" + EscapeSigField(nonce);
    if (!error.empty()) {
        out += "\nerror=" + EscapeSigField(error);
    }
    if (!min_version.empty()) {
        out += "\nmin_version=" + EscapeSigField(min_version);
    }
    if (!update_url.empty()) {
        out += "\nupdate_url=" + EscapeSigField(update_url);
    }
    if (!expires_at.empty()) {
        out += "\nexpires_at=" + EscapeSigField(expires_at);
    }
    if (!dll_url.empty()) {
        out += "\ndll_url=" + EscapeSigField(dll_url);
    }
    if (!dll_sha256.empty()) {
        out += "\ndll_sha256=" + EscapeSigField(dll_sha256);
    }
    if (!event_token.empty()) {
        out += "\nevent_token=" + EscapeSigField(event_token);
    }
    for (const ProgramInfo& program : programs) {
        out += "\nprogram=" + EscapeSigField(WideToUtf8(program.code));
        out += "|" + EscapeSigField(WideToUtf8(program.name));
        out += "|" + EscapeSigField(WideToUtf8(program.updated_at));
        out += "|" + EscapeSigField(WideToUtf8(program.expires_at));
        out += "|" + EscapeSigField(WideToUtf8(program.dll_url));
        out += "|" + EscapeSigField(WideToUtf8(program.status));
        out += "|" + EscapeSigField(WideToUtf8(program.avatar_url));
        out += "|" + EscapeSigField(WideToUtf8(program.watermark));
        out += "|" + EscapeSigField(WideToUtf8(program.payload_sha256));
    }
    return out;
}

bool Base64Decode(const std::string& input, std::vector<BYTE>* out) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr)) {
        return false;
    }
    out->resize(size);
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, out->data(), &size, nullptr, nullptr)) {
        return false;
    }
    out->resize(size);
    return true;
}

bool LoadResponsePublicKey(HCRYPTPROV provider, HCRYPTKEY* key) {
    std::string public_key = GetResponsePublicKeyPem();
    DWORD der_size = 0;
    if (!CryptStringToBinaryA(public_key.c_str(), 0, CRYPT_STRING_BASE64HEADER, nullptr, &der_size, nullptr, nullptr)) {
        return false;
    }
    std::vector<BYTE> der(der_size);
    if (!CryptStringToBinaryA(public_key.c_str(), 0, CRYPT_STRING_BASE64HEADER, der.data(), &der_size, nullptr, nullptr)) {
        return false;
    }

    DWORD info_size = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der.data(), der_size, 0, nullptr, &info_size)) {
        return false;
    }
    std::vector<BYTE> info(info_size);
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der.data(), der_size, 0, info.data(), &info_size)) {
        return false;
    }
    auto* key_info = reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(info.data());
    return CryptImportPublicKeyInfo(provider, X509_ASN_ENCODING, key_info, key) != 0;
}

bool VerifyResponseSignature(const std::string& payload, const std::string& signature_b64, std::wstring* error) {
    std::vector<BYTE> signature;
    if (!Base64Decode(signature_b64, &signature)) {
        if (error) {
            *error = L"Signature decode failed";
        }
        return false;
    }
    std::reverse(signature.begin(), signature.end());

    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (error) {
            *error = L"Crypto init failed";
        }
        return false;
    }

    HCRYPTKEY key = 0;
    if (!LoadResponsePublicKey(provider, &key)) {
        CryptReleaseContext(provider, 0);
        if (error) {
            *error = L"Public key load failed";
        }
        return false;
    }

    HCRYPTHASH hash = 0;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        CryptDestroyKey(key);
        CryptReleaseContext(provider, 0);
        if (error) {
            *error = L"Hash init failed";
        }
        return false;
    }

    if (!CryptHashData(hash, reinterpret_cast<const BYTE*>(payload.data()), static_cast<DWORD>(payload.size()), 0)) {
        CryptDestroyHash(hash);
        CryptDestroyKey(key);
        CryptReleaseContext(provider, 0);
        if (error) {
            *error = L"Hash update failed";
        }
        return false;
    }

    bool ok = CryptVerifySignatureW(hash, signature.data(), static_cast<DWORD>(signature.size()), key, nullptr, 0) != 0;
    CryptDestroyHash(hash);
    CryptDestroyKey(key);
    CryptReleaseContext(provider, 0);
    if (!ok && error) {
        *error = L"Signature mismatch";
    }
    return ok;
}

bool ParseProgramsJson(const std::string& json, std::vector<ProgramInfo>* programs) {
    std::string array_json;
    if (!ExtractJsonArray(json, "programs", &array_json)) {
        return false;
    }
    std::vector<std::string> objects = ExtractJsonObjects(array_json);
    for (const std::string& obj : objects) {
        std::string code;
        std::string name;
        std::string updated;
        std::string expires;
        std::string dll_url;
        std::string status;
        std::string watermark;
        std::string payload_hash;
        std::string avatar_url;
        if (!JsonGetString(obj, "code", &code) || !JsonGetString(obj, "name", &name) || !JsonGetString(obj, "dll_url", &dll_url)) {
            continue;
        }
        JsonGetString(obj, "updated_at", &updated);
        JsonGetString(obj, "expires_at", &expires);
        JsonGetString(obj, "status", &status);
        JsonGetString(obj, "watermark", &watermark);
        JsonGetString(obj, "payload_sha256", &payload_hash);
        JsonGetString(obj, "avatar_url", &avatar_url);
        ProgramInfo info;
        info.code = Utf8ToWide(code);
        info.name = Utf8ToWide(name);
        info.updated_at = Utf8ToWide(updated);
        info.expires_at = Utf8ToWide(expires);
        info.dll_url = Utf8ToWide(dll_url);
        info.status = Utf8ToWide(status);
        if (info.status.empty()) {
            info.status = L"ready";
        }
        info.watermark = Utf8ToWide(watermark);
        info.payload_sha256 = Utf8ToWide(payload_hash);
        info.avatar_url = Utf8ToWide(avatar_url);
        if (!info.avatar_url.empty()) {
            std::vector<char> avatar_bytes;
            std::wstring download_error;
            if (HttpGetBinary(info.avatar_url, &avatar_bytes, &download_error)) {
                std::wstring avatar_path = GetTempAvatarPath(info.code);
                if (WriteFileBinary(avatar_path, avatar_bytes)) {
                    info.avatar_path = avatar_path;
                }
            }
        }
        programs->push_back(info);
    }
    return !programs->empty();
}

std::wstring FriendlyErrorMessage(const std::string& code) {
    if (code == "invalid_key") {
        return L"Invalid key";
    }
    if (code == "expired") {
        return L"Subscription expired";
    }
    if (code == "hwid_mismatch") {
        return L"Device mismatch";
    }
    if (code == "no_products") {
        return L"No programs on this key";
    }
    if (code == "missing_key_or_hwid") {
        return L"Missing key or device id";
    }
    if (code == "device_limit") {
        return L"Device limit reached";
    }
    if (code == "update_required") {
        return L"Update required";
    }
    return Utf8ToWide(code);
}

bool ParseIso8601Utc(const std::wstring& iso, FILETIME* out) {
    if (iso.size() < 19) {
        return false;
    }
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (swscanf_s(iso.c_str(), L"%4d-%2d-%2dT%2d:%2d:%2d", &year, &month, &day, &hour, &minute, &second) != 6) {
        return false;
    }
    SYSTEMTIME st = {};
    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);
    return SystemTimeToFileTime(&st, out) != 0;
}

std::wstring FormatDateLocal(const FILETIME& utc_filetime) {
    FILETIME local_filetime = {};
    if (!FileTimeToLocalFileTime(&utc_filetime, &local_filetime)) {
        return L"";
    }
    SYSTEMTIME local_time = {};
    if (!FileTimeToSystemTime(&local_filetime, &local_time)) {
        return L"";
    }
    wchar_t buffer[64] = {};
    if (!GetDateFormatEx(LOCALE_NAME_USER_DEFAULT, DATE_SHORTDATE, &local_time, nullptr, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0])), nullptr)) {
        return L"";
    }
    return std::wstring(buffer);
}

int64_t GetUnixTimeMs() {
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli = {};
    uli.HighPart = ft.dwHighDateTime;
    uli.LowPart = ft.dwLowDateTime;
    const uint64_t kUnixEpochTicks = 116444736000000000ULL;
    uint64_t ticks = uli.QuadPart;
    if (ticks < kUnixEpochTicks) {
        return 0;
    }
    return static_cast<int64_t>((ticks - kUnixEpochTicks) / 10000ULL);
}

std::wstring FormatUpdatedLabel(const std::wstring& iso) {
    FILETIME ft = {};
    if (!ParseIso8601Utc(iso, &ft)) {
        return L"-";
    }
    std::wstring date = FormatDateLocal(ft);
    if (date.empty()) {
        return L"-";
    }
    return date;
}

std::wstring FormatExpiryLabel(const std::wstring& iso) {
    FILETIME expiry = {};
    if (!ParseIso8601Utc(iso, &expiry)) {
        return L"Ending -";
    }
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);

    ULARGE_INTEGER now_val = {};
    ULARGE_INTEGER expiry_val = {};
    now_val.LowPart = now.dwLowDateTime;
    now_val.HighPart = now.dwHighDateTime;
    expiry_val.LowPart = expiry.dwLowDateTime;
    expiry_val.HighPart = expiry.dwHighDateTime;

    if (expiry_val.QuadPart <= now_val.QuadPart) {
        return L"Expired";
    }

    ULONGLONG diff_seconds = (expiry_val.QuadPart - now_val.QuadPart) / 10000000ULL;
    if (diff_seconds <= 3600) {
        int minutes = static_cast<int>((diff_seconds + 59) / 60);
        wchar_t buffer[64] = {};
        swprintf_s(buffer, L"Ending %dm", minutes);
        return std::wstring(buffer);
    }
    if (diff_seconds <= 86400) {
        int hours = static_cast<int>((diff_seconds + 3599) / 3600);
        wchar_t buffer[64] = {};
        swprintf_s(buffer, L"Ending %dh", hours);
        return std::wstring(buffer);
    }

    std::wstring date = FormatDateLocal(expiry);
    if (date.empty()) {
        return L"Ending -";
    }
    return L"Ending " + date;
}

std::wstring BytesToHexUpper(const BYTE* bytes, DWORD size) {
    static const wchar_t kHex[] = L"0123456789ABCDEF";
    std::wstring out;
    out.reserve(size * 2);
    for (DWORD i = 0; i < size; ++i) {
        BYTE b = bytes[i];
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

bool VerifySignedByThumbprint(const std::wstring& file_path, const std::wstring& expected_thumbprint, std::wstring* error) {
    if (expected_thumbprint.empty()) {
        if (error) {
            *error = L"Missing expected thumbprint";
        }
        return false;
    }

    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = file_path.c_str();

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = 0;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policy, &trust_data);
    if (status != ERROR_SUCCESS) {
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policy, &trust_data);
        if (error) {
            *error = L"Signature verification failed";
        }
        return false;
    }

    CRYPT_PROVIDER_DATA* provider_data = WTHelperProvDataFromStateData(trust_data.hWVTStateData);
    if (!provider_data) {
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policy, &trust_data);
        if (error) {
            *error = L"No signature data";
        }
        return false;
    }

    CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provider_data, 0, FALSE, 0);
    if (!signer) {
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policy, &trust_data);
        if (error) {
            *error = L"No signer found";
        }
        return false;
    }

    CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(signer, 0);
    if (!cert || !cert->pCert) {
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policy, &trust_data);
        if (error) {
            *error = L"No certificate found";
        }
        return false;
    }

    BYTE hash[20] = {};
    DWORD hash_size = sizeof(hash);
    if (!CertGetCertificateContextProperty(cert->pCert, CERT_SHA1_HASH_PROP_ID, hash, &hash_size)) {
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policy, &trust_data);
        if (error) {
            *error = L"Failed to read certificate hash";
        }
        return false;
    }

    std::wstring thumbprint = BytesToHexUpper(hash, hash_size);
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trust_data);

    if (thumbprint != expected_thumbprint) {
        if (error) {
            *error = L"Certificate thumbprint mismatch";
        }
        return false;
    }

    return true;
}

bool WriteFileBinary(const std::wstring& path, const std::vector<char>& data) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(file);
    return ok && written == data.size();
}

bool ReadFileBinary(const std::wstring& path, std::vector<BYTE>* data) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    data->resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(file, data->data(), static_cast<DWORD>(data->size()), &read, nullptr);
    CloseHandle(file);
    return ok && read == data->size();
}

bool SaveKey(const std::wstring& key) {
    if (key.empty()) {
        return false;
    }
    std::vector<BYTE> input((key.size() + 1) * sizeof(wchar_t));
    memcpy(input.data(), key.c_str(), input.size());
    DATA_BLOB in_blob = {static_cast<DWORD>(input.size()), input.data()};
    DATA_BLOB out_blob = {};
    if (!CryptProtectData(&in_blob, L"u3ware-key", nullptr, nullptr, nullptr, 0, &out_blob)) {
        return false;
    }
    std::vector<char> output(out_blob.cbData);
    memcpy(output.data(), out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
    return WriteFileBinary(GetKeyPath(), output);
}

bool LoadSavedKey(std::wstring* key) {
    std::vector<BYTE> data;
    if (!ReadFileBinary(GetKeyPath(), &data)) {
        return false;
    }
    DATA_BLOB in_blob = {static_cast<DWORD>(data.size()), data.data()};
    DATA_BLOB out_blob = {};
    if (!CryptUnprotectData(&in_blob, nullptr, nullptr, nullptr, nullptr, 0, &out_blob)) {
        return false;
    }
    std::wstring value(reinterpret_cast<wchar_t*>(out_blob.pbData));
    LocalFree(out_blob.pbData);
    if (value.empty()) {
        return false;
    }
    *key = value;
    return true;
}

void ClearSavedKey() {
    DeleteFileW(GetKeyPath().c_str());
}

bool HttpGetBinary(const std::wstring& url, std::vector<char>* out, std::wstring* error) {
    std::string response;
    if (!HttpRequest(L"GET", url, {}, &response, error)) {
        return false;
    }
    out->assign(response.begin(), response.end());
    return true;
}

bool IsSafeTokenChar(wchar_t ch) {
    return (ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') || ch == L'-' || ch == L'_';
}

std::wstring SanitizeToken(const std::wstring& value) {
    std::wstring out;
    out.reserve(value.size());
    for (wchar_t ch : value) {
        if (IsSafeTokenChar(ch)) {
            out.push_back(ch);
        }
    }
    if (out.empty()) {
        return L"anon";
    }
    return out;
}

std::wstring GetTempDllPath(const ProgramInfo& program) {
    wchar_t temp_path[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_path);
    std::wstring name = L"payload";
    if (!program.code.empty()) {
        name += L"_" + SanitizeToken(program.code);
    }
    if (!program.watermark.empty()) {
        name += L"_" + SanitizeToken(program.watermark);
    }
    name += L".dll";
    return std::wstring(temp_path) + name;
}

void CenterWindow(HWND hwnd) {
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

int RandomDelayMs(int min_ms, int max_ms) {
    static bool seeded = false;
    if (!seeded) {
        srand(static_cast<unsigned int>(GetTickCount()));
        seeded = true;
    }
    if (max_ms <= min_ms) {
        return min_ms;
    }
    int range = max_ms - min_ms + 1;
    return min_ms + (rand() % range);
}

void DrawBackground(HDC dc, const RECT& rc) {
    TRIVERTEX verts[2] = {};
    verts[0].x = rc.left;
    verts[0].y = rc.top;
    verts[0].Red = static_cast<COLOR16>(GetRValue(kBgTop) << 8);
    verts[0].Green = static_cast<COLOR16>(GetGValue(kBgTop) << 8);
    verts[0].Blue = static_cast<COLOR16>(GetBValue(kBgTop) << 8);
    verts[0].Alpha = 0xFFFF;
    verts[1].x = rc.right;
    verts[1].y = rc.bottom;
    verts[1].Red = static_cast<COLOR16>(GetRValue(kBgBottom) << 8);
    verts[1].Green = static_cast<COLOR16>(GetGValue(kBgBottom) << 8);
    verts[1].Blue = static_cast<COLOR16>(GetBValue(kBgBottom) << 8);
    verts[1].Alpha = 0xFFFF;
    GRADIENT_RECT gradient = {0, 1};
    GradientFill(dc, verts, 2, &gradient, 1, GRADIENT_FILL_RECT_V);

    HPEN grid = CreatePen(PS_SOLID, 1, RGB(18, 24, 34));
    HPEN old_pen = reinterpret_cast<HPEN>(SelectObject(dc, grid));
    int step = Scale(96);
    int offset = Scale(48);
    for (int x = rc.left + offset; x < rc.right; x += step) {
        MoveToEx(dc, x, rc.top, nullptr);
        LineTo(dc, x, rc.bottom);
    }
    SelectObject(dc, old_pen);
    DeleteObject(grid);
}

void DrawPanel(HDC dc, const RECT& rc) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return;
    }
    int radius = Scale(12);
    RECT shadow = rc;
    OffsetRect(&shadow, Scale(3), Scale(5));
    HRGN shadow_rgn = CreateRoundRectRgn(shadow.left, shadow.top, shadow.right + 1, shadow.bottom + 1, radius, radius);
    HBRUSH shadow_brush = CreateSolidBrush(RGB(6, 8, 12));
    FillRgn(dc, shadow_rgn, shadow_brush);
    DeleteObject(shadow_brush);
    DeleteObject(shadow_rgn);

    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    SelectClipRgn(dc, rgn);
    TRIVERTEX verts[2] = {};
    verts[0].x = rc.left;
    verts[0].y = rc.top;
    verts[0].Red = static_cast<COLOR16>(GetRValue(kSurface) << 8);
    verts[0].Green = static_cast<COLOR16>(GetGValue(kSurface) << 8);
    verts[0].Blue = static_cast<COLOR16>(GetBValue(kSurface) << 8);
    verts[0].Alpha = 0xFFFF;
    verts[1].x = rc.right;
    verts[1].y = rc.bottom;
    verts[1].Red = static_cast<COLOR16>(GetRValue(kSurfaceAlt) << 8);
    verts[1].Green = static_cast<COLOR16>(GetGValue(kSurfaceAlt) << 8);
    verts[1].Blue = static_cast<COLOR16>(GetBValue(kSurfaceAlt) << 8);
    verts[1].Alpha = 0xFFFF;
    GRADIENT_RECT gradient = {0, 1};
    GradientFill(dc, verts, 2, &gradient, 1, GRADIENT_FILL_RECT_V);
    SelectClipRgn(dc, nullptr);

    HBRUSH border = CreateSolidBrush(kSurfaceBorder);
    FrameRgn(dc, rgn, border, 1, 1);
    DeleteObject(border);

    int accent_width = min(Scale(140), rc.right - rc.left - Scale(32));
    if (accent_width > 0) {
        RECT accent = {rc.left + Scale(16), rc.top + Scale(2), rc.left + Scale(16) + accent_width, rc.top + Scale(4)};
        HBRUSH accent_brush = CreateSolidBrush(kAccentAlt);
        FillRect(dc, &accent, accent_brush);
        DeleteObject(accent_brush);
    }
    DeleteObject(rgn);
}

void DrawTableHeader(HDC dc, const RECT& rc) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return;
    }
    HBRUSH fill = CreateSolidBrush(kSurfaceAlt);
    FillRect(dc, &rc, fill);
    DeleteObject(fill);

    HPEN line = CreatePen(PS_SOLID, 1, kSurfaceBorder);
    HPEN old_pen = reinterpret_cast<HPEN>(SelectObject(dc, line));
    MoveToEx(dc, rc.left, rc.bottom - 1, nullptr);
    LineTo(dc, rc.right, rc.bottom - 1);
    SelectObject(dc, old_pen);
    DeleteObject(line);
}

void DrawProgramCard(HDC dc, const RECT& item, const ProgramInfo& program, bool selected) {
    RECT card = item;
    int pad_x = Scale(8);
    int pad_y = Scale(4);
    card.left += pad_x;
    card.right -= pad_x;
    card.top += pad_y / 2;
    card.bottom -= pad_y / 2;

    COLORREF border = selected ? kAccentAlt : kSurfaceBorder;
    COLORREF fill = selected ? RGB(26, 36, 50) : kSurfaceAlt;

    HBRUSH fill_brush = CreateSolidBrush(fill);
    FillRect(dc, &card, fill_brush);
    DeleteObject(fill_brush);
    HBRUSH border_brush = CreateSolidBrush(border);
    FrameRect(dc, &card, border_brush);
    DeleteObject(border_brush);

    RECT top_line = {card.left + Scale(10), card.top + Scale(2), card.right - Scale(10), card.top + Scale(4)};
    HBRUSH top_brush = CreateSolidBrush(selected ? kAccentColor : kSurfaceBorder);
    FillRect(dc, &top_line, top_brush);
    DeleteObject(top_brush);

    COLORREF status_color = GetStatusColor(program.status);
    RECT bar = {card.left + Scale(4), card.top + Scale(6), card.left + Scale(8), card.bottom - Scale(6)};
    HBRUSH bar_brush = CreateSolidBrush(status_color);
    FillRect(dc, &bar, bar_brush);
    DeleteObject(bar_brush);

    int card_height = card.bottom - card.top;
    int avatar_size = min(Scale(44), card_height - Scale(10));
    if (avatar_size < Scale(28)) {
        avatar_size = max(Scale(20), card_height - Scale(6));
    }
    int avatar_x = card.left + Scale(14);
    int avatar_y = card.top + (card_height - avatar_size) / 2;
    if (g_avatar_list) {
        int image_index = GetAvatarIndex(program.code);
        HICON icon = ImageList_GetIcon(g_avatar_list, image_index, ILD_TRANSPARENT);
        if (icon) {
            DrawIconEx(dc, avatar_x, avatar_y, icon, avatar_size, avatar_size, 0, nullptr, DI_NORMAL);
            DestroyIcon(icon);
        }
    }

    int text_x = avatar_x + avatar_size + Scale(12);
    HFONT old_font = nullptr;
    TEXTMETRIC tm = {};
    int title_height = Scale(16);
    int subtitle_height = Scale(12);
    if (g_body_font) {
        old_font = reinterpret_cast<HFONT>(SelectObject(dc, g_body_font));
        if (GetTextMetrics(dc, &tm)) {
            title_height = tm.tmHeight;
        }
        SelectObject(dc, old_font);
    }
    if (g_small_font) {
        old_font = reinterpret_cast<HFONT>(SelectObject(dc, g_small_font));
        if (GetTextMetrics(dc, &tm)) {
            subtitle_height = tm.tmHeight;
        }
        SelectObject(dc, old_font);
    }

    int text_top = card.top + Scale(10);
    int subtitle_top = text_top + title_height + Scale(4);
    int text_bottom_limit = card.bottom - Scale(8);
    if (subtitle_top + subtitle_height > text_bottom_limit) {
        subtitle_top = text_bottom_limit - subtitle_height;
    }
    if (subtitle_top < text_top + Scale(2)) {
        subtitle_top = text_top + Scale(2);
    }
    RECT title = {text_x, text_top, card.right - Scale(12), card.bottom};
    old_font = reinterpret_cast<HFONT>(SelectObject(dc, g_body_font ? g_body_font : g_small_font));
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, kTextColor);
    DrawTextW(dc, program.name.c_str(), -1, &title, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS);
    SelectObject(dc, old_font);

    std::wstring updated = FormatUpdatedLabel(program.updated_at);
    std::wstring expiry = FormatExpiryLabel(program.expires_at);
    std::wstring subtitle = L"Updated " + updated + L" \u2022 " + expiry;
    RECT sub = {text_x, subtitle_top, card.right - Scale(12), card.bottom};
    old_font = reinterpret_cast<HFONT>(SelectObject(dc, g_small_font ? g_small_font : g_body_font));
    SetTextColor(dc, kMutedColor);
    DrawTextW(dc, subtitle.c_str(), -1, &sub, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS);
    SelectObject(dc, old_font);
}

void DrawTitleBar(HDC dc, int width) {
    RECT rc = {0, 0, width, g_titlebar_height};
    if (rc.bottom <= rc.top) {
        return;
    }

    TRIVERTEX verts[2] = {};
    verts[0].x = rc.left;
    verts[0].y = rc.top;
    verts[0].Red = static_cast<COLOR16>(GetRValue(kTitleTop) << 8);
    verts[0].Green = static_cast<COLOR16>(GetGValue(kTitleTop) << 8);
    verts[0].Blue = static_cast<COLOR16>(GetBValue(kTitleTop) << 8);
    verts[0].Alpha = 0xFFFF;
    verts[1].x = rc.right;
    verts[1].y = rc.bottom;
    verts[1].Red = static_cast<COLOR16>(GetRValue(kTitleBottom) << 8);
    verts[1].Green = static_cast<COLOR16>(GetGValue(kTitleBottom) << 8);
    verts[1].Blue = static_cast<COLOR16>(GetBValue(kTitleBottom) << 8);
    verts[1].Alpha = 0xFFFF;
    GRADIENT_RECT gradient = {0, 1};
    GradientFill(dc, verts, 2, &gradient, 1, GRADIENT_FILL_RECT_V);

    HPEN border = CreatePen(PS_SOLID, 1, kFrameBorder);
    HPEN old_pen = reinterpret_cast<HPEN>(SelectObject(dc, border));
    MoveToEx(dc, rc.left, rc.bottom - 1, nullptr);
    LineTo(dc, rc.right, rc.bottom - 1);
    SelectObject(dc, old_pen);
    DeleteObject(border);

    int accent_width = min(Scale(120), width - Scale(40));
    if (accent_width > 0) {
        HPEN accent = CreatePen(PS_SOLID, 1, kAccentAlt);
        old_pen = reinterpret_cast<HPEN>(SelectObject(dc, accent));
        MoveToEx(dc, rc.left + Scale(20), rc.bottom - 2, nullptr);
        LineTo(dc, rc.left + Scale(20) + accent_width, rc.bottom - 2);
        SelectObject(dc, old_pen);
        DeleteObject(accent);
    }
}

void DrawTitleButton(HDC dc, const RECT& rc, bool hover, bool pressed, bool is_close) {
    if (hover || pressed) {
        HBRUSH brush = CreateSolidBrush(pressed ? kButtonPressed : kButtonHover);
        FillRect(dc, &rc, brush);
        DeleteObject(brush);
    }

    COLORREF glyph = hover && is_close ? RGB(255, 120, 120) : kTextColor;
    HPEN pen = CreatePen(PS_SOLID, Scale(2), glyph);
    HPEN old_pen = reinterpret_cast<HPEN>(SelectObject(dc, pen));
    int pad = Scale(8);
    if (is_close) {
        MoveToEx(dc, rc.left + pad, rc.top + pad, nullptr);
        LineTo(dc, rc.right - pad, rc.bottom - pad);
        MoveToEx(dc, rc.right - pad, rc.top + pad, nullptr);
        LineTo(dc, rc.left + pad, rc.bottom - pad);
    } else {
        int y = (rc.top + rc.bottom) / 2 + Scale(4);
        MoveToEx(dc, rc.left + pad, y, nullptr);
        LineTo(dc, rc.right - pad, y);
    }
    SelectObject(dc, old_pen);
    DeleteObject(pen);
}

void DrawButtonSurface(HDC dc, const RECT& rc, COLORREF top, COLORREF bottom, COLORREF border) {
    int radius = Scale(14);
    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    SelectClipRgn(dc, rgn);

    TRIVERTEX verts[2] = {};
    verts[0].x = rc.left;
    verts[0].y = rc.top;
    verts[0].Red = static_cast<COLOR16>(GetRValue(top) << 8);
    verts[0].Green = static_cast<COLOR16>(GetGValue(top) << 8);
    verts[0].Blue = static_cast<COLOR16>(GetBValue(top) << 8);
    verts[0].Alpha = 0xFFFF;
    verts[1].x = rc.right;
    verts[1].y = rc.bottom;
    verts[1].Red = static_cast<COLOR16>(GetRValue(bottom) << 8);
    verts[1].Green = static_cast<COLOR16>(GetGValue(bottom) << 8);
    verts[1].Blue = static_cast<COLOR16>(GetBValue(bottom) << 8);
    verts[1].Alpha = 0xFFFF;
    GRADIENT_RECT gradient = {0, 1};
    GradientFill(dc, verts, 2, &gradient, 1, GRADIENT_FILL_RECT_V);

    SelectClipRgn(dc, nullptr);
    HBRUSH border_brush = CreateSolidBrush(border);
    FrameRgn(dc, rgn, border_brush, 1, 1);
    DeleteObject(border_brush);
    DeleteObject(rgn);
}

COLORREF GetStatusColor(const std::wstring& status) {
    std::wstring s = ToLowerString(status);
    if (s.find(L"ready") != std::wstring::npos) {
        return RGB(88, 220, 148);
    }
    if (s.find(L"risky") != std::wstring::npos || s.find(L"risk") != std::wstring::npos) {
        return RGB(248, 158, 84);
    }
    if (s.find(L"updat") != std::wstring::npos) {
        return RGB(244, 210, 90);
    }
    if (s.find(L"off") != std::wstring::npos || s.find(L"down") != std::wstring::npos) {
        return RGB(240, 92, 92);
    }
    return kSurfaceBorder;
}

void SetRoundedRegion(HWND hwnd, int radius) {
    if (!hwnd) {
        return;
    }
    RECT rc = {};
    GetClientRect(hwnd, &rc);
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return;
    }
    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    SetWindowRgn(hwnd, rgn, TRUE);
}

std::wstring ToLowerString(const std::wstring& value) {
    std::wstring out = value;
    for (wchar_t& ch : out) {
        if (ch >= L'A' && ch <= L'Z') {
            ch = static_cast<wchar_t>(ch - L'A' + L'a');
        }
    }
    return out;
}

HBITMAP CreateAvatarBitmap(COLORREF fill_color, COLORREF ring_color, const wchar_t* label, int size) {
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = size;
    bmi.bmiHeader.biHeight = -size;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HDC screen = GetDC(nullptr);
    HBITMAP bitmap = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, screen);
    if (!bitmap) {
        return nullptr;
    }

    HDC mem = CreateCompatibleDC(nullptr);
    HBITMAP old = reinterpret_cast<HBITMAP>(SelectObject(mem, bitmap));
    HBRUSH mask_brush = CreateSolidBrush(kMaskColor);
    RECT rc = {0, 0, size, size};
    FillRect(mem, &rc, mask_brush);
    DeleteObject(mask_brush);

    TRIVERTEX verts[2] = {};
    verts[0].x = 0;
    verts[0].y = 0;
    verts[0].Red = static_cast<COLOR16>(GetRValue(fill_color) << 8);
    verts[0].Green = static_cast<COLOR16>(GetGValue(fill_color) << 8);
    verts[0].Blue = static_cast<COLOR16>(GetBValue(fill_color) << 8);
    verts[0].Alpha = 0xFFFF;
    verts[1].x = size;
    verts[1].y = size;
    verts[1].Red = static_cast<COLOR16>(GetRValue(ring_color) << 8);
    verts[1].Green = static_cast<COLOR16>(GetGValue(ring_color) << 8);
    verts[1].Blue = static_cast<COLOR16>(GetBValue(ring_color) << 8);
    verts[1].Alpha = 0xFFFF;
    GRADIENT_RECT gradient = {0, 1};
    GradientFill(mem, verts, 2, &gradient, 1, GRADIENT_FILL_RECT_V);
    HBRUSH border = CreateSolidBrush(ring_color);
    FrameRect(mem, &rc, border);
    DeleteObject(border);

    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, RGB(255, 255, 255));
    HFONT old_font = reinterpret_cast<HFONT>(SelectObject(mem, g_avatar_font ? g_avatar_font : g_small_font));
    DrawTextW(mem, label, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(mem, old_font);

    SelectObject(mem, old);
    DeleteDC(mem);
    return bitmap;
}

void InitAvatarList() {
    if (!g_list) {
        return;
    }
    if (g_avatar_list) {
        ImageList_Destroy(g_avatar_list);
        g_avatar_list = nullptr;
    }
    for (HBITMAP bmp : g_avatar_bitmaps) {
        DeleteObject(bmp);
    }
    g_avatar_bitmaps.clear();
    g_avatar_index.clear();
    int size = Scale(52);
    g_avatar_list = ImageList_Create(size, size, ILC_COLOR32 | ILC_MASK, 4, 1);
    if (!g_avatar_list) {
        return;
    }

    HBITMAP avatar1 = CreateAvatarBitmap(RGB(86, 196, 255), RGB(70, 120, 255), L"G1", size);
    HBITMAP avatar2 = CreateAvatarBitmap(RGB(98, 232, 200), RGB(62, 170, 140), L"G2", size);
    HBITMAP avatar3 = CreateAvatarBitmap(RGB(132, 142, 168), RGB(90, 100, 128), L"U3", size);

    if (avatar1) {
        ImageList_AddMasked(g_avatar_list, avatar1, kMaskColor);
        DeleteObject(avatar1);
    }
    if (avatar2) {
        ImageList_AddMasked(g_avatar_list, avatar2, kMaskColor);
        DeleteObject(avatar2);
    }
    if (avatar3) {
        ImageList_AddMasked(g_avatar_list, avatar3, kMaskColor);
        DeleteObject(avatar3);
    }

    ListView_SetImageList(g_list, g_avatar_list, LVSIL_SMALL);
}

int GetAvatarIndex(const std::wstring& code) {
    auto it = g_avatar_index.find(code);
    if (it != g_avatar_index.end()) {
        return it->second;
    }
    std::wstring normalized = ToLowerString(code);
    if (normalized == L"game1") {
        return 0;
    }
    if (normalized == L"game2") {
        return 1;
    }
    return 2;
}

void EnsureAvatarForProgram(const ProgramInfo& program) {
    if (!g_avatar_list || program.avatar_path.empty()) {
        return;
    }
    if (g_avatar_index.find(program.code) != g_avatar_index.end()) {
        return;
    }
    int size = Scale(52);
    HBITMAP bmp = LoadAvatarBitmap(program.avatar_path, size);
    if (!bmp) {
        return;
    }
    int index = ImageList_Add(g_avatar_list, bmp, nullptr);
    if (index >= 0) {
        g_avatar_index[program.code] = index;
        g_avatar_bitmaps.push_back(bmp);
    } else {
        DeleteObject(bmp);
    }
}

void PopulateProgramsList() {
    if (!g_list) {
        return;
    }
    InitAvatarList();
    ListView_DeleteAllItems(g_list);
    g_selected_index = -1;
    EnterCriticalSection(&g_programs_lock);
    std::vector<ProgramInfo> programs = g_programs;
    LeaveCriticalSection(&g_programs_lock);

    for (size_t i = 0; i < programs.size(); ++i) {
        const ProgramInfo& program = programs[i];
        EnsureAvatarForProgram(program);
        LVITEMW item = {};
        item.mask = LVIF_TEXT | LVIF_IMAGE;
        item.iItem = static_cast<int>(i);
        item.pszText = const_cast<wchar_t*>(program.name.c_str());
        item.iImage = GetAvatarIndex(program.code);
        ListView_InsertItem(g_list, &item);

        std::wstring updated = FormatUpdatedLabel(program.updated_at);
        std::wstring expiry = FormatExpiryLabel(program.expires_at);
        ListView_SetItemText(g_list, static_cast<int>(i), 1, const_cast<wchar_t*>(updated.c_str()));
        ListView_SetItemText(g_list, static_cast<int>(i), 2, const_cast<wchar_t*>(expiry.c_str()));
    }

    ListView_SetItemState(g_list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetSelectionMark(g_list, -1);
}

void ResetPrograms() {
    EnterCriticalSection(&g_programs_lock);
    g_programs.clear();
    LeaveCriticalSection(&g_programs_lock);
    g_selected_index = -1;
    if (g_list) {
        ListView_DeleteAllItems(g_list);
    }
}

void UpdateButtonText() {
    if (!g_button) {
        return;
    }
    if (g_stage == UiStage::Login) {
        SetWindowTextW(g_button, L"Activate key");
    } else {
        SetWindowTextW(g_button, L"Load");
    }
}

void SetStage(UiStage stage) {
    g_stage = stage;
    bool login = stage == UiStage::Login;
    bool connecting = stage == UiStage::Connecting;
    bool dashboard = stage == UiStage::Dashboard;
    bool loading = stage == UiStage::Loading;
    g_validated = dashboard;
    ShowWindow(g_label_key, login ? SW_SHOW : SW_HIDE);
    ShowWindow(g_edit, login ? SW_SHOW : SW_HIDE);
    if (g_label_programs) {
        if (login) {
            SetWindowTextW(g_label_programs, L"Status");
        } else if (connecting) {
            SetWindowTextW(g_label_programs, L"Connecting");
        } else if (loading) {
            SetWindowTextW(g_label_programs, L"Loader");
        } else {
            SetWindowTextW(g_label_programs, L"Builds");
        }
        ShowWindow(g_label_programs, SW_SHOW);
    }
    ShowWindow(g_label_col_program, SW_HIDE);
    ShowWindow(g_label_col_updated, SW_HIDE);
    ShowWindow(g_label_col_expires, SW_HIDE);
    ShowWindow(g_list, dashboard ? SW_SHOW : SW_HIDE);
    ShowWindow(g_button, (login || dashboard) ? SW_SHOW : SW_HIDE);
    g_status_anim_tick = 0;
    if (!connecting && !loading && !g_status_base.empty()) {
        EnterCriticalSection(&g_status_lock);
        g_status_text = g_status_base;
        LeaveCriticalSection(&g_status_lock);
        PostMessageW(g_hwnd, kMsgUpdateStatus, 0, 0);
    }
    if (connecting || loading) {
        if (!g_status_hwnd) {
            g_status_hwnd = CreateWindowExW(WS_EX_APPWINDOW, L"LoaderStatusWindow", L"u3ware",
                                            WS_POPUP | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 380, 200,
                                            nullptr, nullptr, GetModuleHandleW(nullptr), reinterpret_cast<LPVOID>(1));
            CenterWindow(g_status_hwnd);
        }
        if (g_status_title) {
            SetWindowTextW(g_status_title, connecting ? L"Connecting" : L"Loading");
        }
        if (g_status_overlay) {
            ShowWindow(g_status_overlay, SW_HIDE);
        }
        ShowWindow(g_hwnd, SW_HIDE);
        ShowWindow(g_status_hwnd, SW_SHOW);
        SetForegroundWindow(g_status_hwnd);
    } else {
        if (g_status_hwnd) {
            ShowWindow(g_status_hwnd, SW_HIDE);
        }
        ShowWindow(g_hwnd, SW_SHOW);
        CenterWindow(g_hwnd);
    }
    UpdateButtonText();
    if (g_hwnd) {
        if (login || dashboard) {
            int width = login ? Scale(480) : Scale(760);
            int height = login ? Scale(320) : Scale(520);
            SetWindowPos(g_hwnd, nullptr, 0, 0, width, height, SWP_NOZORDER | SWP_NOMOVE);
            CenterWindow(g_hwnd);
        }
        LayoutControls(g_hwnd);
    }
}

void SetStatus(HWND hwnd, const std::wstring& text) {
    EnterCriticalSection(&g_status_lock);
    g_status_base = text;
    g_status_text = text;
    LeaveCriticalSection(&g_status_lock);
    if (g_status_title && g_status_hwnd) {
        SetWindowTextW(g_status_title, text.c_str());
        InvalidateRect(g_status_hwnd, nullptr, TRUE);
        UpdateWindow(g_status_hwnd);
    }
    PostMessageW(hwnd, kMsgUpdateStatus, 0, 0);
}

void ShowErrorBox(HWND hwnd, const std::wstring& message) {
    HWND owner = g_status_hwnd ? g_status_hwnd : hwnd;
    MessageBoxW(owner, message.c_str(), L"u3ware", MB_OK | MB_ICONERROR);
}

void EnableButton(bool enabled) {
    if (g_button) {
        EnableWindow(g_button, enabled ? TRUE : FALSE);
    }
}

DWORD WINAPI WorkerThread(LPVOID param) {
    WorkerArgs* args = static_cast<WorkerArgs*>(param);
    std::wstring key = args->key;
    TaskType task = args->task;
    ProgramInfo program = args->program;
    bool is_auto = args->is_auto;
    HWND hwnd = args->hwnd;
    delete args;

    auto fail_login = [&](const std::wstring& message) -> DWORD {
        SetStatus(hwnd, message);
        ShowErrorBox(hwnd, message);
        SetStage(UiStage::Login);
        EnableButton(true);
        return 0;
    };

    auto fail_dashboard = [&](const std::wstring& message) -> DWORD {
        SetStatus(hwnd, message);
        ShowErrorBox(hwnd, message);
        SetStage(UiStage::Dashboard);
        EnableButton(true);
        return 0;
    };

    if (task == TaskType::Validate) {
        // Дополнительная проверка на отладчик перед валидацией (ВРЕМЕННО ОТКЛЮЧЕНА)
        // ANTI_CRACK_CHECK(anti_debug::IsDebuggerDetected());

        int validate_attempts = 0;
    validate_retry:
        validate_attempts++;

        SetStatus(hwnd, L"Connecting");

        std::string hwid = BuildHwid();
        if (hwid.empty()) {
            return fail_login(L"An unknown error occured: D1000001/D1000001"); // Failed to build HWID
        }
        
        // Валидация HWID на спуфинг
        auto hwid_validation = hwid_validator::ValidateHWID();
        
        std::string key_utf8 = WideToUtf8(key);
        std::string cpu = WideToUtf8(GetCpuName());
        std::string gpu = WideToUtf8(GetGpuName());
        std::string build = WideToUtf8(GetWindowsBuild());
        std::string os = WideToUtf8(GetOsVersion());
        std::string name = WideToUtf8(GetComputerNameSafe());
        
        // Формируем JSON с флагами валидации
        std::string flags_json = "[";
        for (size_t i = 0; i < hwid_validation.flags.size(); i++) {
            if (i > 0) flags_json += ",";
            flags_json += "\"" + JsonEscape(hwid_validation.flags[i]) + "\"";
        }
        flags_json += "]";
        
        std::string body = "{\"key\":\"" + JsonEscape(key_utf8) + "\",\"hwid\":\"" + JsonEscape(hwid) +
            "\",\"version\":\"" + std::string(kLoaderVersion) +
            "\",\"device_cpu\":\"" + JsonEscape(cpu) +
            "\",\"device_gpu\":\"" + JsonEscape(gpu) +
            "\",\"device_build\":\"" + JsonEscape(build) +
            "\",\"device_os\":\"" + JsonEscape(os) +
            "\",\"device_name\":\"" + JsonEscape(name) +
            "\",\"hwid_score\":" + std::to_string(hwid_validation.suspicion_score) +
            ",\"hwid_flags\":" + flags_json + "}";

        std::string response;
        std::wstring error;
        if (!HttpRequest(L"POST", g_config.server_url + L"/validate", body, &response, &error)) {
            return fail_login(L"An unknown error occured: D1000002/D1000002"); // Server request failed
        }
        Sleep(RandomDelayMs(1000, 3000));
        SetStatus(hwnd, L"Validating license");

        bool ok = false;
        if (!JsonGetBoolTopLevel(response, "ok", &ok)) {
            return fail_login(L"An unknown error occured: D1000003/D1000003"); // Invalid server response
        }

        std::string sig;
        std::string nonce;
        int64_t ts = 0;
        if (!JsonGetStringTopLevel(response, "sig", &sig) || !JsonGetStringTopLevel(response, "nonce", &nonce) || !JsonGetInt64TopLevel(response, "ts", &ts)) {
            return fail_login(L"An unknown error occured: D1000004/D1000004"); // Missing response signature
        }

        int64_t now_ms = GetUnixTimeMs();
        int64_t skew_ms = now_ms - ts;
        if (skew_ms < 0) {
            skew_ms = -skew_ms;
        }
        if (skew_ms > 300000) {
            return fail_login(L"An unknown error occured: D1000005/D1000005"); // Response timestamp invalid
        }

        std::string error_code;
        JsonGetStringTopLevel(response, "error", &error_code);
        std::string min_version;
        JsonGetStringTopLevel(response, "min_version", &min_version);
        std::string update_url;
        JsonGetStringTopLevel(response, "update_url", &update_url);
        std::string expires_at;
        JsonGetStringTopLevel(response, "expires_at", &expires_at);
        std::string dll_url;
        JsonGetStringTopLevel(response, "dll_url", &dll_url);
        std::string dll_sha256;
        JsonGetStringTopLevel(response, "dll_sha256", &dll_sha256);
        std::string event_token;
        JsonGetStringTopLevel(response, "event_token", &event_token);

        std::vector<ProgramInfo> programs;
        ParseProgramsJson(response, &programs);

        std::string sig_payload = BuildSigPayload(ok, ts, nonce, error_code, min_version, update_url, expires_at, dll_url, dll_sha256, event_token, programs);
        std::wstring sig_error;
        
        // Критическая точка - дополнительная проверка (ВРЕМЕННО ОТКЛЮЧЕНА)
        // ANTI_CRACK_CHECK(anti_debug::IsDebuggerDetected());
        
        if (!VerifyResponseSignature(sig_payload, sig, &sig_error)) {
            return fail_login(L"An unknown error occured: D1000006/D1000006"); // Signature invalid
        }
        
        // Еще одна проверка после верификации (ВРЕМЕННО ОТКЛЮЧЕНА)
        // ANTI_CRACK_CHECK(anti_debug::IsDebuggerDetected());

        if (!ok) {
            bool clear_saved_key = true;
            if (!error_code.empty()) {
                std::wstring message;
                if (error_code == "missing_key_or_hwid") {
                    if (is_auto && validate_attempts < 2) {
                        Sleep(700);
                        goto validate_retry;
                    }
                    message = L"An unknown error occured: D1000017/D1000017"; // Missing key or device id
                    clear_saved_key = false;
                } else if (error_code == "update_required") {
                    message = L"An unknown error occured: D1000014/D1000014"; // Update required
                } else if (error_code == "invalid_key") {
                    message = L"An unknown error occured: D200/D200"; // Invalid key
                } else if (error_code == "expired") {
                    message = L"An unknown error occured: D200/D200"; // Subscription expired
                } else if (error_code == "hwid_mismatch") {
                    message = L"An unknown error occured: D1000015/D1000015"; // Device mismatch
                } else if (error_code == "no_products") {
                    message = L"An unknown error occured: D1000016/D1000016"; // No programs on this key
                } else if (error_code == "device_limit") {
                    message = L"An unknown error occured: D1000018/D1000018"; // Device limit reached
                } else {
                    message = L"An unknown error occured: D1000019/D1000019"; // Unknown server error
                }
                SetStatus(hwnd, message);
                ShowErrorBox(hwnd, message);
                if (error_code == "invalid_key" || error_code == "expired") {
                    if (g_status_hwnd) {
                        PostMessageW(g_status_hwnd, WM_CLOSE, 0, 0);
                    }
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    return 0;
                }
            } else {
                std::wstring message = L"An unknown error occured: D1000020/D1000020"; // License rejected
                SetStatus(hwnd, message);
                ShowErrorBox(hwnd, message);
            }
            if (clear_saved_key) {
                ClearSavedKey();
                g_cached_key.clear();
            }
            PostMessageW(hwnd, kMsgProgramsUpdated, 0, 0);
            EnableButton(true);
            return 0;
        }

        if (programs.empty()) {
            std::string dll_url_utf8;
            if (JsonGetString(response, "dll_url", &dll_url_utf8)) {
                ProgramInfo fallback;
                fallback.code = L"default";
                fallback.name = L"Default";
                fallback.updated_at = L"";
                std::string expires_at;
                JsonGetString(response, "expires_at", &expires_at);
                fallback.expires_at = Utf8ToWide(expires_at);
                fallback.dll_url = Utf8ToWide(dll_url_utf8);
                fallback.status = L"ready";
                fallback.payload_sha256 = Utf8ToWide(dll_sha256);
                programs.push_back(fallback);
            }
        }

        if (programs.empty()) {
            return fail_login(L"An unknown error occured: D1000007/D1000007"); // No programs selected
        }

        g_event_token = event_token;
        SaveKey(key);
        g_cached_key = key;
        EnterCriticalSection(&g_programs_lock);
        g_programs = programs;
        LeaveCriticalSection(&g_programs_lock);
        Sleep(RandomDelayMs(1000, 3000));
        PostMessageW(hwnd, kMsgProgramsUpdated, 1, 0);
        SetStatus(hwnd, L"Connected - Choose build");
        EnableButton(true);
        return 0;
    }

    Sleep(RandomDelayMs(1000, 3000));
    std::wstring download_status = L"Downloading " + (program.name.empty() ? std::wstring(L"build") : program.name) + L"...";
    SetStatus(hwnd, download_status);
    std::string hwid_event = BuildHwid();
    auto log_event = [&](const std::string& type, const std::string& detail) {
        if (!g_cached_key.empty() && !hwid_event.empty()) {
            SendEvent(g_config.server_url, g_cached_key, hwid_event, program.code, type, detail);
        }
    };
    std::vector<char> dll_bytes;
    std::wstring error;
    if (!HttpGetBinary(program.dll_url, &dll_bytes, &error)) {
        log_event("download_fail", WideToUtf8(error));
        return fail_dashboard(L"An unknown error occured: D1000008/D1000008"); // Failed to download DLL
    }

    SetStatus(hwnd, L"Verifying build...");
    if (program.payload_sha256.empty()) {
        log_event("verify_fail", "missing_hash");
        return fail_dashboard(L"An unknown error occured: D00013FF/D00013FF"); //Missing build hash
    }
    std::wstring expected_hash = ToLowerString(program.payload_sha256);
    std::wstring actual_hash = ToLowerString(Utf8ToWide(Sha256HexBytes(dll_bytes)));
    if (expected_hash != actual_hash) {
        log_event("verify_fail", "hash_mismatch");
        return fail_dashboard(L"An unknown error occured: D00BAD01/D00BAD01"); //Build hash mismatch
    }

    SetStatus(hwnd, L"[U] Loading..."); //Payload verified
    Sleep(RandomDelayMs(500, 1500));

    // Инжект DLL в целевой процесс
    SetStatus(hwnd, L"Waiting for game"); //Searching target process...
    Sleep(RandomDelayMs(500, 1000));

    // Ожидаем появления целевого процесса
    DWORD target_pid = injector::WaitForProcessId(g_config.target_process);
    
    if (target_pid == 0) {
        return fail_dashboard(L"An unknown error occured: D1000009/D1000009"); // Target process not found
    }
    
    // Подготавливаем конфигурацию для DLL через shared memory
    shared_config::SharedConfig sharedCfg = {};
    sharedCfg.magic = SHARED_CONFIG_MAGIC;
    sharedCfg.version = 1;
    wcscpy_s(sharedCfg.server_url, g_config.server_url.c_str());
    wcscpy_s(sharedCfg.license_key, g_cached_key.c_str());
    
    // HWID в wide string
    std::wstring hwid_wide = Utf8ToWide(hwid_event);
    
    if (hwid_wide.length() >= 128) {
        hwid_wide = hwid_wide.substr(0, 127);
    }
    
    wcscpy_s(sharedCfg.hwid, hwid_wide.c_str());
    
    if (program.code.length() >= 32) {
        return fail_dashboard(L"An unknown error occured: D1000010/D1000010"); // Product code too long
    }
    wcscpy_s(sharedCfg.product_code, program.code.c_str());
    
    if (!g_event_token.empty()) {
        if (g_event_token.length() >= 512) {
            return fail_dashboard(L"An unknown error occured: D1000011/D1000011"); // Event token too long
        }
        strcpy_s(sharedCfg.event_token, g_event_token.c_str());
    }
    
    sharedCfg.heartbeat_interval_ms = 60000; // 1 минута
    sharedCfg.flags = CONFIG_FLAG_HEARTBEAT_ENABLED | CONFIG_FLAG_PROTECTION_ENABLED;
    
    // Создаём shared memory для целевого процесса
    HANDLE sharedHandle = shared_config::WriteConfig(target_pid, sharedCfg);
    
    if (!sharedHandle || sharedHandle == INVALID_HANDLE_VALUE) {
        return fail_dashboard(L"An unknown error occured: D1000012/D1000012"); // Failed to create shared memory
    }
    
    // Затираем локальную копию конфигурации
    SecureZeroMemory(&sharedCfg, sizeof(sharedCfg));
    
    // Инжектим по PID
    auto inject_result = injector::InjectDllByPid(target_pid, dll_bytes);
    
    if (!inject_result.success) {
        // Закрываем shared memory при ошибке
        shared_config::CleanupConfig(sharedHandle);
        log_event("inject_fail", WideToUtf8(inject_result.error));
        return fail_dashboard(L"An unknown error occured: D1000013/D1000013"); // Inject failed: inject_result.error
    }

    {
        if (!hwid_event.empty() && !g_cached_key.empty()) {
            SendEvent(g_config.server_url, g_cached_key, hwid_event, program.code, "inject_ok", "");
        }
    }

    SetStatus(hwnd, L"[U] Initialization");
    Sleep(2000);
    
    // Закрываем shared memory (DLL уже прочитала данные)
    shared_config::CleanupConfig(sharedHandle);

    // Закрываем окно статуса и показываем главное окно
    if (g_status_hwnd) {
        PostMessageW(g_status_hwnd, WM_CLOSE, 0, 0);
    }
    
    EnableButton(true);
    PostMessageW(hwnd, WM_CLOSE, 0, 0);

    return 0;
}

void LayoutControls(HWND hwnd) {
    RECT rc = {};
    GetClientRect(hwnd, &rc);

    int padding = Scale(32);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    int x = padding;
    g_titlebar_height = Scale(52);
    int y = g_titlebar_height + Scale(16);
    int field_width = width - padding * 2;
    int button_width = Scale(200);

    if (!g_edit) {
        return;
    }

    int title_height = GetFontHeight(hwnd, g_title_font);
    int subtitle_height = GetFontHeight(hwnd, g_subtitle_font);
    int label_height = GetFontHeight(hwnd, g_small_font);
    int header_height = GetFontHeight(hwnd, g_body_font);
    int body_height = GetFontHeight(hwnd, g_body_font);
    int edit_height = body_height + Scale(8);
    int button_height = body_height + Scale(12);
    int status_height = label_height;
    int column_height = label_height;
    int card_padding = Scale(20);

    int title_y = (g_titlebar_height - title_height) / 2;
    MoveWindow(g_title, x, title_y, field_width, title_height, TRUE);

    int button_size = Scale(28);
    int button_y = (g_titlebar_height - button_size) / 2;
    int button_right = width - Scale(16);
    g_btn_close = {button_right - button_size, button_y, button_right, button_y + button_size};
    g_btn_min = {g_btn_close.left - Scale(10) - button_size, button_y, g_btn_close.left - Scale(10), button_y + button_size};

    MoveWindow(g_subtitle, x, y, field_width, subtitle_height, TRUE);
    y += subtitle_height + Scale(20);

    if (g_stage == UiStage::Login) {
        int card_width = min(field_width, Scale(860));
        int card_left = (width - card_width) / 2;
        int panel_gap = Scale(18);
        int panel_width = (card_width - panel_gap) / 2;

        int left_left = card_left;
        int left_top = y;
        int left_y = left_top + card_padding;
        int left_field_width = panel_width - card_padding * 2;
        MoveWindow(g_label_key, left_left + card_padding, left_y, left_field_width, label_height, TRUE);
        left_y += label_height + Scale(8);

        MoveWindow(g_edit, left_left + card_padding, left_y, left_field_width, edit_height, TRUE);
        left_y += edit_height + Scale(14);

        MoveWindow(g_button, left_left + card_padding, left_y, left_field_width, button_height, TRUE);
        SetRoundedRegion(g_button, Scale(14));
        left_y += button_height + Scale(10);
        g_card_auth = {left_left, left_top, left_left + panel_width, left_y + card_padding};

        int right_left = left_left + panel_width + panel_gap;
        int right_top = left_top;
        int right_y = right_top + card_padding;
        int right_field_width = panel_width - card_padding * 2;
        MoveWindow(g_label_programs, right_left + card_padding, right_y, right_field_width, header_height, TRUE);
        right_y += header_height + Scale(8);
        MoveWindow(g_status, right_left + card_padding, right_y, right_field_width, status_height, TRUE);
        right_y += status_height + Scale(10);
        g_card_programs = {right_left, right_top, right_left + panel_width, right_y + card_padding};
        g_table_header = {};
    } else if (g_stage == UiStage::Connecting || g_stage == UiStage::Loading) {
        int card_width = min(field_width, Scale(520));
        int card_height = Scale(180);
        int card_left = (width - card_width) / 2;
        int card_top = (height - card_height) / 2;
        int card_padding = Scale(20);
        g_card_auth = {card_left, card_top, card_left + card_width, card_top + card_height};
        g_card_programs = {};
        g_table_header = {};

        int header_y = card_top + card_padding;
        MoveWindow(g_label_programs, card_left + card_padding, header_y, card_width - card_padding * 2, header_height, TRUE);
        header_y += header_height + Scale(10);
        MoveWindow(g_status, card_left + card_padding, header_y, card_width - card_padding * 2, status_height, TRUE);
    } else {
        int panel_width = min(field_width, Scale(860));
        int panel_left = (width - panel_width) / 2;
        int panel_padding = Scale(18);

        int toolbar_top = y;
        int header_y = toolbar_top + panel_padding;
        MoveWindow(g_label_programs, panel_left + panel_padding, header_y,
                   panel_width - panel_padding * 2 - button_width - Scale(12), header_height, TRUE);
        MoveWindow(g_button, panel_left + panel_width - panel_padding - button_width, header_y - Scale(4), button_width, button_height, TRUE);
        SetRoundedRegion(g_button, Scale(14));
        header_y += header_height + Scale(8);
        MoveWindow(g_status, panel_left + panel_padding, header_y, panel_width - panel_padding * 2, status_height, TRUE);
        int toolbar_bottom = header_y + status_height + panel_padding;
        g_card_auth = {panel_left, toolbar_top, panel_left + panel_width, toolbar_bottom};

        int list_top = toolbar_bottom + Scale(18);
        int list_padding = Scale(18);
        int list_width = panel_width - list_padding * 2;
        int list_y = list_top + list_padding;
        int list_height = height - list_y - padding;
        if (g_list) {
            MoveWindow(g_list, panel_left + list_padding, list_y, list_width, list_height, TRUE);
            ListView_SetColumnWidth(g_list, 0, list_width);
            ListView_SetColumnWidth(g_list, 1, 0);
            ListView_SetColumnWidth(g_list, 2, 0);
        }

        g_table_header = {};
        g_card_programs = {panel_left, list_top, panel_left + panel_width, list_y + list_height + list_padding};
    }
    InvalidateRect(hwnd, nullptr, TRUE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<WindowState*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    if (state && state->is_status && msg != WM_CREATE) {
        switch (msg) {
            case WM_SIZE: {
                RECT rc = {};
                GetClientRect(hwnd, &rc);
                int width = rc.right - rc.left;
                int height = rc.bottom - rc.top;
                int card_width = min(width - Scale(48), Scale(420));
                int card_height = Scale(160);
                int card_left = (width - card_width) / 2;
                int card_top = (height - card_height) / 2;
                state->card = {card_left, card_top, card_left + card_width, card_top + card_height};
                int padding = Scale(18);
                int header_height = g_title_font ? GetFontHeight(hwnd, g_title_font) : Scale(18);
                int body_height = g_body_font ? GetFontHeight(hwnd, g_body_font) : Scale(16);
                int title_y = card_top + padding;
                if (g_status_title) {
                    MoveWindow(g_status_title, card_left + padding, title_y, card_width - padding * 2, header_height, TRUE);
                }
                if (g_status_overlay) {
                    MoveWindow(g_status_overlay, card_left + padding, title_y + header_height + Scale(10),
                               card_width - padding * 2, body_height, TRUE);
                }
                return 0;
            }
            case WM_PAINT: {
                PAINTSTRUCT ps = {};
                HDC dc = BeginPaint(hwnd, &ps);
                RECT rc = {};
                GetClientRect(hwnd, &rc);
                DrawBackground(dc, rc);
                HBRUSH border = CreateSolidBrush(kFrameBorder);
                FrameRect(dc, &rc, border);
                DeleteObject(border);
                DrawPanel(dc, state->card);
                EndPaint(hwnd, &ps);
                return 0;
            }
            case WM_CTLCOLORSTATIC: {
                HDC dc = reinterpret_cast<HDC>(wparam);
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, kTextColor);
                return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
            }
            case WM_ERASEBKGND:
                return 1;
            case WM_NCHITTEST:
                return HTCAPTION;
            case WM_DPICHANGED: {
                g_dpi = HIWORD(wparam);
                RECT* rect = reinterpret_cast<RECT*>(lparam);
                SetWindowPos(hwnd, nullptr, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top,
                             SWP_NOZORDER | SWP_NOACTIVATE);
                SendMessageW(hwnd, WM_SIZE, 0, 0);
                return 0;
            }
            case WM_DESTROY:
                if (g_status_hwnd == hwnd) {
                    g_status_hwnd = nullptr;
                    g_status_title = nullptr;
                    g_status_overlay = nullptr;
                }
                delete state;
                SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);
                return 0;
            default:
                break;
        }
    }
    switch (msg) {
        case WM_CREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCT*>(lparam);
            auto* new_state = new WindowState();
            new_state->is_status = cs->lpCreateParams != nullptr;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(new_state));
            if (new_state->is_status) {
                if (!g_title_font || !g_body_font) {
                    CreateFonts();
                }
                g_status_title = CreateWindowW(L"STATIC", L"Connecting", WS_CHILD | WS_VISIBLE,
                                               0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
                g_status_overlay = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                                 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
                if (g_status_title) {
                    SendMessageW(g_status_title, WM_SETFONT, reinterpret_cast<WPARAM>(g_title_font), TRUE);
                }
                if (g_status_overlay) {
                    SendMessageW(g_status_overlay, WM_SETFONT, reinterpret_cast<WPARAM>(g_body_font), TRUE);
                    ShowWindow(g_status_overlay, SW_HIDE);
                }
                SendMessageW(hwnd, WM_SIZE, 0, 0);
                return 0;
            }

            g_bg_brush = CreateSolidBrush(kBgBottom);
            g_panel_brush = CreateSolidBrush(kSurface);
            g_panel_alt_brush = CreateSolidBrush(kSurfaceAlt);
            g_dpi = GetDpiForWindow(hwnd);
            CreateFonts();
            StartGdiPlus();

            LONG_PTR ex_style = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
            SetWindowLongPtr(hwnd, GWL_EXSTYLE, ex_style | WS_EX_LAYERED);
            SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
            g_fade_active = true;
            g_fade_alpha = 0;
            SetTimer(hwnd, kUiTimerId, 80, nullptr);

            g_title = CreateWindowW(L"STATIC", L"u3ware", WS_CHILD | WS_VISIBLE,
                                    0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_subtitle = CreateWindowW(L"STATIC", L"best solutions for you <3", WS_CHILD | WS_VISIBLE,
                                       0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_label_key = CreateWindowW(L"STATIC", L"Activation key", WS_CHILD | WS_VISIBLE,
                                        0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);

            g_edit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                     0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<intptr_t>(kControlIdEdit)), nullptr, nullptr);

            g_button = CreateWindowW(L"BUTTON", L"Validate key", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                     0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<intptr_t>(kControlIdButton)), nullptr, nullptr);

            g_status = CreateWindowW(L"STATIC", L"Paste your key to continue", WS_CHILD | WS_VISIBLE,
                                     0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<intptr_t>(kControlIdStatus)), nullptr, nullptr);

            g_label_programs = CreateWindowW(L"STATIC", L"Builds", WS_CHILD | WS_VISIBLE,
                                             0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_label_col_program = CreateWindowW(L"STATIC", L"Build", WS_CHILD | WS_VISIBLE,
                                                0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_label_col_updated = CreateWindowW(L"STATIC", L"Updated", WS_CHILD | WS_VISIBLE,
                                                0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_label_col_expires = CreateWindowW(L"STATIC", L"Subscription", WS_CHILD | WS_VISIBLE,
                                                0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);

            g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                     WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOCOLUMNHEADER,
                                     0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<intptr_t>(kControlIdList)), nullptr, nullptr);
            ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            SendMessageW(g_list, WM_CHANGEUISTATE, MAKEWPARAM(UIS_SET, UISF_HIDEFOCUS), 0);
            ListView_SetBkColor(g_list, kSurface);
            ListView_SetTextBkColor(g_list, kSurface);
            ListView_SetTextColor(g_list, kTextColor);
            ListView_SetImageList(g_list, g_avatar_list, LVSIL_SMALL);

            LVCOLUMNW column = {};
            column.mask = LVCF_TEXT | LVCF_WIDTH;
            column.pszText = const_cast<wchar_t*>(L"Build");
            column.cx = 200;
            ListView_InsertColumn(g_list, 0, &column);
            column.pszText = const_cast<wchar_t*>(L"Updated");
            column.cx = 140;
            ListView_InsertColumn(g_list, 1, &column);
            column.pszText = const_cast<wchar_t*>(L"Subscription");
            column.cx = 180;
            ListView_InsertColumn(g_list, 2, &column);

            ApplyFonts();
            InitAvatarList();

            SetStage(UiStage::Login);
            UpdateButtonText();
            LayoutControls(hwnd);
            return 0;
        }
        case WM_SIZE:
            LayoutControls(hwnd);
            return 0;
        case WM_NCCALCSIZE:
            return 0;
        case WM_NCHITTEST: {
            POINT pt = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            RECT win = {};
            GetWindowRect(hwnd, &win);

            POINT client = pt;
            ScreenToClient(hwnd, &client);
            if (PtInRect(&g_btn_close, client) || PtInRect(&g_btn_min, client)) {
                return HTCLIENT;
            }
            if (client.y >= 0 && client.y < g_titlebar_height) {
                return HTCAPTION;
            }
            return HTCLIENT;
        }
        case WM_DPICHANGED: {
            g_dpi = HIWORD(wparam);
            RECT* rect = reinterpret_cast<RECT*>(lparam);
            SetWindowPos(hwnd, nullptr, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            CreateFonts();
            ApplyFonts();
            InitAvatarList();
            LayoutControls(hwnd);
            return 0;
        }
        case WM_SYSCOMMAND: {
            UINT command = static_cast<UINT>(wparam & 0xFFF0);
            if (command == SC_SIZE || command == SC_MAXIMIZE) {
                return 0;
            }
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wparam) == kControlIdEdit && HIWORD(wparam) == EN_CHANGE) {
                if (g_stage != UiStage::Login) {
                    SetStage(UiStage::Login);
                    ResetPrograms();
                }
                ClearSavedKey();
                g_cached_key.clear();
                SetStatus(hwnd, L"Enter a key to continue");
                return 0;
            }
            if (LOWORD(wparam) == kControlIdButton) {
                if (g_stage == UiStage::Login) {
                    wchar_t key_buffer[256] = {};
                    GetWindowTextW(g_edit, key_buffer, static_cast<int>(sizeof(key_buffer) / sizeof(key_buffer[0])));
                    std::wstring key(key_buffer);
                    if (key.empty()) {
                        SetStatus(hwnd, L"Enter a key first");
                        return 0;
                    }
                    SetStage(UiStage::Connecting);
                    SetStatus(hwnd, L"Connecting");
                    EnableButton(false);
                    WorkerArgs* args = new WorkerArgs{ hwnd, TaskType::Validate, key, {}, false };
                    CreateThread(nullptr, 0, WorkerThread, args, 0, nullptr);
                    return 0;
                }

                int selected = g_selected_index;
                if (selected < 0) {
                    SetStatus(hwnd, L"Select a build first");
                    return 0;
                }

                EnterCriticalSection(&g_programs_lock);
                if (static_cast<size_t>(selected) >= g_programs.size()) {
                    LeaveCriticalSection(&g_programs_lock);
                    SetStatus(hwnd, L"Select a build first");
                    return 0;
                }
                ProgramInfo program = g_programs[static_cast<size_t>(selected)];
                LeaveCriticalSection(&g_programs_lock);

                SetStage(UiStage::Loading);
                SetStatus(hwnd, L"Preparing build");
                EnableButton(false);
                WorkerArgs* args = new WorkerArgs{ hwnd, TaskType::LoadProgram, g_cached_key, program, false };
                CreateThread(nullptr, 0, WorkerThread, args, 0, nullptr);
            }
            return 0;
        case WM_LBUTTONDOWN: {
            POINT pt = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            if (PtInRect(&g_btn_close, pt)) {
                g_pressed_close = true;
                SetCapture(hwnd);
                InvalidateRect(hwnd, &g_btn_close, TRUE);
                return 0;
            }
            if (PtInRect(&g_btn_min, pt)) {
                g_pressed_min = true;
                SetCapture(hwnd);
                InvalidateRect(hwnd, &g_btn_min, TRUE);
                return 0;
            }
            break;
        }
        case WM_LBUTTONUP: {
            if (g_pressed_close || g_pressed_min) {
                POINT pt = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
                bool close_hit = g_pressed_close && PtInRect(&g_btn_close, pt);
                bool min_hit = g_pressed_min && PtInRect(&g_btn_min, pt);
                g_pressed_close = false;
                g_pressed_min = false;
                ReleaseCapture();
                InvalidateRect(hwnd, &g_btn_close, TRUE);
                InvalidateRect(hwnd, &g_btn_min, TRUE);
                if (close_hit) {
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                } else if (min_hit) {
                    ShowWindow(hwnd, SW_MINIMIZE);
                }
                return 0;
            }
            break;
        }
        case WM_MOUSEMOVE: {
            POINT pt = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            bool hover_close = PtInRect(&g_btn_close, pt);
            bool hover_min = PtInRect(&g_btn_min, pt);
            if (hover_close != g_hover_close || hover_min != g_hover_min) {
                g_hover_close = hover_close;
                g_hover_min = hover_min;
                InvalidateRect(hwnd, &g_btn_close, TRUE);
                InvalidateRect(hwnd, &g_btn_min, TRUE);
            }
            if (!g_tracking_mouse) {
                TRACKMOUSEEVENT tme = {};
                tme.cbSize = sizeof(tme);
                tme.dwFlags = TME_LEAVE;
                tme.hwndTrack = hwnd;
                if (TrackMouseEvent(&tme)) {
                    g_tracking_mouse = true;
                }
            }
            break;
        }
        case WM_MOUSELEAVE:
            g_tracking_mouse = false;
            if (g_hover_close || g_hover_min) {
                g_hover_close = false;
                g_hover_min = false;
                InvalidateRect(hwnd, &g_btn_close, TRUE);
                InvalidateRect(hwnd, &g_btn_min, TRUE);
            }
            return 0;
        case WM_NOTIFY: {
            auto* header = reinterpret_cast<NMHDR*>(lparam);
            if (header && header->hwndFrom == g_list && header->code == NM_CUSTOMDRAW) {
                auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lparam);
                if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) {
                    return CDRF_NOTIFYITEMDRAW;
                }
                if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                    int index = static_cast<int>(draw->nmcd.dwItemSpec);
                    RECT item = {};
                    if (ListView_GetItemRect(g_list, index, &item, LVIR_BOUNDS)) {
                        ProgramInfo info;
                        EnterCriticalSection(&g_programs_lock);
                        if (index >= 0 && static_cast<size_t>(index) < g_programs.size()) {
                            info = g_programs[static_cast<size_t>(index)];
                        }
                        LeaveCriticalSection(&g_programs_lock);
                        bool selected = (index == g_selected_index);
                        DrawProgramCard(draw->nmcd.hdc, item, info, selected);
                    }
                    return CDRF_SKIPDEFAULT;
                }
            }
            if (header && header->hwndFrom == g_list && header->code == LVN_ITEMCHANGED) {
                auto* change = reinterpret_cast<NMLISTVIEW*>(lparam);
                if ((change->uChanged & LVIF_STATE) != 0) {
                    if ((change->uNewState & LVIS_SELECTED) != 0) {
                        g_selected_index = change->iItem;
                        InvalidateRect(g_list, nullptr, TRUE);
                    }
                }
                return 0;
            }
            break;
        }
        case WM_DRAWITEM: {
            auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
            if (dis->CtlID == kControlIdButton) {
                HDC dc = dis->hDC;
                RECT rect = dis->rcItem;

                bool enabled = IsWindowEnabled(dis->hwndItem) != FALSE;
                bool pressed = (dis->itemState & ODS_SELECTED) != 0;
                if (g_panel_brush) {
                    FillRect(dc, &rect, g_panel_brush);
                }
                COLORREF top = enabled ? (pressed ? kAccentAlt : kAccentColor) : kSurfaceBorder;
                COLORREF bottom = enabled ? (pressed ? kAccentColor : kAccentAlt) : kSurfaceBorder;
                COLORREF border = enabled ? kAccentAlt : kSurfaceBorder;
                DrawButtonSurface(dc, rect, top, bottom, border);

                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, enabled ? RGB(255, 255, 255) : kMutedColor);

                wchar_t text[64] = {};
                GetWindowTextW(dis->hwndItem, text, static_cast<int>(sizeof(text) / sizeof(text[0])));
                DrawTextW(dc, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                return TRUE;
            }
            break;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps = {};
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc = {};
            GetClientRect(hwnd, &rc);
            DrawBackground(dc, rc);
            DrawTitleBar(dc, rc.right - rc.left);
            HBRUSH border = CreateSolidBrush(kFrameBorder);
            FrameRect(dc, &rc, border);
            DeleteObject(border);
            DrawPanel(dc, g_card_auth);
            DrawPanel(dc, g_card_programs);
            if (!IsRectEmpty(&g_table_header)) {
                DrawTableHeader(dc, g_table_header);
            }
            DrawTitleButton(dc, g_btn_min, g_hover_min, g_pressed_min, false);
            DrawTitleButton(dc, g_btn_close, g_hover_close, g_pressed_close, true);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            HWND control = reinterpret_cast<HWND>(lparam);
            if (control == g_title) {
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, kTextColor);
                return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
            }
            if (control == g_subtitle) {
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, kMutedColor);
                return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
            }

            bool is_column_label = (control == g_label_col_program || control == g_label_col_updated || control == g_label_col_expires);
            if (is_column_label) {
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, kMutedColor);
                return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
            }

            bool is_panel_label = (control == g_label_key || control == g_status || control == g_label_programs);
            if (is_panel_label) {
                SetBkMode(dc, OPAQUE);
                SetBkColor(dc, kSurface);
                SetTextColor(dc, (control == g_status || control == g_label_programs) ? kTextColor : kMutedColor);
                return reinterpret_cast<LRESULT>(g_panel_brush);
            }
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, kMutedColor);
            return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            SetTextColor(dc, kTextColor);
            SetBkColor(dc, kSurface);
            return reinterpret_cast<LRESULT>(g_panel_brush);
        }
        case WM_ERASEBKGND: {
            return 1;
        }
        case kMsgUpdateStatus: {
            EnterCriticalSection(&g_status_lock);
            std::wstring status = g_status_text;
            LeaveCriticalSection(&g_status_lock);
            if (!status.empty() && g_status) {
                SetWindowTextW(g_status, status.c_str());
                RECT status_rect = {};
                GetWindowRect(g_status, &status_rect);
                MapWindowPoints(nullptr, hwnd, reinterpret_cast<POINT*>(&status_rect), 2);
                InvalidateRect(hwnd, &status_rect, TRUE);
                UpdateWindow(hwnd);
            }
            return 0;
        }
        case kMsgProgramsUpdated: {
            bool ok = (wparam != 0);
            if (ok) {
                SetStage(UiStage::Dashboard);
                PopulateProgramsList();
            } else {
                SetStage(UiStage::Login);
                ResetPrograms();
            }
            return 0;
        }
        case kMsgAutoValidate: {
            if (g_cached_key.empty()) {
                return 0;
            }
            SetStage(UiStage::Connecting);
            SetStatus(hwnd, L"Validating saved key...");
            SetWindowTextW(g_edit, g_cached_key.c_str());
            EnableButton(false);
            WorkerArgs* args = new WorkerArgs{ hwnd, TaskType::Validate, g_cached_key, {}, true };
            CreateThread(nullptr, 0, WorkerThread, args, 0, nullptr);
            return 0;
        }
        case WM_TIMER: {
            if (wparam == kUiTimerId) {
                if (g_fade_active) {
                    BYTE next_alpha = static_cast<BYTE>(std::min<int>(255, g_fade_alpha + kFadeStep));
                    g_fade_alpha = next_alpha;
                    SetLayeredWindowAttributes(hwnd, 0, g_fade_alpha, LWA_ALPHA);
                    if (g_fade_alpha >= 255) {
                        g_fade_active = false;
                    }
                }
                bool animate_status = (g_stage == UiStage::Connecting || g_stage == UiStage::Loading);
                if (animate_status && !g_status_base.empty()) {
                    int dots = g_status_anim_tick++ % 4;
                    std::wstring animated = g_status_base + std::wstring(dots, L'.');
                    EnterCriticalSection(&g_status_lock);
                    g_status_text = animated;
                    LeaveCriticalSection(&g_status_lock);
                    if (g_status) {
                        SetWindowTextW(g_status, animated.c_str());
                    }
                    if (g_status_title && g_status_hwnd) {
                        SetWindowTextW(g_status_title, animated.c_str());
                        InvalidateRect(g_status_hwnd, nullptr, TRUE);
                        UpdateWindow(g_status_hwnd);
                    }
                }
            }
            return 0;
        }
        case WM_DESTROY:
            KillTimer(hwnd, kUiTimerId);
            DestroyFonts();
            StopGdiPlus();
            if (g_avatar_list) {
                ImageList_Destroy(g_avatar_list);
                g_avatar_list = nullptr;
            }
            for (HBITMAP bmp : g_avatar_bitmaps) {
                DeleteObject(bmp);
            }
            g_avatar_bitmaps.clear();
            g_avatar_index.clear();
            if (g_bg_brush) {
                DeleteObject(g_bg_brush);
            }
            if (g_panel_brush) {
                DeleteObject(g_panel_brush);
            }
            if (g_panel_alt_brush) {
                DeleteObject(g_panel_alt_brush);
            }
            if (state) {
                delete state;
                SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);
            }
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

} // namespace loader

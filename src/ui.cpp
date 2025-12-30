#include "app.h"
#include "injector.h"
#include "anti_debug.h"
#include "protection.h"
#include "anti_crack.h"
#include "shared_config.h"
#include "hwid_validator.h"
#include "process_info.h"
#include "ui_dx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <schannel.h>
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
#include <mutex>
#include <memory>
#include <cwctype>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "gdiplus.lib")

namespace loader {
std::wstring ToLowerString(const std::wstring& value);
std::wstring NormalizeKeyWide(const std::wstring& input);
std::wstring FormatKeyDisplay(const std::wstring& input);
int CountKeyChars(const std::wstring& input, size_t up_to);
int MapKeyIndexToFormatted(int key_index, int total_key_chars);
COLORREF GetStatusColor(const std::wstring& status);
int GetAvatarIndex(const std::wstring& code);
std::string EscapeSigField(const std::string& value);
bool JsonGetBoolTopLevel(const std::string& json, const std::string& key, bool* value);
bool JsonGetStringTopLevel(const std::string& json, const std::string& key, std::string* value);
bool JsonGetInt64TopLevel(const std::string& json, const std::string& key, int64_t* value);
bool VerifyResponseSignature(const std::string& payload, const std::string& signature_b64, std::wstring* error);
std::wstring BytesToHexUpper(const BYTE* bytes, DWORD size);
bool HttpGetBinary(const std::wstring& url, std::vector<char>* out, std::wstring* error);
bool WriteFileBinary(const std::wstring& path, const std::vector<char>& data);
std::string Sha256HexBytes(const std::vector<char>& data);
std::wstring SanitizeToken(const std::wstring& value);

static std::unordered_map<std::wstring, int> g_avatar_index;
static std::vector<HBITMAP> g_avatar_bitmaps;
static bool g_gdiplus_started = false;
static ULONG_PTR g_gdiplus_token = 0;
static bool g_ignore_key_change = false;
static std::unique_ptr<DxUiRenderer> g_dx_ui;
static constexpr bool kEnableDxUi = true;

constexpr UINT kUiTimerId = 1;
constexpr BYTE kFadeStep = 18;
static bool g_fade_active = false;
static BYTE g_fade_alpha = 0;
static std::wstring g_status_base;
static int g_status_anim_tick = 0;
static bool g_button_hover = false;
static POINT g_button_hover_pt = {};
static bool g_button_layered = false;
static bool g_dx_button_pressed = false;

void ConfigureDxButtonWindow(HWND hwnd) {
    if (!hwnd) {
        return;
    }
    LONG_PTR ex_style = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    if ((ex_style & WS_EX_LAYERED) != 0) {
        SetWindowLongPtr(hwnd, GWL_EXSTYLE, ex_style & ~WS_EX_LAYERED);
    }
    g_button_layered = false;
}

void SetDxButtonAlpha(HWND hwnd, BYTE alpha) {
    if (!hwnd) {
        return;
    }
    if (!g_button_layered) {
        ConfigureDxButtonWindow(hwnd);
    }
    if (g_button_layered) {
        SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA);
    }
}

static LRESULT CALLBACK ButtonSubclassProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                                           UINT_PTR, DWORD_PTR) {
    switch (msg) {
        case WM_ERASEBKGND:
            return 1;
        case WM_NCDESTROY:
            RemoveWindowSubclass(hwnd, ButtonSubclassProc, 0);
            break;
        default:
            break;
    }
    return DefSubclassProc(hwnd, msg, wparam, lparam);
}

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
    if (config->expected_thumbprint.empty()) {
        return false;
    }
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
    g_title_font = CreateFontW(-Scale(28), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                               OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_subtitle_font = CreateFontW(-Scale(12), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                  OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_body_font = CreateFontW(-Scale(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_small_font = CreateFontW(-Scale(11), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                               OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
    g_avatar_font = CreateFontW(-Scale(11), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
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

std::string TrimTrailingZeros(std::string value) {
    size_t dot = value.find('.');
    if (dot == std::string::npos) {
        return value;
    }
    while (!value.empty() && value.back() == '0') {
        value.pop_back();
    }
    if (!value.empty() && value.back() == '.') {
        value.pop_back();
    }
    return value;
}

void AppendJsonStringField(std::string* out, const char* key, const std::string& value) {
    if (!out || value.empty()) {
        return;
    }
    *out += ",\"";
    *out += key;
    *out += "\":\"";
    *out += JsonEscape(value);
    *out += "\"";
}

void AppendJsonIntField(std::string* out, const char* key, int value) {
    if (!out || value <= 0) {
        return;
    }
    *out += ",\"";
    *out += key;
    *out += "\":";
    *out += std::to_string(value);
}

void AppendJsonNumberField(std::string* out, const char* key, double value) {
    if (!out || value <= 0.0) {
        return;
    }
    std::string text = TrimTrailingZeros(std::to_string(value));
    if (text.empty()) {
        return;
    }
    *out += ",\"";
    *out += key;
    *out += "\":";
    *out += text;
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

std::wstring GetArchName() {
    SYSTEM_INFO info = {};
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return L"x64";
        case PROCESSOR_ARCHITECTURE_INTEL:
            return L"x86";
        case PROCESSOR_ARCHITECTURE_ARM64:
            return L"arm64";
        case PROCESSOR_ARCHITECTURE_ARM:
            return L"arm";
        case PROCESSOR_ARCHITECTURE_IA64:
            return L"ia64";
        default:
            return L"unknown";
    }
}

int GetCpuCoreCount() {
    SYSTEM_INFO info = {};
    GetNativeSystemInfo(&info);
    if (info.dwNumberOfProcessors > 0) {
        return static_cast<int>(info.dwNumberOfProcessors);
    }
    return 0;
}

double GetTotalRamGb() {
    MEMORYSTATUSEX status = {};
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx(&status)) {
        return 0.0;
    }
    return static_cast<double>(status.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
}

double GetSystemDiskGb() {
    wchar_t system_path[MAX_PATH] = {};
    if (!GetSystemDirectoryW(system_path, MAX_PATH)) {
        return 0.0;
    }
    if (system_path[0] == L'\0' || system_path[1] != L':') {
        return 0.0;
    }
    wchar_t root_path[4] = { system_path[0], system_path[1], L'\\', L'\0' };
    ULARGE_INTEGER total = {};
    if (!GetDiskFreeSpaceExW(root_path, nullptr, &total, nullptr)) {
        return 0.0;
    }
    return static_cast<double>(total.QuadPart) / (1024.0 * 1024.0 * 1024.0);
}

std::wstring GetLocaleNameSafe() {
    wchar_t locale[LOCALE_NAME_MAX_LENGTH] = {};
    if (GetUserDefaultLocaleName(locale, LOCALE_NAME_MAX_LENGTH)) {
        return std::wstring(locale);
    }
    wchar_t fallback[128] = {};
    if (GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SNAME, fallback, 128) > 0) {
        return std::wstring(fallback);
    }
    return L"";
}

std::wstring FormatUtcOffsetMinutes(LONG bias_minutes) {
    int offset = -static_cast<int>(bias_minutes);
    wchar_t sign = offset >= 0 ? L'+' : L'-';
    offset = abs(offset);
    int hours = offset / 60;
    int minutes = offset % 60;
    wchar_t buffer[16] = {};
    swprintf_s(buffer, L"UTC%c%02d:%02d", sign, hours, minutes);
    return std::wstring(buffer);
}

std::wstring GetTimezoneName() {
    TIME_ZONE_INFORMATION info = {};
    DWORD id = GetTimeZoneInformation(&info);
    LONG bias = info.Bias;
    if (id == TIME_ZONE_ID_DAYLIGHT) {
        bias += info.DaylightBias;
    } else if (id == TIME_ZONE_ID_STANDARD) {
        bias += info.StandardBias;
    }
    std::wstring name;
    if (id == TIME_ZONE_ID_DAYLIGHT && info.DaylightName[0]) {
        name = info.DaylightName;
    } else if (info.StandardName[0]) {
        name = info.StandardName;
    }
    std::wstring offset = FormatUtcOffsetMinutes(bias);
    if (!name.empty()) {
        return name + L" (" + offset + L")";
    }
    return offset;
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

struct TcpUrlParts {
    std::wstring host;
    std::wstring port;
    std::wstring path;
    bool use_tls = false;
};

namespace {
constexpr DWORD kTcpTimeoutMs = 15000;
constexpr uint32_t kTcpMaxResponseBytes = 50u * 1024u * 1024u;
std::once_flag g_winsock_once;
bool g_winsock_ready = false;

void InitWinsock() {
    WSADATA wsa = {};
    g_winsock_ready = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
}

bool EnsureWinsock(std::wstring* error) {
    std::call_once(g_winsock_once, InitWinsock);
    if (!g_winsock_ready) {
        if (error) {
            *error = L"Failed to initialize Winsock";
        }
        return false;
    }
    return true;
}

bool SendAll(SOCKET sock, const char* data, size_t size, std::wstring* error) {
    size_t sent_total = 0;
    while (sent_total < size) {
        int sent = send(sock, data + sent_total, static_cast<int>(size - sent_total), 0);
        if (sent == SOCKET_ERROR) {
            if (error) {
                DWORD win_error = WSAGetLastError();
                wchar_t buf[256];
                swprintf_s(buf, L"Socket send failed (err: %lu)", win_error);
                *error = buf;
            }
            return false;
        }
        if (sent == 0) {
            break;
        }
        sent_total += static_cast<size_t>(sent);
    }
    return sent_total == size;
}

bool RecvAll(SOCKET sock, char* data, size_t size, std::wstring* error) {
    size_t received_total = 0;
    while (received_total < size) {
        int received = recv(sock, data + received_total, static_cast<int>(size - received_total), 0);
        if (received == SOCKET_ERROR) {
            if (error) {
                DWORD win_error = WSAGetLastError();
                wchar_t buf[256];
                swprintf_s(buf, L"Socket receive failed (err: %lu)", win_error);
                *error = buf;
            }
            return false;
        }
        if (received == 0) {
            if (error) {
                *error = L"Connection closed unexpectedly";
            }
            return false;
        }
        received_total += static_cast<size_t>(received);
    }
    return true;
}

struct TlsConnection {
    SOCKET sock = INVALID_SOCKET;
    CredHandle cred = {};
    CtxtHandle ctxt = {};
    SecPkgContext_StreamSizes sizes = {};
    bool ready = false;
    std::vector<char> enc_buffer;
    std::vector<char> dec_buffer;
    size_t dec_offset = 0;
};

bool RecvSome(SOCKET sock, std::vector<char>* buffer, std::wstring* error) {
    char temp[4096];
    int received = recv(sock, temp, sizeof(temp), 0);
    if (received == SOCKET_ERROR) {
        if (error) {
            DWORD win_error = WSAGetLastError();
            wchar_t buf[256];
            swprintf_s(buf, L"Socket receive failed (err: %lu)", win_error);
            *error = buf;
        }
        return false;
    }
    if (received == 0) {
        if (error) {
            *error = L"Connection closed unexpectedly";
        }
        return false;
    }
    buffer->insert(buffer->end(), temp, temp + received);
    return true;
}

bool VerifyServerThumbprint(PCCERT_CONTEXT cert, const std::wstring& expected_thumbprint, std::wstring* error) {
    if (expected_thumbprint.empty()) {
        return true;
    }

    BYTE hash[32] = {};
    DWORD hash_size = sizeof(hash);
    DWORD prop_id = CERT_SHA256_HASH_PROP_ID;
    if (!CertGetCertificateContextProperty(cert, prop_id, hash, &hash_size)) {
        prop_id = CERT_SHA1_HASH_PROP_ID;
        hash_size = sizeof(hash);
        if (!CertGetCertificateContextProperty(cert, prop_id, hash, &hash_size)) {
            if (error) {
                *error = L"Failed to read certificate hash";
            }
            return false;
        }
    }

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

bool TlsHandshake(SOCKET sock,
                  const std::wstring& host,
                  const std::wstring& expected_thumbprint,
                  TlsConnection* out,
                  std::wstring* error) {
    if (!out) {
        return false;
    }
    if (expected_thumbprint.empty()) {
        if (error) {
            *error = L"Missing TLS thumbprint";
        }
        return false;
    }

    bool manual_validation = !expected_thumbprint.empty();
    SCHANNEL_CRED cred = {};
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.dwFlags = SCH_USE_STRONG_CRYPTO;
    if (manual_validation) {
        cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;
    }

    TimeStamp expiry = {};
    SECURITY_STATUS status = AcquireCredentialsHandleW(
        nullptr,
        const_cast<wchar_t*>(UNISP_NAME),
        SECPKG_CRED_OUTBOUND,
        nullptr,
        &cred,
        nullptr,
        nullptr,
        &out->cred,
        &expiry);
    if (status != SEC_E_OK) {
        if (error) {
            *error = L"TLS credential initialization failed";
        }
        return false;
    }

    DWORD ctx_req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                    ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    if (manual_validation) {
        ctx_req |= ISC_REQ_MANUAL_CRED_VALIDATION;
    }
    DWORD ctx_attr = 0;

    SecBuffer out_buffer = {};
    out_buffer.BufferType = SECBUFFER_TOKEN;
    SecBufferDesc out_desc = {};
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buffer;

    status = InitializeSecurityContextW(
        &out->cred,
        nullptr,
        host.empty() ? nullptr : const_cast<wchar_t*>(host.c_str()),
        ctx_req,
        0,
        0,
        nullptr,
        0,
        &out->ctxt,
        &out_desc,
        &ctx_attr,
        nullptr);

    if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
        if (error) {
            *error = L"TLS handshake failed";
        }
        FreeCredentialsHandle(&out->cred);
        return false;
    }

    if (out_buffer.cbBuffer && out_buffer.pvBuffer) {
        bool sent = SendAll(sock, reinterpret_cast<const char*>(out_buffer.pvBuffer), out_buffer.cbBuffer, error);
        FreeContextBuffer(out_buffer.pvBuffer);
        out_buffer.pvBuffer = nullptr;
        if (!sent) {
            FreeCredentialsHandle(&out->cred);
            return false;
        }
    }

    std::vector<char> in_buffer;
    while (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE ||
           status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
        if (status == SEC_E_INCOMPLETE_MESSAGE || in_buffer.empty()) {
            if (!RecvSome(sock, &in_buffer, error)) {
                DeleteSecurityContext(&out->ctxt);
                FreeCredentialsHandle(&out->cred);
                return false;
            }
        }

        SecBuffer in_buffers[2] = {};
        in_buffers[0].BufferType = SECBUFFER_TOKEN;
        in_buffers[0].pvBuffer = in_buffer.data();
        in_buffers[0].cbBuffer = static_cast<ULONG>(in_buffer.size());
        in_buffers[1].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc in_desc = {};
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 2;
        in_desc.pBuffers = in_buffers;

        out_buffer = {};
        out_buffer.BufferType = SECBUFFER_TOKEN;
        out_desc.pBuffers = &out_buffer;
        out_desc.cBuffers = 1;

        status = InitializeSecurityContextW(
            &out->cred,
            &out->ctxt,
            host.empty() ? nullptr : const_cast<wchar_t*>(host.c_str()),
            ctx_req,
            0,
            0,
            &in_desc,
            0,
            &out->ctxt,
            &out_desc,
            &ctx_attr,
            nullptr);

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            continue;
        }

        if (status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
            if (CompleteAuthToken(&out->ctxt, &out_desc) != SEC_E_OK) {
                if (error) {
                    *error = L"TLS handshake failed";
                }
                DeleteSecurityContext(&out->ctxt);
                FreeCredentialsHandle(&out->cred);
                return false;
            }
        }

        if (out_buffer.cbBuffer && out_buffer.pvBuffer) {
            bool sent = SendAll(sock, reinterpret_cast<const char*>(out_buffer.pvBuffer), out_buffer.cbBuffer, error);
            FreeContextBuffer(out_buffer.pvBuffer);
            out_buffer.pvBuffer = nullptr;
            if (!sent) {
                DeleteSecurityContext(&out->ctxt);
                FreeCredentialsHandle(&out->cred);
                return false;
            }
        }

        if (status == SEC_E_OK) {
            if (in_buffers[1].BufferType == SECBUFFER_EXTRA && in_buffers[1].cbBuffer > 0) {
                size_t extra = in_buffers[1].cbBuffer;
                out->enc_buffer.assign(in_buffer.end() - extra, in_buffer.end());
            }
            break;
        }

        if (status != SEC_I_CONTINUE_NEEDED && status != SEC_I_COMPLETE_AND_CONTINUE) {
            if (error) {
                *error = L"TLS handshake failed";
            }
            DeleteSecurityContext(&out->ctxt);
            FreeCredentialsHandle(&out->cred);
            return false;
        }

        if (in_buffers[1].BufferType == SECBUFFER_EXTRA && in_buffers[1].cbBuffer > 0) {
            size_t extra = in_buffers[1].cbBuffer;
            std::vector<char> leftover(in_buffer.end() - extra, in_buffer.end());
            in_buffer.swap(leftover);
        } else {
            in_buffer.clear();
        }
    }

    if (status != SEC_E_OK) {
        if (error) {
            *error = L"TLS handshake failed";
        }
        DeleteSecurityContext(&out->ctxt);
        FreeCredentialsHandle(&out->cred);
        return false;
    }

    PCCERT_CONTEXT cert = nullptr;
    if (QueryContextAttributes(&out->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert) == SEC_E_OK && cert) {
        bool ok = VerifyServerThumbprint(cert, expected_thumbprint, error);
        CertFreeCertificateContext(cert);
        if (!ok) {
            DeleteSecurityContext(&out->ctxt);
            FreeCredentialsHandle(&out->cred);
            return false;
        }
    } else if (!expected_thumbprint.empty()) {
        if (error) {
            *error = L"Failed to read server certificate";
        }
        DeleteSecurityContext(&out->ctxt);
        FreeCredentialsHandle(&out->cred);
        return false;
    }

    if (QueryContextAttributes(&out->ctxt, SECPKG_ATTR_STREAM_SIZES, &out->sizes) != SEC_E_OK) {
        if (error) {
            *error = L"TLS stream initialization failed";
        }
        DeleteSecurityContext(&out->ctxt);
        FreeCredentialsHandle(&out->cred);
        return false;
    }

    out->sock = sock;
    out->ready = true;
    return true;
}

bool TlsSendAll(TlsConnection* conn, const char* data, size_t size, std::wstring* error) {
    if (!conn || !conn->ready) {
        return false;
    }
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = size - offset;
        if (chunk > conn->sizes.cbMaximumMessage) {
            chunk = conn->sizes.cbMaximumMessage;
        }
        std::vector<char> buffer(conn->sizes.cbHeader + chunk + conn->sizes.cbTrailer);
        memcpy(buffer.data() + conn->sizes.cbHeader, data + offset, chunk);

        SecBuffer buffers[4] = {};
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = buffer.data();
        buffers[0].cbBuffer = conn->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = buffer.data() + conn->sizes.cbHeader;
        buffers[1].cbBuffer = static_cast<ULONG>(chunk);
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = buffer.data() + conn->sizes.cbHeader + chunk;
        buffers[2].cbBuffer = conn->sizes.cbTrailer;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc = {};
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;

        SECURITY_STATUS status = EncryptMessage(&conn->ctxt, 0, &desc, 0);
        if (status != SEC_E_OK) {
            if (error) {
                *error = L"TLS encrypt failed";
            }
            return false;
        }

        size_t to_send = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        if (!SendAll(conn->sock, buffer.data(), to_send, error)) {
            return false;
        }
        offset += chunk;
    }
    return true;
}

bool TlsFillDecrypted(TlsConnection* conn, std::wstring* error) {
    if (!conn || !conn->ready) {
        return false;
    }

    while (conn->dec_buffer.empty()) {
        if (conn->enc_buffer.empty()) {
            if (!RecvSome(conn->sock, &conn->enc_buffer, error)) {
                return false;
            }
        }

        SecBuffer buffers[4] = {};
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[0].pvBuffer = conn->enc_buffer.data();
        buffers[0].cbBuffer = static_cast<ULONG>(conn->enc_buffer.size());
        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc = {};
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;

        SECURITY_STATUS status = DecryptMessage(&conn->ctxt, &desc, 0, nullptr);
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            if (!RecvSome(conn->sock, &conn->enc_buffer, error)) {
                return false;
            }
            continue;
        }
        if (status == SEC_I_CONTEXT_EXPIRED) {
            if (error) {
                *error = L"TLS connection closed";
            }
            return false;
        }
        if (status == SEC_I_RENEGOTIATE) {
            if (error) {
                *error = L"TLS renegotiation not supported";
            }
            return false;
        }
        if (status != SEC_E_OK) {
            if (error) {
                *error = L"TLS decrypt failed";
            }
            return false;
        }

        for (int i = 0; i < 4; ++i) {
            if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].cbBuffer > 0) {
                char* data = reinterpret_cast<char*>(buffers[i].pvBuffer);
                conn->dec_buffer.insert(conn->dec_buffer.end(), data, data + buffers[i].cbBuffer);
            }
        }

        size_t extra = 0;
        for (int i = 0; i < 4; ++i) {
            if (buffers[i].BufferType == SECBUFFER_EXTRA && buffers[i].cbBuffer > 0) {
                extra = buffers[i].cbBuffer;
                break;
            }
        }
        if (extra > 0) {
            std::vector<char> leftover(conn->enc_buffer.end() - extra, conn->enc_buffer.end());
            conn->enc_buffer.swap(leftover);
        } else {
            conn->enc_buffer.clear();
        }
    }

    conn->dec_offset = 0;
    return true;
}

bool TlsRecvAll(TlsConnection* conn, char* data, size_t size, std::wstring* error) {
    if (!conn || !conn->ready) {
        return false;
    }
    size_t received = 0;
    while (received < size) {
        if (conn->dec_buffer.empty() || conn->dec_offset >= conn->dec_buffer.size()) {
            conn->dec_buffer.clear();
            conn->dec_offset = 0;
            if (!TlsFillDecrypted(conn, error)) {
                return false;
            }
        }
        size_t available = conn->dec_buffer.size() - conn->dec_offset;
        size_t take = size - received;
        if (take > available) {
            take = available;
        }
        memcpy(data + received, conn->dec_buffer.data() + conn->dec_offset, take);
        conn->dec_offset += take;
        received += take;
    }
    return true;
}

void TlsClose(TlsConnection* conn) {
    if (!conn || !conn->ready) {
        return;
    }

    DWORD shutdown = SCHANNEL_SHUTDOWN;
    SecBuffer in_buffer = {};
    in_buffer.BufferType = SECBUFFER_TOKEN;
    in_buffer.pvBuffer = &shutdown;
    in_buffer.cbBuffer = sizeof(shutdown);

    SecBufferDesc in_desc = {};
    in_desc.ulVersion = SECBUFFER_VERSION;
    in_desc.cBuffers = 1;
    in_desc.pBuffers = &in_buffer;
    ApplyControlToken(&conn->ctxt, &in_desc);

    SecBuffer out_buffer = {};
    out_buffer.BufferType = SECBUFFER_TOKEN;
    SecBufferDesc out_desc = {};
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buffer;
    DWORD ctx_attr = 0;

    if (InitializeSecurityContextW(&conn->cred, &conn->ctxt, nullptr, 0, 0, 0, nullptr, 0, &conn->ctxt, &out_desc, &ctx_attr, nullptr) == SEC_E_OK) {
        if (out_buffer.cbBuffer && out_buffer.pvBuffer) {
            SendAll(conn->sock, reinterpret_cast<const char*>(out_buffer.pvBuffer), out_buffer.cbBuffer, nullptr);
            FreeContextBuffer(out_buffer.pvBuffer);
            out_buffer.pvBuffer = nullptr;
        }
    }

    DeleteSecurityContext(&conn->ctxt);
    FreeCredentialsHandle(&conn->cred);
    conn->ready = false;
}
} // namespace

bool ParseTcpUrl(const std::wstring& url, TcpUrlParts* out, std::wstring* error) {
    if (!out) {
        return false;
    }
    std::wstring input = url;
    size_t scheme_pos = input.find(L"://");
    if (scheme_pos == std::wstring::npos) {
        if (error) {
            *error = L"TLS required";
        }
        return false;
    }
    std::wstring scheme = ToLowerString(input.substr(0, scheme_pos));
    if (scheme != L"tcps" && scheme != L"tls") {
        if (error) {
            *error = L"TLS required";
        }
        return false;
    }
    size_t start = scheme_pos + 3;
    bool use_tls = true;

    size_t path_pos = input.find(L'/', start);
    std::wstring hostport = path_pos == std::wstring::npos ? input.substr(start) : input.substr(start, path_pos - start);
    std::wstring path = path_pos == std::wstring::npos ? L"/" : input.substr(path_pos);
    if (path.size() > 1 && path[0] == L'/' && path[1] == L'/') {
        path.erase(path.begin());
    }
    if (hostport.empty()) {
        if (error) {
            *error = L"Missing host";
        }
        return false;
    }

    std::wstring host;
    std::wstring port;
    if (!hostport.empty() && hostport.front() == L'[') {
        size_t end = hostport.find(L']');
        if (end == std::wstring::npos) {
            if (error) {
                *error = L"Invalid IPv6 host";
            }
            return false;
        }
        host = hostport.substr(1, end - 1);
        if (end + 1 < hostport.size() && hostport[end + 1] == L':') {
            port = hostport.substr(end + 2);
        }
    } else {
        size_t colon = hostport.rfind(L':');
        if (colon == std::wstring::npos) {
            if (error) {
                *error = L"Missing port";
            }
            return false;
        }
        host = hostport.substr(0, colon);
        port = hostport.substr(colon + 1);
    }

    if (host.empty() || port.empty()) {
        if (error) {
            *error = L"Invalid host or port";
        }
        return false;
    }

    out->host = host;
    out->port = port;
    out->path = path.empty() ? L"/" : path;
    out->use_tls = use_tls;
    return true;
}

#if 0
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
#endif

bool HttpRequest(const std::wstring& method, const std::wstring& url, const std::string& body, std::string* response, std::wstring* error) {
    TcpUrlParts parts = {};
    if (!ParseTcpUrl(url, &parts, error)) {
        return false;
    }
    if (!EnsureWinsock(error)) {
        return false;
    }

    addrinfoW hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfoW* results = nullptr;
    if (GetAddrInfoW(parts.host.c_str(), parts.port.c_str(), &hints, &results) != 0) {
        if (error) {
            DWORD win_error = WSAGetLastError();
            wchar_t buf[256];
            swprintf_s(buf, L"Failed to resolve %s:%s (err: %lu)", parts.host.c_str(), parts.port.c_str(), win_error);
            *error = buf;
        }
        return false;
    }

    SOCKET sock = INVALID_SOCKET;
    for (addrinfoW* ptr = results; ptr != nullptr; ptr = ptr->ai_next) {
        sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }
        DWORD timeout = kTcpTimeoutMs;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        if (connect(sock, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == SOCKET_ERROR) {
            closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        break;
    }
    FreeAddrInfoW(results);

    if (sock == INVALID_SOCKET) {
        if (error) {
            *error = L"Failed to connect to server";
        }
        return false;
    }

    TlsConnection tls = {};
    if (parts.use_tls) {
        if (!TlsHandshake(sock, parts.host, g_config.expected_thumbprint, &tls, error)) {
            closesocket(sock);
            return false;
        }
    }

    std::string request_line = WideToUtf8(method) + " " + WideToUtf8(parts.path) + "\n";
    std::string headers = "User-Agent: " + WideToUtf8(g_config.user_agent) + "\n";
    std::string payload = request_line + headers + "\n" + body;
    uint32_t payload_size = static_cast<uint32_t>(payload.size());
    uint32_t payload_size_net = htonl(payload_size);

    auto send_all = [&](const char* data_ptr, size_t size) -> bool {
        if (parts.use_tls) {
            return TlsSendAll(&tls, data_ptr, size, error);
        }
        return SendAll(sock, data_ptr, size, error);
    };

    auto recv_all = [&](char* data_ptr, size_t size) -> bool {
        if (parts.use_tls) {
            return TlsRecvAll(&tls, data_ptr, size, error);
        }
        return RecvAll(sock, data_ptr, size, error);
    };

    if (!send_all(reinterpret_cast<const char*>(&payload_size_net), sizeof(payload_size_net)) ||
        (payload_size > 0 && !send_all(payload.data(), payload.size()))) {
        if (parts.use_tls) {
            TlsClose(&tls);
        }
        closesocket(sock);
        return false;
    }

    uint32_t response_size_net = 0;
    if (!recv_all(reinterpret_cast<char*>(&response_size_net), sizeof(response_size_net))) {
        if (parts.use_tls) {
            TlsClose(&tls);
        }
        closesocket(sock);
        return false;
    }
    uint32_t response_size = ntohl(response_size_net);
    if (response_size > kTcpMaxResponseBytes) {
        if (parts.use_tls) {
            TlsClose(&tls);
        }
        closesocket(sock);
        if (error) {
            *error = L"Response too large";
        }
        return false;
    }

    std::string out;
    out.resize(response_size);
    if (response_size > 0 && !recv_all(out.data(), response_size)) {
        if (parts.use_tls) {
            TlsClose(&tls);
        }
        closesocket(sock);
        return false;
    }

    if (parts.use_tls) {
        TlsClose(&tls);
    }
    closesocket(sock);

    if (response) {
        *response = std::move(out);
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

void AppendDeviceInfoFields(std::string* body) {
    if (!body) {
        return;
    }
    std::string cpu = WideToUtf8(GetCpuName());
    std::string gpu = WideToUtf8(GetGpuName());
    std::string build = WideToUtf8(GetWindowsBuild());
    std::string os = WideToUtf8(GetOsVersion());
    std::string name = WideToUtf8(GetComputerNameSafe());
    std::string arch = WideToUtf8(GetArchName());
    int cores = GetCpuCoreCount();
    double ram_gb = GetTotalRamGb();
    double disk_gb = GetSystemDiskGb();
    std::string locale = WideToUtf8(GetLocaleNameSafe());
    std::string timezone = WideToUtf8(GetTimezoneName());
    std::string bios = WideToUtf8(GetBiosSerial());
    std::string board = WideToUtf8(GetBaseBoardSerial());
    std::string smbios = WideToUtf8(GetSmbiosUuid());

    AppendJsonStringField(body, "device_cpu", cpu);
    AppendJsonStringField(body, "device_gpu", gpu);
    AppendJsonStringField(body, "device_build", build);
    AppendJsonStringField(body, "device_os", os);
    AppendJsonStringField(body, "device_name", name);
    AppendJsonStringField(body, "device_arch", arch);
    AppendJsonIntField(body, "device_cores", cores);
    AppendJsonNumberField(body, "device_ram_gb", ram_gb);
    AppendJsonNumberField(body, "device_disk_gb", disk_gb);
    AppendJsonStringField(body, "device_locale", locale);
    AppendJsonStringField(body, "device_timezone", timezone);
    AppendJsonStringField(body, "device_bios", bios);
    AppendJsonStringField(body, "device_board", board);
    AppendJsonStringField(body, "device_smbios", smbios);
}

void SendEvent(const std::wstring& server_url,
               const std::wstring& key,
               const std::string& hwid,
               const std::wstring& product_code,
               const std::string& event_type,
               const std::string& detail) {
    std::string key_utf8 = WideToUtf8(key);
    std::string code_utf8 = WideToUtf8(product_code);
    if (g_event_token.empty()) {
        return;
    }
    std::string body = "{\"key\":\"" + JsonEscape(key_utf8) + "\",\"hwid\":\"" + JsonEscape(hwid) +
        "\",\"type\":\"" + JsonEscape(event_type) + "\",\"product_code\":\"" + JsonEscape(code_utf8) +
        "\",\"detail\":\"" + JsonEscape(detail) + "\",\"token\":\"" + JsonEscape(g_event_token) + "\"";
    AppendDeviceInfoFields(&body);
    body += "}";
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

bool DecryptAes256Cbc(const std::vector<char>& input,
                      const std::vector<BYTE>& key,
                      const std::vector<BYTE>& iv,
                      std::vector<char>* out,
                      std::wstring* error) {
    if (key.size() != 32 || iv.size() != 16) {
        if (error) {
            *error = L"Invalid decryption key";
        }
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    DWORD obj_size = 0;
    DWORD obj_size_len = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        if (error) {
            *error = L"Crypto init failed";
        }
        return false;
    }

    status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        if (error) {
            *error = L"Crypto init failed";
        }
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_size), sizeof(obj_size), &obj_size_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        if (error) {
            *error = L"Crypto init failed";
        }
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    std::vector<BYTE> key_object(obj_size);
    status = BCryptGenerateSymmetricKey(alg, &key_handle, key_object.data(), obj_size,
                                        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        if (error) {
            *error = L"Crypto init failed";
        }
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    DWORD out_size = 0;
    status = BCryptDecrypt(key_handle,
                           reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                           static_cast<ULONG>(input.size()),
                           nullptr,
                           const_cast<PUCHAR>(iv.data()),
                           static_cast<ULONG>(iv.size()),
                           nullptr,
                           0,
                           &out_size,
                           BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        if (error) {
            *error = L"Decrypt failed";
        }
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    out->assign(out_size, 0);
    status = BCryptDecrypt(key_handle,
                           reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                           static_cast<ULONG>(input.size()),
                           nullptr,
                           const_cast<PUCHAR>(iv.data()),
                           static_cast<ULONG>(iv.size()),
                           reinterpret_cast<PUCHAR>(out->data()),
                           out_size,
                           &out_size,
                           BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        if (error) {
            *error = L"Decrypt failed";
        }
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    out->resize(out_size);

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
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

static bool IsLifetimeSeconds(ULONGLONG diff_seconds) {
    const ULONGLONG kLifetimeSeconds = 60ULL * 60 * 24 * 365 * 2;
    return diff_seconds >= kLifetimeSeconds;
}

bool IsLifetimeSubscription(const std::wstring& iso) {
    FILETIME expiry = {};
    if (!ParseIso8601Utc(iso, &expiry)) {
        return false;
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
        return false;
    }

    ULONGLONG diff_seconds = (expiry_val.QuadPart - now_val.QuadPart) / 10000000ULL;
    return IsLifetimeSeconds(diff_seconds);
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
    if (IsLifetimeSeconds(diff_seconds)) {
        return L"Lifetime";
    }
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
    value = FormatKeyDisplay(value);
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

void FillHorizontalGradient(HDC dc, const RECT& rc, COLORREF left, COLORREF right) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return;
    }
    TRIVERTEX verts[2] = {};
    verts[0].x = rc.left;
    verts[0].y = rc.top;
    verts[0].Red = static_cast<COLOR16>(GetRValue(left) << 8);
    verts[0].Green = static_cast<COLOR16>(GetGValue(left) << 8);
    verts[0].Blue = static_cast<COLOR16>(GetBValue(left) << 8);
    verts[0].Alpha = 0xFFFF;
    verts[1].x = rc.right;
    verts[1].y = rc.bottom;
    verts[1].Red = static_cast<COLOR16>(GetRValue(right) << 8);
    verts[1].Green = static_cast<COLOR16>(GetGValue(right) << 8);
    verts[1].Blue = static_cast<COLOR16>(GetBValue(right) << 8);
    verts[1].Alpha = 0xFFFF;
    GRADIENT_RECT gradient = {0, 1};
    GradientFill(dc, verts, 2, &gradient, 1, GRADIENT_FILL_RECT_H);
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

    HPEN grid = CreatePen(PS_SOLID, 1, RGB(20, 22, 28));
    HPEN old_pen = reinterpret_cast<HPEN>(SelectObject(dc, grid));
    int step = Scale(88);
    int height = rc.bottom - rc.top;
    for (int x = rc.left - height; x < rc.right; x += step) {
        MoveToEx(dc, x, rc.bottom, nullptr);
        LineTo(dc, x + height, rc.top);
    }
    SelectObject(dc, old_pen);
    DeleteObject(grid);
}

void DrawPanel(HDC dc, const RECT& rc) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return;
    }
    int radius = Scale(10);
    RECT shadow = rc;
    OffsetRect(&shadow, Scale(2), Scale(4));
    HRGN shadow_rgn = CreateRoundRectRgn(shadow.left, shadow.top, shadow.right + 1, shadow.bottom + 1, radius, radius);
    HBRUSH shadow_brush = CreateSolidBrush(RGB(8, 10, 14));
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

    RECT inner = rc;
    InflateRect(&inner, -1, -1);
    int inner_radius = max(0, radius - Scale(2));
    HRGN inner_rgn = CreateRoundRectRgn(inner.left, inner.top, inner.right + 1, inner.bottom + 1, inner_radius, inner_radius);
    HBRUSH inner_brush = CreateSolidBrush(RGB(16, 18, 22));
    FrameRgn(dc, inner_rgn, inner_brush, 1, 1);
    DeleteObject(inner_brush);
    DeleteObject(inner_rgn);

    int accent_inset = Scale(14);
    RECT accent = {rc.left + accent_inset, rc.top + Scale(3), rc.right - accent_inset, rc.top + Scale(5)};
    if (accent.right > accent.left && accent.bottom > accent.top) {
        FillHorizontalGradient(dc, accent, kAccentAlt, kAccentColor);
    }
    DeleteObject(rgn);
}

void DrawTableHeader(HDC dc, const RECT& rc) {
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return;
    }
    HBRUSH fill = CreateSolidBrush(kSurface);
    FillRect(dc, &rc, fill);
    DeleteObject(fill);

    HPEN line = CreatePen(PS_SOLID, 1, kSurfaceBorder);
    HPEN old_pen = reinterpret_cast<HPEN>(SelectObject(dc, line));
    MoveToEx(dc, rc.left, rc.bottom - 1, nullptr);
    LineTo(dc, rc.right, rc.bottom - 1);
    SelectObject(dc, old_pen);
    DeleteObject(line);

    RECT accent = {rc.left + Scale(12), rc.top + Scale(2), rc.right - Scale(12), rc.top + Scale(3)};
    FillHorizontalGradient(dc, accent, kAccentAlt, kAccentColor);
}

void DrawProgramCard(HDC dc, const RECT& item, const ProgramInfo& program, bool selected, int index) {
    RECT card = item;
    int pad_x = Scale(10);
    int pad_y = Scale(6);
    card.left += pad_x;
    card.right -= pad_x;
    card.top += pad_y / 2;
    card.bottom -= pad_y / 2;

    COLORREF fill = selected ? kRowSelected : ((index % 2 == 0) ? kRowEven : kRowOdd);
    COLORREF border = selected ? kAccentAlt : kSurfaceBorder;

    int radius = Scale(8);
    HRGN card_rgn = CreateRoundRectRgn(card.left, card.top, card.right + 1, card.bottom + 1, radius, radius);
    HBRUSH fill_brush = CreateSolidBrush(fill);
    FillRgn(dc, card_rgn, fill_brush);
    DeleteObject(fill_brush);
    HBRUSH border_brush = CreateSolidBrush(border);
    FrameRgn(dc, card_rgn, border_brush, 1, 1);
    DeleteObject(border_brush);

    COLORREF accent_left = selected ? kAccentAlt : kSurfaceBorder;
    COLORREF accent_right = selected ? kAccentColor : kSurfaceBorder;
    RECT top_line = {card.left + Scale(10), card.top + Scale(2), card.right - Scale(10), card.top + Scale(3)};
    FillHorizontalGradient(dc, top_line, accent_left, accent_right);

    COLORREF status_color = GetStatusColor(program.status);
    RECT bar = {card.left + Scale(4), card.top + Scale(6), card.left + Scale(7), card.bottom - Scale(6)};
    HBRUSH bar_brush = CreateSolidBrush(status_color);
    FillRect(dc, &bar, bar_brush);
    DeleteObject(bar_brush);

    int card_height = card.bottom - card.top;
    int avatar_size = min(Scale(48), card_height - Scale(12));
    if (avatar_size < Scale(30)) {
        avatar_size = max(Scale(22), card_height - Scale(8));
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

    int text_top = card.top + Scale(8);
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
    DeleteObject(card_rgn);
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

    RECT accent = {rc.left + Scale(18), rc.bottom - Scale(3), rc.right - Scale(18), rc.bottom - Scale(2)};
    FillHorizontalGradient(dc, accent, kAccentAlt, kAccentColor);
}

void DrawTitleButton(HDC dc, const RECT& rc, bool hover, bool pressed, bool is_close) {
    if (hover || pressed) {
        HBRUSH brush = CreateSolidBrush(pressed ? kButtonPressed : kButtonHover);
        FillRect(dc, &rc, brush);
        DeleteObject(brush);
    }

    COLORREF glyph = hover && is_close ? RGB(255, 110, 110) : kTextColor;
    int stroke = max(1, Scale(1));
    HPEN pen = CreatePen(PS_SOLID, stroke, glyph);
    HPEN old_pen = reinterpret_cast<HPEN>(SelectObject(dc, pen));
    int pad = Scale(9);
    if (is_close) {
        MoveToEx(dc, rc.left + pad, rc.top + pad, nullptr);
        LineTo(dc, rc.right - pad, rc.bottom - pad);
        MoveToEx(dc, rc.right - pad, rc.top + pad, nullptr);
        LineTo(dc, rc.left + pad, rc.bottom - pad);
    } else {
        int y = (rc.top + rc.bottom) / 2;
        MoveToEx(dc, rc.left + pad, y, nullptr);
        LineTo(dc, rc.right - pad, y);
    }
    SelectObject(dc, old_pen);
    DeleteObject(pen);
}

int GetButtonCornerRadius(const RECT& rc, bool use_dx);

void DrawButtonSurface(HDC dc, const RECT& rc, COLORREF top, COLORREF bottom, COLORREF border) {
    int radius = GetButtonCornerRadius(rc, g_dx_ui != nullptr);
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
    RECT inner = rc;
    InflateRect(&inner, -1, -1);
    int inner_radius = max(0, radius - Scale(2));
    HRGN inner_rgn = CreateRoundRectRgn(inner.left, inner.top, inner.right + 1, inner.bottom + 1, inner_radius, inner_radius);
    HBRUSH inner_brush = CreateSolidBrush(RGB(16, 18, 22));
    FrameRgn(dc, inner_rgn, inner_brush, 1, 1);
    DeleteObject(inner_brush);
    DeleteObject(inner_rgn);
    DeleteObject(rgn);
}

void AddRoundedRectPath(Gdiplus::GraphicsPath* path, const Gdiplus::RectF& rect, float radius) {
    if (!path) {
        return;
    }
    float diameter = radius * 2.0f;
    if (diameter <= 0.0f) {
        path->AddRectangle(rect);
        return;
    }
    Gdiplus::RectF arc(rect.X, rect.Y, diameter, diameter);
    path->AddArc(arc, 180.0f, 90.0f);
    arc.X = rect.GetRight() - diameter;
    path->AddArc(arc, 270.0f, 90.0f);
    arc.Y = rect.GetBottom() - diameter;
    path->AddArc(arc, 0.0f, 90.0f);
    arc.X = rect.X;
    path->AddArc(arc, 90.0f, 90.0f);
    path->CloseFigure();
}

COLORREF BlendColor(COLORREF base, COLORREF overlay, float alpha) {
    if (alpha <= 0.0f) {
        return base;
    }
    if (alpha >= 1.0f) {
        return overlay;
    }
    auto blend = [alpha](int b, int o) -> BYTE {
        return static_cast<BYTE>(b + static_cast<int>((o - b) * alpha));
    };
    return RGB(blend(GetRValue(base), GetRValue(overlay)),
               blend(GetGValue(base), GetGValue(overlay)),
               blend(GetBValue(base), GetBValue(overlay)));
}

bool IsInjectableStatus(const std::wstring& status) {
    std::wstring s = ToLowerString(status);
    return (s == L"safe" || s == L"risky");
}

COLORREF GetStatusColor(const std::wstring& status) {
    std::wstring s = ToLowerString(status);
    if (s.find(L"ready") != std::wstring::npos || s.find(L"safe") != std::wstring::npos) {
        return RGB(88, 220, 148);
    }
    if (s.find(L"risky") != std::wstring::npos || s.find(L"risk") != std::wstring::npos) {
        return RGB(248, 158, 84);
    }
    if (s.find(L"updat") != std::wstring::npos) {
        return RGB(244, 210, 90);
    }
    if (s.find(L"off") != std::wstring::npos ||
        s.find(L"down") != std::wstring::npos ||
        s.find(L"disable") != std::wstring::npos) {
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

int GetButtonCornerRadius(const RECT& rc, bool use_dx) {
    if (!use_dx) {
        return Scale(10);
    }
    int height = rc.bottom - rc.top;
    int radius = Scale(12);
    if (height > 0) {
        radius = (std::min)(radius, height / 2);
    }
    return radius;
}

void SetButtonRoundedRegion(HWND hwnd, bool use_dx) {
    if (!hwnd) {
        return;
    }
    RECT rc = {};
    GetClientRect(hwnd, &rc);
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return;
    }
    SetRoundedRegion(hwnd, GetButtonCornerRadius(rc, use_dx));
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
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

constexpr int kKeyGroupSize = 8;

bool IsKeyChar(wchar_t ch) {
    return (ch >= L'0' && ch <= L'9') ||
           (ch >= L'A' && ch <= L'Z') ||
           (ch >= L'a' && ch <= L'z');
}

std::wstring NormalizeKeyWide(const std::wstring& input) {
    std::wstring out;
    out.reserve(input.size());
    for (wchar_t ch : input) {
        if (IsKeyChar(ch)) {
            out.push_back(static_cast<wchar_t>(std::towupper(ch)));
        }
    }
    return out;
}

std::wstring FormatKeyDisplay(const std::wstring& input) {
    std::wstring normalized = NormalizeKeyWide(input);
    if (normalized.empty()) {
        return normalized;
    }
    std::wstring out;
    out.reserve(normalized.size() + normalized.size() / kKeyGroupSize);
    for (size_t i = 0; i < normalized.size(); ++i) {
        if (i > 0 && (i % kKeyGroupSize) == 0) {
            out.push_back(L'-');
        }
        out.push_back(normalized[i]);
    }
    return out;
}

int CountKeyChars(const std::wstring& input, size_t up_to) {
    size_t limit = (std::min)(up_to, input.size());
    int count = 0;
    for (size_t i = 0; i < limit; ++i) {
        if (IsKeyChar(input[i])) {
            ++count;
        }
    }
    return count;
}

int MapKeyIndexToFormatted(int key_index, int total_key_chars) {
    if (total_key_chars <= 0) {
        return 0;
    }
    key_index = (std::max)(0, (std::min)(key_index, total_key_chars));
    int dashes = key_index / kKeyGroupSize;
    if (key_index == total_key_chars && (total_key_chars % kKeyGroupSize) == 0) {
        dashes = (std::max)(0, dashes - 1);
    }
    return key_index + dashes;
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
    int size = Scale(56);
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
    int size = Scale(56);
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
    g_products_scroll = 0;
    g_hover_product_index = -1;
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
    g_products_scroll = 0;
    g_hover_product_index = -1;
    if (g_list) {
        ListView_DeleteAllItems(g_list);
    }
}

void UpdateButtonText() {
    if (!g_button) {
        return;
    }
    if (g_stage == UiStage::Login) {
        SetWindowTextW(g_button, g_dx_ui ? L"AUTHENTICATE" : L"Activate key");
    } else if (g_dx_ui && g_stage == UiStage::Loading) {
        SetWindowTextW(g_button, L"Loading");
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
    bool dx_loading = loading && g_dx_ui;
    bool dashboard_like = dashboard || dx_loading;
    g_validated = dashboard_like;
    g_hover_product_index = -1;
    ShowWindow(g_label_key, login ? SW_SHOW : SW_HIDE);
    ShowWindow(g_edit, login ? SW_SHOW : SW_HIDE);
    if (g_label_programs) {
        if (login) {
            SetWindowTextW(g_label_programs, L"Status");
        } else if (connecting) {
            SetWindowTextW(g_label_programs, g_dx_ui ? L"INITIALIZING" : L"Connecting");
        } else if (loading) {
            SetWindowTextW(g_label_programs, g_dx_ui ? L"LOADING" : L"Loader");
        } else {
            SetWindowTextW(g_label_programs, L"Builds");
        }
        ShowWindow(g_label_programs, SW_SHOW);
    }
    ShowWindow(g_label_col_program, SW_HIDE);
    ShowWindow(g_label_col_updated, SW_HIDE);
    ShowWindow(g_label_col_expires, SW_HIDE);
    ShowWindow(g_list, (dashboard && !g_dx_ui) ? SW_SHOW : SW_HIDE);
    bool show_button = (!g_dx_ui && (login || dashboard_like));
    ShowWindow(g_button, show_button ? SW_SHOW : SW_HIDE);
    if (g_button && !show_button) {
        SendMessageW(g_button, BM_SETSTATE, FALSE, 0);
        g_dx_button_pressed = false;
    }
    g_status_anim_tick = 0;
    if (!connecting && !loading && !g_status_base.empty()) {
        EnterCriticalSection(&g_status_lock);
        g_status_text = g_status_base;
        LeaveCriticalSection(&g_status_lock);
        PostMessageW(g_hwnd, kMsgUpdateStatus, 0, 0);
    }
    if (connecting || loading) {
        if (g_dx_ui) {
            if (g_status_hwnd) {
                ShowWindow(g_status_hwnd, SW_HIDE);
            }
            ShowWindow(g_hwnd, SW_SHOW);
            CenterWindow(g_hwnd);
        } else {
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
        }
    } else {
        if (g_status_hwnd) {
            ShowWindow(g_status_hwnd, SW_HIDE);
        }
        ShowWindow(g_hwnd, SW_SHOW);
        CenterWindow(g_hwnd);
    }
    UpdateButtonText();
    if (g_hwnd) {
    if (login || dashboard_like) {
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
    if (g_dx_ui && g_button && (g_stage == UiStage::Dashboard || g_stage == UiStage::Loading)) {
        std::wstring lower = ToLowerString(text);
        const wchar_t* label = L"Load";
        if (lower.find(L"waiting") != std::wstring::npos) {
            label = L"Waiting for game";
        } else if (g_stage == UiStage::Loading) {
            label = L"Loading";
        }
        SetWindowTextW(g_button, label);
        SetButtonRoundedRegion(g_button, g_dx_ui != nullptr);
        InvalidateRect(g_button, nullptr, g_dx_ui ? FALSE : TRUE);
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
        std::wstring normalized_key = NormalizeKeyWide(key);
        if (normalized_key.empty()) {
            SetStatus(hwnd, L"Enter a key first");
            SetStage(UiStage::Login);
            EnableButton(true);
            return 0;
        }
        key = FormatKeyDisplay(normalized_key);
        // Дополнительная проверка на отладчик перед валидацией (ВРЕМЕННО ОТКЛЮЧЕНА)
        // ANTI_CRACK_CHECK(anti_debug::IsDebuggerDetected());

        int validate_attempts = 0;
        EnterCriticalSection(&g_status_lock);
        g_last_error_code.clear();
        LeaveCriticalSection(&g_status_lock);
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
        
        // Формируем JSON с флагами валидации
        std::string flags_json = "[";
        for (size_t i = 0; i < hwid_validation.flags.size(); i++) {
            if (i > 0) flags_json += ",";
            flags_json += "\"" + JsonEscape(hwid_validation.flags[i]) + "\"";
        }
        flags_json += "]";
        
        std::string body = "{\"key\":\"" + JsonEscape(key_utf8) + "\",\"hwid\":\"" + JsonEscape(hwid) +
            "\",\"version\":\"" + std::string(kLoaderVersion) + "\"";
        AppendDeviceInfoFields(&body);
        body += ",\"hwid_score\":" + std::to_string(hwid_validation.suspicion_score) +
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
        EnterCriticalSection(&g_status_lock);
        g_last_error_code = ok ? std::string() : error_code;
        LeaveCriticalSection(&g_status_lock);
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
                    message = L"An unknown error occured: D2000011/D2000012"; // Invalid key
                } else if (error_code == "expired") {
                    message = L"An unknown error occured: D2000011/D2000013"; // Subscription expired
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
    std::string hwid_event = BuildHwid();
    auto log_event = [&](const std::string& type, const std::string& detail) {
        if (!g_cached_key.empty() && !hwid_event.empty()) {
            SendEvent(g_config.server_url, g_cached_key, hwid_event, program.code, type, detail);
        }
    };
    
    // Сначала находим процесс игры для сбора информации
    SetStatus(hwnd, L"Waiting for game");
    Sleep(RandomDelayMs(500, 1000));
    
    DWORD target_pid = injector::WaitForProcessId(g_config.target_process);
    if (target_pid == 0) {
        return fail_dashboard(L"An unknown error occured: D1000009/D1000009"); // Target process not found
    }
    
    // Собираем информацию о процессе для защиты
    SetStatus(hwnd, L"Analyzing process...");
    process_info::ProcessInfo proc_info = {};
    if (!process_info::CollectProcessInfo(target_pid, &proc_info)) {
        log_event("process_info_fail", "failed_to_collect");
        return fail_dashboard(L"An unknown error occured: D1000014/D1000014"); // Failed to collect process info
    }
    
    // Отправляем информацию на сервер для получения уникальной DLL
    SetStatus(hwnd, L"Requesting secure build...");
    std::string process_info_json = process_info::ProcessInfoToJson(proc_info);
    
    // Проверяем наличие event_token
    if (g_event_token.empty()) {
        log_event("request_dll_fail", "missing_event_token");
        return fail_dashboard(L"An unknown error occured: D1000028/D1000028"); // Missing event token
    }
    
    // Формируем запрос на сервер
    std::string request_body = "{\"token\":\"" + JsonEscape(g_event_token) + 
                               "\",\"product_code\":\"" + JsonEscape(WideToUtf8(program.code)) +
                               "\",\"process_info\":" + process_info_json + "}";
    
    std::string response;
    std::wstring error;
    std::wstring request_url = g_config.server_url + L"/request-dll";
    
    if (!HttpRequest(L"POST", request_url, request_body, &response, &error)) {
        log_event("request_dll_fail", WideToUtf8(error));
        return fail_dashboard(L"An unknown error occured: D1000015/D1000015"); // Failed to request DLL
    }
    
    // Парсим ответ - получаем уникальный URL для скачивания
    std::string dll_url_utf8;
    std::string dll_sha256;
    std::string dll_key_b64;
    std::string dll_iv_b64;
    std::string dll_alg;
    bool ok = false;
    
    // Сначала пытаемся получить ok
    JsonGetBoolTopLevel(response, "ok", &ok);
    
        if (!ok) {
            std::string error_msg;
            JsonGetStringTopLevel(response, "error", &error_msg);
            log_event("request_dll_fail", error_msg.empty() ? "invalid_response" : error_msg);
        
        // Показываем более информативное сообщение об ошибке
        if (error_msg == "invalid_token") {
            return fail_dashboard(L"An unknown error occured: D1000020/D1000020"); // Invalid token
        } else if (error_msg == "invalid_key") {
            return fail_dashboard(L"An unknown error occured: D1000021/D1000021"); // Invalid key
        } else if (error_msg == "hwid_mismatch") {
            return fail_dashboard(L"An unknown error occured: D1000022/D1000022"); // HWID mismatch
        } else if (error_msg == "expired") {
            return fail_dashboard(L"An unknown error occured: D1000023/D1000023"); // Expired
        } else if (error_msg == "missing_fields") {
            return fail_dashboard(L"An unknown error occured: D1000024/D1000024"); // Missing fields
        } else if (error_msg == "missing_payload") {
            return fail_dashboard(L"An unknown error occured: D1000025/D1000025"); // Missing payload
        } else if (error_msg == "protection_failed") {
            return fail_dashboard(L"An unknown error occured: D1000026/D1000026"); // Protection failed
        } else if (error_msg == "build_failed") {
            return fail_dashboard(L"An unknown error occured: D1000027/D1000027"); // Build failed
        } else if (error_msg == "status_blocked") {
            return fail_dashboard(L"An unknown error occured: D1000034/D1000034"); // Product status blocked
        }
        
        return fail_dashboard(L"An unknown error occured: D1000016/D1000016"); // Invalid server response
    }
    
    if (!JsonGetStringTopLevel(response, "dll_url", &dll_url_utf8) || 
        !JsonGetStringTopLevel(response, "dll_sha256", &dll_sha256)) {
        log_event("request_dll_fail", "missing_url_or_hash");
        return fail_dashboard(L"An unknown error occured: D1000017/D1000017"); // Missing DLL URL or hash
    }

    JsonGetStringTopLevel(response, "dll_key", &dll_key_b64);
    JsonGetStringTopLevel(response, "dll_iv", &dll_iv_b64);
    JsonGetStringTopLevel(response, "dll_alg", &dll_alg);
    bool has_encryption = !dll_key_b64.empty() || !dll_iv_b64.empty() || !dll_alg.empty();
    if (has_encryption && dll_alg.empty()) {
        dll_alg = "aes-256-cbc";
    }
    
    // Скачиваем уникальную DLL
    std::wstring download_status = L"Downloading " + (program.name.empty() ? std::wstring(L"build") : program.name) + L"...";
    SetStatus(hwnd, download_status);
    
    std::vector<char> dll_bytes;

    std::wstring dll_url_wide = Utf8ToWide(dll_url_utf8);
    if (!HttpGetBinary(dll_url_wide, &dll_bytes, &error)) {
        log_event("download_fail", WideToUtf8(error));
        return fail_dashboard(L"An unknown error occured: D1000008/D1000008"); // Failed to download DLL
    }

    if (has_encryption) {
        std::vector<BYTE> key_bytes, iv_bytes;
        Base64Decode(dll_key_b64, &key_bytes);
        Base64Decode(dll_iv_b64, &iv_bytes);
        
        std::vector<char> decrypted;
        std::wstring decrypt_error;

        if (!DecryptAes256Cbc(dll_bytes, key_bytes, iv_bytes, &decrypted, &decrypt_error)) {
             log_event("decrypt_fail", WideToUtf8(decrypt_error));
             return fail_dashboard(L"An unknown error occured: D1000032/D1000032"); //Payload decrypt failed
        }
        dll_bytes = decrypted;
    }

    SetStatus(hwnd, L"Verifying build...");
    if (dll_sha256.empty()) {
        log_event("verify_fail", "missing_hash");
        return fail_dashboard(L"An unknown error occured: D00013FF/D00013FF"); //Missing build hash
    }
    std::wstring expected_hash = ToLowerString(Utf8ToWide(dll_sha256));
    std::wstring actual_hash = ToLowerString(Utf8ToWide(Sha256HexBytes(dll_bytes)));
    
    if (expected_hash != actual_hash) {
        log_event("verify_fail", "hash_mismatch");
        return fail_dashboard(L"An unknown error occured: D00BAD01/D00BAD01"); //Build hash mismatch
    }

    SetStatus(hwnd, L"Loading..."); //Payload verified
    Sleep(RandomDelayMs(500, 1500));
    
    // Подготавливаем конфигурацию для DLL через shared memory
    shared_config::SharedConfig sharedCfg = {};
    sharedCfg.magic = SHARED_CONFIG_MAGIC;
    sharedCfg.version = 2;
    wcscpy_s(sharedCfg.server_url, g_config.server_url.c_str());
    wcscpy_s(sharedCfg.server_thumbprint, g_config.expected_thumbprint.c_str());
    
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

    SetStatus(hwnd, L"Initialization");
    Sleep(5000);
    
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

    int padding = Scale(28);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    int x = padding;
    bool use_dx = (g_dx_ui != nullptr);
    if (use_dx) {
        SetRoundedRegion(hwnd, Scale(18));
    } else {
        SetWindowRgn(hwnd, nullptr, TRUE);
    }
    int base_titlebar_height = Scale(46);
    int extra_titlebar = 0;
    if (use_dx && (g_stage == UiStage::Dashboard || g_stage == UiStage::Loading)) {
        extra_titlebar = Scale(40);
    }
    g_titlebar_height = base_titlebar_height + extra_titlebar;
    int y = g_titlebar_height + Scale(12);
    int field_width = width - padding * 2;
    int button_width = Scale(180);

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
    if (use_dx && g_stage == UiStage::Login) {
        button_height = Scale(44);
    }
    if (use_dx && (g_stage == UiStage::Dashboard || g_stage == UiStage::Loading)) {
        button_height = Scale(46);
    }
    int status_height = label_height;
    int column_height = label_height;
    int card_padding = Scale(18);

    int title_y = (base_titlebar_height - title_height) / 2;
    MoveWindow(g_title, x, title_y, field_width, title_height, TRUE);

    int button_size = Scale(28);
    int button_y = (base_titlebar_height - button_size) / 2;
    int button_right = width - Scale(16);
    g_btn_close = {button_right - button_size, button_y, button_right, button_y + button_size};
    g_btn_min = {g_btn_close.left - Scale(10) - button_size, button_y, g_btn_close.left - Scale(10), button_y + button_size};

    MoveWindow(g_subtitle, x, y, field_width, subtitle_height, TRUE);
    y += subtitle_height + Scale(20);

    if (g_title) {
        ShowWindow(g_title, use_dx ? SW_HIDE : SW_SHOW);
    }
    if (g_subtitle) {
        ShowWindow(g_subtitle, use_dx ? SW_HIDE : SW_SHOW);
    }
    if (!(use_dx && g_stage == UiStage::Login)) {
        if (g_label_key) {
            ShowWindow(g_label_key, g_stage == UiStage::Login ? SW_SHOW : SW_HIDE);
        }
        if (g_status) {
            ShowWindow(g_status, SW_SHOW);
        }
    }

    if (g_stage == UiStage::Login && use_dx) {
        int content_top = g_titlebar_height + Scale(20);
        int card_width = min(field_width, Scale(440));
        int left = (width - card_width) / 2;
        int spacing = Scale(10);
        int field_height = Scale(44);
        int card_height = card_padding * 2 + label_height + spacing + field_height + Scale(12) + button_height +
                          spacing + status_height;
        int available_height = height - content_top - padding;
        int top = content_top;
        if (available_height > card_height) {
            top = content_top + (available_height - card_height) / 2;
        }

        int inner_x = left + card_padding;
        int inner_y = top + card_padding;
        int inner_width = card_width - card_padding * 2;

        if (g_label_key) {
            SetWindowTextW(g_label_key, L"PRODUCT KEY");
        }
        MoveWindow(g_label_key, inner_x, inner_y, inner_width, label_height, TRUE);
        inner_y += label_height + spacing;

        int field_padding_x = Scale(12);
        int field_padding_y = (std::max)(0, (field_height - edit_height) / 2 + Scale(5));
        g_field_key = {inner_x, inner_y, inner_x + inner_width, inner_y + field_height};
        MoveWindow(g_edit, inner_x + field_padding_x, inner_y + field_padding_y,
                   inner_width - field_padding_x * 2, edit_height, TRUE);
        inner_y += field_height + Scale(12);

        MoveWindow(g_button, inner_x, inner_y, inner_width, button_height, TRUE);
        SetButtonRoundedRegion(g_button, use_dx);
        inner_y += button_height + Scale(14);

        MoveWindow(g_status, inner_x, inner_y, inner_width, status_height, TRUE);

        g_card_auth = {left, top, left + card_width, top + card_height};
        g_card_programs = {};
        g_card_telemetry = {};
        g_table_header = {};

        if (g_label_programs) {
            ShowWindow(g_label_programs, SW_HIDE);
        }
        ShowWindow(g_label_key, SW_HIDE);
        ShowWindow(g_status, SW_HIDE);
        ShowWindow(g_label_col_program, SW_HIDE);
        ShowWindow(g_label_col_updated, SW_HIDE);
        ShowWindow(g_label_col_expires, SW_HIDE);
        ShowWindow(g_list, SW_HIDE);
    } else if (g_stage == UiStage::Login) {
        g_field_key = {};
        int card_width = min(field_width, Scale(900));
        int card_left = (width - card_width) / 2;
        int panel_gap = Scale(20);
        int left_width = static_cast<int>(card_width * 0.42f);
        int right_width = card_width - panel_gap - left_width;

        int left_left = card_left;
        int left_top = y;
        int left_y = left_top + card_padding;
        int left_field_width = left_width - card_padding * 2;
        MoveWindow(g_label_key, left_left + card_padding, left_y, left_field_width, label_height, TRUE);
        left_y += label_height + Scale(10);

        MoveWindow(g_edit, left_left + card_padding, left_y, left_field_width, edit_height, TRUE);
        left_y += edit_height + Scale(12);

        MoveWindow(g_button, left_left + card_padding, left_y, left_field_width, button_height, TRUE);
        SetButtonRoundedRegion(g_button, use_dx);
        left_y += button_height + Scale(12);
        g_card_auth = {left_left, left_top, left_left + left_width, left_y + card_padding};

        int right_left = left_left + left_width + panel_gap;
        int right_top = left_top;
        int right_y = right_top + card_padding;
        int right_field_width = right_width - card_padding * 2;
        MoveWindow(g_label_programs, right_left + card_padding, right_y, right_field_width, header_height, TRUE);
        right_y += header_height + Scale(8);
        MoveWindow(g_status, right_left + card_padding, right_y, right_field_width, status_height, TRUE);
        right_y += status_height + Scale(12);
        g_card_programs = {right_left, right_top, right_left + right_width, right_y + card_padding};
        g_table_header = {};
    } else if (g_stage == UiStage::Connecting || (!use_dx && g_stage == UiStage::Loading)) {
        g_field_key = {};
        int card_width = min(field_width, Scale(540));
        int card_height = Scale(190);
        int card_left = (width - card_width) / 2;
        int card_top = (height - card_height) / 2;
        int card_padding = Scale(18);
        g_card_auth = {card_left, card_top, card_left + card_width, card_top + card_height};
        g_card_programs = {};
        g_card_telemetry = {};
        g_table_header = {};

        int header_y = card_top + card_padding;
        MoveWindow(g_label_programs, card_left + card_padding, header_y, card_width - card_padding * 2, header_height, TRUE);
        header_y += header_height + Scale(10);
        MoveWindow(g_status, card_left + card_padding, header_y, card_width - card_padding * 2, status_height, TRUE);
        if (use_dx) {
            ShowWindow(g_label_programs, SW_HIDE);
            ShowWindow(g_status, SW_HIDE);
        }
    } else {
        g_field_key = {};
        if (use_dx) {
            int content_top = g_titlebar_height + Scale(20);
            int panel_width = min(field_width, Scale(980));
            int panel_left = (width - panel_width) / 2;
            int gap = Scale(14);
            int card_padding = Scale(14);
            int available_height = height - content_top - padding;
            int telemetry_height = Scale(200);
            int top_row_height = available_height - telemetry_height - gap;
            if (top_row_height < Scale(200)) {
                telemetry_height = (std::max)(Scale(140), available_height - gap - Scale(200));
                top_row_height = available_height - telemetry_height - gap;
            }
            int row_top = content_top;
            int left_width = static_cast<int>((panel_width - gap) * 0.57f);
            int right_width = panel_width - gap - left_width;

            int left_left = panel_left;
            int right_left = panel_left + left_width + gap;
            int row_bottom = row_top + top_row_height;
            g_card_auth = {left_left, row_top, left_left + left_width, row_bottom};
            g_card_programs = {right_left, row_top, right_left + right_width, row_bottom};
            g_card_telemetry = {panel_left, row_bottom + gap, panel_left + panel_width, row_bottom + gap + telemetry_height};
            g_table_header = {};

            int left_inner_x = left_left + card_padding;
            int left_inner_y = row_top + card_padding + header_height + Scale(10);
            int left_inner_width = left_width - card_padding * 2;
            int left_inner_height = row_bottom - card_padding - left_inner_y;
            if (g_list) {
                MoveWindow(g_list, left_inner_x, left_inner_y, left_inner_width, left_inner_height, TRUE);
                ListView_SetColumnWidth(g_list, 0, left_inner_width);
                ListView_SetColumnWidth(g_list, 1, 0);
                ListView_SetColumnWidth(g_list, 2, 0);
                ShowWindow(g_list, SW_HIDE);
            }

            int right_inner_x = right_left + card_padding;
            int right_inner_width = right_width - card_padding * 2;
            int right_header_y = row_top + card_padding;
            int button_y = right_header_y + header_height + Scale(12);
            MoveWindow(g_button, right_inner_x, button_y, right_inner_width, button_height, TRUE);
            SetButtonRoundedRegion(g_button, use_dx);
            int status_y = button_y + button_height + Scale(16);
            MoveWindow(g_status, right_inner_x, status_y, right_inner_width, status_height, TRUE);

            ShowWindow(g_label_programs, SW_HIDE);
            ShowWindow(g_status, SW_HIDE);
        } else {
            int panel_width = min(field_width, Scale(900));
            int panel_left = (width - panel_width) / 2;
            int panel_padding = Scale(16);

            int toolbar_top = y;
            int header_y = toolbar_top + panel_padding;
            MoveWindow(g_label_programs, panel_left + panel_padding, header_y,
                       panel_width - panel_padding * 2 - button_width - Scale(12), header_height, TRUE);
            MoveWindow(g_button, panel_left + panel_width - panel_padding - button_width, header_y - Scale(4), button_width, button_height, TRUE);
            SetButtonRoundedRegion(g_button, use_dx);
            header_y += header_height + Scale(8);
            MoveWindow(g_status, panel_left + panel_padding, header_y, panel_width - panel_padding * 2, status_height, TRUE);
            int toolbar_bottom = header_y + status_height + panel_padding;
            g_card_auth = {panel_left, toolbar_top, panel_left + panel_width, toolbar_bottom};

            int list_top = toolbar_bottom + Scale(16);
            int list_padding = Scale(14);
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
            g_card_telemetry = {};
        }
    }
    InvalidateRect(hwnd, nullptr, g_dx_ui ? FALSE : TRUE);
}

struct DxProductsLayout {
    RECT list = {};
    int item_height = 0;
    int item_gap = 0;
    int visible = 0;
    int total = 0;
};

bool GetDxProductsLayout(DxProductsLayout* layout) {
    if (!layout || !g_dx_ui || IsRectEmpty(&g_card_auth)) {
        return false;
    }
    if (g_stage != UiStage::Dashboard && g_stage != UiStage::Loading) {
        return false;
    }

    int pad = Scale(kDxUiCardPadding);
    int header = Scale(kDxUiHeaderHeight);
    int gap = Scale(kDxUiListItemGap);
    int item_height = Scale(kDxUiListItemHeight);
    int top = g_card_auth.top + pad + header + Scale(10);
    int left = g_card_auth.left + pad;
    int right = g_card_auth.right - pad;
    int bottom = g_card_auth.bottom - pad;
    if (right <= left || bottom <= top) {
        return false;
    }

    int list_height = bottom - top;
    int visible = (list_height + gap) / (item_height + gap);
    if (visible < 1) {
        visible = 1;
    }

    int total = 0;
    EnterCriticalSection(&g_programs_lock);
    total = static_cast<int>(g_programs.size());
    LeaveCriticalSection(&g_programs_lock);

    layout->list = {left, top, right, bottom};
    layout->item_height = item_height;
    layout->item_gap = gap;
    layout->visible = visible;
    layout->total = total;
    return true;
}

bool HitTestDxProductList(POINT pt, int* out_index) {
    DxProductsLayout layout;
    if (!GetDxProductsLayout(&layout)) {
        return false;
    }
    if (!PtInRect(&layout.list, pt)) {
        return false;
    }

    int max_scroll = (std::max)(0, layout.total - layout.visible);
    int scroll = (std::min)((std::max)(g_products_scroll, 0), max_scroll);

    int rel_y = pt.y - layout.list.top;
    int slot = rel_y / (layout.item_height + layout.item_gap);
    if (slot < 0 || slot >= layout.visible) {
        return false;
    }

    int item_top = layout.list.top + slot * (layout.item_height + layout.item_gap);
    if (pt.y > item_top + layout.item_height) {
        return false;
    }

    int index = scroll + slot;
    if (index < 0 || index >= layout.total) {
        return false;
    }
    if (out_index) {
        *out_index = index;
    }
    return true;
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

            if (kEnableDxUi) {
                g_dx_ui = std::make_unique<DxUiRenderer>();
                if (!g_dx_ui->Initialize(hwnd)) {
                    g_dx_ui.reset();
                } else {
                    g_dx_ui->SetDpi(g_dpi);
                }
            }

            if (!g_dx_ui) {
                LONG_PTR ex_style = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
                SetWindowLongPtr(hwnd, GWL_EXSTYLE, ex_style | WS_EX_LAYERED);
                SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
                g_fade_active = true;
                g_fade_alpha = 0;
            } else {
                g_fade_active = false;
                g_fade_alpha = 255;
                LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
                SetWindowLongPtr(hwnd, GWL_STYLE, style | WS_CLIPCHILDREN | WS_CLIPSIBLINGS);
                SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
            }
            UINT timer_ms = g_dx_ui ? 16 : 80;
            SetTimer(hwnd, kUiTimerId, timer_ms, nullptr);

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
            if (g_button) {
                SetWindowSubclass(g_button, ButtonSubclassProc, 0, 0);
                if (g_dx_ui) {
                    ConfigureDxButtonWindow(g_button);
                }
            }

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
        case WM_SIZE: {
            if (g_dx_ui) {
                g_dx_ui->Resize(LOWORD(lparam), HIWORD(lparam));
            }
            LayoutControls(hwnd);
            return 0;
        }
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
            if (g_dx_ui) {
                g_dx_ui->SetDpi(g_dpi);
            }
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
        case WM_KEYDOWN: {
            if (g_dx_ui && (g_stage == UiStage::Dashboard || g_stage == UiStage::Loading)) {
                DxProductsLayout layout;
                if (!GetDxProductsLayout(&layout) || layout.total <= 0) {
                    break;
                }

                int index = g_selected_index;
                if (index < 0) {
                    index = 0;
                }
                int next = index;
                switch (wparam) {
                    case VK_UP:
                        next = (std::max)(0, index - 1);
                        break;
                    case VK_DOWN:
                        next = (std::min)(layout.total - 1, index + 1);
                        break;
                    case VK_HOME:
                        next = 0;
                        break;
                    case VK_END:
                        next = layout.total - 1;
                        break;
                    case VK_PRIOR:
                        next = (std::max)(0, index - layout.visible);
                        break;
                    case VK_NEXT:
                        next = (std::min)(layout.total - 1, index + layout.visible);
                        break;
                    case VK_RETURN:
                        if (g_button && IsWindowEnabled(g_button)) {
                            SendMessageW(hwnd, WM_COMMAND,
                                         MAKEWPARAM(kControlIdButton, BN_CLICKED),
                                         reinterpret_cast<LPARAM>(g_button));
                            return 0;
                        }
                        break;
                    default:
                        break;
                }

                if (next != index) {
                    g_selected_index = next;
                    g_hover_product_index = -1;
                    g_keyboard_nav_active = true;
                    int max_scroll = (std::max)(0, layout.total - layout.visible);
                    if (g_selected_index < g_products_scroll) {
                        g_products_scroll = g_selected_index;
                    } else if (g_selected_index >= g_products_scroll + layout.visible) {
                        g_products_scroll = g_selected_index - layout.visible + 1;
                    }
                    g_products_scroll = (std::min)((std::max)(g_products_scroll, 0), max_scroll);
                    InvalidateRect(hwnd, nullptr, TRUE);
                    return 0;
                }
            }
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wparam) == kControlIdEdit && HIWORD(wparam) == EN_CHANGE) {
                if (g_ignore_key_change) {
                    return 0;
                }
                int text_len = GetWindowTextLengthW(g_edit);
                std::wstring raw(text_len + 1, L'\0');
                int copied = GetWindowTextW(g_edit, &raw[0], text_len + 1);
                if (copied < 0) {
                    copied = 0;
                }
                raw.resize(static_cast<size_t>(copied));
                DWORD sel_start = 0;
                DWORD sel_end = 0;
                SendMessageW(g_edit, EM_GETSEL, reinterpret_cast<WPARAM>(&sel_start),
                             reinterpret_cast<LPARAM>(&sel_end));
                int key_before_start = CountKeyChars(raw, static_cast<size_t>(sel_start));
                int key_before_end = CountKeyChars(raw, static_cast<size_t>(sel_end));
                std::wstring normalized = NormalizeKeyWide(raw);
                std::wstring formatted = FormatKeyDisplay(normalized);
                if (formatted != raw) {
                    g_ignore_key_change = true;
                    SetWindowTextW(g_edit, formatted.c_str());
                    int total_keys = static_cast<int>(normalized.size());
                    int new_start = MapKeyIndexToFormatted(key_before_start, total_keys);
                    int new_end = MapKeyIndexToFormatted(key_before_end, total_keys);
                    SendMessageW(g_edit, EM_SETSEL, new_start, new_end);
                    g_ignore_key_change = false;
                }
                if (g_stage != UiStage::Login) {
                    SetStage(UiStage::Login);
                    ResetPrograms();
                }
                ClearSavedKey();
                g_cached_key.clear();
                EnterCriticalSection(&g_status_lock);
                g_last_error_code.clear();
                LeaveCriticalSection(&g_status_lock);
                SetStatus(hwnd, L"Enter a key to continue");
                return 0;
            }
            if (LOWORD(wparam) == kControlIdButton) {
                if (g_stage == UiStage::Login) {
                    int text_len = GetWindowTextLengthW(g_edit);
                    std::wstring raw(text_len + 1, L'\0');
                    int copied = GetWindowTextW(g_edit, &raw[0], text_len + 1);
                    if (copied < 0) {
                        copied = 0;
                    }
                    raw.resize(static_cast<size_t>(copied));
                    std::wstring key = NormalizeKeyWide(raw);
                    if (key.empty()) {
                        EnterCriticalSection(&g_status_lock);
                        g_last_error_code.clear();
                        LeaveCriticalSection(&g_status_lock);
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

                if (!IsInjectableStatus(program.status)) {
                    std::wstring message = L"An unknown error occured: D1000033/D1000033"; // Build not injectable
                    SetStatus(hwnd, message);
                    ShowErrorBox(hwnd, message);
                    return 0;
                }

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
            if (g_dx_ui && (g_stage == UiStage::Dashboard || g_stage == UiStage::Loading || g_stage == UiStage::Login)) {
                if (g_button && IsWindowEnabled(g_button)) {
                    RECT button_rect = {};
                    if (GetWindowRect(g_button, &button_rect)) {
                        MapWindowPoints(nullptr, hwnd, reinterpret_cast<POINT*>(&button_rect), 2);
                        if (PtInRect(&button_rect, pt)) {
                            g_dx_button_pressed = true;
                            SendMessageW(g_button, BM_SETSTATE, TRUE, 0);
                            SetCapture(hwnd);
                            InvalidateRect(hwnd, nullptr, FALSE);
                            return 0;
                        }
                    }
                }
            }
            if (g_dx_ui && g_stage == UiStage::Dashboard) {
                int index = -1;
                if (HitTestDxProductList(pt, &index)) {
                    if (index != g_selected_index) {
                        g_selected_index = index;
                        g_keyboard_nav_active = false;
                        InvalidateRect(hwnd, nullptr, TRUE);
                    }
                    return 0;
                }
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
            if (g_dx_button_pressed) {
                g_dx_button_pressed = false;
                if (g_button) {
                    SendMessageW(g_button, BM_SETSTATE, FALSE, 0);
                }
                ReleaseCapture();
                if (g_dx_ui && (g_stage == UiStage::Dashboard || g_stage == UiStage::Loading || g_stage == UiStage::Login) &&
                    g_button && IsWindowEnabled(g_button)) {
                    POINT pt = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
                    RECT button_rect = {};
                    if (GetWindowRect(g_button, &button_rect)) {
                        MapWindowPoints(nullptr, hwnd, reinterpret_cast<POINT*>(&button_rect), 2);
                        if (PtInRect(&button_rect, pt)) {
                            SendMessageW(hwnd, WM_COMMAND,
                                         MAKEWPARAM(kControlIdButton, BN_CLICKED),
                                         reinterpret_cast<LPARAM>(g_button));
                        }
                    }
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            break;
        }
        case WM_MOUSEMOVE: {
            POINT pt = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            g_mouse_pos = pt;
            g_mouse_in_window = true;
            bool hover_close = PtInRect(&g_btn_close, pt);
            bool hover_min = PtInRect(&g_btn_min, pt);
            if (hover_close != g_hover_close || hover_min != g_hover_min) {
                g_hover_close = hover_close;
                g_hover_min = hover_min;
                InvalidateRect(hwnd, &g_btn_close, TRUE);
                InvalidateRect(hwnd, &g_btn_min, TRUE);
            }
            if (g_button) {
                RECT button_rect = {};
                if (GetWindowRect(g_button, &button_rect)) {
                    MapWindowPoints(nullptr, hwnd, reinterpret_cast<POINT*>(&button_rect), 2);
                    bool over = PtInRect(&button_rect, pt) != FALSE;
                    if (over) {
                        POINT local = {pt.x - button_rect.left, pt.y - button_rect.top};
                        if (!g_button_hover ||
                            std::abs(local.x - g_button_hover_pt.x) > 1 ||
                            std::abs(local.y - g_button_hover_pt.y) > 1) {
                            g_button_hover = true;
                            g_button_hover_pt = local;
                            InvalidateRect(g_button, nullptr, g_dx_ui ? FALSE : TRUE);
                        }
                    } else if (g_button_hover) {
                        g_button_hover = false;
                        InvalidateRect(g_button, nullptr, g_dx_ui ? FALSE : TRUE);
                    }
                }
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
            if (g_dx_ui && g_stage == UiStage::Dashboard) {
                int hover_index = -1;
                if (!HitTestDxProductList(pt, &hover_index)) {
                    hover_index = -1;
                }
                if (hover_index != -1 && g_keyboard_nav_active) {
                    g_keyboard_nav_active = false;
                }
                if (hover_index != g_hover_product_index) {
                    g_hover_product_index = hover_index;
                    InvalidateRect(hwnd, nullptr, TRUE);
                }
            }
            if (g_dx_ui && g_stage == UiStage::Login) {
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            break;
        }
        case WM_MOUSELEAVE:
            g_tracking_mouse = false;
            g_mouse_in_window = false;
            if (g_hover_close || g_hover_min) {
                g_hover_close = false;
                g_hover_min = false;
                InvalidateRect(hwnd, &g_btn_close, TRUE);
                InvalidateRect(hwnd, &g_btn_min, TRUE);
            }
            if (g_hover_product_index != -1) {
                g_hover_product_index = -1;
                InvalidateRect(hwnd, nullptr, TRUE);
            }
            if (g_button_hover) {
                g_button_hover = false;
                InvalidateRect(g_button, nullptr, g_dx_ui ? FALSE : TRUE);
            }
            return 0;
        case WM_MOUSEWHEEL: {
            if (g_dx_ui && g_stage == UiStage::Dashboard) {
                DxProductsLayout layout;
                if (GetDxProductsLayout(&layout)) {
                    POINT pt = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
                    ScreenToClient(hwnd, &pt);
                    if (!PtInRect(&layout.list, pt)) {
                        break;
                    }
                    int max_scroll = (std::max)(0, layout.total - layout.visible);
                    if (max_scroll > 0) {
                        int step = GET_WHEEL_DELTA_WPARAM(wparam) / WHEEL_DELTA;
                        if (step != 0) {
                            g_keyboard_nav_active = false;
                            int next = g_products_scroll - step;
                            next = (std::max)(0, (std::min)(next, max_scroll));
                            if (next != g_products_scroll) {
                                g_products_scroll = next;
                                g_hover_product_index = -1;
                                InvalidateRect(hwnd, nullptr, TRUE);
                                return 0;
                            }
                        }
                    }
                }
            }
            break;
        }
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
                        DrawProgramCard(draw->nmcd.hdc, item, info, selected, index);
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
                if (g_dx_ui && (g_stage == UiStage::Dashboard || g_stage == UiStage::Loading || g_stage == UiStage::Login)) {
                    return TRUE;
                }
                HDC dc = dis->hDC;
                RECT rect = dis->rcItem;
                if (g_dx_ui) {
                    SetButtonRoundedRegion(dis->hwndItem, true);
                }
                int width = rect.right - rect.left;
                int height = rect.bottom - rect.top;
                HDC paint_dc = dc;
                HBITMAP buffer = nullptr;
                HBITMAP old_bmp = nullptr;
                HDC mem_dc = nullptr;
                RECT paint_rect = rect;
                if (g_dx_ui && width > 0 && height > 0) {
                    mem_dc = CreateCompatibleDC(dc);
                    if (mem_dc) {
                        buffer = CreateCompatibleBitmap(dc, width, height);
                        if (buffer) {
                            old_bmp = reinterpret_cast<HBITMAP>(SelectObject(mem_dc, buffer));
                            paint_dc = mem_dc;
                            paint_rect = {0, 0, width, height};
                        } else {
                            DeleteDC(mem_dc);
                            mem_dc = nullptr;
                        }
                    }
                }
                if (mem_dc) {
                    HBRUSH back_brush = g_panel_brush;
                    if (back_brush) {
                        FillRect(mem_dc, &paint_rect, back_brush);
                    }
                }
                int paint_width = paint_rect.right - paint_rect.left;
                int paint_height = paint_rect.bottom - paint_rect.top;

                bool enabled = IsWindowEnabled(dis->hwndItem) != FALSE;
                bool pressed = (dis->itemState & ODS_SELECTED) != 0;
                bool focused = (GetFocus() == dis->hwndItem);
                if (g_dx_ui && g_stage == UiStage::Login) {
                    if (g_panel_brush) {
                        int radius = GetButtonCornerRadius(paint_rect, g_dx_ui != nullptr);
                        HRGN clip = CreateRoundRectRgn(paint_rect.left, paint_rect.top,
                                                       paint_rect.right + 1, paint_rect.bottom + 1,
                                                       radius, radius);
                        int saved = SaveDC(paint_dc);
                        SelectClipRgn(paint_dc, clip);
                        FillRect(paint_dc, &paint_rect, g_panel_brush);
                        RestoreDC(paint_dc, saved);
                        DeleteObject(clip);
                    }
                    std::wstring status_snapshot;
                    EnterCriticalSection(&g_status_lock);
                    status_snapshot = g_status_text;
                    LeaveCriticalSection(&g_status_lock);
                    std::wstring status_lower = ToLowerString(status_snapshot);
                    bool waiting = (g_stage != UiStage::Login &&
                                    status_lower.find(L"waiting") != std::wstring::npos);
                    COLORREF base = kSurfaceAlt;
                    COLORREF accent = waiting ? RGB(255, 176, 32) : kAccentColor;
                    COLORREF top = base;
                    COLORREF bottom = base;
                    COLORREF border = kSurfaceBorder;
                    float strength = enabled ? (waiting ? 0.9f : 1.0f) : 0.35f;
                    float top_alpha = pressed ? 0.18f : 0.22f;
                    float bottom_alpha = pressed ? 0.08f : 0.10f;
                    top = BlendColor(base, accent, top_alpha * strength);
                    bottom = BlendColor(base, accent, bottom_alpha * strength);
                    border = BlendColor(base, accent, (pressed ? 0.22f : 0.28f) * strength);
                    DrawButtonSurface(paint_dc, paint_rect, top, bottom, border);

                    bool show_spinner = (g_stage == UiStage::Loading) || waiting;
                    COLORREF spinner_color = waiting ? RGB(255, 176, 32) : accent;
                    bool use_effects = g_gdiplus_started &&
                                       ((g_button_hover && enabled) || show_spinner || (focused && enabled));
                    if (use_effects) {
                        Gdiplus::Graphics graphics(paint_dc);
                        graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
                        graphics.SetCompositingMode(Gdiplus::CompositingModeSourceOver);
                        Gdiplus::RectF clip_rect(static_cast<Gdiplus::REAL>(paint_rect.left),
                                                 static_cast<Gdiplus::REAL>(paint_rect.top),
                                                 static_cast<Gdiplus::REAL>(paint_width),
                                                 static_cast<Gdiplus::REAL>(paint_height));
                        float clip_radius =
                            static_cast<float>(GetButtonCornerRadius(paint_rect, g_dx_ui != nullptr)) * 0.5f;
                        Gdiplus::GraphicsPath clip_path;
                        AddRoundedRectPath(&clip_path, clip_rect, clip_radius);
                        graphics.SetClip(&clip_path, Gdiplus::CombineModeReplace);

                        if (g_button_hover && enabled) {
                            float draw_width = static_cast<float>(paint_width);
                            float draw_height = static_cast<float>(paint_height);
                            float glow_w = (std::min)(draw_width * 0.9f, static_cast<float>(Scale(180)));
                            float glow_h = (std::min)(draw_height * 0.9f, static_cast<float>(Scale(80)));
                            float cx = static_cast<float>(paint_rect.left + g_button_hover_pt.x);
                            float cy = static_cast<float>(paint_rect.top + g_button_hover_pt.y);

                            Gdiplus::GraphicsPath path;
                            path.AddEllipse(cx - glow_w * 0.5f, cy - glow_h * 0.5f, glow_w, glow_h);

                            Gdiplus::PathGradientBrush brush(&path);
                            Gdiplus::Color center(70, GetRValue(accent), GetGValue(accent), GetBValue(accent));
                            brush.SetCenterColor(center);
                            Gdiplus::Color surround(0, GetRValue(accent), GetGValue(accent), GetBValue(accent));
                            int count = 1;
                            brush.SetSurroundColors(&surround, &count);
                            graphics.FillPath(&brush, &path);
                        }

                        if (show_spinner) {
                            float draw_width = static_cast<float>(paint_width);
                            float draw_height = static_cast<float>(paint_height);
                            float spin_size = (std::min)(draw_width, draw_height) * 0.45f;
                            spin_size = (std::min)((std::max)(spin_size, 10.0f), 16.0f);
                            float spin_x = static_cast<float>(paint_rect.left + Scale(12));
                            float spin_y = static_cast<float>(paint_rect.top) + (draw_height - spin_size) * 0.5f;
                            float angle = static_cast<float>((GetTickCount64() % 900ULL) / 900.0f) * 360.0f;
                            Gdiplus::RectF spin_rect(spin_x, spin_y, spin_size, spin_size);
                            Gdiplus::Pen pen(Gdiplus::Color(220, GetRValue(spinner_color), GetGValue(spinner_color),
                                                            GetBValue(spinner_color)),
                                             2.0f);
                            graphics.DrawArc(&pen, spin_rect, angle, 270.0f);
                        }

                        if (focused && enabled) {
                            float inset = static_cast<float>(Scale(2));
                            float draw_width = static_cast<float>(paint_width);
                            float draw_height = static_cast<float>(paint_height);
                            Gdiplus::RectF ring(paint_rect.left + inset, paint_rect.top + inset,
                                                draw_width - inset * 2.0f, draw_height - inset * 2.0f);
                            float radius = (std::max)(
                                0.0f,
                                static_cast<float>(GetButtonCornerRadius(paint_rect, g_dx_ui != nullptr)) * 0.5f -
                                    inset);
                            Gdiplus::GraphicsPath path;
                            AddRoundedRectPath(&path, ring, radius);
                            Gdiplus::Color ring_color(180, GetRValue(accent), GetGValue(accent), GetBValue(accent));
                            Gdiplus::Pen pen(ring_color, 2.0f);
                            pen.SetAlignment(Gdiplus::PenAlignmentInset);
                            graphics.DrawPath(&pen, &path);
                        }
                    }

                    SetBkMode(paint_dc, TRANSPARENT);
                    SetTextColor(paint_dc, enabled ? kTextColor : kMutedColor);

                    wchar_t text[64] = {};
                    GetWindowTextW(dis->hwndItem, text, static_cast<int>(sizeof(text) / sizeof(text[0])));
                    RECT text_rect = paint_rect;
                    if (show_spinner) {
                        text_rect.left += Scale(16);
                    }
                    DrawTextW(paint_dc, text, -1, &text_rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                    if (mem_dc && buffer) {
                        BitBlt(dc, rect.left, rect.top, width, height, mem_dc, 0, 0, SRCCOPY);
                        SelectObject(mem_dc, old_bmp);
                        DeleteObject(buffer);
                        DeleteDC(mem_dc);
                    }
                    return TRUE;
                }
                if (g_panel_brush) {
                    FillRect(dc, &rect, g_panel_brush);
                }
                COLORREF top = enabled ? (pressed ? RGB(30, 36, 44) : RGB(36, 42, 52)) : kSurfaceBorder;
                COLORREF bottom = enabled ? (pressed ? RGB(26, 30, 38) : RGB(30, 34, 42)) : kSurfaceBorder;
                COLORREF border = enabled ? (pressed ? kAccentColor : kAccentAlt) : kSurfaceBorder;
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
            BeginPaint(hwnd, &ps);
            if (g_dx_ui) {
                g_dx_ui->Render();
                EndPaint(hwnd, &ps);
                return 0;
            }
            HDC dc = ps.hdc;
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
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, (control == g_status || control == g_label_programs) ? kTextColor : kMutedColor);
                return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
            }
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, kMutedColor);
            return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            SetTextColor(dc, kTextColor);
            SetBkColor(dc, kSurfaceAlt);
            return reinterpret_cast<LRESULT>(g_panel_alt_brush);
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
                InvalidateRect(hwnd, &status_rect, g_dx_ui ? FALSE : TRUE);
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
            std::wstring saved_key = g_cached_key;
            std::wstring display_key = FormatKeyDisplay(saved_key);
            SetStage(UiStage::Connecting);
            SetStatus(hwnd, L"Validating saved key...");
            g_ignore_key_change = true;
            SetWindowTextW(g_edit, display_key.c_str());
            g_ignore_key_change = false;
            EnableButton(false);
            WorkerArgs* args = new WorkerArgs{ hwnd, TaskType::Validate, saved_key, {}, true };
            CreateThread(nullptr, 0, WorkerThread, args, 0, nullptr);
            return 0;
        }
        case WM_TIMER: {
            if (wparam == kUiTimerId) {
                if (g_fade_active) {
                    BYTE next_alpha = static_cast<BYTE>((std::min<int>)(255, static_cast<int>(g_fade_alpha) + kFadeStep));
                    g_fade_alpha = next_alpha;
                    SetLayeredWindowAttributes(hwnd, 0, g_fade_alpha, LWA_ALPHA);
                    if (g_fade_alpha >= 255) {
                        g_fade_active = false;
                    }
                }
                if (g_dx_ui && (g_stage == UiStage::Connecting || g_stage == UiStage::Loading || g_stage == UiStage::Dashboard ||
                                (g_stage == UiStage::Login && g_mouse_in_window))) {
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                if (g_dx_ui && g_stage == UiStage::Login && g_mouse_in_window && g_button) {
                    InvalidateRect(g_button, nullptr, g_dx_ui ? FALSE : TRUE);
                }
                if (g_dx_ui && g_button && (g_stage == UiStage::Loading || g_stage == UiStage::Dashboard)) {
                    bool show_spinner = (g_stage == UiStage::Loading);
                    if (!show_spinner) {
                        std::wstring status_snapshot;
                        EnterCriticalSection(&g_status_lock);
                        status_snapshot = g_status_text;
                        LeaveCriticalSection(&g_status_lock);
                        std::wstring status_lower = ToLowerString(status_snapshot);
                        show_spinner = (status_lower.find(L"waiting") != std::wstring::npos);
                    }
                    if (show_spinner) {
                        InvalidateRect(g_button, nullptr, g_dx_ui ? FALSE : TRUE);
                    }
                }
                bool animate_status = (g_stage == UiStage::Connecting || (g_stage == UiStage::Loading && !g_dx_ui));
                if (animate_status && !g_status_base.empty()) {
                    ULONGLONG now = GetTickCount64();
                    int dots = static_cast<int>((now / 320ULL) % 4ULL);
                    g_status_anim_tick = dots;
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
                    if (g_dx_ui) {
                        InvalidateRect(hwnd, nullptr, FALSE);
                    }
                }
            }
            return 0;
        }
        case WM_DESTROY:
            KillTimer(hwnd, kUiTimerId);
            if (g_dx_ui) {
                g_dx_ui->Shutdown();
                g_dx_ui.reset();
            }
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

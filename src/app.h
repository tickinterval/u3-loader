#pragma once

#include <windows.h>
#include <commctrl.h>

#include <string>
#include <vector>
#include <cstdint>

namespace loader {

struct Config {
    std::wstring server_url;
    std::wstring expected_thumbprint;
    std::wstring user_agent;
    std::wstring target_process;
};

struct ProgramInfo {
    std::wstring code;
    std::wstring name;
    std::wstring updated_at;
    std::wstring expires_at;
    std::wstring dll_url;
    std::wstring payload_sha256;
    std::wstring status;
    std::wstring watermark;
    std::wstring avatar_url;
    std::wstring avatar_path;
};

enum class TaskType {
    Validate,
    LoadProgram,
};

enum class UiStage {
    Login,
    Connecting,
    Dashboard,
    Loading,
};

struct WorkerArgs {
    HWND hwnd;
    TaskType task;
    std::wstring key;
    ProgramInfo program;
};

extern const COLORREF kBgTop;
extern const COLORREF kBgBottom;
extern const COLORREF kTitleTop;
extern const COLORREF kTitleBottom;
extern const COLORREF kFrameBorder;
extern const COLORREF kSurface;
extern const COLORREF kSurfaceAlt;
extern const COLORREF kSurfaceBorder;
extern const COLORREF kButtonHover;
extern const COLORREF kButtonPressed;
extern const COLORREF kRowEven;
extern const COLORREF kRowOdd;
extern const COLORREF kRowSelected;
extern const COLORREF kTextColor;
extern const COLORREF kAccentColor;
extern const COLORREF kAccentAlt;
extern const COLORREF kMutedColor;
extern const COLORREF kMaskColor;

extern const char kLoaderVersion[];
std::string GetResponsePublicKeyPem();
extern const wchar_t kDefaultServerUrl[];
extern const wchar_t kDefaultExpectedThumbprint[];
extern const wchar_t kDefaultUserAgent[];
extern const wchar_t kDefaultTargetProcess[];

constexpr int kControlIdEdit = 1001;
constexpr int kControlIdButton = 1002;
constexpr int kControlIdStatus = 1003;
constexpr int kControlIdList = 1004;

constexpr UINT kMsgUpdateStatus = WM_APP + 1;
constexpr UINT kMsgProgramsUpdated = WM_APP + 2;
constexpr UINT kMsgAutoValidate = WM_APP + 3;

extern HWND g_edit;
extern HWND g_button;
extern HWND g_status;
extern HWND g_title;
extern HWND g_subtitle;
extern HWND g_label_key;
extern HWND g_label_programs;
extern HWND g_label_col_program;
extern HWND g_label_col_updated;
extern HWND g_label_col_expires;
extern HWND g_list;
extern HWND g_status_hwnd;
extern HWND g_status_title;
extern HWND g_status_overlay;
extern HFONT g_title_font;
extern HFONT g_subtitle_font;
extern HFONT g_body_font;
extern HFONT g_small_font;
extern HFONT g_avatar_font;
extern HIMAGELIST g_avatar_list;
extern HBRUSH g_bg_brush;
extern HBRUSH g_panel_brush;
extern HBRUSH g_panel_alt_brush;
extern Config g_config;
extern CRITICAL_SECTION g_status_lock;
extern std::wstring g_status_text;
extern CRITICAL_SECTION g_programs_lock;
extern std::vector<ProgramInfo> g_programs;
extern bool g_validated;
extern UINT g_dpi;
extern RECT g_card_auth;
extern RECT g_card_programs;
extern RECT g_table_header;
extern RECT g_btn_close;
extern RECT g_btn_min;
extern int g_titlebar_height;
extern bool g_hover_close;
extern bool g_hover_min;
extern bool g_pressed_close;
extern bool g_pressed_min;
extern bool g_tracking_mouse;
extern UiStage g_stage;
extern std::wstring g_cached_key;
extern HWND g_hwnd;
extern int g_selected_index;
extern std::string g_event_token;

bool LoadConfig(Config* config);
bool SaveKey(const std::wstring& key);
bool LoadSavedKey(std::wstring* key);
void ClearSavedKey();

// HWID функции
std::wstring GetMachineGuid();
std::wstring GetVolumeSerial();
std::wstring GetCpuName();
std::wstring GetGpuName();
std::wstring GetSmbiosUuid();
std::wstring GetBiosSerial();
std::wstring GetBaseBoardSerial();

std::wstring FormatUpdatedLabel(const std::wstring& iso);
std::wstring FormatExpiryLabel(const std::wstring& iso);
std::wstring FriendlyErrorMessage(const std::string& code);

std::wstring GetCpuName();
std::wstring GetGpuName();
std::wstring GetWindowsBuild();
bool CheckForUpdateSilent();

void SetStatus(HWND hwnd, const std::wstring& text);
void EnableButton(bool enabled);
void SetStage(UiStage stage);
void UpdateButtonText();
void LayoutControls(HWND hwnd);
void PopulateProgramsList();
void ResetPrograms();
void InitAvatarList();
void CreateFonts();
void DestroyFonts();
void ApplyFonts();

DWORD WINAPI WorkerThread(LPVOID param);
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

} // namespace loader

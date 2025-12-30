#include "ui_dx.h"

#include "app.h"

#include <d2d1.h>
#include <dwrite.h>
#include <objbase.h>
#include <wincodec.h>
#include <wrl/client.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "windowscodecs.lib")

namespace loader {

using Microsoft::WRL::ComPtr;

bool IsLifetimeSubscription(const std::wstring& iso);

namespace {

struct Theme {
    D2D1_COLOR_F bg;
    D2D1_COLOR_F bg2;
    D2D1_COLOR_F surface;
    D2D1_COLOR_F stroke;
    D2D1_COLOR_F text;
    D2D1_COLOR_F muted;
    D2D1_COLOR_F faint;
    D2D1_COLOR_F accent;
    D2D1_COLOR_F accent2;
    D2D1_COLOR_F warn;
};

D2D1_COLOR_F ColorFromHex(uint32_t rgb, float a = 1.0f) {
    float r = static_cast<float>((rgb >> 16) & 0xFF) / 255.0f;
    float g = static_cast<float>((rgb >> 8) & 0xFF) / 255.0f;
    float b = static_cast<float>(rgb & 0xFF) / 255.0f;
    return D2D1::ColorF(r, g, b, a);
}

Theme GetTheme() {
    Theme t = {};
    t.bg = ColorFromHex(0x0E1116);
    t.bg2 = ColorFromHex(0x0B0E13);
    t.surface = ColorFromHex(0x151A22, 0.86f);
    t.stroke = ColorFromHex(0x2A3240);
    t.text = ColorFromHex(0xE8EDF5);
    t.muted = ColorFromHex(0x9AA6B2);
    t.faint = ColorFromHex(0x6E7A87);
    t.accent = ColorFromHex(0x5981EB);
    t.accent2 = ColorFromHex(0x5981EB);
    t.warn = ColorFromHex(0xFFB020);
    return t;
}

struct TelemetryLine {
    std::wstring ts;
    std::wstring msg;
    ULONGLONG tick = 0;
};

struct LoginChip {
    std::wstring tag;
    std::wstring message;
    bool show = false;
    bool warn = false;
};

std::wstring FormatTimestamp() {
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t buffer[16] = {};
    swprintf_s(buffer, L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
    return std::wstring(buffer);
}

std::wstring FormatHourMinute() {
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t buffer[8] = {};
    swprintf_s(buffer, L"%02u:%02u", st.wHour, st.wMinute);
    return std::wstring(buffer);
}

LoginChip BuildLoginChip(const std::wstring& status, const std::string& error_code) {
    LoginChip chip;
    if (error_code.empty()) {
        return chip;
    }

    chip.show = true;
    chip.warn = true;
    chip.message = FriendlyErrorMessage(error_code);
    if (chip.message.empty()) {
        chip.message = status;
    }

    if (error_code == "invalid_key") {
        chip.tag = L"KEY";
    } else if (error_code == "expired") {
        chip.tag = L"SUB";
    } else if (error_code == "hwid_mismatch") {
        chip.tag = L"DEVICE";
    } else if (error_code == "no_products") {
        chip.tag = L"PRODUCT";
    } else if (error_code == "missing_key_or_hwid") {
        chip.tag = L"KEY";
    } else if (error_code == "device_limit") {
        chip.tag = L"DEVICE";
    } else if (error_code == "update_required") {
        chip.tag = L"UPDATE";
    } else {
        chip.tag = L"ERROR";
    }
    return chip;
}

std::wstring GetStatusSnapshot() {
    std::wstring out;
    EnterCriticalSection(&g_status_lock);
    out = g_status_text;
    LeaveCriticalSection(&g_status_lock);
    return out;
}

std::wstring ToLowerCopy(const std::wstring& value);
bool ContainsInsensitive(const std::wstring& value, const wchar_t* needle);

std::wstring BuildTargetLabel() {
    std::wstring target = g_config.target_process;
    if (target.empty()) {
        return target;
    }
    size_t slash = target.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        target = target.substr(slash + 1);
    }
    std::wstring lower = ToLowerCopy(target);
    if (lower.size() > 4 && lower.rfind(L".exe") == lower.size() - 4) {
        target = target.substr(0, target.size() - 4);
        lower = ToLowerCopy(target);
    }
    if (lower == L"cs2") {
        return L"Counter-Strike 2";
    }
    for (wchar_t& ch : target) {
        if (ch == L'_' || ch == L'-') {
            ch = L' ';
        }
    }
    return target;
}

std::wstring NormalizeSubscriptionDate(std::wstring value) {
    size_t start = 0;
    while (start < value.size() && iswspace(value[start])) {
        ++start;
    }
    size_t end = value.size();
    while (end > start && iswspace(value[end - 1])) {
        --end;
    }
    value = value.substr(start, end - start);
    if (value.size() > 1 && value.front() == L'[' && value.back() == L']') {
        value = value.substr(1, value.size() - 2);
    }
    if (value.empty()) {
        return value;
    }
    std::wstring date_part = value;
    std::wstring time_part;
    size_t cut = value.find(L'T');
    if (cut == std::wstring::npos) {
        cut = value.find(L' ');
    }
    if (cut != std::wstring::npos) {
        date_part = value.substr(0, cut);
        time_part = value.substr(cut + 1);
    }

    if (!time_part.empty()) {
        size_t z = time_part.find(L'Z');
        if (z != std::wstring::npos) {
            time_part = time_part.substr(0, z);
        }
        size_t tz = time_part.find_first_of(L"+-");
        if (tz != std::wstring::npos) {
            time_part = time_part.substr(0, tz);
        }
        size_t dot = time_part.find(L'.');
        if (dot != std::wstring::npos) {
            time_part = time_part.substr(0, dot);
        }
        if (time_part.size() >= 8) {
            time_part = time_part.substr(0, 8);
        } else if (time_part.size() == 5) {
            time_part += L":00";
        }
        for (wchar_t& ch : time_part) {
            if (ch == L':') {
                ch = L'.';
            }
        }
    }

    if (date_part.size() >= 10 && date_part[4] == L'-' && date_part[7] == L'-') {
        std::wstring yyyy = date_part.substr(0, 4);
        std::wstring mm = date_part.substr(5, 2);
        std::wstring dd = date_part.substr(8, 2);
        date_part = dd + L"." + mm + L"." + yyyy;
    }

    if (time_part.empty()) {
        time_part = L"00:00:00";
    }
    return date_part + L" " + time_part;
}

std::wstring BuildSubscriptionLabel() {
    std::wstring expires;
    EnterCriticalSection(&g_programs_lock);
    int index = g_selected_index;
    if (index < 0 && !g_programs.empty()) {
        index = 0;
    }
    if (index >= 0 && static_cast<size_t>(index) < g_programs.size()) {
        expires = g_programs[static_cast<size_t>(index)].expires_at;
    }
    LeaveCriticalSection(&g_programs_lock);
    if (expires.empty()) {
        return expires;
    }
    if (IsLifetimeSubscription(expires)) {
        return L"Lifetime";
    }
    expires = NormalizeSubscriptionDate(expires);
    if (!expires.empty() && expires.front() != L'[') {
        expires = L"[" + expires + L"]";
    }
    return expires;
}

void UpdateTelemetryFeed(std::vector<TelemetryLine>* lines, std::wstring* last_status) {
    if (!lines || !last_status) {
        return;
    }
    std::wstring status = GetStatusSnapshot();
    if (status.empty() || status == *last_status) {
        return;
    }
    *last_status = status;
    std::vector<std::wstring> messages;
    if (ContainsInsensitive(status, L"waiting for game")) {
        messages.emplace_back(L"Loaded \x2022 waiting for game...");
        messages.emplace_back(L"Waiting: start the game to attach");
        std::wstring target = BuildTargetLabel();
        if (!target.empty()) {
            messages.emplace_back(L"Target: " + target);
        }
        std::wstring subscription = BuildSubscriptionLabel();
        if (!subscription.empty()) {
            messages.emplace_back(L"Subscription: " + subscription);
        }
    } else if (ContainsInsensitive(status, L"connected")) {
        messages.emplace_back(L"Connected \x2022 session ready");
        std::wstring target = BuildTargetLabel();
        if (!target.empty()) {
            messages.emplace_back(L"Target: " + target);
        }
        std::wstring subscription = BuildSubscriptionLabel();
        if (!subscription.empty()) {
            messages.emplace_back(L"Subscription till: " + subscription);
        }
    } else {
        messages.push_back(status);
    }

    ULONGLONG tick = GetTickCount64();
    std::wstring stamp = FormatTimestamp();
    for (auto it = messages.rbegin(); it != messages.rend(); ++it) {
        TelemetryLine line{stamp, *it, tick};
        lines->insert(lines->begin(), std::move(line));
    }
    constexpr size_t kMaxLines = 7;
    if (lines->size() > kMaxLines) {
        lines->resize(kMaxLines);
    }
}

std::wstring BuildLabelText(const char* value) {
    std::wstring out;
    if (!value) {
        return out;
    }
    size_t len = strlen(value);
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(static_cast<wchar_t>(value[i]));
    }
    return out;
}

const wchar_t* TitleForStage(UiStage stage) {
    switch (stage) {
        case UiStage::Login:
            return L"PRODUCT KEY";
        case UiStage::Connecting:
            return L"INITIALIZING";
        case UiStage::Loading:
            return IsRectEmpty(&g_card_programs) ? L"LOADING" : L"U3WARE";
        case UiStage::Dashboard:
            return L"U3WARE";
        default:
            return L"U3WARE";
    }
}

std::wstring ToLowerCopy(const std::wstring& value) {
    std::wstring out = value;
    for (wchar_t& ch : out) {
        if (ch >= L'A' && ch <= L'Z') {
            ch = static_cast<wchar_t>(ch - L'A' + L'a');
        }
    }
    return out;
}

bool ContainsInsensitive(const std::wstring& value, const wchar_t* needle) {
    if (!needle || !*needle) {
        return false;
    }
    std::wstring hay = ToLowerCopy(value);
    std::wstring find = ToLowerCopy(needle);
    return hay.find(find) != std::wstring::npos;
}

bool StartsWithInsensitive(const std::wstring& value, const wchar_t* prefix) {
    if (!prefix || !*prefix) {
        return false;
    }
    std::wstring hay = ToLowerCopy(value);
    std::wstring find = ToLowerCopy(prefix);
    if (hay.size() < find.size()) {
        return false;
    }
    return hay.compare(0, find.size(), find) == 0;
}

std::wstring DeriveModeFromStatus(const std::wstring& status) {
    if (ContainsInsensitive(status, L"waiting")) {
        return L"WAITING";
    }
    if (ContainsInsensitive(status, L"loading") ||
        ContainsInsensitive(status, L"preparing") ||
        ContainsInsensitive(status, L"downloading") ||
        ContainsInsensitive(status, L"requesting") ||
        ContainsInsensitive(status, L"analyzing") ||
        ContainsInsensitive(status, L"initial") ||
        ContainsInsensitive(status, L"starting") ||
        ContainsInsensitive(status, L"verifying")) {
        return L"RUNNING";
    }
    return L"READY";
}

std::wstring DerivePhaseFromStatus(const std::wstring& status) {
    if (ContainsInsensitive(status, L"waiting")) {
        return L"ready";
    }
    if (ContainsInsensitive(status, L"validating") ||
        ContainsInsensitive(status, L"license") ||
        ContainsInsensitive(status, L"key")) {
        return L"auth";
    }
    if (ContainsInsensitive(status, L"connecting") ||
        ContainsInsensitive(status, L"sync") ||
        ContainsInsensitive(status, L"requesting") ||
        ContainsInsensitive(status, L"analyzing") ||
        ContainsInsensitive(status, L"prepar") ||
        ContainsInsensitive(status, L"download")) {
        return L"sync";
    }
    if (ContainsInsensitive(status, L"verify") ||
        ContainsInsensitive(status, L"load") ||
        ContainsInsensitive(status, L"initial") ||
        ContainsInsensitive(status, L"signature") ||
        ContainsInsensitive(status, L"hash")) {
        return L"verify";
    }
    if (ContainsInsensitive(status, L"ready") ||
        ContainsInsensitive(status, L"connected") ||
        ContainsInsensitive(status, L"choose")) {
        return L"ready";
    }
    return L"idle";
}

std::wstring FormatUptimeValue(ULONGLONG seconds) {
    unsigned int minutes = static_cast<unsigned int>(seconds / 60ULL);
    unsigned int secs = static_cast<unsigned int>(seconds % 60ULL);
    wchar_t buffer[16] = {};
    swprintf_s(buffer, L"%02u:%02u", minutes, secs);
    return std::wstring(buffer);
}

float ProgressForModePhase(const std::wstring& mode, const std::wstring& phase) {
    if (mode == L"WAITING") {
        return 100.0f;
    }
    if (mode == L"RUNNING") {
        if (phase == L"auth") {
            return 25.0f;
        }
        if (phase == L"sync") {
            return 55.0f;
        }
        if (phase == L"verify") {
            return 80.0f;
        }
        if (phase == L"ready") {
            return 95.0f;
        }
        return 15.0f;
    }
    return 0.0f;
}

} // namespace

class DxUiRendererImpl {
public:
    explicit DxUiRendererImpl(HWND hwnd)
        : hwnd_(hwnd)
        , dpi_(96.0f) {}

    bool Initialize();
    void Shutdown();
    void SetDpi(UINT dpi);
    void Resize(UINT width, UINT height);
    void Render();

private:
    bool CreateDeviceResources();
    void CreateSizeDependentResources();
    void DiscardDeviceResources();

    void DrawBackground();
    void DrawPanel();
    void DrawTopBar();
    void DrawCards();
    void DrawStageContent();
    void DrawLoadingContent();
    void DrawDashboardContent();
    void DrawProductsList();
    void DrawProductItem(const D2D1_RECT_F& rect, const ProgramInfo& program, bool selected, bool hovered);
    void DrawTitle();
    void DrawStatusPills();
    void DrawTitleButtons();
    void DrawCardMeta(const RECT& rc, const std::wstring& text);
    void DrawActionsSubgrid(const D2D1_RECT_F& card,
                            const D2D1_RECT_F* status_rect,
                            const std::wstring& mode,
                            const std::wstring& phase);
    void DrawActionButton();
    void UpdateSessionState(const std::wstring& mode);
    void DrawCardRect(const RECT& rc);
    void DrawField(const RECT& rc, bool focused, bool error);
    void DrawSpinner(D2D1_POINT_2F center, float radius);
    void DrawCardHeader(const RECT& rc, const wchar_t* text);
    bool LoadBitmapFromFile(const wchar_t* path, ID2D1Bitmap** bitmap);
    ID2D1Bitmap* GetAvatarBitmap(const std::wstring& path);
    bool GetChildRect(HWND child, D2D1_RECT_F* out) const;
    float MeasureTextWidth(const std::wstring& text, IDWriteTextFormat* format) const;
    static std::wstring GetWindowTextString(HWND hwnd);

    float ToDip(float px) const {
        float scale = dpi_ <= 0.0f ? 1.0f : (dpi_ / 96.0f);
        return px / scale;
    }

    D2D1_RECT_F RectFromPixels(const RECT& rc) const {
        return D2D1::RectF(ToDip(static_cast<float>(rc.left)),
                           ToDip(static_cast<float>(rc.top)),
                           ToDip(static_cast<float>(rc.right)),
                           ToDip(static_cast<float>(rc.bottom)));
    }

    HWND hwnd_;
    float dpi_;
    D2D1_SIZE_F size_ = D2D1::SizeF(0.0f, 0.0f);

    Theme theme_ = GetTheme();

    ComPtr<ID2D1Factory> factory_;
    ComPtr<IDWriteFactory> dwrite_factory_;
    ComPtr<IWICImagingFactory> wic_factory_;
    ComPtr<ID2D1HwndRenderTarget> render_target_;

    ComPtr<IDWriteTextFormat> title_format_;
    ComPtr<IDWriteTextFormat> pill_format_;
    ComPtr<IDWriteTextFormat> label_format_;
    ComPtr<IDWriteTextFormat> status_format_;
    ComPtr<IDWriteTextFormat> mono_format_;
    ComPtr<IDWriteTextFormat> telemetry_format_;
    ComPtr<IDWriteRenderingParams> gdi_rendering_params_;

    ComPtr<ID2D1SolidColorBrush> text_brush_;
    ComPtr<ID2D1SolidColorBrush> muted_brush_;
    ComPtr<ID2D1SolidColorBrush> faint_brush_;
    ComPtr<ID2D1SolidColorBrush> panel_brush_;
    ComPtr<ID2D1SolidColorBrush> panel_border_brush_;
    ComPtr<ID2D1SolidColorBrush> field_fill_brush_;
    ComPtr<ID2D1SolidColorBrush> field_border_brush_;
    ComPtr<ID2D1SolidColorBrush> field_focus_brush_;
    ComPtr<ID2D1SolidColorBrush> field_focus_glow_brush_;
    ComPtr<ID2D1SolidColorBrush> card_border_brush_;
    ComPtr<ID2D1SolidColorBrush> shadow_brush_;
    ComPtr<ID2D1SolidColorBrush> grid_brush_;
    ComPtr<ID2D1SolidColorBrush> accent_brush_;
    ComPtr<ID2D1SolidColorBrush> accent2_brush_;
    ComPtr<ID2D1SolidColorBrush> warn_brush_;
    ComPtr<ID2D1StrokeStyle> round_stroke_;

    ComPtr<ID2D1GradientStopCollection> bg_stops_;
    ComPtr<ID2D1GradientStopCollection> card_stops_;
    ComPtr<ID2D1GradientStopCollection> progress_stops_;
    ComPtr<ID2D1GradientStopCollection> mark_spin_stops_;
    ComPtr<ID2D1GradientStopCollection> glow_stops_;
    ComPtr<ID2D1GradientStopCollection> glow2_stops_;
    ComPtr<ID2D1GradientStopCollection> hover_stops_;

    ComPtr<ID2D1LinearGradientBrush> bg_brush_;
    ComPtr<ID2D1LinearGradientBrush> progress_brush_;
    ComPtr<ID2D1LinearGradientBrush> mark_spin_brush_;
    ComPtr<ID2D1RadialGradientBrush> glow_brush_;
    ComPtr<ID2D1RadialGradientBrush> glow2_brush_;
    ComPtr<ID2D1RadialGradientBrush> hover_brush_;
    ComPtr<ID2D1Bitmap> noise_bitmap_;
    ComPtr<ID2D1BitmapBrush> noise_brush_;
    std::unordered_map<std::wstring, ComPtr<ID2D1Bitmap>> avatar_cache_;

    D2D1_RECT_F panel_rect_ = D2D1::RectF(0, 0, 0, 0);
    std::vector<TelemetryLine> telemetry_lines_;
    std::wstring telemetry_last_status_;
    bool session_active_ = false;
    ULONGLONG session_start_tick_ = 0;
    std::wstring last_run_label_;
    float telemetry_progress_ = 0.0f;
    float telemetry_progress_target_ = 0.0f;
    ULONGLONG telemetry_progress_tick_ = 0;
    float telemetry_scan_ = 0.0f;
    ULONGLONG telemetry_scan_tick_ = 0;
    bool com_initialized_ = false;
};

bool DxUiRendererImpl::Initialize() {
    HRESULT hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, factory_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                             reinterpret_cast<IUnknown**>(dwrite_factory_.GetAddressOf()));
    if (FAILED(hr)) {
        return false;
    }
    if (!wic_factory_) {
        HRESULT wic_hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                          IID_PPV_ARGS(wic_factory_.GetAddressOf()));
        if (wic_hr == CO_E_NOTINITIALIZED) {
            HRESULT init_hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (SUCCEEDED(init_hr)) {
                com_initialized_ = true;
                wic_hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                          IID_PPV_ARGS(wic_factory_.GetAddressOf()));
            }
        }
    }
    ComPtr<IDWriteRenderingParams> default_params;
    if (SUCCEEDED(dwrite_factory_->CreateRenderingParams(default_params.GetAddressOf())) && default_params) {
        float gamma = default_params->GetGamma();
        float contrast = default_params->GetEnhancedContrast();
        float clear_type = default_params->GetClearTypeLevel();
        DWRITE_PIXEL_GEOMETRY pixel = default_params->GetPixelGeometry();
        dwrite_factory_->CreateCustomRenderingParams(gamma, contrast, clear_type, pixel,
                                                     DWRITE_RENDERING_MODE_NATURAL,
                                                     gdi_rendering_params_.GetAddressOf());
    }
    return CreateDeviceResources();
}

void DxUiRendererImpl::Shutdown() {
    DiscardDeviceResources();
    wic_factory_.Reset();
    dwrite_factory_.Reset();
    factory_.Reset();
    if (com_initialized_) {
        CoUninitialize();
        com_initialized_ = false;
    }
}

void DxUiRendererImpl::SetDpi(UINT dpi) {
    dpi_ = static_cast<float>(dpi);
    if (render_target_) {
        render_target_->SetDpi(dpi_, dpi_);
    }
}

void DxUiRendererImpl::Resize(UINT width, UINT height) {
    if (!render_target_ || width == 0 || height == 0) {
        return;
    }
    D2D1_SIZE_U size = D2D1::SizeU(width, height);
    render_target_->Resize(size);
    size_ = render_target_->GetSize();
    CreateSizeDependentResources();
}

void DxUiRendererImpl::Render() {
    if (!render_target_) {
        if (!CreateDeviceResources()) {
            return;
        }
    }

    size_ = render_target_->GetSize();
    if (size_.width <= 0.0f || size_.height <= 0.0f) {
        return;
    }

    render_target_->BeginDraw();
    render_target_->SetTransform(D2D1::Matrix3x2F::Identity());

    DrawBackground();
    DrawPanel();
    DrawTopBar();
    DrawCards();
    DrawStageContent();
    DrawTitle();
    DrawStatusPills();
    DrawTitleButtons();

    HRESULT hr = render_target_->EndDraw();
    if (hr == D2DERR_RECREATE_TARGET) {
        DiscardDeviceResources();
    }
}

bool DxUiRendererImpl::CreateDeviceResources() {
    if (render_target_) {
        return true;
    }

    RECT rc = {};
    GetClientRect(hwnd_, &rc);
    D2D1_SIZE_U size = D2D1::SizeU(static_cast<UINT>((std::max)(0L, rc.right - rc.left)),
                                   static_cast<UINT>((std::max)(0L, rc.bottom - rc.top)));

    HRESULT hr = factory_->CreateHwndRenderTarget(
        D2D1::RenderTargetProperties(),
        D2D1::HwndRenderTargetProperties(hwnd_, size),
        render_target_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    render_target_->SetDpi(dpi_, dpi_);
    size_ = render_target_->GetSize();
    render_target_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE);
    if (gdi_rendering_params_) {
        render_target_->SetTextRenderingParams(gdi_rendering_params_.Get());
    }

    hr = render_target_->CreateSolidColorBrush(theme_.text, text_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(theme_.muted, muted_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(theme_.faint, faint_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(theme_.surface, panel_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(theme_.stroke, panel_border_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(ColorFromHex(0x1E2229), field_fill_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(ColorFromHex(0xFFFFFF, 0.10f), field_border_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    D2D1_COLOR_F focus = theme_.accent;
    focus.a = 0.45f;
    hr = render_target_->CreateSolidColorBrush(focus, field_focus_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    D2D1_COLOR_F focus_glow = theme_.accent;
    focus_glow.a = 0.12f;
    hr = render_target_->CreateSolidColorBrush(focus_glow, field_focus_glow_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(ColorFromHex(0xFFFFFF, 0.09f), card_border_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(ColorFromHex(0x000000, 0.35f), shadow_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(ColorFromHex(0xFFFFFF, 0.04f), grid_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(theme_.accent, accent_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(theme_.accent2, accent2_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = render_target_->CreateSolidColorBrush(theme_.warn, warn_brush_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    D2D1_STROKE_STYLE_PROPERTIES stroke = D2D1::StrokeStyleProperties();
    stroke.startCap = D2D1_CAP_STYLE_ROUND;
    stroke.endCap = D2D1_CAP_STYLE_ROUND;
    stroke.dashCap = D2D1_CAP_STYLE_ROUND;
    stroke.lineJoin = D2D1_LINE_JOIN_ROUND;
    hr = factory_->CreateStrokeStyle(stroke, nullptr, 0, round_stroke_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    hr = dwrite_factory_->CreateTextFormat(L"Verdana", nullptr, DWRITE_FONT_WEIGHT_SEMI_BOLD,
                                           DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.0f, L"en-us",
                                           title_format_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    title_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    title_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    hr = dwrite_factory_->CreateTextFormat(L"Verdana", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
                                           DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 11.0f, L"en-us",
                                           pill_format_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    pill_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    pill_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    hr = dwrite_factory_->CreateTextFormat(L"Verdana", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
                                           DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 11.0f, L"en-us",
                                           label_format_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    label_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    label_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

    hr = dwrite_factory_->CreateTextFormat(L"Verdana", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
                                           DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.0f, L"en-us",
                                           status_format_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    status_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    status_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

    hr = dwrite_factory_->CreateTextFormat(L"Verdana", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
                                           DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 11.0f, L"en-us",
                                           mono_format_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    mono_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    mono_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

    hr = dwrite_factory_->CreateTextFormat(L"Verdana", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
                                           DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.0f, L"en-us",
                                           telemetry_format_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    telemetry_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    telemetry_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

    D2D1_GRADIENT_STOP bg_stops[] = {
        {0.0f, theme_.bg2},
        {1.0f, theme_.bg},
    };
    hr = render_target_->CreateGradientStopCollection(bg_stops, 2, bg_stops_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    D2D1_GRADIENT_STOP card_stops[] = {
        {0.0f, ColorFromHex(0xFFFFFF, 0.04f)},
        {1.0f, ColorFromHex(0x000000, 0.18f)},
    };
    hr = render_target_->CreateGradientStopCollection(card_stops, 2, card_stops_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    D2D1_GRADIENT_STOP progress_stops[] = {
        {0.0f, theme_.accent},
        {1.0f, theme_.accent2},
    };
    hr = render_target_->CreateGradientStopCollection(progress_stops, 2, progress_stops_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    D2D1_COLOR_F spin_fade = theme_.accent;
    spin_fade.a = 0.0f;
    D2D1_COLOR_F spin_core = theme_.accent;
    spin_core.a = 0.22f;
    D2D1_GRADIENT_STOP mark_spin_stops[] = {
        {0.0f, spin_fade},
        {0.5f, spin_core},
        {1.0f, spin_fade},
    };
    hr = render_target_->CreateGradientStopCollection(mark_spin_stops, 3, mark_spin_stops_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    D2D1_COLOR_F glow_start = theme_.accent;
    glow_start.a = 0.10f;
    D2D1_COLOR_F glow_end = theme_.accent;
    glow_end.a = 0.0f;
    D2D1_GRADIENT_STOP glow_stops[] = {
        {0.0f, glow_start},
        {1.0f, glow_end},
    };
    hr = render_target_->CreateGradientStopCollection(glow_stops, 2, glow_stops_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    D2D1_COLOR_F glow2_start = theme_.accent2;
    glow2_start.a = 0.08f;
    D2D1_COLOR_F glow2_end = theme_.accent2;
    glow2_end.a = 0.0f;
    D2D1_GRADIENT_STOP glow2_stops[] = {
        {0.0f, glow2_start},
        {1.0f, glow2_end},
    };
    hr = render_target_->CreateGradientStopCollection(glow2_stops, 2, glow2_stops_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    D2D1_COLOR_F hover_start = theme_.accent;
    hover_start.a = 0.18f;
    D2D1_COLOR_F hover_end = theme_.accent;
    hover_end.a = 0.0f;
    D2D1_GRADIENT_STOP hover_stops[] = {
        {0.0f, hover_start},
        {1.0f, hover_end},
    };
    hr = render_target_->CreateGradientStopCollection(hover_stops, 2, hover_stops_.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    {
        constexpr UINT kNoiseSize = 64;
        std::vector<uint32_t> noise(static_cast<size_t>(kNoiseSize) * kNoiseSize);
        uint32_t seed = 0xA5125A5Fu;
        for (size_t i = 0; i < noise.size(); ++i) {
            seed = seed * 1664525u + 1013904223u;
            uint8_t value = static_cast<uint8_t>(seed >> 24);
            noise[i] = (0xFFu << 24) | (static_cast<uint32_t>(value) << 16) |
                       (static_cast<uint32_t>(value) << 8) | static_cast<uint32_t>(value);
        }

        D2D1_BITMAP_PROPERTIES props = {};
        props.pixelFormat = D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED);
        props.dpiX = dpi_;
        props.dpiY = dpi_;

        hr = render_target_->CreateBitmap(D2D1::SizeU(kNoiseSize, kNoiseSize),
                                          noise.data(),
                                          kNoiseSize * sizeof(uint32_t),
                                          props,
                                          noise_bitmap_.GetAddressOf());
        if (SUCCEEDED(hr) && noise_bitmap_) {
            D2D1_BITMAP_BRUSH_PROPERTIES brush_props =
                D2D1::BitmapBrushProperties(D2D1_EXTEND_MODE_WRAP,
                                            D2D1_EXTEND_MODE_WRAP,
                                            D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR);
            hr = render_target_->CreateBitmapBrush(noise_bitmap_.Get(), brush_props, noise_brush_.GetAddressOf());
            if (SUCCEEDED(hr) && noise_brush_) {
                float scale = 240.0f / static_cast<float>(kNoiseSize);
                noise_brush_->SetTransform(D2D1::Matrix3x2F::Scale(scale, scale));
            }
        }
    }

    CreateSizeDependentResources();
    return true;
}

void DxUiRendererImpl::CreateSizeDependentResources() {
    if (!render_target_) {
        return;
    }

    bg_brush_.Reset();
    progress_brush_.Reset();
    mark_spin_brush_.Reset();
    glow_brush_.Reset();
    glow2_brush_.Reset();
    hover_brush_.Reset();

    D2D1_POINT_2F start = D2D1::Point2F(0.0f, 0.0f);
    D2D1_POINT_2F end = D2D1::Point2F(0.0f, size_.height);
    render_target_->CreateLinearGradientBrush(D2D1::LinearGradientBrushProperties(start, end), bg_stops_.Get(),
                                              bg_brush_.GetAddressOf());

    render_target_->CreateLinearGradientBrush(
        D2D1::LinearGradientBrushProperties(D2D1::Point2F(0.0f, 0.0f), D2D1::Point2F(100.0f, 0.0f)),
        progress_stops_.Get(), progress_brush_.GetAddressOf());

    if (mark_spin_stops_) {
        render_target_->CreateLinearGradientBrush(
            D2D1::LinearGradientBrushProperties(D2D1::Point2F(0.0f, 0.0f), D2D1::Point2F(1.0f, 0.0f)),
            mark_spin_stops_.Get(), mark_spin_brush_.GetAddressOf());
    }

    render_target_->CreateRadialGradientBrush(
        D2D1::RadialGradientBrushProperties(D2D1::Point2F(0.0f, 0.0f), D2D1::Point2F(0.0f, 0.0f), 1.0f, 1.0f),
        glow_stops_.Get(), glow_brush_.GetAddressOf());

    render_target_->CreateRadialGradientBrush(
        D2D1::RadialGradientBrushProperties(D2D1::Point2F(0.0f, 0.0f), D2D1::Point2F(0.0f, 0.0f), 1.0f, 1.0f),
        glow2_stops_.Get(), glow2_brush_.GetAddressOf());

    render_target_->CreateRadialGradientBrush(
        D2D1::RadialGradientBrushProperties(D2D1::Point2F(0.0f, 0.0f), D2D1::Point2F(0.0f, 0.0f), 1.0f, 1.0f),
        hover_stops_.Get(), hover_brush_.GetAddressOf());
}

void DxUiRendererImpl::DiscardDeviceResources() {
    bg_brush_.Reset();
    progress_brush_.Reset();
    mark_spin_brush_.Reset();
    glow_brush_.Reset();
    glow2_brush_.Reset();
    hover_brush_.Reset();
    noise_brush_.Reset();
    noise_bitmap_.Reset();
    avatar_cache_.clear();
    bg_stops_.Reset();
    card_stops_.Reset();
    progress_stops_.Reset();
    mark_spin_stops_.Reset();
    glow_stops_.Reset();
    glow2_stops_.Reset();
    hover_stops_.Reset();
    text_brush_.Reset();
    muted_brush_.Reset();
    faint_brush_.Reset();
    panel_brush_.Reset();
    panel_border_brush_.Reset();
    field_fill_brush_.Reset();
    field_border_brush_.Reset();
    field_focus_brush_.Reset();
    field_focus_glow_brush_.Reset();
    card_border_brush_.Reset();
    shadow_brush_.Reset();
    grid_brush_.Reset();
    accent_brush_.Reset();
    accent2_brush_.Reset();
    warn_brush_.Reset();
    round_stroke_.Reset();
    title_format_.Reset();
    pill_format_.Reset();
    label_format_.Reset();
    status_format_.Reset();
    mono_format_.Reset();
    telemetry_format_.Reset();
    render_target_.Reset();
    telemetry_progress_ = 0.0f;
    telemetry_progress_target_ = 0.0f;
    telemetry_progress_tick_ = 0;
    telemetry_scan_ = 0.0f;
    telemetry_scan_tick_ = 0;
}

void DxUiRendererImpl::DrawBackground() {
    D2D1_RECT_F rc = D2D1::RectF(0.0f, 0.0f, size_.width, size_.height);
    render_target_->Clear(theme_.bg);
    if (bg_brush_) {
        render_target_->FillRectangle(rc, bg_brush_.Get());
    }

    if (glow_brush_) {
        float radius = (std::max)(size_.width, size_.height) * 0.7f;
        D2D1_POINT_2F center = D2D1::Point2F(size_.width * 0.1f, size_.height * 0.1f);
        glow_brush_->SetCenter(center);
        glow_brush_->SetRadiusX(radius);
        glow_brush_->SetRadiusY(radius);
        render_target_->FillEllipse(D2D1::Ellipse(center, radius, radius), glow_brush_.Get());
    }

    if (glow2_brush_) {
        float radius = (std::max)(size_.width, size_.height) * 0.55f;
        D2D1_POINT_2F center = D2D1::Point2F(size_.width * 0.9f, size_.height * 0.2f);
        glow2_brush_->SetCenter(center);
        glow2_brush_->SetRadiusX(radius);
        glow2_brush_->SetRadiusY(radius);
        render_target_->FillEllipse(D2D1::Ellipse(center, radius, radius), glow2_brush_.Get());
    }

    const float step = 44.0f;
    if (grid_brush_) {
        float center_x = size_.width * 0.5f;
        float center_y = size_.height * 0.35f;
        float max_dist = (std::max)(size_.width, size_.height) * 0.65f;
        float base_alpha = 0.16f;

        auto line_alpha = [&](float x, float y) {
            float dx = x - center_x;
            float dy = y - center_y;
            float dist = std::sqrt(dx * dx + dy * dy);
            float t = (std::min)(1.0f, dist / max_dist);
            float mask = 1.0f - t;
            mask *= mask;
            return base_alpha * mask;
        };

        for (float x = 0.0f; x <= size_.width; x += step) {
            grid_brush_->SetOpacity(line_alpha(x, center_y));
            render_target_->DrawLine(D2D1::Point2F(x, 0.0f), D2D1::Point2F(x, size_.height), grid_brush_.Get(), 1.0f);
        }
        for (float y = 0.0f; y <= size_.height; y += step) {
            grid_brush_->SetOpacity(line_alpha(center_x, y));
            render_target_->DrawLine(D2D1::Point2F(0.0f, y), D2D1::Point2F(size_.width, y), grid_brush_.Get(), 1.0f);
        }
        grid_brush_->SetOpacity(1.0f);
    }

    if (noise_brush_) {
        noise_brush_->SetOpacity(0.06f);
        render_target_->FillRectangle(rc, noise_brush_.Get());
        noise_brush_->SetOpacity(1.0f);
    }
}

void DxUiRendererImpl::DrawPanel() {
    panel_rect_ = D2D1::RectF(0.0f, 0.0f, size_.width, size_.height);
    const float radius = 18.0f;
    const float inset = 0.5f;
    D2D1_RECT_F panel_rect = panel_rect_;
    panel_rect.left += inset;
    panel_rect.top += inset;
    panel_rect.right -= inset;
    panel_rect.bottom -= inset;
    D2D1_ROUNDED_RECT panel = D2D1::RoundedRect(panel_rect, radius - inset, radius - inset);
    if (panel_brush_) {
        render_target_->FillRoundedRectangle(panel, panel_brush_.Get());
    }
    if (g_mouse_in_window && hover_brush_) {
        D2D1_POINT_2F mouse = D2D1::Point2F(ToDip(static_cast<float>(g_mouse_pos.x)),
                                            ToDip(static_cast<float>(g_mouse_pos.y)));
        if (mouse.x >= panel_rect.left && mouse.x <= panel_rect.right &&
            mouse.y >= panel_rect.top && mouse.y <= panel_rect.bottom) {
            float panel_w = panel_rect.right - panel_rect.left;
            float panel_h = panel_rect.bottom - panel_rect.top;
            float radius_x = (std::max)(160.0f, panel_w * 0.28f);
            float radius_y = (std::max)(110.0f, panel_h * 0.18f);
            hover_brush_->SetCenter(mouse);
            hover_brush_->SetRadiusX(radius_x);
            hover_brush_->SetRadiusY(radius_y);
            hover_brush_->SetOpacity(0.6f);
            ComPtr<ID2D1RoundedRectangleGeometry> clip;
            bool clipped = false;
            if (factory_ &&
                SUCCEEDED(factory_->CreateRoundedRectangleGeometry(panel, clip.GetAddressOf())) &&
                clip) {
                render_target_->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), clip.Get()), nullptr);
                clipped = true;
            }
            render_target_->FillEllipse(D2D1::Ellipse(mouse, radius_x, radius_y), hover_brush_.Get());
            if (clipped) {
                render_target_->PopLayer();
            }
            hover_brush_->SetOpacity(1.0f);
        }
    }
    if (panel_border_brush_) {
        render_target_->DrawRoundedRectangle(panel, panel_border_brush_.Get(), 1.0f);
    }
}

void DxUiRendererImpl::DrawTopBar() {
    float topbar_height = ToDip(static_cast<float>(g_titlebar_height > 0 ? g_titlebar_height : 46));
    D2D1_RECT_F bar = panel_rect_;
    bar.bottom = bar.top + topbar_height;

    if (panel_border_brush_) {
        render_target_->DrawLine(D2D1::Point2F(bar.left, bar.bottom - 0.5f),
                                 D2D1::Point2F(bar.right, bar.bottom - 0.5f), panel_border_brush_.Get(), 1.0f);
    }

    if (accent_brush_) {
        D2D1_RECT_F accent = bar;
        accent.left += 18.0f;
        accent.right -= 18.0f;
        accent.top = bar.bottom - 3.0f;
        accent.bottom = bar.bottom - 2.0f;
        render_target_->FillRectangle(accent, accent_brush_.Get());
    }
}

void DxUiRendererImpl::DrawCards() {
    if (!IsRectEmpty(&g_card_auth)) {
        DrawCardRect(g_card_auth);
    }
    if (!IsRectEmpty(&g_card_programs)) {
        DrawCardRect(g_card_programs);
    }
    if (!IsRectEmpty(&g_card_telemetry)) {
        DrawCardRect(g_card_telemetry);
    }
}

void DxUiRendererImpl::DrawStageContent() {
    if (g_stage == UiStage::Login) {
        if (IsRectEmpty(&g_field_key)) {
            return;
        }

        std::wstring status = GetWindowTextString(g_status);
        std::string error_code_snapshot;
        EnterCriticalSection(&g_status_lock);
        error_code_snapshot = g_last_error_code;
        LeaveCriticalSection(&g_status_lock);
        LoginChip chip = BuildLoginChip(status, error_code_snapshot);
        bool error_field = chip.show && chip.warn;

        DrawField(g_field_key, GetFocus() == g_edit, error_field);

        if (label_format_ && faint_brush_) {
            label_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            D2D1_RECT_F label_rect = {};
            if (GetChildRect(g_label_key, &label_rect)) {
                std::wstring label = GetWindowTextString(g_label_key);
                if (!label.empty()) {
                    render_target_->DrawTextW(label.c_str(), static_cast<UINT32>(label.size()), label_format_.Get(),
                                              label_rect, faint_brush_.Get());
                }
            }
        }

        if (status_format_ && muted_brush_) {
            status_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            D2D1_RECT_F status_rect = {};
            if (GetChildRect(g_status, &status_rect)) {
                if (chip.show && pill_format_) {
                    float chip_height = 22.0f;
                    float pad_x = 8.0f;
                    float gap = 8.0f;
                    float tag_width = MeasureTextWidth(chip.tag, pill_format_.Get()) + pad_x * 2.0f;
                    float y = (status_rect.top + status_rect.bottom - chip_height) * 0.5f;
                    D2D1_RECT_F tag_rect = D2D1::RectF(status_rect.left, y, status_rect.left + tag_width,
                                                       y + chip_height);
                    D2D1_ROUNDED_RECT tag_round = D2D1::RoundedRect(tag_rect, chip_height * 0.5f, chip_height * 0.5f);

                    ID2D1SolidColorBrush* tone = chip.warn ? warn_brush_.Get() : accent_brush_.Get();
                    if (tone) {
                        tone->SetOpacity(0.12f);
                        render_target_->FillRoundedRectangle(tag_round, tone);
                        tone->SetOpacity(1.0f);
                        render_target_->DrawRoundedRectangle(tag_round, tone, 1.0f);
                    } else if (field_border_brush_) {
                        render_target_->DrawRoundedRectangle(tag_round, field_border_brush_.Get(), 1.0f);
                    }

                    pill_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
                    pill_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
                    if (tone) {
                        render_target_->DrawTextW(chip.tag.c_str(), static_cast<UINT32>(chip.tag.size()),
                                                  pill_format_.Get(), tag_rect, tone);
                    } else if (text_brush_) {
                        render_target_->DrawTextW(chip.tag.c_str(), static_cast<UINT32>(chip.tag.size()),
                                                  pill_format_.Get(), tag_rect, text_brush_.Get());
                    }
                    pill_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
                    pill_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

                    D2D1_RECT_F msg_rect = D2D1::RectF(tag_rect.right + gap, status_rect.top,
                                                       status_rect.right, status_rect.bottom);
                    ID2D1SolidColorBrush* msg_brush = chip.warn ? warn_brush_.Get() : muted_brush_.Get();
                    if (msg_brush) {
                        status_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
                        status_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
                        render_target_->DrawTextW(chip.message.c_str(), static_cast<UINT32>(chip.message.size()),
                                                  status_format_.Get(), msg_rect, msg_brush);
                        status_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
                    }
                } else if (!status.empty()) {
                    render_target_->DrawTextW(status.c_str(), static_cast<UINT32>(status.size()), status_format_.Get(),
                                              status_rect, muted_brush_.Get());
                }
            }
        }
        DrawActionButton();
        return;
    }

    if (g_stage == UiStage::Connecting) {
        DrawLoadingContent();
        return;
    }
    if (g_stage == UiStage::Loading) {
        if (!IsRectEmpty(&g_card_programs)) {
            DrawDashboardContent();
        } else {
            DrawLoadingContent();
        }
        return;
    }
    if (g_stage == UiStage::Dashboard) {
        DrawDashboardContent();
    }
}

void DxUiRendererImpl::DrawLoadingContent() {
    if (IsRectEmpty(&g_card_auth)) {
        return;
    }

    D2D1_RECT_F card = RectFromPixels(g_card_auth);
    float center_x = (card.left + card.right) * 0.5f;
    float mark_size = 44.0f;
    float mark_radius = 16.0f;
    float spinner_size = 34.0f;
    float spinner_radius = spinner_size * 0.5f;
    float status_height = 14.0f;
    float progress_height = 10.0f;
    float gap_mark = 12.0f;
    float gap_spinner = 10.0f;
    float gap_status = 12.0f;

    bool show_mark = false;
    float total = spinner_size + gap_spinner + status_height + gap_status + progress_height;
    if (show_mark) {
        total += mark_size + gap_mark;
    }
    float top = (card.top + card.bottom - total) * 0.5f;
    float min_top = card.top + 24.0f;
    if (top < min_top) {
        top = min_top;
    }

    auto draw_mark = [&](float x, float y, float size, float radius) {
        D2D1_RECT_F mark_rect = D2D1::RectF(x, y, x + size, y + size);
        D2D1_ROUNDED_RECT mark = D2D1::RoundedRect(mark_rect, radius, radius);
        float inset = 1.5f;
        float inner_radius = (std::max)(0.0f, radius - inset);
        D2D1_ROUNDED_RECT mark_inner =
            D2D1::RoundedRect(D2D1::RectF(x + inset, y + inset, x + size - inset, y + size - inset),
                              inner_radius, inner_radius);

        if (field_fill_brush_) {
            render_target_->FillRoundedRectangle(mark, field_fill_brush_.Get());
        }
        if (progress_brush_) {
            progress_brush_->SetStartPoint(D2D1::Point2F(x, y));
            progress_brush_->SetEndPoint(D2D1::Point2F(x + size, y + size));
            progress_brush_->SetOpacity(0.30f);
            render_target_->FillRoundedRectangle(mark, progress_brush_.Get());
            progress_brush_->SetOpacity(1.0f);
        } else if (accent_brush_) {
            accent_brush_->SetOpacity(0.30f);
            render_target_->FillRoundedRectangle(mark, accent_brush_.Get());
            accent_brush_->SetOpacity(1.0f);
        }
        if (text_brush_) {
            text_brush_->SetOpacity(0.16f);
            D2D1_POINT_2F glow_center = D2D1::Point2F(x + size * 0.3f, y + size * 0.3f);
            render_target_->FillEllipse(D2D1::Ellipse(glow_center, size * 0.35f, size * 0.35f),
                                        text_brush_.Get());
            text_brush_->SetOpacity(1.0f);
        }
        if (mark_spin_brush_) {
            ULONGLONG now = GetTickCount64();
            float angle = static_cast<float>((now % 5400ULL) / 5400.0f) * 6.2831853f;
            float sweep = size * 1.0f;
            D2D1_POINT_2F center = D2D1::Point2F(x + size * 0.5f, y + size * 0.5f);
            float dx = std::cos(angle);
            float dy = std::sin(angle);
            mark_spin_brush_->SetStartPoint(D2D1::Point2F(center.x - dx * sweep, center.y - dy * sweep));
            mark_spin_brush_->SetEndPoint(D2D1::Point2F(center.x + dx * sweep, center.y + dy * sweep));
            mark_spin_brush_->SetOpacity(0.55f);
            render_target_->FillRoundedRectangle(mark_inner, mark_spin_brush_.Get());
            mark_spin_brush_->SetOpacity(1.0f);
        }
        if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(mark, field_border_brush_.Get(), 1.0f);
        } else if (panel_border_brush_) {
            render_target_->DrawRoundedRectangle(mark, panel_border_brush_.Get(), 1.0f);
        }
    };

    float cursor_y = top;
    if (show_mark) {
        float mark_x = center_x - mark_size * 0.5f;
        float mark_y = cursor_y;
        draw_mark(mark_x, mark_y, mark_size, mark_radius);
        cursor_y += mark_size + gap_mark;
    }

    float spinner_center_y = cursor_y + spinner_radius;
    DrawSpinner(D2D1::Point2F(center_x, spinner_center_y), spinner_radius);

    std::wstring status = GetWindowTextString(g_status);
    float status_y = cursor_y + spinner_size + gap_spinner;
    if (!status.empty() && faint_brush_) {
        D2D1_RECT_F status_rect = D2D1::RectF(card.left + 20.0f, status_y, card.right - 20.0f,
                                              status_y + status_height);
        IDWriteTextFormat* status_format = mono_format_ ? mono_format_.Get() : status_format_.Get();
        if (status_format) {
            status_format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
            status_format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            render_target_->DrawTextW(status.c_str(), static_cast<UINT32>(status.size()), status_format, status_rect,
                                      faint_brush_.Get());
            status_format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            status_format->SetParagraphAlignment(status_format == mono_format_.Get()
                                                     ? DWRITE_PARAGRAPH_ALIGNMENT_NEAR
                                                     : DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        }
    }

    float bar_width = (std::min)(320.0f, card.right - card.left - 80.0f);
    float bar_x = center_x - bar_width * 0.5f;
    float bar_y = status_y + status_height + gap_status;
    D2D1_RECT_F bar = D2D1::RectF(bar_x, bar_y, bar_x + bar_width, bar_y + progress_height);
    float bar_radius = progress_height * 0.5f;
    D2D1_ROUNDED_RECT bar_round = D2D1::RoundedRect(bar, bar_radius, bar_radius);

    if (field_fill_brush_) {
        render_target_->FillRoundedRectangle(bar_round, field_fill_brush_.Get());
    }
    if (field_border_brush_) {
        render_target_->DrawRoundedRectangle(bar_round, field_border_brush_.Get(), 1.0f);
    }

    ULONGLONG now = GetTickCount64();
    float t = static_cast<float>((now % 1100ULL) / 1100.0f);
    float seg_width = bar_width * 0.36f;
    float travel = bar_width + seg_width;
    float seg_x = bar.left + t * travel - seg_width;
    D2D1_RECT_F seg = D2D1::RectF(seg_x, bar.top, seg_x + seg_width, bar.bottom);

    if (progress_brush_) {
        progress_brush_->SetStartPoint(D2D1::Point2F(seg.left, seg.top));
        progress_brush_->SetEndPoint(D2D1::Point2F(seg.right, seg.top));
    } else if (progress_stops_) {
        render_target_->CreateLinearGradientBrush(
            D2D1::LinearGradientBrushProperties(D2D1::Point2F(seg.left, seg.top),
                                                D2D1::Point2F(seg.right, seg.top)),
            progress_stops_.Get(), progress_brush_.GetAddressOf());
    }

    if (progress_brush_ || accent_brush_) {
        ComPtr<ID2D1RoundedRectangleGeometry> clip;
        bool clipped = false;
        if (factory_ && SUCCEEDED(factory_->CreateRoundedRectangleGeometry(bar_round, clip.GetAddressOf())) && clip) {
            render_target_->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), clip.Get()), nullptr);
            clipped = true;
        }

        if (progress_brush_) {
            render_target_->FillRoundedRectangle(D2D1::RoundedRect(seg, bar_radius, bar_radius), progress_brush_.Get());
        } else if (accent_brush_) {
            render_target_->FillRoundedRectangle(D2D1::RoundedRect(seg, bar_radius, bar_radius), accent_brush_.Get());
        }

        if (clipped) {
            render_target_->PopLayer();
        }
    }
}

void DxUiRendererImpl::DrawCardRect(const RECT& rc) {
    if (!render_target_ || IsRectEmpty(&rc)) {
        return;
    }

    D2D1_RECT_F rect = RectFromPixels(rc);
    const float radius = 14.0f;
    const float shadow_dx = 2.0f;
    const float shadow_dy = 4.0f;

    D2D1_RECT_F shadow_rect = rect;
    shadow_rect.left += shadow_dx;
    shadow_rect.right += shadow_dx;
    shadow_rect.top += shadow_dy;
    shadow_rect.bottom += shadow_dy;

    if (shadow_brush_) {
        D2D1_ROUNDED_RECT shadow = D2D1::RoundedRect(shadow_rect, radius, radius);
        render_target_->FillRoundedRectangle(shadow, shadow_brush_.Get());
    }

    ComPtr<ID2D1LinearGradientBrush> card_brush;
    if (card_stops_) {
        D2D1_POINT_2F start = D2D1::Point2F(rect.left, rect.top);
        D2D1_POINT_2F end = D2D1::Point2F(rect.left, rect.bottom);
        render_target_->CreateLinearGradientBrush(D2D1::LinearGradientBrushProperties(start, end), card_stops_.Get(),
                                                  card_brush.GetAddressOf());
    }

    D2D1_ROUNDED_RECT card = D2D1::RoundedRect(rect, radius, radius);
    if (card_brush) {
        render_target_->FillRoundedRectangle(card, card_brush.Get());
    } else if (panel_brush_) {
        render_target_->FillRoundedRectangle(card, panel_brush_.Get());
    }

    bool hovered = false;
    if (g_mouse_in_window) {
        POINT mouse = g_mouse_pos;
        hovered = PtInRect(&rc, mouse) != FALSE;
    }

    if (hovered && hover_brush_) {
        D2D1_POINT_2F mouse = D2D1::Point2F(ToDip(static_cast<float>(g_mouse_pos.x)),
                                            ToDip(static_cast<float>(g_mouse_pos.y)));
        float glow_radius = (std::max)(rect.right - rect.left, rect.bottom - rect.top) * 0.6f;
        hover_brush_->SetCenter(mouse);
        hover_brush_->SetRadiusX(glow_radius);
        hover_brush_->SetRadiusY(glow_radius);
        ComPtr<ID2D1RoundedRectangleGeometry> clip;
        bool clipped = false;
        if (factory_ &&
            SUCCEEDED(factory_->CreateRoundedRectangleGeometry(card, clip.GetAddressOf())) &&
            clip) {
            render_target_->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), clip.Get()), nullptr);
            clipped = true;
        }
        render_target_->FillEllipse(D2D1::Ellipse(mouse, glow_radius, glow_radius), hover_brush_.Get());
        if (clipped) {
            render_target_->PopLayer();
        }
    }

    bool focus_card = false;
    HWND focus_hwnd = GetFocus();
    if (g_stage == UiStage::Login && EqualRect(&rc, &g_card_auth) && focus_hwnd == g_edit) {
        focus_card = true;
    } else if ((g_stage == UiStage::Dashboard || g_stage == UiStage::Loading) &&
               EqualRect(&rc, &g_card_programs) && focus_hwnd == g_button) {
        focus_card = true;
    }

    if (focus_card && accent_brush_) {
        D2D1_RECT_F focus_rect = rect;
        focus_rect.left -= 2.0f;
        focus_rect.top -= 2.0f;
        focus_rect.right += 2.0f;
        focus_rect.bottom += 2.0f;
        D2D1_ROUNDED_RECT focus = D2D1::RoundedRect(focus_rect, radius + 2.0f, radius + 2.0f);
        accent_brush_->SetOpacity(0.35f);
        render_target_->DrawRoundedRectangle(focus, accent_brush_.Get(), 1.4f);
        accent_brush_->SetOpacity(1.0f);
    }

    if (card_border_brush_) {
        render_target_->DrawRoundedRectangle(card, card_border_brush_.Get(), 1.0f);
    }
}

void DxUiRendererImpl::DrawField(const RECT& rc, bool focused, bool error) {
    if (!render_target_ || IsRectEmpty(&rc)) {
        return;
    }

    D2D1_RECT_F rect = RectFromPixels(rc);
    const float radius = 14.0f;
    D2D1_ROUNDED_RECT field = D2D1::RoundedRect(rect, radius, radius);

    if (error && warn_brush_) {
        D2D1_RECT_F glow_rect = rect;
        glow_rect.left -= 3.0f;
        glow_rect.top -= 3.0f;
        glow_rect.right += 3.0f;
        glow_rect.bottom += 3.0f;
        D2D1_ROUNDED_RECT glow = D2D1::RoundedRect(glow_rect, radius + 3.0f, radius + 3.0f);
        warn_brush_->SetOpacity(0.12f);
        render_target_->FillRoundedRectangle(glow, warn_brush_.Get());
        warn_brush_->SetOpacity(1.0f);
    } else if (field_focus_glow_brush_ && focused) {
        D2D1_RECT_F glow_rect = rect;
        glow_rect.left -= 3.0f;
        glow_rect.top -= 3.0f;
        glow_rect.right += 3.0f;
        glow_rect.bottom += 3.0f;
        D2D1_ROUNDED_RECT glow = D2D1::RoundedRect(glow_rect, radius + 3.0f, radius + 3.0f);
        render_target_->FillRoundedRectangle(glow, field_focus_glow_brush_.Get());
    }

    if (field_fill_brush_) {
        render_target_->FillRoundedRectangle(field, field_fill_brush_.Get());
    }

    if (error && warn_brush_) {
        render_target_->DrawRoundedRectangle(field, warn_brush_.Get(), 1.0f);
    } else if (focused && field_focus_brush_) {
        render_target_->DrawRoundedRectangle(field, field_focus_brush_.Get(), 1.0f);
    } else if (field_border_brush_) {
        render_target_->DrawRoundedRectangle(field, field_border_brush_.Get(), 1.0f);
    }
}

void DxUiRendererImpl::DrawProductsList() {
    if (IsRectEmpty(&g_card_auth)) {
        return;
    }

    D2D1_RECT_F card = RectFromPixels(g_card_auth);
    float pad = static_cast<float>(kDxUiCardPadding);
    float header_height = static_cast<float>(kDxUiHeaderHeight);
    float top = card.top + pad + header_height + 10.0f;
    float left = card.left + pad;
    float right = card.right - pad;
    float bottom = card.bottom - pad;
    if (right <= left || bottom <= top) {
        return;
    }

    float item_height = static_cast<float>(kDxUiListItemHeight);
    float gap = static_cast<float>(kDxUiListItemGap);
    float list_height = bottom - top;
    int visible = static_cast<int>((list_height + gap) / (item_height + gap));
    if (visible < 1) {
        visible = 1;
    }

    std::vector<ProgramInfo> programs;
    EnterCriticalSection(&g_programs_lock);
    programs = g_programs;
    LeaveCriticalSection(&g_programs_lock);
    int total = static_cast<int>(programs.size());
    if (total <= 0) {
        return;
    }

    int max_scroll = (std::max)(0, total - visible);
    if (g_products_scroll > max_scroll) {
        g_products_scroll = max_scroll;
    }
    if (g_products_scroll < 0) {
        g_products_scroll = 0;
    }

    int start = g_products_scroll;
    if (g_selected_index >= 0 && g_keyboard_nav_active) {
        if (g_selected_index < start) {
            start = g_selected_index;
        } else if (g_selected_index >= start + visible) {
            start = g_selected_index - visible + 1;
        }
        if (start < 0) {
            start = 0;
        }
        if (start > max_scroll) {
            start = max_scroll;
        }
        if (start != g_products_scroll) {
            g_products_scroll = start;
        }
    }

    int end = (std::min)(total, start + visible);
    for (int i = start; i < end; ++i) {
        float item_top = top + static_cast<float>(i - start) * (item_height + gap);
        D2D1_RECT_F rect = D2D1::RectF(left, item_top, right, item_top + item_height);
        bool selected = (i == g_selected_index);
        bool hovered = (i == g_hover_product_index);
        DrawProductItem(rect, programs[static_cast<size_t>(i)], selected, hovered);
    }
}

void DxUiRendererImpl::DrawProductItem(const D2D1_RECT_F& rect, const ProgramInfo& program, bool selected, bool hovered) {
    if (!render_target_) {
        return;
    }

    float radius = 14.0f;
    D2D1_ROUNDED_RECT item = D2D1::RoundedRect(rect, radius, radius);

    if (field_fill_brush_) {
        render_target_->FillRoundedRectangle(item, field_fill_brush_.Get());
    }
    if (selected && accent_brush_) {
        accent_brush_->SetOpacity(0.08f);
        render_target_->FillRoundedRectangle(item, accent_brush_.Get());
        accent_brush_->SetOpacity(1.0f);
    }

    if (selected && accent_brush_) {
        accent_brush_->SetOpacity(0.45f);
        render_target_->DrawRoundedRectangle(item, accent_brush_.Get(), 1.0f);
        accent_brush_->SetOpacity(1.0f);
    } else if (hovered && accent_brush_) {
        accent_brush_->SetOpacity(0.2f);
        render_target_->DrawRoundedRectangle(item, accent_brush_.Get(), 1.0f);
        accent_brush_->SetOpacity(1.0f);
    } else if (field_border_brush_) {
        render_target_->DrawRoundedRectangle(item, field_border_brush_.Get(), 1.0f);
    }

    if (selected && g_keyboard_nav_active && !hovered && accent_brush_) {
        D2D1_RECT_F focus_rect = rect;
        focus_rect.left -= 2.0f;
        focus_rect.top -= 2.0f;
        focus_rect.right += 2.0f;
        focus_rect.bottom += 2.0f;
        D2D1_ROUNDED_RECT focus = D2D1::RoundedRect(focus_rect, radius + 2.0f, radius + 2.0f);
        accent_brush_->SetOpacity(0.55f);
        render_target_->DrawRoundedRectangle(focus, accent_brush_.Get(), 1.4f);
        accent_brush_->SetOpacity(1.0f);
    }

    if (selected) {
        D2D1_RECT_F line = D2D1::RectF(rect.left + 10.0f, rect.bottom - 4.0f, rect.right - 10.0f, rect.bottom - 2.0f);
        if (progress_brush_) {
            progress_brush_->SetStartPoint(D2D1::Point2F(line.left, line.top));
            progress_brush_->SetEndPoint(D2D1::Point2F(line.right, line.top));
            render_target_->FillRectangle(line, progress_brush_.Get());
        } else if (accent_brush_) {
            render_target_->FillRectangle(line, accent_brush_.Get());
        }
    }

    std::wstring name = program.name.empty() ? program.code : program.name;
    std::wstring updated = FormatUpdatedLabel(program.updated_at);
    std::wstring expiry = FormatExpiryLabel(program.expires_at);
    std::wstring meta = L"Updated " + updated + L" - " + expiry;

    std::wstring status = program.status;
    if (status.empty()) {
        status = L"available";
    }
    bool status_hot = ContainsInsensitive(status, L"update") ||
                      ContainsInsensitive(status, L"ready") ||
                      ContainsInsensitive(status, L"live");

    float pad = 12.0f;
    float text_left = rect.left + pad;
    float text_right = rect.right - pad;
    float image_slot = 0.0f;

    ID2D1Bitmap* avatar_bitmap = nullptr;
    if (!program.avatar_path.empty()) {
        avatar_bitmap = GetAvatarBitmap(program.avatar_path);
    }

    if (avatar_bitmap) {
        float image_gap = 12.0f;
        float image_size = rect.bottom - rect.top - pad * 2.0f;
        if (image_size < 24.0f) {
            image_size = 24.0f;
        }
        D2D1_RECT_F image_rect = D2D1::RectF(rect.left + pad, rect.top + pad,
                                             rect.left + pad + image_size, rect.top + pad + image_size);
        if (field_fill_brush_) {
            render_target_->FillRectangle(image_rect, field_fill_brush_.Get());
        }
        if (field_border_brush_) {
            render_target_->DrawRectangle(image_rect, field_border_brush_.Get(), 1.0f);
        }

        D2D1_SIZE_F bitmap_size = avatar_bitmap->GetSize();
        float draw_w = image_size;
        float draw_h = image_size;
        if (bitmap_size.width > 0.0f && bitmap_size.height > 0.0f) {
            float scale = (std::min)(image_size / bitmap_size.width, image_size / bitmap_size.height);
            draw_w = bitmap_size.width * scale;
            draw_h = bitmap_size.height * scale;
        }
        float image_left = image_rect.left + (image_size - draw_w) * 0.5f;
        float image_top = image_rect.top + (image_size - draw_h) * 0.5f;
        D2D1_RECT_F bitmap_rect = D2D1::RectF(image_left, image_top, image_left + draw_w, image_top + draw_h);
        render_target_->DrawBitmap(avatar_bitmap, bitmap_rect, 1.0f,
                                   D2D1_BITMAP_INTERPOLATION_MODE_LINEAR, nullptr);

        image_slot = image_size + image_gap;
        text_left = rect.left + pad + image_slot;
    }

    if (pill_format_) {
        float pill_height = 22.0f;
        float pill_pad = 8.0f;
        float pill_text_width = MeasureTextWidth(status, pill_format_.Get());
        float pill_width = pill_text_width + pill_pad * 2.0f;
        float pill_right = rect.right - pad;
        float pill_left = pill_right - pill_width;
        float pill_top = rect.top + pad - 2.0f;
        if (pill_left > rect.left + pad + image_slot + 40.0f) {
            D2D1_RECT_F pill = D2D1::RectF(pill_left, pill_top, pill_right, pill_top + pill_height);
            D2D1_ROUNDED_RECT pill_round = D2D1::RoundedRect(pill, pill_height * 0.5f, pill_height * 0.5f);
            if (field_fill_brush_) {
                render_target_->FillRoundedRectangle(pill_round, field_fill_brush_.Get());
            }
            if (status_hot && accent_brush_) {
                accent_brush_->SetOpacity(0.12f);
                render_target_->FillRoundedRectangle(pill_round, accent_brush_.Get());
                accent_brush_->SetOpacity(1.0f);
            }
            if (status_hot && accent_brush_) {
                render_target_->DrawRoundedRectangle(pill_round, accent_brush_.Get(), 1.0f);
            } else if (field_border_brush_) {
                render_target_->DrawRoundedRectangle(pill_round, field_border_brush_.Get(), 1.0f);
            }
            pill_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
            pill_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            ID2D1SolidColorBrush* pill_brush = status_hot ? (accent_brush_ ? accent_brush_.Get() : text_brush_.Get())
                                                          : (muted_brush_.Get());
            if (pill_brush) {
                render_target_->DrawTextW(status.c_str(), static_cast<UINT32>(status.size()), pill_format_.Get(), pill,
                                          pill_brush);
            }
            pill_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            pill_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            text_right = pill_left - 8.0f;
        }
    }

    D2D1_RECT_F name_rect = D2D1::RectF(text_left, rect.top + pad, text_right, rect.top + pad + 20.0f);
    if (status_format_ && text_brush_) {
        status_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        status_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        render_target_->DrawTextW(name.c_str(), static_cast<UINT32>(name.size()), status_format_.Get(), name_rect,
                                  text_brush_.Get());
    }

    D2D1_RECT_F meta_rect = D2D1::RectF(text_left, rect.top + pad + 22.0f, rect.right - pad,
                                        rect.bottom - pad);
    if (mono_format_ && muted_brush_) {
        mono_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        mono_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        render_target_->DrawTextW(meta.c_str(), static_cast<UINT32>(meta.size()), mono_format_.Get(), meta_rect,
                                  muted_brush_.Get());
    }
}

void DxUiRendererImpl::DrawDashboardContent() {
    if (IsRectEmpty(&g_card_auth) || IsRectEmpty(&g_card_programs)) {
        return;
    }

    DrawCardHeader(g_card_auth, L"PRODUCTS");
    DrawCardHeader(g_card_programs, L"ACTIONS");
    if (!IsRectEmpty(&g_card_telemetry)) {
        DrawCardHeader(g_card_telemetry, L"TELEMETRY");
    }

    int product_count = 0;
    EnterCriticalSection(&g_programs_lock);
    product_count = static_cast<int>(g_programs.size());
    LeaveCriticalSection(&g_programs_lock);
    if (product_count > 0) {
        std::wstring meta = std::to_wstring(product_count) + L" available";
        DrawCardMeta(g_card_auth, meta);
    } else {
        DrawCardMeta(g_card_auth, L"No products");
    }

    DrawProductsList();

    std::wstring status_snapshot = GetStatusSnapshot();
    std::wstring mode = DeriveModeFromStatus(status_snapshot);
    std::wstring phase = DerivePhaseFromStatus(status_snapshot);
    if (g_stage == UiStage::Dashboard && mode == L"READY") {
        phase = L"idle";
    }
    UpdateSessionState(mode);
    telemetry_progress_target_ = ProgressForModePhase(mode, phase);
    ULONGLONG progress_now = GetTickCount64();
    float dt = 0.016f;
    if (telemetry_progress_tick_ != 0 && progress_now > telemetry_progress_tick_) {
        ULONGLONG delta = progress_now - telemetry_progress_tick_;
        if (delta > 80ULL) {
            delta = 80ULL;
        }
        dt = static_cast<float>(delta) / 1000.0f;
    }
    telemetry_progress_tick_ = progress_now;
    float response = 1.0f - std::exp(-dt / 0.25f);
    telemetry_progress_ += (telemetry_progress_target_ - telemetry_progress_) * response;
    if (std::fabs(telemetry_progress_ - telemetry_progress_target_) < 0.15f) {
        telemetry_progress_ = telemetry_progress_target_;
    }
    if (telemetry_scan_tick_ == 0) {
        telemetry_scan_tick_ = progress_now;
    }
    float scan_period = (mode == L"WAITING") ? 3.0f : 2.2f;
    telemetry_scan_ += dt / scan_period;
    if (telemetry_scan_ >= 1.0f) {
        telemetry_scan_ -= std::floor(telemetry_scan_);
    }
    telemetry_scan_tick_ = progress_now;

    DrawCardMeta(g_card_programs, L"state: " + mode);
    if (!IsRectEmpty(&g_card_telemetry)) {
        DrawCardMeta(g_card_telemetry, phase);
    }

    if (status_format_ && muted_brush_) {
        status_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        D2D1_RECT_F status_rect = {};
        if (GetChildRect(g_status, &status_rect)) {
            std::wstring status = GetWindowTextString(g_status);
            if (!status.empty()) {
                render_target_->DrawTextW(status.c_str(), static_cast<UINT32>(status.size()), status_format_.Get(),
                                          status_rect, muted_brush_.Get());
            }
            DrawActionsSubgrid(RectFromPixels(g_card_programs), &status_rect, mode, phase);
        } else {
            DrawActionsSubgrid(RectFromPixels(g_card_programs), nullptr, mode, phase);
        }
    }
    DrawActionButton();

    if (IsRectEmpty(&g_card_telemetry)) {
        return;
    }

    UpdateTelemetryFeed(&telemetry_lines_, &telemetry_last_status_);

    D2D1_RECT_F card = RectFromPixels(g_card_telemetry);
    float pad = 14.0f;
    float header_height = 16.0f;
    float bar_height = 10.0f;
    float bar_top = card.top + pad + header_height + 10.0f;
    float pct_width = 52.0f;
    D2D1_RECT_F bar = D2D1::RectF(card.left + pad, bar_top, card.right - pad - pct_width, bar_top + bar_height);
    D2D1_RECT_F pct = D2D1::RectF(bar.right + 8.0f, bar_top - 2.0f, card.right - pad, bar_top + bar_height + 2.0f);

    if (field_fill_brush_) {
        render_target_->FillRoundedRectangle(D2D1::RoundedRect(bar, bar_height * 0.5f, bar_height * 0.5f),
                                             field_fill_brush_.Get());
    }
    if (field_border_brush_) {
        render_target_->DrawRoundedRectangle(D2D1::RoundedRect(bar, bar_height * 0.5f, bar_height * 0.5f),
                                             field_border_brush_.Get(), 1.0f);
    }

    bool waiting_mode = (mode == L"WAITING");
    float progress = (std::min)((std::max)(telemetry_progress_, 0.0f), 100.0f);
    D2D1_RECT_F fill = bar;
    bool has_fill = false;
    if (bar.right > bar.left && progress > 0.0f) {
        float width = (bar.right - bar.left) * (progress / 100.0f);
        fill = D2D1::RectF(bar.left, bar.top, bar.left + width, bar.bottom);
        has_fill = true;
        float fill_width = fill.right - fill.left;
        float fill_radius = (std::min)(bar_height * 0.5f, fill_width * 0.5f);
        ID2D1Brush* fill_brush = nullptr;
        if (waiting_mode && warn_brush_) {
            fill_brush = warn_brush_.Get();
        } else if (progress_brush_) {
            progress_brush_->SetStartPoint(D2D1::Point2F(fill.left, fill.top));
            progress_brush_->SetEndPoint(D2D1::Point2F(fill.right, fill.top));
            fill_brush = progress_brush_.Get();
        } else if (accent_brush_) {
            fill_brush = accent_brush_.Get();
        }
        if (fill_brush) {
            render_target_->FillRoundedRectangle(D2D1::RoundedRect(fill, fill_radius, fill_radius), fill_brush);
        }
    }

    if (has_fill && (mode == L"RUNNING" || mode == L"WAITING") && text_brush_) {
        float stripe_width = 5.0f;
        float stripe_gap = 10.0f;
        float stripe_step = stripe_width + stripe_gap;
        float height = fill.bottom - fill.top;
        ULONGLONG now = GetTickCount64();
        ULONGLONG period = (mode == L"WAITING") ? 900ULL : 650ULL;
        float offset = static_cast<float>((now % period) / static_cast<float>(period)) * stripe_step;
        float fill_width = fill.right - fill.left;
        float fill_radius = (std::min)(bar_height * 0.5f, fill_width * 0.5f);
        D2D1_ROUNDED_RECT fill_round = D2D1::RoundedRect(fill, fill_radius, fill_radius);
        ComPtr<ID2D1RoundedRectangleGeometry> clip;
        bool clipped = false;
        if (factory_ && SUCCEEDED(factory_->CreateRoundedRectangleGeometry(fill_round, clip.GetAddressOf())) && clip) {
            render_target_->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), clip.Get()), nullptr);
            clipped = true;
        }
        float stripe_alpha = (mode == L"WAITING") ? 0.12f : 0.16f;
        text_brush_->SetOpacity(stripe_alpha);
        for (float x = fill.left - height - stripe_step + offset; x < fill.right + stripe_step; x += stripe_step) {
            D2D1_POINT_2F p0 = D2D1::Point2F(x, fill.bottom);
            D2D1_POINT_2F p1 = D2D1::Point2F(x + height, fill.top);
            render_target_->DrawLine(p0, p1, text_brush_.Get(), stripe_width);
        }
        text_brush_->SetOpacity(1.0f);
        if (clipped) {
            render_target_->PopLayer();
        }
    }

    float scan_t = telemetry_scan_;
    float scan_width = 40.0f;
    float scan_x = bar.left + scan_t * ((bar.right - bar.left) + scan_width) - scan_width;
    D2D1_RECT_F scan = D2D1::RectF(scan_x, bar.top, scan_x + scan_width, bar.bottom);
    ID2D1SolidColorBrush* scan_brush = accent_brush_.Get();
    if (mode == L"WAITING" && warn_brush_) {
        scan_brush = warn_brush_.Get();
    }
    if (scan_brush) {
        float scan_opacity = 0.12f;
        if (mode == L"RUNNING") {
            scan_opacity = 0.22f;
        } else if (mode == L"WAITING") {
            scan_opacity = 0.16f;
        }
        D2D1_ROUNDED_RECT bar_round = D2D1::RoundedRect(bar, bar_height * 0.5f, bar_height * 0.5f);
        ComPtr<ID2D1RoundedRectangleGeometry> clip;
        bool clipped = false;
        if (factory_ && SUCCEEDED(factory_->CreateRoundedRectangleGeometry(bar_round, clip.GetAddressOf())) && clip) {
            render_target_->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), clip.Get()), nullptr);
            clipped = true;
        }
        scan_brush->SetOpacity(scan_opacity);
        float scan_radius = (std::min)(bar_height * 0.5f, (scan.right - scan.left) * 0.5f);
        render_target_->FillRoundedRectangle(D2D1::RoundedRect(scan, scan_radius, scan_radius), scan_brush);
        scan_brush->SetOpacity(1.0f);
        if (clipped) {
            render_target_->PopLayer();
        }
    }

    if (mono_format_ && faint_brush_) {
        mono_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
        wchar_t pct_text[8] = {};
        swprintf_s(pct_text, L"%d%%", static_cast<int>(progress + 0.5f));
        render_target_->DrawTextW(pct_text, static_cast<UINT32>(wcslen(pct_text)), mono_format_.Get(), pct,
                                  faint_brush_.Get());
        mono_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    }

    float feed_top = bar.bottom + 14.0f;
    D2D1_RECT_F feed = D2D1::RectF(card.left + pad, feed_top, card.right - pad, card.bottom - pad);
    if (feed.bottom > feed.top + 20.0f) {
        if (field_fill_brush_) {
            render_target_->FillRoundedRectangle(D2D1::RoundedRect(feed, 12.0f, 12.0f), field_fill_brush_.Get());
        }
        if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(D2D1::RoundedRect(feed, 12.0f, 12.0f), field_border_brush_.Get(),
                                                 1.0f);
        }

        IDWriteTextFormat* feed_format = telemetry_format_ ? telemetry_format_.Get() : mono_format_.Get();
        if (feed_format) {
            float inner_pad = 12.0f;
            D2D1_RECT_F inner = D2D1::RectF(feed.left + inner_pad, feed.top + inner_pad, feed.right - inner_pad,
                                            feed.bottom - inner_pad);
            float line_height = 18.0f;
            float ts_width = 62.0f;
            ULONGLONG line_now = GetTickCount64();
            size_t max_lines = telemetry_lines_.size();
            ID2D1SolidColorBrush* placeholder_brush = muted_brush_ ? muted_brush_.Get() : faint_brush_.Get();
            if (max_lines == 0 && placeholder_brush) {
                std::wstring placeholder = L"Awaiting telemetry.";
                render_target_->DrawTextW(placeholder.c_str(), static_cast<UINT32>(placeholder.size()),
                                          feed_format, inner, placeholder_brush);
            } else {
                for (size_t i = 0; i < max_lines; ++i) {
                    const TelemetryLine& line = telemetry_lines_[i];
                    float age_ms = 1000.0f;
                    if (line.tick > 0 && line_now > line.tick) {
                        age_ms = static_cast<float>(line_now - line.tick);
                    }
                    float alpha = (std::min)(1.0f, age_ms / 220.0f);
                    float rise = (1.0f - alpha) * 6.0f;
                    float y = inner.top + (line_height + 4.0f) * static_cast<float>(i) - rise;
                    D2D1_RECT_F ts_rect = D2D1::RectF(inner.left, y, inner.left + ts_width, y + line_height);
                    const std::wstring& msg = line.msg;
                    float msg_indent = 6.0f;
                    if (msg.empty()) {
                        msg_indent = 0.0f;
                    }
                    D2D1_RECT_F msg_rect = D2D1::RectF(inner.left + ts_width + msg_indent, y,
                                                       inner.right, y + line_height);
                    if (faint_brush_) {
                        faint_brush_->SetOpacity(alpha);
                        render_target_->DrawTextW(line.ts.c_str(), static_cast<UINT32>(line.ts.size()),
                                                  feed_format, ts_rect, faint_brush_.Get());
                        faint_brush_->SetOpacity(1.0f);
                    }
                    bool drew_split = false;
                    if (feed_format && (muted_brush_ || text_brush_)) {
                        bool split_line = StartsWithInsensitive(msg, L"target") ||
                                          StartsWithInsensitive(msg, L"subscription");
                        if (split_line) {
                            size_t value_start = msg.find(L':');
                            if (value_start == std::wstring::npos) {
                                value_start = msg.find(L' ');
                            }
                            if (value_start != std::wstring::npos && value_start + 1 < msg.size()) {
                                value_start += 1;
                                while (value_start < msg.size() &&
                                       (msg[value_start] == L' ' || msg[value_start] == L'\t')) {
                                    ++value_start;
                                }
                                if (value_start < msg.size()) {
                                    std::wstring label = msg.substr(0, value_start);
                                    std::wstring value = msg.substr(value_start);
                                    if (!value.empty() && value.front() != L' ') {
                                        value.insert(value.begin(), L' ');
                                    }
                                    float label_width = MeasureTextWidth(label, feed_format);
                                    float split_gap = 0.0f;
                                    if (muted_brush_) {
                                        muted_brush_->SetOpacity(alpha);
                                        render_target_->DrawTextW(label.c_str(), static_cast<UINT32>(label.size()),
                                                                  feed_format, msg_rect, muted_brush_.Get());
                                        muted_brush_->SetOpacity(1.0f);
                                    }
                                    if (text_brush_) {
                                        D2D1_RECT_F val_rect = msg_rect;
                                        val_rect.left += label_width + split_gap;
                                        text_brush_->SetOpacity(alpha);
                                        render_target_->DrawTextW(value.c_str(), static_cast<UINT32>(value.size()),
                                                                  feed_format, val_rect, text_brush_.Get());
                                        text_brush_->SetOpacity(1.0f);
                                    }
                                    drew_split = true;
                                }
                            }
                        }
                    }
                    if (!drew_split && muted_brush_) {
                        muted_brush_->SetOpacity(alpha);
                        render_target_->DrawTextW(msg.c_str(), static_cast<UINT32>(msg.size()),
                                                  feed_format, msg_rect, muted_brush_.Get());
                        muted_brush_->SetOpacity(1.0f);
                    }
                    if (!drew_split && feed_format && (text_brush_ || warn_brush_)) {
                        auto draw_overlay = [&](const std::wstring& text, float x, ID2D1SolidColorBrush* brush) {
                            if (!brush || text.empty()) {
                                return;
                            }
                            brush->SetOpacity(alpha);
                            D2D1_RECT_F seg = D2D1::RectF(x, y, msg_rect.right, y + line_height);
                            render_target_->DrawTextW(text.c_str(), static_cast<UINT32>(text.size()), feed_format, seg,
                                                      brush);
                            brush->SetOpacity(1.0f);
                        };

                        if (StartsWithInsensitive(msg, L"waiting")) {
                            size_t len = (std::min)(msg.size(), std::wstring(L"Waiting").size());
                            draw_overlay(msg.substr(0, len), msg_rect.left,
                                         warn_brush_ ? warn_brush_.Get() : text_brush_.Get());
                        } else if (StartsWithInsensitive(msg, L"loaded")) {
                            size_t len = (std::min)(msg.size(), std::wstring(L"Loaded").size());
                            draw_overlay(msg.substr(0, len), msg_rect.left, text_brush_.Get());
                        } else if (StartsWithInsensitive(msg, L"connected")) {
                            size_t len = (std::min)(msg.size(), std::wstring(L"Connected").size());
                            draw_overlay(msg.substr(0, len), msg_rect.left, text_brush_.Get());
                        }
                    }
                    if (y + line_height > inner.bottom) {
                        break;
                    }
                }
            }
        }
    }
}

void DxUiRendererImpl::DrawCardHeader(const RECT& rc, const wchar_t* text) {
    if (!text || !label_format_ || !muted_brush_) {
        return;
    }
    if (IsRectEmpty(&rc)) {
        return;
    }
    D2D1_RECT_F rect = RectFromPixels(rc);
    float pad = 14.0f;
    float height = 16.0f;
    D2D1_RECT_F header = D2D1::RectF(rect.left + pad, rect.top + pad, rect.right - pad, rect.top + pad + height);
    label_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    render_target_->DrawTextW(text, static_cast<UINT32>(wcslen(text)), label_format_.Get(), header, muted_brush_.Get());
}

void DxUiRendererImpl::DrawCardMeta(const RECT& rc, const std::wstring& text) {
    if (!render_target_ || !pill_format_ || !faint_brush_) {
        return;
    }
    if (text.empty() || IsRectEmpty(&rc)) {
        return;
    }
    D2D1_RECT_F rect = RectFromPixels(rc);
    float pad = 14.0f;
    float height = 16.0f;
    D2D1_RECT_F header = D2D1::RectF(rect.left + pad, rect.top + pad, rect.right - pad, rect.top + pad + height);
    pill_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
    render_target_->DrawTextW(text.c_str(), static_cast<UINT32>(text.size()), pill_format_.Get(), header,
                              faint_brush_.Get());
    pill_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
}

void DxUiRendererImpl::DrawActionsSubgrid(const D2D1_RECT_F& card,
                                          const D2D1_RECT_F* status_rect,
                                          const std::wstring& mode,
                                          const std::wstring& phase) {
    if (!render_target_ || card.right <= card.left || card.bottom <= card.top) {
        return;
    }

    float pad = 14.0f;
    float sub_pad = 12.0f;
    float max_bottom = card.bottom - pad;
    float min_top = status_rect ? status_rect->bottom + 12.0f : card.top + pad + 60.0f;
    if (max_bottom <= min_top + 20.0f) {
        return;
    }

    float step_height = 24.0f;
    float step_pad_x = 10.0f;
    float step_gap = 8.0f;

    int active_count = 0;
    if (mode == L"READY") {
        active_count = 0;
    } else if (phase == L"auth") {
        active_count = 1;
    } else if (phase == L"sync") {
        active_count = 2;
    } else if (phase == L"verify") {
        active_count = 3;
    } else if (phase == L"ready") {
        active_count = 4;
    }

    const wchar_t* steps[] = {L"AUTH", L"SYNC", L"VERIFY", L"READY"};
    IDWriteTextFormat* step_format = mono_format_ ? mono_format_.Get() : pill_format_.Get();
    int current_index = active_count > 0 ? active_count - 1 : -1;
    float pulse = 0.0f;
    if (current_index >= 0) {
        ULONGLONG now = GetTickCount64();
        float t = static_cast<float>((now % 1200ULL) / 1200.0f);
        pulse = 0.5f + 0.5f * std::sin(t * 6.2831853f);
    }

    int draw_count = 4;
    float max_left = card.left + pad;
    float max_right = card.right - pad;
    float max_available = max_right - max_left - sub_pad * 2.0f;
    if (max_available <= 0.0f) {
        return;
    }
    float max_label_width = 0.0f;
    for (int i = 0; i < draw_count; ++i) {
        std::wstring label = steps[i];
        float label_width = step_format ? MeasureTextWidth(label, step_format) : 36.0f;
        if (label_width > max_label_width) {
            max_label_width = label_width;
        }
    }

    float width = max_label_width + step_pad_x * 2.0f;
    float max_width = (max_available - step_gap * static_cast<float>(draw_count - 1)) /
                      static_cast<float>(draw_count);
    if (max_width < width) {
        width = (std::max)(0.0f, max_width);
    }
    float total_width = width * static_cast<float>(draw_count) + step_gap * static_cast<float>(draw_count - 1);

    float sub_width = total_width + sub_pad * 2.0f;
    float sub_left = (card.left + card.right - sub_width) * 0.5f;
    if (sub_left < max_left) {
        sub_left = max_left;
    }
    if (sub_left + sub_width > max_right) {
        sub_left = max_right - sub_width;
    }
    float sub_height = step_height + sub_pad * 2.0f;
    float top = (std::max)(min_top, max_bottom - sub_height);
    float sub_bottom = top + sub_height;
    if (sub_bottom > max_bottom) {
        sub_bottom = max_bottom;
    }

    D2D1_RECT_F sub = D2D1::RectF(sub_left, top, sub_left + sub_width, sub_bottom);
    D2D1_ROUNDED_RECT sub_round = D2D1::RoundedRect(sub, 14.0f, 14.0f);
    if (field_fill_brush_) {
        render_target_->FillRoundedRectangle(sub_round, field_fill_brush_.Get());
    }
    if (field_border_brush_) {
        render_target_->DrawRoundedRectangle(sub_round, field_border_brush_.Get(), 1.0f);
    }

    float inner_left = sub.left + sub_pad;
    float inner_top = sub.top + sub_pad;
    float inner_right = sub.right - sub_pad;
    float inner_bottom = sub.bottom - sub_pad;
    if (inner_bottom <= inner_top + 12.0f) {
        return;
    }

    float step_y = inner_top + (inner_bottom - inner_top - step_height) * 0.5f;
    float row_left = inner_left;
    float x = std::floor(row_left + 0.5f);
    float stats_top = step_y + step_height + 10.0f;
    float stats_gap = 10.0f;
    float stats_width = inner_right - inner_left;
    float col_width = (stats_width - stats_gap) * 0.5f;
    float rows_height = inner_bottom - stats_top;
    float row_height = (rows_height - stats_gap) * 0.5f;
    bool draw_stats = row_height >= 32.0f && col_width >= 60.0f;

    for (int i = 0; i < draw_count; ++i) {
        std::wstring label = steps[i];
        D2D1_RECT_F step_rect = D2D1::RectF(x, step_y, x + width, step_y + step_height);
        D2D1_ROUNDED_RECT step_round = D2D1::RoundedRect(step_rect, step_height * 0.5f, step_height * 0.5f);
        bool active = i < active_count;
        bool current = (i == current_index);
        float active_fill_opacity = current ? (0.16f + 0.08f * pulse) : 0.12f;
        float active_border = current ? (1.2f + 0.6f * pulse) : 1.0f;

        if (field_fill_brush_) {
            render_target_->FillRoundedRectangle(step_round, field_fill_brush_.Get());
        }
        if (active && accent_brush_) {
            accent_brush_->SetOpacity(active_fill_opacity);
            render_target_->FillRoundedRectangle(step_round, accent_brush_.Get());
            accent_brush_->SetOpacity(1.0f);
        }
        if (active && accent_brush_) {
            render_target_->DrawRoundedRectangle(step_round, accent_brush_.Get(), active_border);
        } else if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(step_round, field_border_brush_.Get(), 1.0f);
        }

        if (step_format && dwrite_factory_) {
            ID2D1SolidColorBrush* brush = active ? (accent_brush_ ? accent_brush_.Get() : text_brush_.Get())
                                                 : (muted_brush_.Get());
            if (brush) {
                ComPtr<IDWriteTextLayout> layout;
                HRESULT hr = dwrite_factory_->CreateTextLayout(label.c_str(), static_cast<UINT32>(label.size()),
                                                               step_format, width, step_height,
                                                               layout.GetAddressOf());
                if (SUCCEEDED(hr) && layout) {
                    layout->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
                    layout->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
                    render_target_->DrawTextLayout(D2D1::Point2F(step_rect.left, step_rect.top), layout.Get(), brush);
                } else {
                    D2D1_RECT_F text_rect = step_rect;
                    step_format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
                    step_format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
                    render_target_->DrawTextW(label.c_str(), static_cast<UINT32>(label.size()), step_format, text_rect,
                                              brush);
                    step_format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
                    step_format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
                }
            }
        }

        x += width + step_gap;
    }

    if (!draw_stats) {
        return;
    }

    std::wstring phase_value = phase.empty() ? L"idle" : phase;
    std::wstring uptime_value = L"00:00";
    if (session_active_ && session_start_tick_ != 0) {
        ULONGLONG elapsed = (GetTickCount64() - session_start_tick_) / 1000ULL;
        uptime_value = FormatUptimeValue(elapsed);
    }
    std::wstring last_run_value = last_run_label_.empty() ? L"-" : last_run_label_;
    std::wstring mode_value = mode.empty() ? L"standard" : ToLowerCopy(mode);

    struct Stat {
        const wchar_t* key;
        const std::wstring* value;
    };
    const Stat stats[] = {
        {L"Phase", &phase_value},
        {L"Uptime", &uptime_value},
        {L"Last run", &last_run_value},
        {L"Mode", &mode_value},
    };

    for (int i = 0; i < 4; ++i) {
        float row = static_cast<float>(i / 2);
        float col = static_cast<float>(i % 2);
        float left = inner_left + col * (col_width + stats_gap);
        float top_row = stats_top + row * (row_height + stats_gap);
        D2D1_RECT_F stat_rect = D2D1::RectF(left, top_row, left + col_width, top_row + row_height);
        D2D1_ROUNDED_RECT stat_round = D2D1::RoundedRect(stat_rect, 12.0f, 12.0f);

        if (field_fill_brush_) {
            render_target_->FillRoundedRectangle(stat_round, field_fill_brush_.Get());
        }
        if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(stat_round, field_border_brush_.Get(), 1.0f);
        }

        float inner_pad = 8.0f;
        D2D1_RECT_F key_rect = D2D1::RectF(stat_rect.left + inner_pad, stat_rect.top + inner_pad,
                                           stat_rect.right - inner_pad, stat_rect.top + inner_pad + 12.0f);
        D2D1_RECT_F value_rect = D2D1::RectF(stat_rect.left + inner_pad, key_rect.bottom + 4.0f,
                                             stat_rect.right - inner_pad, stat_rect.bottom - inner_pad);

        if (label_format_ && muted_brush_) {
            label_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            label_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
            render_target_->DrawTextW(stats[i].key, static_cast<UINT32>(wcslen(stats[i].key)), label_format_.Get(),
                                      key_rect, muted_brush_.Get());
        }
        if (status_format_ && text_brush_) {
            status_format_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            status_format_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
            render_target_->DrawTextW(stats[i].value->c_str(), static_cast<UINT32>(stats[i].value->size()),
                                      status_format_.Get(), value_rect, text_brush_.Get());
        }
    }
}

void DxUiRendererImpl::DrawActionButton() {
    if (!render_target_ || !g_button) {
        return;
    }
    if (g_stage != UiStage::Dashboard && g_stage != UiStage::Loading && g_stage != UiStage::Login) {
        return;
    }

    RECT rc = {};
    if (!GetWindowRect(g_button, &rc)) {
        return;
    }
    MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&rc), 2);
    if (IsRectEmpty(&rc)) {
        return;
    }

    D2D1_RECT_F rect = RectFromPixels(rc);
    float height = rect.bottom - rect.top;
    float radius = (std::min)(12.0f, height * 0.5f);
    D2D1_ROUNDED_RECT round = D2D1::RoundedRect(rect, radius, radius);

    bool enabled = IsWindowEnabled(g_button) != FALSE;
    bool hovered = g_mouse_in_window && PtInRect(&rc, g_mouse_pos);
    bool pressed = (SendMessageW(g_button, BM_GETSTATE, 0, 0) & BST_PUSHED) != 0;
    if (hovered && (GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        pressed = true;
    }

    std::wstring label = GetWindowTextString(g_button);
    if (label.empty()) {
        label = L"Load";
    }
    std::wstring lower = ToLowerCopy(label);
    bool waiting = (lower.find(L"waiting") != std::wstring::npos);
    bool loading = (lower.find(L"loading") != std::wstring::npos) || (g_stage == UiStage::Loading);
    bool show_spinner = waiting || loading;

    ID2D1SolidColorBrush* accent = nullptr;
    if (waiting && warn_brush_) {
        accent = warn_brush_.Get();
    } else if (accent_brush_) {
        accent = accent_brush_.Get();
    }

    if (field_fill_brush_) {
        render_target_->FillRoundedRectangle(round, field_fill_brush_.Get());
    } else if (panel_brush_) {
        render_target_->FillRoundedRectangle(round, panel_brush_.Get());
    }

    if (accent) {
        float overlay = pressed ? 0.22f : (hovered ? 0.18f : 0.12f);
        if (!enabled) {
            overlay *= 0.5f;
        }
        accent->SetOpacity(overlay);
        render_target_->FillRoundedRectangle(round, accent);
        accent->SetOpacity(1.0f);
    }

    if (hovered && enabled && hover_brush_) {
        D2D1_POINT_2F mouse = D2D1::Point2F(ToDip(static_cast<float>(g_mouse_pos.x)),
                                            ToDip(static_cast<float>(g_mouse_pos.y)));
        float glow_radius = (std::max)(rect.right - rect.left, rect.bottom - rect.top) * 0.7f;
        hover_brush_->SetCenter(mouse);
        hover_brush_->SetRadiusX(glow_radius);
        hover_brush_->SetRadiusY(glow_radius);
        hover_brush_->SetOpacity(0.65f);
        ComPtr<ID2D1RoundedRectangleGeometry> clip;
        bool clipped = false;
        if (factory_ && SUCCEEDED(factory_->CreateRoundedRectangleGeometry(round, clip.GetAddressOf())) && clip) {
            render_target_->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), clip.Get()), nullptr);
            clipped = true;
        }
        render_target_->FillEllipse(D2D1::Ellipse(mouse, glow_radius, glow_radius), hover_brush_.Get());
        if (clipped) {
            render_target_->PopLayer();
        }
        hover_brush_->SetOpacity(1.0f);
    }

    if (accent && (hovered || show_spinner)) {
        float border_opacity = hovered ? 0.55f : 0.4f;
        if (!enabled) {
            border_opacity *= 0.5f;
        }
        accent->SetOpacity(border_opacity);
        render_target_->DrawRoundedRectangle(round, accent, 1.0f);
        accent->SetOpacity(1.0f);
    } else if (field_border_brush_) {
        render_target_->DrawRoundedRectangle(round, field_border_brush_.Get(), 1.0f);
    }

    auto draw_spinner = [&](D2D1_POINT_2F center, float radius_value, ID2D1Brush* brush) {
        float thickness = 2.0f;
        if (text_brush_) {
            text_brush_->SetOpacity(0.22f);
            render_target_->DrawEllipse(D2D1::Ellipse(center, radius_value, radius_value), text_brush_.Get(), thickness,
                                        round_stroke_.Get());
            text_brush_->SetOpacity(1.0f);
        }
        if (!factory_ || !brush) {
            return;
        }

        ULONGLONG now = GetTickCount64();
        float t = static_cast<float>((now % 900ULL) / 900.0f);
        float start_angle = t * 6.2831853f;
        float sweep = 1.4f;
        float end_angle = start_angle + sweep;

        D2D1_POINT_2F start = D2D1::Point2F(center.x + std::cos(start_angle) * radius_value,
                                            center.y + std::sin(start_angle) * radius_value);
        D2D1_POINT_2F end = D2D1::Point2F(center.x + std::cos(end_angle) * radius_value,
                                          center.y + std::sin(end_angle) * radius_value);

        ComPtr<ID2D1PathGeometry> path;
        if (FAILED(factory_->CreatePathGeometry(path.GetAddressOf())) || !path) {
            return;
        }
        ComPtr<ID2D1GeometrySink> sink;
        if (FAILED(path->Open(sink.GetAddressOf())) || !sink) {
            return;
        }

        sink->BeginFigure(start, D2D1_FIGURE_BEGIN_HOLLOW);
        D2D1_ARC_SEGMENT arc = {};
        arc.point = end;
        arc.size = D2D1::SizeF(radius_value, radius_value);
        arc.sweepDirection = D2D1_SWEEP_DIRECTION_CLOCKWISE;
        arc.arcSize = D2D1_ARC_SIZE_SMALL;
        sink->AddArc(arc);
        sink->EndFigure(D2D1_FIGURE_END_OPEN);
        sink->Close();

        float arc_opacity = enabled ? 1.0f : 0.5f;
        brush->SetOpacity(arc_opacity);
        render_target_->DrawGeometry(path.Get(), brush, thickness, round_stroke_.Get());
        brush->SetOpacity(1.0f);
    };

    float center_y = (rect.top + rect.bottom) * 0.5f;
    D2D1_RECT_F text_rect = rect;
    if (show_spinner) {
        float spinner_radius = 7.5f;
        float spinner_pad = 14.0f;
        D2D1_POINT_2F spinner_center = D2D1::Point2F(rect.left + spinner_pad + spinner_radius, center_y);
        draw_spinner(spinner_center, spinner_radius, accent ? accent : text_brush_.Get());
        text_rect.left = spinner_center.x + spinner_radius + 10.0f;
    }

    IDWriteTextFormat* format = status_format_ ? status_format_.Get() : pill_format_.Get();
    ID2D1SolidColorBrush* label_brush = enabled ? text_brush_.Get() : muted_brush_.Get();
    if (format && label_brush) {
        format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        float label_opacity = enabled ? 1.0f : 0.6f;
        label_brush->SetOpacity(label_opacity);
        render_target_->DrawTextW(label.c_str(), static_cast<UINT32>(label.size()), format, text_rect, label_brush);
        label_brush->SetOpacity(1.0f);
        format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
    }
}

void DxUiRendererImpl::DrawSpinner(D2D1_POINT_2F center, float radius) {
    float thickness = 3.0f;
    if (text_brush_) {
        text_brush_->SetOpacity(0.22f);
        render_target_->DrawEllipse(D2D1::Ellipse(center, radius, radius), text_brush_.Get(), thickness,
                                    round_stroke_.Get());
        text_brush_->SetOpacity(1.0f);
    }

    if (!accent_brush_ || !factory_) {
        return;
    }

    ULONGLONG now = GetTickCount64();
    float t = static_cast<float>((now % 900ULL) / 900.0f);
    float start_angle = t * 6.2831853f;
    float sweep = 1.4f;
    float end_angle = start_angle + sweep;

    D2D1_POINT_2F start = D2D1::Point2F(center.x + std::cos(start_angle) * radius,
                                        center.y + std::sin(start_angle) * radius);
    D2D1_POINT_2F end = D2D1::Point2F(center.x + std::cos(end_angle) * radius,
                                      center.y + std::sin(end_angle) * radius);

    ComPtr<ID2D1PathGeometry> path;
    if (FAILED(factory_->CreatePathGeometry(path.GetAddressOf())) || !path) {
        return;
    }
    ComPtr<ID2D1GeometrySink> sink;
    if (FAILED(path->Open(sink.GetAddressOf())) || !sink) {
        return;
    }

    sink->BeginFigure(start, D2D1_FIGURE_BEGIN_HOLLOW);
    D2D1_ARC_SEGMENT arc = {};
    arc.point = end;
    arc.size = D2D1::SizeF(radius, radius);
    arc.sweepDirection = D2D1_SWEEP_DIRECTION_CLOCKWISE;
    arc.arcSize = D2D1_ARC_SIZE_SMALL;
    sink->AddArc(arc);
    sink->EndFigure(D2D1_FIGURE_END_OPEN);
    sink->Close();

    render_target_->DrawGeometry(path.Get(), accent_brush_.Get(), thickness, round_stroke_.Get());
}

bool DxUiRendererImpl::LoadBitmapFromFile(const wchar_t* path, ID2D1Bitmap** bitmap) {
    if (!bitmap) {
        return false;
    }
    *bitmap = nullptr;
    if (!render_target_ || !wic_factory_ || !path || !*path) {
        return false;
    }

    ComPtr<IWICBitmapDecoder> decoder;
    HRESULT hr = wic_factory_->CreateDecoderFromFilename(path, nullptr, GENERIC_READ,
                                                         WICDecodeMetadataCacheOnLoad, decoder.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    ComPtr<IWICBitmapFrameDecode> frame;
    hr = decoder->GetFrame(0, frame.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }

    ComPtr<IWICFormatConverter> converter;
    hr = wic_factory_->CreateFormatConverter(converter.GetAddressOf());
    if (FAILED(hr)) {
        return false;
    }
    hr = converter->Initialize(frame.Get(), GUID_WICPixelFormat32bppPBGRA, WICBitmapDitherTypeNone, nullptr, 0.0,
                               WICBitmapPaletteTypeMedianCut);
    if (FAILED(hr)) {
        return false;
    }

    hr = render_target_->CreateBitmapFromWicBitmap(converter.Get(), nullptr, bitmap);
    return SUCCEEDED(hr);
}

ID2D1Bitmap* DxUiRendererImpl::GetAvatarBitmap(const std::wstring& path) {
    if (path.empty()) {
        return nullptr;
    }
    auto it = avatar_cache_.find(path);
    if (it != avatar_cache_.end()) {
        return it->second.Get();
    }

    ComPtr<ID2D1Bitmap> bitmap;
    if (LoadBitmapFromFile(path.c_str(), bitmap.GetAddressOf())) {
        avatar_cache_[path] = bitmap;
        return avatar_cache_[path].Get();
    }

    avatar_cache_[path] = nullptr;
    return nullptr;
}

bool DxUiRendererImpl::GetChildRect(HWND child, D2D1_RECT_F* out) const {
    if (!child || !out) {
        return false;
    }
    RECT rc = {};
    if (!GetWindowRect(child, &rc)) {
        return false;
    }
    MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&rc), 2);
    *out = RectFromPixels(rc);
    return true;
}

std::wstring DxUiRendererImpl::GetWindowTextString(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    int len = GetWindowTextLengthW(hwnd);
    if (len <= 0) {
        return {};
    }
    std::wstring text(static_cast<size_t>(len), L'\0');
    int read = GetWindowTextW(hwnd, text.data(), len + 1);
    if (read <= 0) {
        return {};
    }
    text.resize(static_cast<size_t>(read));
    return text;
}

void DxUiRendererImpl::DrawTitle() {
    float topbar_height = ToDip(static_cast<float>(g_titlebar_height));
    float row_height = 46.0f;
    if (topbar_height > 0.0f && topbar_height < row_height) {
        row_height = topbar_height;
    }
    float title_offset = 3.0f;
    float center_y = panel_rect_.top + row_height * 0.5f + title_offset;
    float right_limit = panel_rect_.right - 18.0f;
    if (!IsRectEmpty(&g_btn_min)) {
        right_limit = ToDip(static_cast<float>(g_btn_min.left)) - 8.0f;
    } else if (!IsRectEmpty(&g_btn_close)) {
        right_limit = ToDip(static_cast<float>(g_btn_close.left)) - 8.0f;
    }
    float mark_size = 40.0f;
    float mark_x = panel_rect_.left + 18.0f;
    bool show_mark = (g_stage == UiStage::Dashboard ||
                      (g_stage == UiStage::Loading && !IsRectEmpty(&g_card_programs)));
    if (show_mark) {
        float mark_y = center_y - mark_size * 0.5f;
        float mark_radius = 14.0f;
        D2D1_RECT_F mark_rect = D2D1::RectF(mark_x, mark_y, mark_x + mark_size, mark_y + mark_size);
        D2D1_ROUNDED_RECT mark = D2D1::RoundedRect(mark_rect, mark_radius, mark_radius);
        float mark_inset = 1.5f;
        float mark_inner_radius = (std::max)(0.0f, mark_radius - mark_inset);
        D2D1_ROUNDED_RECT mark_inner =
            D2D1::RoundedRect(D2D1::RectF(mark_x + mark_inset, mark_y + mark_inset,
                                          mark_x + mark_size - mark_inset, mark_y + mark_size - mark_inset),
                              mark_inner_radius, mark_inner_radius);
        if (field_fill_brush_) {
            render_target_->FillRoundedRectangle(mark, field_fill_brush_.Get());
        }
        if (progress_brush_) {
            progress_brush_->SetStartPoint(D2D1::Point2F(mark_x, mark_y));
            progress_brush_->SetEndPoint(D2D1::Point2F(mark_x + mark_size, mark_y + mark_size));
            progress_brush_->SetOpacity(0.30f);
            render_target_->FillRoundedRectangle(mark, progress_brush_.Get());
            progress_brush_->SetOpacity(1.0f);
        } else if (accent_brush_) {
            accent_brush_->SetOpacity(0.30f);
            render_target_->FillRoundedRectangle(mark, accent_brush_.Get());
            accent_brush_->SetOpacity(1.0f);
        }
        if (text_brush_) {
            text_brush_->SetOpacity(0.16f);
            D2D1_POINT_2F glow_center = D2D1::Point2F(mark_x + mark_size * 0.3f, mark_y + mark_size * 0.3f);
            render_target_->FillEllipse(D2D1::Ellipse(glow_center, mark_size * 0.35f, mark_size * 0.35f),
                                        text_brush_.Get());
            text_brush_->SetOpacity(1.0f);
        }
        if (mark_spin_brush_) {
            ULONGLONG now = GetTickCount64();
            float angle = static_cast<float>((now % 5400ULL) / 5400.0f) * 6.2831853f;
            float sweep = mark_size * 1.0f;
            D2D1_POINT_2F center = D2D1::Point2F(mark_x + mark_size * 0.5f, mark_y + mark_size * 0.5f);
            float dx = std::cos(angle);
            float dy = std::sin(angle);
            mark_spin_brush_->SetStartPoint(D2D1::Point2F(center.x - dx * sweep, center.y - dy * sweep));
            mark_spin_brush_->SetEndPoint(D2D1::Point2F(center.x + dx * sweep, center.y + dy * sweep));
            mark_spin_brush_->SetOpacity(0.55f);
            render_target_->FillRoundedRectangle(mark_inner, mark_spin_brush_.Get());
            mark_spin_brush_->SetOpacity(1.0f);
        }
        if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(mark, field_border_brush_.Get(), 1.0f);
        } else if (panel_border_brush_) {
            render_target_->DrawRoundedRectangle(mark, panel_border_brush_.Get(), 1.0f);
        }
    }

    std::wstring title = TitleForStage(g_stage);
    D2D1_RECT_F title_rect = panel_rect_;
    title_rect.left = show_mark ? (mark_x + mark_size + 12.0f) : (panel_rect_.left + 18.0f);
    title_rect.top = panel_rect_.top + title_offset;
    title_rect.bottom = title_rect.top + row_height;
    title_rect.right = right_limit - 12.0f;
    if (title_rect.right < title_rect.left + 12.0f) {
        title_rect.right = title_rect.left + 12.0f;
    }

    std::wstring build = L"build " + BuildLabelText(kLoaderVersion);
    float pill_height = 16.0f;
    float pill_pad_x = 5.0f;
    float pill_width = 0.0f;
    bool draw_pill = false;
    float title_width = 0.0f;

    if (title_format_) {
        title_width = MeasureTextWidth(title, title_format_.Get());
    }

    IDWriteTextFormat* build_format = label_format_ ? label_format_.Get()
                                                    : (mono_format_ ? mono_format_.Get() : pill_format_.Get());
    if (build_format && !build.empty()) {
        float build_width = MeasureTextWidth(build, build_format);
        pill_width = build_width + pill_pad_x * 2.0f;
        draw_pill = (pill_width > 0.0f);
    }

    if (title_format_ && text_brush_) {
        render_target_->DrawTextW(title.c_str(), static_cast<UINT32>(title.size()), title_format_.Get(), title_rect,
                                  text_brush_.Get());
    }

    if (draw_pill) {
        float edge = 6.0f;
        float pill_x = panel_rect_.right - edge - pill_width;
        float pill_y = panel_rect_.bottom - edge - pill_height;
        if (!IsRectEmpty(&g_card_telemetry)) {
            D2D1_RECT_F telemetry = RectFromPixels(g_card_telemetry);
            float min_y = telemetry.bottom + 8.0f;
            if (pill_y < min_y) {
                pill_y = min_y;
            }
            if (pill_y + pill_height > panel_rect_.bottom - edge) {
                pill_y = panel_rect_.bottom - edge - pill_height;
            }
        }
        D2D1_RECT_F pill = D2D1::RectF(pill_x, pill_y, pill_x + pill_width, pill_y + pill_height);
        D2D1_ROUNDED_RECT pill_round = D2D1::RoundedRect(pill, pill_height * 0.5f, pill_height * 0.5f);
        if (field_fill_brush_) {
            field_fill_brush_->SetOpacity(0.20f);
            render_target_->FillRoundedRectangle(pill_round, field_fill_brush_.Get());
            field_fill_brush_->SetOpacity(1.0f);
        }
        if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(pill_round, field_border_brush_.Get(), 1.0f);
        } else if (panel_border_brush_) {
            render_target_->DrawRoundedRectangle(pill_round, panel_border_brush_.Get(), 1.0f);
        }
        if (build_format && faint_brush_) {
            build_format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
            build_format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            render_target_->DrawTextW(build.c_str(), static_cast<UINT32>(build.size()), build_format, pill,
                                      faint_brush_.Get());
            build_format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            build_format->SetParagraphAlignment(build_format == mono_format_.Get()
                                                    ? DWRITE_PARAGRAPH_ALIGNMENT_NEAR
                                                    : DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }
    }
}

void DxUiRendererImpl::DrawStatusPills() {
    bool show_pills = (g_stage == UiStage::Dashboard);
    if (!show_pills && g_stage == UiStage::Loading && !IsRectEmpty(&g_card_programs)) {
        show_pills = true;
    }
    if (!show_pills || !render_target_ || !pill_format_) {
        return;
    }

    float topbar_height = ToDip(static_cast<float>(g_titlebar_height));
    float row_height = 46.0f;
    if (topbar_height > 0.0f && topbar_height < row_height) {
        row_height = topbar_height;
    }

    float pill_height = 26.0f;
    float y = panel_rect_.top + row_height + 4.0f;
    float bottom_limit = panel_rect_.top + topbar_height - 6.0f;
    if (y + pill_height > bottom_limit) {
        y = bottom_limit - pill_height;
    }
    if (y < panel_rect_.top + row_height) {
        y = panel_rect_.top + row_height;
    }

    float x = panel_rect_.left + 18.0f;
    float max_right = panel_rect_.right - 18.0f;
    float gap = 10.0f;

    std::wstring status_snapshot = GetStatusSnapshot();
    std::wstring state = DeriveModeFromStatus(status_snapshot);
    bool ready = (state == L"READY");
    bool state_on = true;
    bool blink_ready = ready;
    ID2D1SolidColorBrush* dot_brush = accent_brush_.Get();
    if (state == L"WAITING" && warn_brush_) {
        dot_brush = warn_brush_.Get();
    }

    ProgramInfo sub_program = {};
    bool has_programs = false;
    bool has_selected = false;
    EnterCriticalSection(&g_programs_lock);
    if (!g_programs.empty()) {
        has_programs = true;
        sub_program = g_programs.front();
        if (g_selected_index >= 0 && static_cast<size_t>(g_selected_index) < g_programs.size()) {
            sub_program = g_programs[static_cast<size_t>(g_selected_index)];
            has_selected = true;
        }
    }
    LeaveCriticalSection(&g_programs_lock);

    std::wstring selected_name = has_selected ? sub_program.name : L"None";
    if (has_selected && selected_name.empty()) {
        selected_name = sub_program.code;
    }
    if (!has_programs) {
        selected_name = L"None";
    }

    std::wstring subscription = L"-";
    if (has_programs) {
        subscription = FormatExpiryLabel(sub_program.expires_at);
        if (subscription.empty()) {
            subscription = L"-";
        }
    }

    auto draw_pill = [&](const std::wstring& label,
                         const std::wstring& value,
                         bool show_dot,
                         bool dot_on,
                         ID2D1SolidColorBrush* dot_fill,
                         ID2D1SolidColorBrush* label_brush,
                         ID2D1SolidColorBrush* value_brush) -> bool {
        if (!label_brush) {
            return false;
        }
        float pad_x = 10.0f;
        float dot_size = 8.0f;
        float dot_gap = 8.0f;
        float value_gap = 6.0f;

        float label_width = MeasureTextWidth(label, pill_format_.Get());
        float value_width = value.empty() ? 0.0f : MeasureTextWidth(value, pill_format_.Get());

        float width = pad_x * 2 + label_width;
        if (show_dot) {
            width += dot_size + dot_gap;
        }
        if (!value.empty()) {
            width += value_gap + value_width;
        }

        if (x + width > max_right) {
            return false;
        }

        D2D1_RECT_F pill = D2D1::RectF(x, y, x + width, y + pill_height);
        D2D1_ROUNDED_RECT round = D2D1::RoundedRect(pill, pill_height * 0.5f, pill_height * 0.5f);

        if (field_fill_brush_) {
            render_target_->FillRoundedRectangle(round, field_fill_brush_.Get());
        }
        if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(round, field_border_brush_.Get(), 1.0f);
        }

        float cursor = pill.left + pad_x;
        float center_y = (pill.top + pill.bottom) * 0.5f;

        if (show_dot) {
            D2D1_POINT_2F center = D2D1::Point2F(cursor + dot_size * 0.5f, center_y);
            if (dot_on && dot_fill) {
                if (blink_ready) {
                    float blink = static_cast<float>((GetTickCount64() % 1200ULL) / 1200.0);
                    float blink_sin = 0.4f + 0.6f * std::sin(blink * 6.2831853f);
                    dot_fill->SetOpacity(blink_sin);
                    render_target_->FillEllipse(D2D1::Ellipse(center, dot_size * 0.5f, dot_size * 0.5f), dot_fill);
                    dot_fill->SetOpacity(1.0f);
                } else {
                    dot_fill->SetOpacity(1.0f);
                    render_target_->FillEllipse(D2D1::Ellipse(center, dot_size * 0.5f, dot_size * 0.5f), dot_fill);
                    float pulse = static_cast<float>((GetTickCount64() % 1200ULL) / 1200.0);
                    float pulse_sin = 0.5f + 0.5f * std::sin(pulse * 6.2831853f);
                    float ring_radius = dot_size * 0.5f + 6.0f * pulse_sin;
                    dot_fill->SetOpacity(0.25f * (1.0f - pulse_sin));
                    render_target_->DrawEllipse(D2D1::Ellipse(center, ring_radius, ring_radius), dot_fill, 1.0f);
                    dot_fill->SetOpacity(1.0f);
                }
            } else if (muted_brush_) {
                render_target_->FillEllipse(D2D1::Ellipse(center, dot_size * 0.5f, dot_size * 0.5f),
                                            muted_brush_.Get());
            }
            cursor += dot_size + dot_gap;
        }

        if (!label.empty()) {
            D2D1_RECT_F label_rect = D2D1::RectF(cursor, pill.top, cursor + label_width, pill.bottom);
            render_target_->DrawTextW(label.c_str(), static_cast<UINT32>(label.size()), pill_format_.Get(), label_rect,
                                      label_brush);
        }

        if (!value.empty() && value_brush) {
            float value_x = cursor + label_width + value_gap;
            D2D1_RECT_F value_rect = D2D1::RectF(value_x, pill.top, value_x + value_width, pill.bottom);
            render_target_->DrawTextW(value.c_str(), static_cast<UINT32>(value.size()), pill_format_.Get(), value_rect,
                                      value_brush);
        }

        x += width + gap;
        return true;
    };

    if (text_brush_) {
        draw_pill(state, L"", true, state_on, dot_brush, text_brush_.Get(), text_brush_.Get());
    }
    if (muted_brush_ && text_brush_) {
        draw_pill(L"Selected:", selected_name, false, false, nullptr, muted_brush_.Get(), text_brush_.Get());
        draw_pill(L"Subscription:", subscription, false, false, nullptr, muted_brush_.Get(), text_brush_.Get());
    }
}

void DxUiRendererImpl::UpdateSessionState(const std::wstring& mode) {
    bool active = (mode != L"READY");
    ULONGLONG now = GetTickCount64();
    if (active && !session_active_) {
        session_active_ = true;
        session_start_tick_ = now;
        last_run_label_ = FormatHourMinute();
    } else if (!active && session_active_) {
        session_active_ = false;
        session_start_tick_ = 0;
    }
}

void DxUiRendererImpl::DrawTitleButtons() {
    auto draw_button = [&](const RECT& rc, bool hover, bool pressed, bool close_btn) {
        D2D1_RECT_F rect = RectFromPixels(rc);
        float radius = 12.0f;
        D2D1_ROUNDED_RECT round = D2D1::RoundedRect(rect, radius, radius);
        if (field_fill_brush_) {
            float opacity = pressed ? 0.36f : (hover ? 0.28f : 0.20f);
            field_fill_brush_->SetOpacity(opacity);
            render_target_->FillRoundedRectangle(round, field_fill_brush_.Get());
            field_fill_brush_->SetOpacity(1.0f);
        }
        if (field_border_brush_) {
            render_target_->DrawRoundedRectangle(round, field_border_brush_.Get(), 1.0f);
        } else if (panel_border_brush_) {
            render_target_->DrawRoundedRectangle(round, panel_border_brush_.Get(), 1.0f);
        }

        D2D1_COLOR_F glyph = close_btn && hover ? theme_.warn : theme_.text;
        ComPtr<ID2D1SolidColorBrush> glyph_brush;
        render_target_->CreateSolidColorBrush(glyph, glyph_brush.GetAddressOf());
        if (!glyph_brush) {
            return;
        }

        float pad = 8.0f;
        if (close_btn) {
            render_target_->DrawLine(D2D1::Point2F(rect.left + pad, rect.top + pad),
                                     D2D1::Point2F(rect.right - pad, rect.bottom - pad), glyph_brush.Get(), 1.0f);
            render_target_->DrawLine(D2D1::Point2F(rect.right - pad, rect.top + pad),
                                     D2D1::Point2F(rect.left + pad, rect.bottom - pad), glyph_brush.Get(), 1.0f);
        } else {
            float y = (rect.top + rect.bottom) * 0.5f;
            render_target_->DrawLine(D2D1::Point2F(rect.left + pad, y), D2D1::Point2F(rect.right - pad, y),
                                     glyph_brush.Get(), 1.0f);
        }
    };

    draw_button(g_btn_min, g_hover_min, g_pressed_min, false);
    draw_button(g_btn_close, g_hover_close, g_pressed_close, true);
}

float DxUiRendererImpl::MeasureTextWidth(const std::wstring& text, IDWriteTextFormat* format) const {
    if (!dwrite_factory_ || !format || text.empty()) {
        return 0.0f;
    }
    ComPtr<IDWriteTextLayout> layout;
    HRESULT hr = dwrite_factory_->CreateTextLayout(text.c_str(), static_cast<UINT32>(text.size()), format, 1000.0f,
                                                   100.0f, layout.GetAddressOf());
    if (FAILED(hr) || !layout) {
        return 0.0f;
    }
    DWRITE_TEXT_METRICS metrics = {};
    if (FAILED(layout->GetMetrics(&metrics))) {
        return 0.0f;
    }
    return metrics.width;
}

DxUiRenderer::DxUiRenderer()
    : hwnd_(nullptr)
    , dpi_(96.0f) {}

DxUiRenderer::~DxUiRenderer() {
    Shutdown();
}

bool DxUiRenderer::Initialize(HWND hwnd) {
    hwnd_ = hwnd;
    auto impl = std::make_unique<DxUiRendererImpl>(hwnd_);
    if (!impl->Initialize()) {
        return false;
    }
    impl_.swap(impl);
    return true;
}

void DxUiRenderer::SetDpi(UINT dpi) {
    dpi_ = static_cast<float>(dpi);
    if (impl_) {
        impl_->SetDpi(dpi);
    }
}

void DxUiRenderer::Resize(UINT width, UINT height) {
    if (impl_) {
        impl_->Resize(width, height);
    }
}

void DxUiRenderer::Render() {
    if (impl_) {
        impl_->Render();
    }
}

void DxUiRenderer::Shutdown() {
    if (impl_) {
        impl_->Shutdown();
        impl_.reset();
    }
    hwnd_ = nullptr;
}

} // namespace loader

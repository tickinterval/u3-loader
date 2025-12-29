#pragma once

#include <windows.h>

#include <memory>

namespace loader {

class DxUiRendererImpl;

class DxUiRenderer {
public:
    DxUiRenderer();
    ~DxUiRenderer();

    bool Initialize(HWND hwnd);
    void SetDpi(UINT dpi);
    void Resize(UINT width, UINT height);
    void Render();
    void Shutdown();

private:
    HWND hwnd_;
    float dpi_;
    std::unique_ptr<DxUiRendererImpl> impl_;
};

} // namespace loader

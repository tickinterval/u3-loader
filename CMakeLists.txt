cmake_minimum_required(VERSION 3.20)
project(LoaderApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(loader WIN32
    src/main.cpp
    src/ui.cpp
    src/ui_dx.cpp
    src/app_state.cpp
    src/injector.cpp
    src/anti_debug.cpp
    src/protection.cpp
    src/hwid_validator.cpp
    src/process_info.cpp
    # anti_crack.h - header only
)

target_compile_definitions(loader PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)

target_link_libraries(loader PRIVATE ws2_32 advapi32 bcrypt crypt32 secur32 wintrust comctl32 msimg32 ntdll psapi d2d1 dwrite)

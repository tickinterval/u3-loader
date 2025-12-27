cmake_minimum_required(VERSION 3.20)
project(LoaderApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(loader WIN32
    src/main.cpp
    src/ui.cpp
    src/app_state.cpp
    src/injector.cpp
    src/anti_debug.cpp
    src/protection.cpp
    src/hwid_validator.cpp
    src/process_info.cpp
    # anti_crack.h - header only
)

target_compile_definitions(loader PRIVATE UNICODE _UNICODE)

target_link_libraries(loader PRIVATE winhttp crypt32 wintrust comctl32 msimg32 ntdll psapi)

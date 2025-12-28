#include "injector.h"
#include <tlhelp32.h>
#include <wincrypt.h>
#include <vector>
#include <cstring>

// Определения для совместимости
#ifndef IMAGE_SNAP_BY_ORDINAL
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG) != 0)
#endif

#ifndef IMAGE_ORDINAL
#define IMAGE_ORDINAL(Ordinal) (Ordinal & 0xffff)
#endif

namespace loader {
namespace injector {

using NTSTATUS = LONG;

// ================== ENCRYPTION ==================

// RC4 для шифрования DLL в памяти
class RC4 {
public:
    RC4(const BYTE* key, size_t keyLen) {
        for (int i = 0; i < 256; i++) {
            S[i] = static_cast<BYTE>(i);
        }
        
        BYTE j = 0;
        for (int i = 0; i < 256; i++) {
            j = j + S[i] + key[i % keyLen];
            std::swap(S[i], S[j]);
        }
        
        i_ = 0;
        j_ = 0;
    }
    
    void Process(BYTE* data, size_t len) {
        for (size_t k = 0; k < len; k++) {
            i_ = i_ + 1;
            j_ = j_ + S[i_];
            std::swap(S[i_], S[j_]);
            data[k] ^= S[(S[i_] + S[j_]) & 0xFF];
        }
    }
    
private:
    BYTE S[256];
    BYTE i_, j_;
};

// Генерация случайного ключа
void GenerateRandomKey(BYTE* key, size_t len) {
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, static_cast<DWORD>(len), key);
        CryptReleaseContext(hProv, 0);
    } else {
        // Fallback: используем GetTickCount и другие источники энтропии
        for (size_t i = 0; i < len; i++) {
            key[i] = static_cast<BYTE>((GetTickCount() >> (i % 4) * 8) ^ (i * 0x37) ^ GetCurrentProcessId());
            Sleep(0);
        }
    }
}

// Шифрование DLL bytes в памяти
void EncryptDllBytes(std::vector<char>& dll_bytes, BYTE* key, size_t keyLen) {
    RC4 rc4(key, keyLen);
    rc4.Process(reinterpret_cast<BYTE*>(dll_bytes.data()), dll_bytes.size());
}

// Расшифровка DLL bytes
void DecryptDllBytes(std::vector<char>& dll_bytes, const BYTE* key, size_t keyLen) {
    RC4 rc4(key, keyLen);
    rc4.Process(reinterpret_cast<BYTE*>(dll_bytes.data()), dll_bytes.size());
}

// ================== NT API ==================

// NtCreateThreadEx - менее детектируемый способ создания потока
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList
);

// NtWaitForSingleObject
typedef NTSTATUS(NTAPI* NtWaitForSingleObject_t)(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout
);

// Создание потока через NtCreateThreadEx (менее детектируемый)
HANDLE CreateRemoteThreadNt(HANDLE process, LPVOID startAddress, LPVOID parameter) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return nullptr;
    }
    
    auto NtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_t>(
        GetProcAddress(ntdll, "NtCreateThreadEx"));
    
    if (!NtCreateThreadEx) {
        return nullptr;
    }
    
    HANDLE threadHandle = nullptr;
    NTSTATUS status = NtCreateThreadEx(
        &threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        process,
        startAddress,
        parameter,
        0,      // CreateFlags: 0 = run immediately
        0,      // ZeroBits
        0,      // StackSize (default)
        0,      // MaximumStackSize (default)
        nullptr // AttributeList
    );
    
    if (status < 0) {
        return nullptr;
    }
    
    return threadHandle;
}

// Ожидание через NtWaitForSingleObject
void WaitForThreadNt(HANDLE thread) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        WaitForSingleObject(thread, INFINITE);
        return;
    }
    
    auto NtWaitForSingleObject = reinterpret_cast<NtWaitForSingleObject_t>(
        GetProcAddress(ntdll, "NtWaitForSingleObject"));
    
    if (NtWaitForSingleObject) {
        NtWaitForSingleObject(thread, FALSE, nullptr);
    } else {
        WaitForSingleObject(thread, INFINITE);
    }
}

// ================== PE STRUCTURES ==================

// PE структуры для парсинга
struct ManualMapData {
    LPVOID image_base;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_BASE_RELOCATION base_reloc;
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
};

// Шелл-код для загрузки DLL в удаленном процессе (x86)
#pragma pack(push, 1)
struct LoaderData32 {
    LPVOID image_base;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_BASE_RELOCATION base_reloc;
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
    
    // Функции из kernel32.dll
    decltype(&LoadLibraryA) fn_LoadLibraryA;
    decltype(&GetProcAddress) fn_GetProcAddress;
    decltype(&VirtualProtect) fn_VirtualProtect;
};
#pragma pack(pop)

// Шелл-код для выполнения в удаленном процессе (x86)
DWORD __stdcall LoaderShellcode32(LoaderData32* loader_data) {
    if (!loader_data || !loader_data->image_base || !loader_data->nt_headers) {
        return 0;
    }

    BYTE* base = reinterpret_cast<BYTE*>(loader_data->image_base);
    PIMAGE_NT_HEADERS nt_headers = loader_data->nt_headers;
    PIMAGE_OPTIONAL_HEADER opt_header = &nt_headers->OptionalHeader;

    // Обработка релокаций
    if (loader_data->base_reloc && loader_data->base_reloc->VirtualAddress) {
        PIMAGE_BASE_RELOCATION reloc = loader_data->base_reloc;
        DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(base) - opt_header->ImageBase;
        
        while (reloc->VirtualAddress) {
            if (reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* rel_info = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
                
                for (DWORD i = 0; i < count; i++) {
                    if ((rel_info[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* patch = reinterpret_cast<DWORD*>(base + reloc->VirtualAddress + (rel_info[i] & 0xFFF));
                        *patch += static_cast<DWORD>(delta);
                    }
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
        }
    }

    // Обработка импортов
    if (loader_data->import_descriptor) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = loader_data->import_descriptor;
        
        while (import_desc->Name) {
            char* module_name = reinterpret_cast<char*>(base + import_desc->Name);
            HMODULE module = loader_data->fn_LoadLibraryA(module_name);
            
            if (module) {
                PIMAGE_THUNK_DATA thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA func_ref = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->FirstThunk);
                
                if (!thunk) {
                    thunk = func_ref;
                }
                
                while (thunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                        FARPROC func = loader_data->fn_GetProcAddress(module, 
                            reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(thunk->u1.Ordinal)));
                        func_ref->u1.Function = reinterpret_cast<DWORD_PTR>(func);
                    } else {
                        PIMAGE_IMPORT_BY_NAME import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + thunk->u1.AddressOfData);
                        FARPROC func = loader_data->fn_GetProcAddress(module, import_name->Name);
                        func_ref->u1.Function = reinterpret_cast<DWORD_PTR>(func);
                    }
                    thunk++;
                    func_ref++;
                }
            }
            import_desc++;
        }
    }

    // Установка прав доступа для секций
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = (protect == PAGE_READWRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        
        DWORD old_protect;
        loader_data->fn_VirtualProtect(base + section[i].VirtualAddress, 
            section[i].Misc.VirtualSize, protect, &old_protect);
    }

    // Вызов DllMain
    using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    DllMain_t dll_main = reinterpret_cast<DllMain_t>(base + opt_header->AddressOfEntryPoint);
    
    if (dll_main) {
        dll_main(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr);
    }

    return 1;
}

// Заглушка для определения размера шелл-кода
DWORD __stdcall LoaderShellcodeEnd() {
    return 0;
}

// ================== PROCESS UTILITIES ==================

DWORD FindProcessId(const std::wstring& process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

DWORD WaitForProcessId(const std::wstring& process_name) {
    DWORD pid = 0;
    while (pid == 0) {
        pid = FindProcessId(process_name);
        if (pid == 0) {
            Sleep(500);
        }
    }
    return pid;
}

bool IsProcess32Bit(DWORD process_id) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
    if (!process) {
        return false;
    }

    BOOL is_wow64 = FALSE;
    bool is_32bit = false;

#ifdef _WIN64
    if (IsWow64Process(process, &is_wow64)) {
        is_32bit = (is_wow64 == TRUE);
    }
#else
    is_32bit = true;
#endif

    CloseHandle(process);
    return is_32bit;
}

// ================== SECURE MEMORY ==================

// Затирание памяти (защита от дампа)
void SecureZeroMemoryVector(std::vector<char>& vec) {
    volatile char* p = vec.data();
    size_t n = vec.size();
    while (n--) {
        *p++ = 0;
    }
    vec.clear();
    vec.shrink_to_fit();
}

void SecureZeroMemoryVector(std::vector<BYTE>& vec) {
    volatile BYTE* p = vec.data();
    size_t n = vec.size();
    while (n--) {
        *p++ = 0;
    }
    vec.clear();
    vec.shrink_to_fit();
}

// ================== MAIN INJECTION ==================

// Внутренняя функция инжекта (используется обеими публичными функциями)
static InjectionResult InjectDllInternal(DWORD target_pid, const std::vector<char>& dll_bytes_original) {
    InjectionResult result = { false, L"", target_pid };

    // Создаём копию для работы
    std::vector<char> dll_bytes = dll_bytes_original;

    // Проверка размера DLL
    if (dll_bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.error = L"DLL is too small";
        return result;
    }

    // Парсинг PE заголовков
    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_bytes.data());
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        result.error = L"Invalid signature DOS";
        return result;
    }

    PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_bytes.data() + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        result.error = L"Wrong signature PE";
        return result;
    }

    // Проверка архитектуры DLL
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        result.error = L"DLL must be 32-bit (x86)";
        return result;
    }

    // Сохраняем важные данные до шифрования
    DWORD image_size = nt_headers->OptionalHeader.SizeOfImage;
    DWORD headers_size = nt_headers->OptionalHeader.SizeOfHeaders;
    WORD num_sections = nt_headers->FileHeader.NumberOfSections;
    DWORD e_lfanew = dos_header->e_lfanew;
    DWORD entry_point = nt_headers->OptionalHeader.AddressOfEntryPoint;
    DWORD reloc_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD import_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    // Сохраняем информацию о секциях
    struct SectionInfo {
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD Characteristics;
        DWORD VirtualSize;
    };
    std::vector<SectionInfo> sections_info(num_sections);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < num_sections; i++) {
        sections_info[i].VirtualAddress = section[i].VirtualAddress;
        sections_info[i].SizeOfRawData = section[i].SizeOfRawData;
        sections_info[i].PointerToRawData = section[i].PointerToRawData;
        sections_info[i].Characteristics = section[i].Characteristics;
        sections_info[i].VirtualSize = section[i].Misc.VirtualSize;
    }

    // Шифруем DLL в памяти
    BYTE encryptionKey[32];
    GenerateRandomKey(encryptionKey, sizeof(encryptionKey));
    EncryptDllBytes(dll_bytes, encryptionKey, sizeof(encryptionKey));

    // Открытие процесса
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!process) {
        SecureZeroMemoryVector(dll_bytes);
        result.error = L"Unable to open process (open as admin)";
        return result;
    }

    // Расшифровываем DLL обратно
    DecryptDllBytes(dll_bytes, encryptionKey, sizeof(encryptionKey));
    
    // Затираем ключ
    SecureZeroMemory(encryptionKey, sizeof(encryptionKey));

    // Выделение памяти в целевом процессе
    LPVOID remote_image = VirtualAllocEx(process, nullptr, image_size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remote_image) {
        SecureZeroMemoryVector(dll_bytes);
        result.error = L"An error occured: C0000005/C0000005";
        CloseHandle(process);
        return result;
    }

    // Подготовка образа в локальной памяти
    std::vector<BYTE> local_image(image_size, 0);
    
    // Копирование заголовков
    memcpy(local_image.data(), dll_bytes.data(), headers_size);

    // Копирование секций
    for (WORD i = 0; i < num_sections; i++) {
        if (sections_info[i].SizeOfRawData > 0) {
            memcpy(local_image.data() + sections_info[i].VirtualAddress,
                dll_bytes.data() + sections_info[i].PointerToRawData,
                sections_info[i].SizeOfRawData);
        }
    }

    // Затираем оригинальные байты DLL
    SecureZeroMemoryVector(dll_bytes);

    // Запись образа в процесс
    if (!WriteProcessMemory(process, remote_image, local_image.data(), image_size, nullptr)) {
        SecureZeroMemoryVector(local_image);
        result.error = L"An error occured: 80004005/80004005";
        VirtualFreeEx(process, remote_image, 0, MEM_RELEASE);
        CloseHandle(process);
        return result;
    }

    // Затираем локальный образ
    SecureZeroMemoryVector(local_image);

    // Подготовка данных для загрузчика
    LoaderData32 loader_data = {};
    loader_data.image_base = remote_image;
    loader_data.nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(remote_image) + e_lfanew);
    
    // Релокации
    if (reloc_rva) {
        loader_data.base_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<BYTE*>(remote_image) + reloc_rva);
    }

    // Импорты
    if (import_rva) {
        loader_data.import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            reinterpret_cast<BYTE*>(remote_image) + import_rva);
    }

    // Получение адресов функций kernel32
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    loader_data.fn_LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(GetProcAddress(kernel32, "LoadLibraryA"));
    loader_data.fn_GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(GetProcAddress(kernel32, "GetProcAddress"));
    loader_data.fn_VirtualProtect = reinterpret_cast<decltype(&VirtualProtect)>(GetProcAddress(kernel32, "VirtualProtect"));

    // Выделение памяти для данных загрузчика
    LPVOID remote_loader_data = VirtualAllocEx(process, nullptr, sizeof(LoaderData32), 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remote_loader_data) {
        result.error = L"An error occured: 8024001E/8024001E";
        VirtualFreeEx(process, remote_image, 0, MEM_RELEASE);
        CloseHandle(process);
        return result;
    }

    // Запись данных загрузчика
    if (!WriteProcessMemory(process, remote_loader_data, &loader_data, sizeof(LoaderData32), nullptr)) {
        result.error = L"An error occured: 0BADF00D/0BADF00D";
        VirtualFreeEx(process, remote_image, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_loader_data, 0, MEM_RELEASE);
        CloseHandle(process);
        return result;
    }

    // Выделение памяти для шелл-кода
    SIZE_T shellcode_size = reinterpret_cast<DWORD_PTR>(&LoaderShellcodeEnd) - 
                           reinterpret_cast<DWORD_PTR>(&LoaderShellcode32);
    
    LPVOID remote_shellcode = VirtualAllocEx(process, nullptr, shellcode_size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remote_shellcode) {
        result.error = L"An error occured: 0x887A0006/0x887A0001";
        VirtualFreeEx(process, remote_image, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_loader_data, 0, MEM_RELEASE);
        CloseHandle(process);
        return result;
    }

    // Запись шелл-кода
    if (!WriteProcessMemory(process, remote_shellcode, &LoaderShellcode32, shellcode_size, nullptr)) {
        result.error = L"An error occured: FEEDFACE/FEEDFACE";
        VirtualFreeEx(process, remote_image, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_loader_data, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_shellcode, 0, MEM_RELEASE);
        CloseHandle(process);
        return result;
    }

    // Создание удаленного потока через NtCreateThreadEx (менее детектируемый)
    HANDLE thread = CreateRemoteThreadNt(process, remote_shellcode, remote_loader_data);
    
    // Fallback на CreateRemoteThread если NtCreateThreadEx не сработал
    if (!thread) {
        thread = CreateRemoteThread(process, nullptr, 0, 
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_shellcode),
            remote_loader_data, 0, nullptr);
    }
    
    if (!thread) {
        result.error = L"An error occured: 00000000/00000001";
        VirtualFreeEx(process, remote_image, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_loader_data, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_shellcode, 0, MEM_RELEASE);
        CloseHandle(process);
        return result;
    }

    // Ожидание завершения потока через NT API
    WaitForThreadNt(thread);

    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);

    CloseHandle(thread);

    // Очистка
    VirtualFreeEx(process, remote_loader_data, 0, MEM_RELEASE);
    VirtualFreeEx(process, remote_shellcode, 0, MEM_RELEASE);

    CloseHandle(process);

    if (exit_code == 0) {
        result.error = L"An error occured: 0000ABCD/0000ABCE";
        return result;
    }

    result.success = true;
    return result;
}

// ================== PUBLIC API ==================

InjectionResult InjectDllByPid(DWORD target_pid, const std::vector<char>& dll_bytes) {
    // Проверка архитектуры процесса
    if (!IsProcess32Bit(target_pid)) {
        return { false, L"Process is not 32-bit", target_pid };
    }
    
    return InjectDllInternal(target_pid, dll_bytes);
}

InjectionResult InjectDll(const std::wstring& target_process_name, const std::vector<char>& dll_bytes) {
    // Поиск процесса
    DWORD target_pid = WaitForProcessId(target_process_name);
    
    return InjectDllByPid(target_pid, dll_bytes);
}

} // namespace injector
} // namespace loader

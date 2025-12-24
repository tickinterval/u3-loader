#pragma once

#include <string>
#include <vector>
#include <windows.h>

namespace loader {
namespace protection {

// XOR обфускация строк во время компиляции
template<size_t N>
class ObfuscatedString {
private:
    char data[N];
    
    constexpr void xor_encrypt(const char* str, char key) {
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ key;
        }
    }
    
public:
    constexpr ObfuscatedString(const char* str, char key) : data{} {
        xor_encrypt(str, key);
    }
    
    std::string decrypt(char key) const {
        std::string result;
        result.reserve(N);
        for (size_t i = 0; i < N && data[i] != '\0'; i++) {
            result.push_back(data[i] ^ key);
        }
        return result;
    }
};

// Макрос для обфускации строк
#define OBFUSCATE(str) ([]() { \
    constexpr char key = (__TIME__[7] ^ __TIME__[4]) + 0x42; \
    constexpr auto obf = ObfuscatedString<sizeof(str)>(str, key); \
    return obf.decrypt(key); \
}())

// Wide string версия
#define OBFUSCATE_W(str) ([]() -> std::wstring { \
    constexpr char key = (__TIME__[7] ^ __TIME__[4]) + 0x42; \
    std::string narrow = OBFUSCATE(str); \
    return std::wstring(narrow.begin(), narrow.end()); \
}())

// Получение зашифрованного публичного ключа
std::string GetPublicKey();

// Проверка целостности исполняемого файла
bool VerifyIntegrity();

// Вычисление хеша текущего EXE
std::string GetExeHash();

// Анти-VM проверки
bool IsRunningInVM();

// Проверка на sandboxes
bool IsRunningSandbox();

} // namespace protection
} // namespace loader



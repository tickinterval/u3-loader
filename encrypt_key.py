#!/usr/bin/env python3
"""
Утилита для шифрования RSA публичного ключа
Запускается автоматически при сборке
"""
import sys

# Твой RSA публичный ключ
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9rNMGQOVW5lfHTDZmujK
hUb3o04BBw/WlQVzb4iuZ8GAxHsTn7TlpZA241Tdd//+ZEBvBVrUlqdyLP9N0z09
nbSkjLolRoeeyA6s2CKsk/JeQ951llUEO177Ujo3bz10cObF2RV/Ud2rm/sUDC6x
LQrLOjPwqbGhku97NvA6jkaJProJpxCiTYYQJxsfSMqnT3RZvqCF1xumOeCtXFKk
HUiSEgMrx6n3ixQyDtAE2mAVZ0dOdJoJ9IFjFtgu9t6jSbi60mM+1M5kR0+OonVC
0bg5gJC8U0gJnb9SKcoQ2eFHCkNmsYAG+LxHJVoSm/lHfat8CuWaVELhAZ84dAdu
XQIDAQAB
-----END PUBLIC KEY-----"""

# XOR ключ (меняй при каждой сборке для уникальности)
XOR_KEY = 0x7E

def encrypt_key(key_str, xor_key):
    """Шифрует ключ через XOR"""
    encrypted = []
    for char in key_str:
        encrypted.append(ord(char) ^ xor_key)
    return encrypted

def main():
    encrypted = encrypt_key(PUBLIC_KEY, XOR_KEY)
    
    # Генерируем C++ массив
    output = []
    for i in range(0, len(encrypted), 16):
        chunk = encrypted[i:i+16]
        line = "    " + ", ".join(f"0x{b:02X}" for b in chunk) + ","
        output.append(line)
    
    print("\n".join(output))
    
    # Также выводим размер
    print(f"\n// Size: {len(encrypted)} bytes", file=sys.stderr)
    print(f"// XOR Key: 0x{XOR_KEY:02X}", file=sys.stderr)

if __name__ == "__main__":
    main()






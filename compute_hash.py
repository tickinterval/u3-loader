#!/usr/bin/env python3
"""
Compute and embed the loader integrity hash.

Usage: python compute_hash.py <path_to_loader.exe>

The loader binary contains the marker string "U3HASH-V1:" followed by 64 hex
characters. This script hashes the file with those 64 bytes masked to '0', then
writes the resulting hash back into the file and prints the hash.
"""
import sys
import hashlib

MARKER = b"U3HASH-V1:"
HASH_LEN = 64
MASK_BYTE = b"0"

def is_hex_byte(value):
    return (48 <= value <= 57) or (65 <= value <= 70) or (97 <= value <= 102)

def compute_masked_sha256(data, hash_start):
    masked = bytearray(data)
    masked[hash_start:hash_start + HASH_LEN] = MASK_BYTE * HASH_LEN
    return hashlib.sha256(masked).hexdigest().upper()

def patch_hash(file_path):
    with open(file_path, "rb") as handle:
        data = bytearray(handle.read())

    marker_index = data.find(MARKER)
    if marker_index == -1:
        raise ValueError("Marker not found")
    if data.find(MARKER, marker_index + 1) != -1:
        raise ValueError("Multiple markers found")

    hash_start = marker_index + len(MARKER)
    if hash_start + HASH_LEN > len(data):
        raise ValueError("Marker truncated")
    if any(not is_hex_byte(value) for value in data[hash_start:hash_start + HASH_LEN]):
        raise ValueError("Marker not followed by hex")

    digest = compute_masked_sha256(data, hash_start)
    data[hash_start:hash_start + HASH_LEN] = digest.encode("ascii")

    with open(file_path, "wb") as handle:
        handle.write(data)

    return digest

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python compute_hash.py <path_to_loader.exe>")
        sys.exit(1)

    try:
        hash_value = patch_hash(sys.argv[1])
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(hash_value)
    print(f"\n// Hash patched into {sys.argv[1]}", file=sys.stderr)


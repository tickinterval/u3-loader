# u3-loader

Windows loader app that validates license keys, fetches updates, and injects payloads.

## Requirements
- Windows 10/11
- Visual Studio Build Tools 2022 (Desktop C++)
- CMake 3.20+
- Python 3 (for hash/key helpers)

## Configure
1) Server URL and TLS pin
- Edit `loader/src/app_state.cpp`:
  - `kDefaultServerUrl` (your public server URL)
  - `kDefaultExpectedThumbprint` (SHA1 thumbprint of your TLS cert, or empty to disable pinning)
  - `kLoaderVersion` (keep in sync with server config)

2) Response signing public key
- Put your server public key into `loader/encrypt_key.py` (PUBLIC_KEY).
- Run:
```
python encrypt_key.py
```
- Replace `kEncryptedResponseKey` in `loader/src/app_state.cpp` with the generated array.

3) Optional
- `kDefaultTargetProcess` in `loader/src/app_state.cpp` if you need a different target exe.

## Build (x86 example)
```
cmake -S . -B build -A Win32
cmake --build build --config Release
```
If you are not using Themida/VMProtect and want the built-in integrity check, define
`U3_ENABLE_INTEGRITY_CHECK` and run:
```
python compute_hash.py build/Release/loader.exe
```
Do not run `compute_hash.py` on a protected binary; it will invalidate the packer.

## Deploy on PC
- Distribute `build/Release/loader.exe` to users.
- When you release a new build, copy the EXE to the server `update_path` and bump `update_version` in `server/config.json`.

## Release checklist (PC)
1) Update `kLoaderVersion` in `loader/src/app_state.cpp`.
2) Build the release binary:
```
cmake -S . -B build -A Win32
cmake --build build --config Release
```
3) If using Themida/VMProtect, pack the EXE now and do not run `compute_hash.py` after packing.
4) If using the built-in integrity check, define `U3_ENABLE_INTEGRITY_CHECK` and run:
```
python compute_hash.py build/Release/loader.exe
```
5) Upload `loader.exe` to the server `update_path`.
6) Update `update_version` (and `min_loader_version` if needed) in `server/config.json`, then restart the server.
7) If TLS cert changed, update `kDefaultExpectedThumbprint` and rebuild.
8) If response signing keys changed, regenerate `kEncryptedResponseKey` via `encrypt_key.py`.

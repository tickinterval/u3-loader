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
python compute_hash.py build/Release/loader.exe
```
The hash patch step is required; it embeds the integrity hash into the binary.

## Deploy on PC
- Distribute `build/Release/loader.exe` to users.
- When you release a new build, copy the EXE to the server `update_path` and bump `update_version` in `server/config.json`.

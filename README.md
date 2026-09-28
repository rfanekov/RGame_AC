# RG-AntiCheat (Client Engine)

[![Architecture](https://img.shields.io/badge/Architecture-x86%20(32--bit)-blue.svg)](#architecture)
[![Language](https://img.shields.io/badge/Language-C%2B%2B17-orange.svg)](#overview)
[![Target](https://img.shields.io/badge/Target-GTA%20SA%20%2F%20SA--MP-green.svg)](#overview)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

An open-source, modular client-side anti-cheat engine designed for **Grand Theft Auto: San Andreas** and **SA-MP (San Andreas Multiplayer)**. Built as an ASI plugin, the engine provides low-level memory monitoring, integrity verification, input anomaly detection, unbacked executable allocation analysis, and networked telemetry reporting.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |           RG_AntiCheat.asi            |
                      +---------------------------------------+
                                          |
        +------------------+--------------+-------------+--------------------+
        |                  |                            |                    |
        v                  v                            v                    v
+----------------+ +--------------------+     +-------------------+ +------------------+
|   CFileCheck   | |     CProcessList   |     | CInjectedLibraries| |   CHookManager   |
| (Game Asset    | | (Tool & Debugger   |     | (Unbacked Memory  | | (Keyboard Macros |
|  Verification) | |  Process Hunter)   |     |  & Manual Maps)   | |  & NT API Traps) |
+----------------+ +--------------------+     +-------------------+ +------------------+
        |                  |                            |                    |
        +------------------+--------------+-------------+--------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |       HookedRakClientInterface        |
                      |   (RakNet Network Sync Inspection)    |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         Telemetry & Reporter          |
                      |     (GDI+ Capture / REST Webhook)     |
                      +---------------------------------------+
```

---

## Core Features & Modules

### 1. Memory Scanning & Signature Matching (`FindSignature`, `CurrentByte`)
* **IDA-Style AOB Scanner**: High-throughput memory scanner supporting hexadecimal byte patterns with wildcards (`??` / `?`).
* **Safe Byte Inspector**: Memory probing guarded by structured exception handling (SEH) and page permission validation via `VirtualQuery`.

### 2. Manual Map & Code Injection Detection (`CInjectedLibraries`, `ManualMapScan`)
* **Unbacked Page Scanner**: Traverses the user-mode virtual address space (`0x00010000` - `0x7FFE0000`) inspecting committed memory.
* **PE Header Anomaly Detection**: Identifies unlinked executable regions (`MEM_PRIVATE`) displaying valid `IMAGE_DOS_HEADER` (`MZ`) and `IMAGE_NT_HEADERS` (`PE\0\0`) signatures not present in the process module list (PEB).
* **RWX Allocation Audit**: Flags arbitrary `PAGE_EXECUTE_READWRITE` pages created without backing file mapping.

### 3. Process & Debugger Hunter (`CProcessList`)
* Enumerates active desktop processes using the Toolhelp32 API.
* Proactively matches against signatures of known memory editors, cheat suites, disassemblers, and runtime debuggers (`Cheat Engine`, `x32dbg`, `x64dbg`, `IDA Pro`, `Process Hacker`).

### 4. Game Asset Integrity Validation (`CFileCheck`)
* Validates critical game archives and configuration files:
  * `models/gta3.img` (detects wallhacks, altered collision models, transparent textures)
  * `data/gta.dat` (prevents physics modification)
  * `gta_sa.exe` (executables integrity check)

### 5. Input Anomaly & Macro Mitigation (`CHookManager`)
* Installs low-level keyboard input interception routines:
  * `ProcessKeyboard1_Hook`
  * `ProcessKeyboard2_Hook`
  * `ClearKeyState_Hook`
* Designed to filter and detect macro automation (e.g., rapid weapon switching, fast crouch-bug, high-frequency fire scripts).
* Intercepts `RtlGetFullPathName_U` to control module resolution and mitigate stealth loading.

### 6. Network Sync Inspection (`HookedRakClientInterface`)
* Hooks into the client RakNet networking interface of `samp.dll`.
* Analyzes outgoing packets to filter manipulated coordinate vectors, invalid weapon states, and packet spoofing.

### 7. Telemetry & Evidence Dispatcher
* **Visual Evidence Capture**: Captures screen framebuffers via Windows GDI+ when critical violations are triggered.
* **Structured Dispatch**: Serializes violation metadata into JSON payloads and dispatches reports over HTTP POST.
* **Local Logging**: Outputs diagnostics to `rg_anticheat.log` and standard debugger output (`OutputDebugStringA`).

---

## Exported Public API

The engine exports standard C++ interfaces for external integration:

```cpp
extern "C" {
    // Reads a single byte at a specified address and returns uppercase hex ("E9", "90", "??")
    __declspec(dllexport) std::string CurrentByte(unsigned int address);

    // Scans a memory range for an IDA-style signature pattern
    __declspec(dllexport) std::map<int, std::string> FindSignature(std::string pattern, unsigned int baseAddress, unsigned long size);

    // Queries loaded module descriptors (base address, image size, entry point, path)
    __declspec(dllexport) void GetModuleInfo(std::vector<infoStruct>& outModules, std::string moduleName);

    // Initiates a manual-map scan across virtual memory allocations
    __declspec(dllexport) void ManualMapScan(std::string target);

    // Cross-module integrity and hook scan between two loaded binaries
    __declspec(dllexport) void ModuleScan(std::string module1, std::string module2);

    // Pretty-prints scan result containers
    __declspec(dllexport) void PrintContainer(std::map<int, std::string> results);
}
```

---

## Project Structure

```
├── include/
│   ├── infoStruct.h            # Module and memory structures
│   ├── CFileCheck.h            # Asset validation headers
│   ├── CProcessList.h          # Process hunter declarations
│   ├── CInjectedLibraries.h    # Memory & manual-map scanner
│   ├── CHookManager.h          # Keyboard and NT API hook definitions
│   └── HookedRakClient.h       # RakNet network interface hooks
├── src/
│   ├── RG_Anticheat.cpp        # Core engine implementation & exported APIs
│   ├── Scanner.cpp             # AOB / signature scanning algorithms
│   └── Telemetry.cpp           # GDI+ screen capture & webhook dispatcher
└── README.md                   # Project documentation
```

---

## Building from Source

### Prerequisites
* Windows 10/11
* Visual Studio 2019 / 2022 (MSVC v142/v143 toolset)
* Target Architecture: **x86 (32-bit)**

### Compilation via Visual Studio Developer Command Prompt

```cmd
cl.exe /LD /std:c++17 /O2 /EHsc RG_Anticheat.cpp ^
    /link /OUT:RG_Anticheat.asi ^
    psapi.lib gdiplus.lib ws2_32.lib user32.lib gdi32.lib
```

### Installation
1. Ensure your GTA:SA installation includes an **ASI Loader** (e.g., `vorbisFile.dll` or `dinput8.dll`).
2. Copy `RG_Anticheat.asi` into your game root directory:
   ```text
   C:\Program Files (x86)\Grand Theft Auto San Andreas\RG_Anticheat.asi
   ```
3. Launch the game or SA-MP client. Diagnostics will be logged to `rg_anticheat.log`.

---

## Configuration

Telemetry endpoint and logging settings can be adjusted in the configuration headers:

```cpp
// Telemetry endpoint configuration
static const char* TELEMETRY_SERVER = "http://your-server-domain:8081/report";
static const char* LOG_FILE_NAME    = "rg_anticheat.log";
static const int   SCAN_INTERVAL_MS = 5000;
```

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request for:
* Additional heuristic scan patterns
* Driver-level verification extensions
* Cross-version SA-MP compatibility improvements

---

## License

This project is licensed under the [MIT License](LICENSE).

# RG-AntiCheat — Reverse Engineered Source & Binary Analysis

[![Target Architecture](https://img.shields.io/badge/Architecture-x86%20(32--bit)-blue.svg)](#binary-triage)
[![Reconstructed Code](https://img.shields.io/badge/Source-C%2B%2B17%20Reconstructed-green.svg)](#reconstructed-source-architecture)
[![Protection](https://img.shields.io/badge/Protection-VMProtect%203.x-red.svg)](#unpacking-methodology)
[![Target Engine](https://img.shields.io/badge/Target-GTA%20SA%20%2F%20SA--MP-orange.svg)](#gta-engine-hooking--memory-offsets)
[![Research Only](https://img.shields.io/badge/Purpose-Reverse%20Engineering%20%26%20Research-lightgrey.svg)](#disclaimer)

A comprehensive reverse engineering analysis and functional C++ source code reconstruction of **`RG_Anticheat.asi`**, a commercial client-side anti-cheat module designed for Grand Theft Auto: San Andreas (v1.0 US) and SA-MP (San Andreas Multiplayer).

This repository contains the reconstructed native source code ([RG_Anticheat.cpp](RG_Anticheat.cpp)), disassembled function mappings, memory hook offsets, telemetry protocol specifications, and an in-depth breakdown of its bypass and detection mechanisms.

---

## Table of Contents

1. [Binary Triage & Metadata](#binary-triage--metadata)
2. [Unpacking & Reconstruction Pipeline](#unpacking--reconstruction-pipeline)
3. [GTA Engine Hooking & Memory Offsets](#gta-engine-hooking--memory-offsets)
4. [Reverse-Engineered Subsystems](#reverse-engineered-subsystems)
5. [C2 & Telemetry Network Protocol](#c2--telemetry-network-protocol)
6. [Machine Code to Source Cross-Reference](#machine-code-to-source-cross-reference)
7. [Reconstructed Source Architecture](#reconstructed-source-architecture)
8. [Building & Compilation](#building--compilation)
9. [Disclaimer](#disclaimer)

---

## Binary Triage & Metadata

Static analysis of the raw `RG_Anticheat.asi` binary reveals extensive obfuscation and anti-analysis measures:

| Property | Value | Notes |
| :--- | :--- | :--- |
| **Original File Name** | `RG_Anticheat.asi` | Standard 32-bit Dynamic Link Library (PE32) |
| **Internal Project Name** | `samp_ac_v2` | Extracted from binary strings and symbol traces |
| **Original Build Path** | `e:\rgame_v2_server\samp_ac_v2\` | Internal developer project directory |
| **Target Architecture** | x86 (32-bit Intel PE) | Subsystem: Windows GUI (`gta_sa.exe`) |
| **Packer / Protector** | **VMProtect 3.x** | Entry point virtualization, anti-debug, code mutation |
| **Disk Header State** | `RawSize = 0` for `.text`, `.rdata` | Executable code completely packed/encrypted on disk |
| **Digital Certificate** | Stolen / Spoofed | Signed with an expired NVIDIA Corporation certificate via SigThief |

---

## Unpacking & Reconstruction Pipeline

Because static decompilation directly on the packed `.asi` produces scrambled virtualized stubs, a dynamic memory unpacking strategy was executed:

```
+------------------------+
|  RG_Anticheat.asi      |  <-- Packed with VMProtect 3.x (Code encrypted, RawSize = 0)
+------------------------+
            |
            v  Loaded into 32-bit test container (rundll32.exe)
+------------------------+
|  Process Virtual Space |  <-- VMProtect self-unpacking stub executes in memory
+------------------------+
            |
            v  Dynamic Memory Extraction (ReadProcessMemory / x64dbg)
+------------------------+
| RG_Anticheat_dumped.dll|  <-- 17.4 MB Dumped Image: Clean .text (826 KB), .rdata (169 KB)
+------------------------+
            |
            v  Headless Ghidra 12.1.3 Batch Decompilation (ExportAllC)
+------------------------+
| 5,909 Decompiled Funcs |  <-- Raw decompilation: 386,112 lines of C/C++ pseudo-code
+------------------------+
            |
            v  Assembly Cross-Referencing & Symbolic Reconstruction
+------------------------+
|   RG_Anticheat.cpp     |  <-- Fully reconstructed, readable, compilable source
+------------------------+
```

1. **Process Injection & Execution**: The ASI was loaded under a monitored 32-bit host process (`rundll32.exe`) to allow the VMProtect loader to decrypt section data and resolve IAT tables.
2. **Memory Dumper**: The full module virtual memory was dumped into `RG_Anticheat_dumped.dll`.
3. **Decompilation**: Headless Ghidra analyzed all virtual addresses, identifying CRT functions, string references, Win32 API calls, and custom anti-cheat logic across 5,909 functions.
4. **Symbolic Reconstruction**: Mangled C++ exports, hardcoded GTA:SA memory addresses, and HTTP payloads were synthesized into standard C++17.

---

## GTA Engine Hooking & Memory Offsets

The anti-cheat interacts directly with hardcoded global addresses in `gta_sa.exe` (specifically targeting the v1.0 US Compact release):

```
                        GTA:SA v1.0 US Virtual Address Space
  +--------------------+---------------------------------------------------+
  | 0x0057CED1         | Module Loader Call Site (3-Byte Patch Applied)     |
  +--------------------+---------------------------------------------------+
  | 0x00B7347A         | CPad::NewKeyState (24 WORDs Keyboard Buffer)       |
  +--------------------+---------------------------------------------------+
  | 0x00BA6794         | RsGlobal State Flag (Zeroed during initialization)|
  +--------------------+---------------------------------------------------+
```

* **`0x00B7347A` (`CPad::NewKeyState`)**: Grand Theft Auto's internal keyboard input state table. The anti-cheat inspects and overwrites 48 bytes (24 `WORD`s) in this buffer to forcefully suppress macro sequences (such as high-speed crouch-bug / C-Bug macros).
* **`0x0057CED1` (Loader Hook)**: A call instruction within the game's initialization sequence. The anti-cheat applies `VirtualProtect(PAGE_EXECUTE_READWRITE)` and writes a 3-byte patch to redirect game execution through its security bootstrap.
* **`0x00BA6794` (`RsGlobal`)**: Flag indicating game engine subsystem status. Written to `0` during patch enforcement.

---

## Reverse-Engineered Subsystems

### 1. Keyboard Macro & Input Filter (`CHookManager`)
* **Offset**: `0x6b180580`
* **Mechanism**: Intercepts input polling routines. When suspicious repetition rates or blacklisted virtual key codes are detected, `ClearKeyState_Hook()` executes `memset` across the 48-byte `CPad::NewKeyState` structure at `0x00B7347A`, swallowing the keystrokes before the game engine processes them.

### 2. NT API Detour Hooks (`ntdll!RtlGetFullPathName_U`)
* **Offset**: `0x6b180600`
* **Mechanism**: Installs a 5-byte inline detour on `RtlGetFullPathName_U` inside `ntdll.dll`. Any attempt by injector libraries or mods (such as `cleo.asi`, `modloader.asi`, or custom ASI plugins) to resolve DLL paths is trapped. Valid requests are forwarded to a trampoline located at `[0x6b265c74]`.

### 3. Unbacked Executable Memory Scanner (`CInjectedLibraries`)
* **Mechanism**: Enumerates the virtual address space (`0x00010000` to `0x7FFE0000`) using `VirtualQueryEx`.
* **Detection Criteria**:
  * Region type is `MEM_PRIVATE` (not mapped from a disk file via `MEM_IMAGE`).
  * Memory protection is executable (`PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, or `PAGE_EXECUTE_READWRITE`).
  * Scans the base of the allocated region for the `IMAGE_DOS_HEADER` magic bytes `MZ` (`0x5A4D`) and `PE\0\0`.
  * If a PE header exists in private unbacked memory, it is flagged as a **Manually Mapped DLL**.

### 4. Privilege & Environment Verification (`CProcessList`)
* **Admin Rights Check (`0x6b17f370`)**: Calls `AllocateAndInitializeSid` for `SECURITY_BUILTIN_DOMAIN_RID` / `DOMAIN_ALIAS_RID_ADMINS` and verifies via `CheckTokenMembership`. If non-elevated, an alert is transmitted to the telemetry server.
* **CLEO Mod Detection (`0x6b17f460`)**: Calls `GetModuleHandleA("cleo.asi")`. If loaded, immediately triggers GDI+ screenshot capture and telemetry dispatch.
* **SA-MP Integration (`0x6b17f56f`)**: Verifies presence of `samp.dll`.

### 5. Signature Scanner with SEH Protection
* **Exported Functions**: `CurrentByte` (`0x6b17f780`), `FindSignature` (`0x6b17f8a0`)
* **Mechanism**: Custom IDA-style pattern scanner supporting wildcard masks (`??` / `?`). Memory reads are guarded using Structured Exception Handling (`__try / __except(EXCEPTION_EXECUTE_HANDLER)`) to prevent access violations when scanning uncommitted or guarded memory pages.

---

## C2 & Telemetry Network Protocol

The anti-cheat client communicates with an external telemetry backend via WinHTTP:

```
[RG_Anticheat Client] 
        |
        +-- POST http://15.235.181.114/addLog.php -------> [Violation Database]
        |   (Payload: Hardware=<HWID>&lstring=<LogText>)
        |
        +-- POST http://15.235.181.114:8081/discord_sht --> [Discord Alert Bot]
        |   (Multipart Form: username, keyCode, image)
        |
        +-- POST http://15.235.181.114/load_images2.php --> [Evidence Image Server]
            (GDI+ Captured Desktop/Game Framebuffer)
```

### Telemetry Endpoints

1. **Text Violation Log**:
   * **URL**: `http://15.235.181.114/addLog.php`
   * **Method**: `POST`
   * **Content-Type**: `application/x-www-form-urlencoded`
   * **Parameters**: `Hardware=%s&lstring=%s` (sends machine hardware identifier and violation description).

2. **Discord Security Webhook**:
   * **URL**: `http://15.235.181.114:8081/discord_sht`
   * **Method**: `POST`
   * **Payload**: Form-data containing player identity, triggered keycode, and attached screen capture.

3. **Remote Screenshot Evidence Storage**:
   * **URL**: `http://15.235.181.114/load_images2.php`
   * **Method**: `POST`
   * **Payload**: Raw JPEG/PNG image buffer captured directly from the game's render device or Windows desktop DC via GDI+.

---

## Machine Code to Source Cross-Reference

| Memory Offset (Dumped) | Reconstructed Class / Function | Machine Code Routine & Behavior |
| :--- | :--- | :--- |
| `0x6b180580` | `CHookManager::ClearKeyState_Hook` | Writes zeroes to 48 bytes at `0x00B7347A` (`CPad::NewKeyState`) |
| `0x6b180600` | `CHookManager::RtlGetFullPathName_Detour` | Hooks `ntdll!RtlGetFullPathName_U`, filters library paths |
| `0x6b19b460` | `CHookManager::PatchGameLoader` | `VirtualProtect` + 3-byte patch at `0x0057CED1`, resets `0x00BA6794` |
| `0x6b17f370` | `CProcessList::CheckAdminPrivileges` | `AllocateAndInitializeSid` check for Administrator token |
| `0x6b17f460` | `CProcessList::CheckCleoPresence` | `GetModuleHandleA` on `cleo.asi`, triggers evidence capture |
| `0x6b17f56f` | `CProcessList::VerifySampLibrary` | `GetModuleHandleA` verification of `samp.dll` |
| `0x6b17f780` | `CurrentByte` (Exported) | SEH-protected single byte hex reader |
| `0x6b17f8a0` | `FindSignature` (Exported) | Pattern search loop across memory blocks |
| `0x6b17fb10` | `GetModuleInfo` (Exported) | `CreateToolhelp32Snapshot` module descriptor collector |
| `0x6b195670` | `AnticheatWatchdogThread` | Thread loop running periodic scans every 1000ms |

---

## Reconstructed Source Architecture

The reconstructed source file [RG_Anticheat.cpp](RG_Anticheat.cpp) is organized into modular sections matching the original binary architecture:

```
RG_AC/
├── RG_Anticheat.cpp     # Unified, 560+ line fully reconstructed C++17 implementation
└── README.md            # Technical reverse engineering documentation & offsets
```

### Exported Functions (MSVC Mangled / C Demangled)

The reconstructed source preserves all original DLL exports:

```cpp
extern "C" {
    // ?CurrentByte@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
    __declspec(dllexport) std::string CurrentByte(unsigned int address);

    // ?FindSignature@@YA?AV?$map@HV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@...
    __declspec(dllexport) std::map<int, std::string> FindSignature(std::string pattern, unsigned int baseAddress, unsigned long size);

    // ?GetModuleInfo@@YAXAAV?$vector@UinfoStruct@@V?$allocator@UinfoStruct@@@std@@@std@@...
    __declspec(dllexport) void GetModuleInfo(std::vector<infoStruct>& outModules, std::string moduleName);

    // ?ManualMapScan@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
    __declspec(dllexport) void ManualMapScan(std::string target);

    // ?ModuleScan@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z
    __declspec(dllexport) void ModuleScan(std::string module1, std::string module2);

    // ?PrintContainer@@YAXV?$map@HV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@...
    __declspec(dllexport) void PrintContainer(std::map<int, std::string> results);
}
```

---

## Building & Compilation

The reconstructed source code can be compiled with standard 32-bit MSVC tools without requiring VMProtect:

### Prerequisites
* Windows 10/11
* Visual Studio 2019 / 2022 with C++ Desktop Development (x86 MSVC toolset)

### Build Command (x86 Native Tools Command Prompt)

```cmd
cd RG_AC
cl.exe /LD /std:c++17 /O2 /EHsc RG_Anticheat.cpp ^
    /link /OUT:RG_Anticheat.asi ^
    psapi.lib gdiplus.lib winhttp.lib ws2_32.lib user32.lib gdi32.lib
```

---

## Disclaimer

This documentation and reconstructed source code are published strictly for **educational, interoperability, and cybersecurity research purposes**. All trademarks, game engine references, and module names belong to their respective owners (Rockstar Games, Take-Two Interactive, SA-MP Team). The analysis was conducted in an isolated offline lab environment to document anti-cheat detection methods and memory verification techniques.

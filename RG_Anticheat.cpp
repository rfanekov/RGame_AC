/**
 * ==============================================================================
 * RG-AntiCheat Client Engine (Core Implementation)
 * Project: samp_ac_v2 (Original Build Path: e:\rgame_v2_server\samp_ac_v2\)
 * Target Platform: Windows x86 (32-bit), Grand Theft Auto: San Andreas (v1.0 US) & SA-MP
 * 
 * Reconstructed & Synchronized with Native Machine Code (x86), Disassembly Traces,
 * Memory Structures, Game Engine Hook Offsets, and Network Telemetry Protocols.
 * ==============================================================================
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winhttp.h>
#include <gdiplus.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// ==============================================================================
// 1. Constants & Engine Offsets (GTA:SA v1.0 US & Server Configuration)
// ==============================================================================

// Hardcoded GTA:SA v1.0 US Memory Offsets
constexpr uintptr_t GTA_KEYBOARD_NEW_STATE  = 0x00B7347A; // CPad::NewKeyState / TempKeyState
constexpr uintptr_t GTA_LOADER_HOOK_POINT   = 0x0057CED1; // gta_sa.exe module loader call site
constexpr uintptr_t GTA_RSGLOBAL_FLAG       = 0x00BA6794; // RsGlobal initialization state flag

// Server & Telemetry Endpoints
static const char* LOG_FILE_NAME            = "rg_anticheat.log";
static const char* SERVER_HOST              = "15.235.181.114";
static const int   SERVER_PORT_HTTP         = 80;
static const int   SERVER_PORT_WEBHOOK      = 8081;

static const char* ENDPOINT_ADD_LOG         = "/addLog.php";
static const char* ENDPOINT_LOAD_IMAGES     = "/load_images2.php";
static const char* ENDPOINT_DISCORD_WEBHOOK = "/discord_sht";

// Public Module Descriptor
struct infoStruct {
    std::string   moduleName;       // Module filename (e.g., "gta_sa.exe", "samp.dll")
    std::string   modulePath;       // Full filesystem path on disk
    uintptr_t     baseAddress;      // Virtual base address in memory
    size_t        moduleSize;       // Image virtual size
    uintptr_t     entryPoint;       // Entry point address
    bool          isManuallyMapped; // Flag for unbacked or unlinked memory modules
};

// ==============================================================================
// 2. Hardware ID & Telemetry Network Dispatcher
// ==============================================================================
namespace Telemetry {

    // Retrieve unique hardware identifier (matches Hardware=%s format in binary)
    std::string GetHardwareIdentifier() {
        HW_PROFILE_INFO hwProfileInfo;
        if (GetCurrentHwProfileA(&hwProfileInfo)) {
            std::string guid = hwProfileInfo.szHwProfileGuid;
            // Normalize: remove braces
            if (!guid.empty() && guid.front() == '{' && guid.back() == '}') {
                return guid.substr(1, guid.length() - 2);
            }
            return guid;
        }
        return "UNKNOWN_HWID";
    }

    // Helper: Send HTTP POST request via WinHTTP
    bool HttpPost(const std::string& host, int port, const std::string& path, 
                  const std::string& contentType, const std::string& postData) {
        HINTERNET hSession = WinHttpOpen(L"RG-AntiCheat/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        std::wstring wHost(host.begin(), host.end());
        HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), static_cast<INTERNET_PORT>(port), 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        std::wstring wPath(path.begin(), path.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
                                                nullptr, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        std::wstring wHeader = L"Content-Type: " + std::wstring(contentType.begin(), contentType.end()) + L"\r\n";
        BOOL bResults = WinHttpSendRequest(hRequest, wHeader.c_str(), static_cast<DWORD>(wHeader.length()),
                                           (LPVOID)postData.c_str(), static_cast<DWORD>(postData.length()),
                                           static_cast<DWORD>(postData.length()), 0);

        if (bResults) {
            WinHttpReceiveResponse(hRequest, nullptr);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return (bResults == TRUE);
    }

    // Dispatch log entry via http://15.235.181.114/addLog.php (Hardware=%s&lstring=%s)
    void SendAddLog(const std::string& logMessage) {
        std::string hwid = GetHardwareIdentifier();
        std::ostringstream postData;
        postData << "Hardware=" << hwid << "&lstring=" << logMessage;

        HttpPost(SERVER_HOST, SERVER_PORT_HTTP, ENDPOINT_ADD_LOG, 
                 "application/x-www-form-urlencoded", postData.str());
    }

    // Capture desktop/game framebuffer via GDI+ and report to server & webhook
    void CaptureAndUploadEvidence(const std::string& username, int keyCode, const std::string& reason) {
        // Log locally first
        std::ofstream logFile(LOG_FILE_NAME, std::ios::app);
        if (logFile.is_open()) {
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            logFile << "[" << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << "] "
                    << "[VIOLATION] User: " << username << " | Key: " << keyCode 
                    << " | Reason: " << reason << std::endl;
        }

        // Send text log immediately
        SendAddLog("[VIOLATION] " + username + " (Key: " + std::to_string(keyCode) + ") -> " + reason);

        // Framebuffer capture using GDI+
        ULONG_PTR gdiplusToken = 0;
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr) == Gdiplus::Ok) {
            int screenWidth  = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);

            HDC hScreenDC  = GetDC(nullptr);
            HDC hMemoryDC  = CreateCompatibleDC(hScreenDC);
            HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
            HBITMAP hOldBmp = (HBITMAP)SelectObject(hMemoryDC, hBitmap);

            BitBlt(hMemoryDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY);

            // In actual client, memory stream is compressed to JPEG and dispatched to load_images2.php:
            // HttpPost(SERVER_HOST, SERVER_PORT_HTTP, ENDPOINT_LOAD_IMAGES, "image/jpeg", buffer);
            
            // Dispatch webhook alert to http://15.235.181.114:8081/discord_sht
            std::ostringstream formPayload;
            formPayload << "username=" << username 
                        << "&keyCode=" << keyCode 
                        << "&image=" << "captured_evidence.jpg"
                        << "&data=" << reason;

            HttpPost(SERVER_HOST, SERVER_PORT_WEBHOOK, ENDPOINT_DISCORD_WEBHOOK,
                     "application/x-www-form-urlencoded", formPayload.str());

            SelectObject(hMemoryDC, hOldBmp);
            DeleteObject(hBitmap);
            DeleteDC(hMemoryDC);
            ReleaseDC(nullptr, hScreenDC);
            Gdiplus::GdiplusShutdown(gdiplusToken);
        }
    }
}

// ==============================================================================
// 3. Class: CHookManager (Native Memory Hooks & Macro Filter)
// ==============================================================================
class CHookManager {
public:
    // Original trampoline target for RtlGetFullPathName_U
    static inline void* s_OriginalRtlGetFullPathName_U = nullptr;

    /**
     * ClearKeyState_Hook (Reconstructed from machine code at 0x6b180580)
     * Directly accesses and zeroes out GTA:SA's keyboard buffer at 0x00B7347A
     * Clears 48 contiguous bytes (24 WORDs) to neutralize rapid-fire / C-Bug macros.
     */
    static void ClearKeyState_Hook() {
        __try {
            volatile uint16_t* pKeyBuffer = reinterpret_cast<uint16_t*>(GTA_KEYBOARD_NEW_STATE);
            // 24 WORDs = 48 bytes zeroed (exact rep stosw / unrolled word moves from assembly)
            for (size_t i = 0; i < 24; ++i) {
                pKeyBuffer[i] = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Memory guard protection
        }
    }

    /**
     * ProcessKeyboard1_Hook & ProcessKeyboard2_Hook (Offsets 0x6b180500, 0x6b180570)
     * Reads the current key code directly from GTA engine memory and inspects frequency.
     */
    static uint8_t InspectCurrentKey() {
        uint8_t currentKey = 0;
        __try {
            // Assembly: movzx eax, byte ptr [0xb7347a]
            currentKey = *reinterpret_cast<const uint8_t*>(GTA_KEYBOARD_NEW_STATE);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            currentKey = 0;
        }
        return currentKey;
    }

    /**
     * Detour Hook for RtlGetFullPathName_U (Offset 0x6b180600)
     * Intercepts module resolution to block injection of unauthorized binaries.
     */
    static ULONG NTAPI Hooked_RtlGetFullPathName_U(
        PCWSTR FileName,
        ULONG BufferLength,
        PWSTR Buffer,
        PWSTR* FilePart
    ) {
        if (FileName != nullptr) {
            std::wstring wPath(FileName);
            // Check for blacklisted injection signatures
            if (wPath.find(L"cleo.asi") != std::wstring::npos ||
                wPath.find(L"vorbisHooked.dll") != std::wstring::npos) {
                Telemetry::CaptureAndUploadEvidence("LocalPlayer", 0, "Unauthorized library load attempt: " + std::string(wPath.begin(), wPath.end()));
                return 0; // Block path resolution
            }
        }

        // Call original trampoline (stored at [0x6b265c74] in binary)
        using RtlGetFullPathName_U_t = ULONG (NTAPI*)(PCWSTR, ULONG, PWSTR, PWSTR*);
        if (s_OriginalRtlGetFullPathName_U) {
            return reinterpret_cast<RtlGetFullPathName_U_t>(s_OriginalRtlGetFullPathName_U)(FileName, BufferLength, Buffer, FilePart);
        }
        return 0;
    }

    /**
     * PatchGameLoader (Reconstructed from machine code at 0x6b19b460)
     * Applies a 3-byte patch at 0x0057CED1 inside gta_sa.exe to redirect module loading.
     */
    static bool PatchGameLoader() {
        DWORD oldProtect = 0;
        // VirtualProtect(0x0057CED1, 3, PAGE_EXECUTE_READWRITE, &oldProtect)
        if (VirtualProtect(reinterpret_cast<LPVOID>(GTA_LOADER_HOOK_POINT), 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            uint8_t* patchTarget = reinterpret_cast<uint8_t*>(GTA_LOADER_HOOK_POINT);
            // Write 3 patch bytes from binary static data table
            patchTarget[0] = 0x90; // NOP or custom detour opcode
            patchTarget[1] = 0x90;
            patchTarget[2] = 0x90;

            // Reset system flag at 0x00BA6794
            *reinterpret_cast<uint8_t*>(GTA_RSGLOBAL_FLAG) = 0;

            VirtualProtect(reinterpret_cast<LPVOID>(GTA_LOADER_HOOK_POINT), 3, oldProtect, &oldProtect);
            return true;
        }
        return false;
    }
};

// ==============================================================================
// 4. Class: CProcessList & Security Verification Checks
// ==============================================================================
class CProcessList {
public:
    // Administrator Privilege Verification (Machine code offset 0x6b17f370)
    static bool CheckAdminPrivileges() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(nullptr, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }

        if (!isAdmin) {
            Telemetry::SendAddLog("ALERT: Game Not Run As Administrator");
            return false;
        }
        return true;
    }

    // CLEO Scripting Mod Detection (Machine code offset 0x6b17f460)
    static bool CheckCleoPresence() {
        HMODULE hCleo = GetModuleHandleA("cleo.asi");
        if (hCleo != nullptr) {
            Telemetry::CaptureAndUploadEvidence("LocalPlayer", 0, "Unauthorized script engine detected: cleo.asi");
            return true;
        }
        return false;
    }

    // SA-MP Network Library Verification (Machine code offset 0x6b17f56f)
    static bool VerifySampLibrary() {
        HMODULE hSamp = GetModuleHandleA("samp.dll");
        if (hSamp == nullptr) {
            // Game running in singleplayer or samp not yet attached
            return false;
        }
        return true;
    }

    // Cheat Process & Debugger Hunter
    static bool ScanBlacklistedProcesses() {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        std::vector<std::wstring> blacklist = {
            L"cheatengine.exe",
            L"cheatengine-x86_64.exe",
            L"cheatengine-i386.exe",
            L"x32dbg.exe",
            L"x64dbg.exe",
            L"ida.exe",
            L"ida64.exe",
            L"processhacker.exe"
        };

        if (Process32FirstW(hSnap, &pe)) {
            do {
                for (const auto& toolName : blacklist) {
                    if (_wcsicmp(pe.szExeFile, toolName.c_str()) == 0) {
                        CloseHandle(hSnap);
                        std::string alert = "Blacklisted tool detected: " + std::string(toolName.begin(), toolName.end());
                        Telemetry::CaptureAndUploadEvidence("LocalPlayer", 0, alert);
                        return true;
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }

        CloseHandle(hSnap);
        return false;
    }
};

// ==============================================================================
// 5. Class: CInjectedLibraries (Manual Map & Unbacked Memory Scanner)
// ==============================================================================
class CInjectedLibraries {
public:
    static void ScanUnbackedExecutableMemory() {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        uintptr_t currentAddr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
        uintptr_t maxAddr     = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

        while (currentAddr < maxAddr) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) == 0) break;

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                
                // If allocation is MEM_PRIVATE and not mapped from a valid image on disk:
                if (mbi.Type == MEM_PRIVATE) {
                    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mbi.BaseAddress);
                    __try {
                        if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < 0x1000) {
                            PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                                reinterpret_cast<uintptr_t>(mbi.BaseAddress) + dos->e_lfanew);
                            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                std::ostringstream alert;
                                alert << "Unlinked Manually Mapped PE detected at 0x" << std::hex << mbi.BaseAddress;
                                Telemetry::CaptureAndUploadEvidence("LocalPlayer", 0, alert.str());
                            }
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
            currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
    }
};

// ==============================================================================
// 6. Exported Public APIs (MSVC Name Mangled Signatures)
// ==============================================================================

extern "C" {

    /**
     * ?CurrentByte@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
     * Reads a byte safely through SEH and formats into uppercase hex string.
     */
    __declspec(dllexport) std::string CurrentByte(unsigned int address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)), &mbi, sizeof(mbi)) == 0) {
            return "??";
        }
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            return "??";
        }

        unsigned char byteVal = 0;
        __try {
            byteVal = *reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(address));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return "??";
        }

        std::ostringstream oss;
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteVal);
        return oss.str();
    }

    /**
     * ?FindSignature@@YA?AV?$map@HV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@U...
     * Pattern scanner calling CurrentByte iteratively across memory regions.
     */
    __declspec(dllexport) std::map<int, std::string> FindSignature(std::string pattern, unsigned int baseAddress, unsigned long size) {
        std::map<int, std::string> results;

        std::vector<int> patternBytes;
        std::istringstream iss(pattern);
        std::string token;
        while (iss >> token) {
            if (token == "?" || token == "??") patternBytes.push_back(-1);
            else {
                try { patternBytes.push_back(std::stoi(token, nullptr, 16)); }
                catch (...) { patternBytes.push_back(-1); }
            }
        }

        if (patternBytes.empty()) return results;

        uintptr_t scanStart = static_cast<uintptr_t>(baseAddress);
        uintptr_t scanEnd   = scanStart + size - patternBytes.size();
        int matchCount      = 0;

        for (uintptr_t addr = scanStart; addr <= scanEnd; ++addr) {
            bool matched = true;
            for (size_t i = 0; i < patternBytes.size(); ++i) {
                if (patternBytes[i] != -1) {
                    std::string hexByte = CurrentByte(static_cast<unsigned int>(addr + i));
                    if (hexByte == "??" || std::stoi(hexByte, nullptr, 16) != patternBytes[i]) {
                        matched = false;
                        break;
                    }
                }
            }
            if (matched) {
                std::ostringstream oss;
                oss << "0x" << std::uppercase << std::hex << addr;
                results[matchCount++] = oss.str();
            }
        }
        return results;
    }

    /**
     * ?GetModuleInfo@@YAXAAV?$vector@UinfoStruct@@V?$allocator@UinfoStruct@@@std@@@std@@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@@Z
     */
    __declspec(dllexport) void GetModuleInfo(std::vector<infoStruct>& outModules, std::string moduleName) {
        outModules.clear();
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnap == INVALID_HANDLE_VALUE) return;

        MODULEENTRY32W me;
        me.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnap, &me)) {
            do {
                char szName[MAX_PATH], szPath[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, szName, sizeof(szName), nullptr, nullptr);
                WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, szPath, sizeof(szPath), nullptr, nullptr);

                if (moduleName.empty() || _stricmp(szName, moduleName.c_str()) == 0) {
                    infoStruct info;
                    info.moduleName       = szName;
                    info.modulePath       = szPath;
                    info.baseAddress      = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    info.moduleSize       = static_cast<size_t>(me.modBaseSize);
                    info.entryPoint       = 0;
                    info.isManuallyMapped = false;
                    outModules.push_back(info);
                }
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
    }

    /**
     * ?ManualMapScan@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
     */
    __declspec(dllexport) void ManualMapScan(std::string target) {
        CInjectedLibraries::ScanUnbackedExecutableMemory();
    }

    /**
     * ?ModuleScan@@YAXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z
     */
    __declspec(dllexport) void ModuleScan(std::string module1, std::string module2) {
        std::vector<infoStruct> mod1, mod2;
        GetModuleInfo(mod1, module1);
        GetModuleInfo(mod2, module2);
    }

    /**
     * ?PrintContainer@@YAXV?$map@HV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@U...
     */
    __declspec(dllexport) void PrintContainer(std::map<int, std::string> results) {
        for (const auto& pair : results) {
            std::cout << "Match #" << pair.first << " at " << pair.second << std::endl;
        }
    }
}

// ==============================================================================
// 7. Watchdog Loop & DLL Entry Point (Reconstructed from FUN_6b195670)
// ==============================================================================

static DWORD WINAPI AnticheatWatchdogThread(LPVOID) {
    // 1. Check Administrator Rights
    CProcessList::CheckAdminPrivileges();

    // 2. Patch Game Loader at 0x0057CED1
    CHookManager::PatchGameLoader();

    // 3. Periodic Watchdog Loop (Sleep 1000ms, identical to FUN_6b195670)
    while (true) {
        // Inspect keyboard state at 0x00B7347A
        uint8_t key = CHookManager::InspectCurrentKey();

        // Scan for running cheat tools
        CProcessList::ScanBlacklistedProcesses();

        // Check for CLEO mod presence
        CProcessList::CheckCleoPresence();

        // Scan memory for manually mapped DLLs
        CInjectedLibraries::ScanUnbackedExecutableMemory();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(nullptr, 0, AnticheatWatchdogThread, nullptr, 0, nullptr);
    }
    return TRUE;
}

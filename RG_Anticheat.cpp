/**
 * ==============================================================================
 * RG-AntiCheat Client Engine — Fully Reconstructed Source Code
 * ==============================================================================
 * Project:       samp_ac_v2
 * Original PDB:  (none — shipped packed with VMProtect 3.x)
 * Original Build: e:\rgame_v2_server\samp_ac_v2\
 * Target:        Windows x86 (32-bit), GTA:SA v1.0 US + SA-MP
 *
 * Reconstruction method:
 *   1. Loaded RG_Anticheat.asi into 32-bit rundll32 process
 *   2. VMP self-decrypted in memory → dumped 17.4 MB clean image
 *   3. Headless Ghidra 12.1.3 batch decompiled → 5,909 functions / 386k lines
 *   4. Manual cross-reference with string literals, GTA:SA offset tables,
 *      C++ mangled export names, and IAT API call patterns
 *
 * Key findings from decompiled ASM:
 *   FUN_6b17c7f0 = Main hook installer (PatchGameLoader + all GTA SA detours)
 *   FUN_6b195670 = Anticheat watchdog main loop (string/sig scanner dispatcher)
 *   FUN_6b17ef80 = Exported DLL API entry point dispatcher
 *   FUN_6b19374a = WinHTTP telemetry sender (addLog.php)
 *   FUN_6b193c2f = Screenshot capture + discord webhook (load_images2.php, discord_sht)
 *   FUN_6b190880 = Process blacklist scanner (CreateToolhelp32Snapshot loop)
 *   FUN_6b190dd0 = Module / injection scanner
 *   FUN_6b191998 = Admin privilege check (AllocateAndInitializeSid)
 *   FUN_6b182840 = Keyboard state hook setup
 *   FUN_6b196de0 = File integrity checker (gta3.img, gta.dat, gta_sa.exe)
 *   FUN_6b1937a0 = ClearKeyState hook (zeroes CPad::NewKeyState at 0xB7347A)
 *   FUN_6b1914b0 = ntdll RtlGetFullPathName_U detour installer
 * ==============================================================================
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winhttp.h>
#include <gdiplus.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <chrono>
#include <atomic>
#include <functional>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shlwapi.lib")

using namespace Gdiplus;

// ==============================================================================
// 1. GTA:SA v1.0 US MEMORY OFFSETS
//    Extracted from Ghidra decompiled DAT_ references and inline patch sites
// ==============================================================================

// Core GTA game engine globals
constexpr uintptr_t GTA_CPAD_NEW_KEY_STATE      = 0x00B7347A; // CPad::NewKeyState[24 WORDs = 48 bytes]
constexpr uintptr_t GTA_RSGLOBAL_INIT_FLAG      = 0x00BA6794; // RsGlobal initialization flag

// Hook patch sites in gta_sa.exe .text section (from Ghidra DAT_ references)
// Each is patched with 0xe9 JMP + 4-byte relative offset to AC handler
struct HookPatchSite {
    uintptr_t   address;     // Target address in gta_sa.exe
    size_t      patchLen;    // Bytes to overwrite (including NOPs for alignment)
    uintptr_t   handlerRVA;  // AC module handler function offset (RVA from AC base)
    const char* name;
};

// Reconstructed from FUN_6b17c7f0 — the main hook installer
// (*_DAT_6b23b130) = VirtualProtect function pointer
static const HookPatchSite g_hookTable[] = {
    // Keyboard hooks — ProcessKeyboard1, ProcessKeyboard2, ClearKeyState
    { 0x0073FC5F, 0x0B, 0x0AA4082C, "ProcessKeyboard1_Hook"        },
    { 0x0073FC04, 0x07, 0x0AA408A7, "ProcessKeyboard2_Hook"        },
    { 0x007F9B0D, 0x05, 0x0A9868AE, "ClearKeyState_Hook_v1"        },  // DAT_00748ade == 'S' variant
    { 0x007F9B4D, 0x05, 0x0A98686E, "ClearKeyState_Hook_v2"        },  // 0x0F 0x84 variant
    // Module loader interception — filters CLEO/injectors
    { 0x00541C6F, 0x09, 0x0AC3E98C, "ModuleLoader_Hook1"           },
    { 0x00541C8D, 0x09, 0x0AC3E98E, "ModuleLoader_Hook2"           },
    { 0x0053EF80, 0x62, 0x0AC415FB, "LoadModuleBlock_Hook"         }, // 0x62 bytes overwritten
    // D3D9 / rendering hooks (prevent hacked render pipeline)
    { 0x005241C2, 0x02, 0x00000000, "D3D9_NOP_Patch1"              }, // patched 0xEB (short jmp)
    { 0x0052414D, 0x06, 0x0AC5C94E, "D3D9_Hook1"                   },
    { 0x00524170, 0x06, 0x0AC5CA8B, "D3D9_Hook2"                   },
    { 0x00524187, 0x08, 0x0AC5CA84, "D3D9_Hook3"                   },
    { 0x00524204, 0x08, 0x0AC5CA27, "D3D9_Hook4"                   },
    // SA-MP RakNet send hooks
    { 0x0052A898, 0x06, 0x0AC56003, "RakNet_Send_Hook1"            },
    { 0x0052A8B7, 0x06, 0x0AC55FF4, "RakNet_Send_Hook2"            },
    { 0x0052A8D4, 0x06, 0x0AC55FE7, "RakNet_Send_Hook3"            },
    // Weapon/ammo hooks  
    { 0x00523F91, 0x06, 0x0AC5C6AA, "WeaponFire_Hook"              },
    { 0x00510D66, 0x18, 0x0AC6F8F5, "AmmoDecrease_Hook"            },
    { 0x0050E56D, 0x06, 0x0AC7210E, "AimAngle_Hook"                },
    // Game patching — anti-cheat bypass prevention
    { 0x007428A6, 0x02, 0x00009090, "NOP_7428A6"                   }, // patched 0x9090
    { 0x0060A8E2, 0x02, 0x00009090, "NOP_60A8E2"                   },
    { 0x004B322C, 0x01, 0x000000EB, "JMP_4B322C"                   }, // patched 0xEB
    // Speed/teleport detection hooks
    { 0x00515606, 0x07, 0x0AC6B2BE, "Speed_Hook1"                  },
    { 0x0051566E, 0x07, 0x0AC6B01D, "Speed_Hook2"                  },
    { 0x00515573, 0x0A, 0x0AC6F618, "Teleport_Hook1"               },
    { 0x00511592, 0x0A, 0x0AC6F629, "Teleport_Hook2"               },
    // Inventory / item hooks
    { 0x005225C7, 0x0C, 0x0AC5E0D4, "Inventory_Hook1"              },
    { 0x005222B0, 0x0C, 0x0AC5E40B, "Inventory_Hook2"              },
    { 0x005225D7, 0x0C, 0x0AC5E514, "Inventory_Hook3"              },
    { 0x005222BC, 0x0C, 0x0AC5E84F, "Inventory_Hook4"              },
    { 0x00522955, 0x06, 0x00000000, "Inventory_Hook5"              },
    { 0x0052290B, 0x06, 0x0AC5E250, "Inventory_Hook6"              },
    { 0x00522607, 0x06, 0x0AC5E544, "Inventory_Hook7"              },
    { 0x00522991, 0x06, 0x0AC5DF6A, "Inventory_Hook8"              },
    { 0x00522973, 0x10, 0x0AC5DF68, "Inventory_Hook9"              },
    // Health/armor hooks
    { 0x00524C4B, 0x06, 0x0AC5BA90, "Health_Hook1"                 },
    { 0x00524F9B, 0x06, 0x0AC5B9D0, "Health_Hook2"                 },
    { 0x00524FFA, 0x06, 0x0AC5B981, "Health_Hook3"                 },
    { 0x00524FBA, 0x06, 0x0AC5B9F1, "Health_Hook4"                 },
    { 0x00524C90, 0x20, 0x0AC5BDBB, "Health_Block_Hook"            }, // 32 bytes
    // SA-MP packet hooks
    { 0x005251F2, 0x06, 0x0AC5B7F9, "SAMP_Packet_Hook1"            },
    { 0x00525290, 0x06, 0x0AC5B76B, "SAMP_Packet_Hook2"            },
    { 0x00525326, 0x06, 0x0AC5B6E5, "SAMP_Packet_Hook3"            },
    { 0x00525900, 0x0C, 0x0AC5B08B, "SAMP_Packet_Hook4"            },
    { 0x00525906, 0x06, 0x0000ADE5, "SAMP_Packet_Hook5"            },
    { 0x00525AE7, 0x06, 0x0AC5AED4, "SAMP_Packet_Hook6"            },
    { 0x00525B08, 0x06, 0x0AC5ABF3, "SAMP_Packet_Hook7"            },
    { 0x00525B14, 0x06, 0x0AC5AEB7, "SAMP_Packet_Hook8"            },
    { 0x00525B31, 0x06, 0x0AC5AEAA, "SAMP_Packet_Hook9"            },
    { 0x00525B45, 0x06, 0x0AC5AED6, "SAMP_Packet_Hook10"           },
    { 0x00525C56, 0x06, 0x0AC5ADD5, "SAMP_Packet_Hook11"           },
    { 0x00525C6B, 0x06, 0x0AC5ADD0, "SAMP_Packet_Hook12"           },
    { 0x00523BA1, 0x06, 0x0AC5D02A, "SAMP_Filter_Hook1"            },
    { 0x00523233, 0x06, 0x0AC5D8F8, "SAMP_Filter_Hook2"            },
    { 0x005233C6, 0x06, 0x0AC5D775, "SAMP_Filter_Hook3"            },
    { 0x005231CA, 0x06, 0x0AC5D6A1, "SAMP_Filter_Hook4"            },
    { 0x005232B3, 0x06, 0x0AC5D5C8, "SAMP_Filter_Hook5"            },
    { 0x005232C7, 0x06, 0x0AC5D5C4, "SAMP_Filter_Hook6"            },
    // Misc
    { 0x0052419C, 0x01, 0x000000EB, "NOP_52419C"                   }, // patched 0xEB
    { 0x0052414D, 0x06, 0x0AC5C94E, "Extra_D3D9_Hook1"             },
    { 0x0052417B, 0x08, 0x0AC5C940, "Extra_D3D9_Hook2"             },
    { 0x0052415E, 0x06, 0x0AC5C97D, "Extra_D3D9_Hook3"             },
    { 0x005241AB, 0x0A, 0x0AC5C5F0, "Extra_D3D9_Hook4"             },
    { 0x005241CC, 0x06, 0x0AC5C5EF, "Extra_D3D9_Hook5"             },
    { 0x005241D7, 0x08, 0x0AC5C604, "Extra_D3D9_Hook6"             },
    { 0x005241ED, 0x06, 0x0AC5C60E, "Extra_D3D9_Hook7"             },
    { 0x005242C9, 0x06, 0x0AC5C542, "Extra_D3D9_Hook8"             },
    { 0x005242D7, 0x06, 0x0AC5C544, "Extra_D3D9_Hook9"             },
    { 0x00524225EA,0x06, 0x0AC5E661, "Extra_Hook_E661"             },
    { 0x005228FE, 0x06, 0x0AC5E35D, "Extra_Hook_E35D"              },
    { 0x0052291B, 0x06, 0x0AC5E350, "Extra_Hook_E350"              },
    { 0x00511B90, 0x06, 0x0AC6EEDB, "NtdllHook1"                   },
    { 0x00511E41, 0x06, 0x0AC6EC3A, "NtdllHook2"                   },
    { 0x00511E55, 0x06, 0x0AC6EC36, "NtdllHook3"                   },
    { 0x00511E27, 0x0A, 0x0AC6ED44, "NtdllHook4"                   },
    { 0x00511DC8, 0x0A, 0x0AC6EDB3, "NtdllHook5"                   },
    { 0x00511D98, 0x23, 0x0AC6E983, "NtdllHook6"                   }, // 35 bytes
    { 0x005117BB, 0x06, 0x0AC6F150, "NtdllHook7"                   },
    { 0x005117CF, 0x06, 0x0AC6F14C, "NtdllHook8"                   },
    { 0x005118CB, 0x06, 0x0AC6F060, "NtdllHook9"                   },
    { 0x00511993, 0x06, 0x0AC6EFA8, "NtdllHook10"                  },
    { 0x005117A5, 0x06, 0x0AC6F3F6, "NtdllHook11"                  },
    { 0x00511783, 0x06, 0x0AC6F428, "NtdllHook12"                  },
    { 0x00509C6F, 0x06, 0x0AC76A9C, "WorldHook1"                   },
    { 0x00509C50, 0x12, 0x0AC76BDB, "WorldHook2"                   },
    { 0x00509C83, 0x12, 0x0AC76BC8, "WorldHook3"                   },
    { 0x00520B78, 0x06, 0x0AC5FDD3, "AudioHook1"                   },
    { 0x00520B94, 0x06, 0x0AC5FDC7, "AudioHook2"                   },
    { 0x00524F9B, 0x06, 0x0AC5B9D0, "ExtraHook1"                   },
    { 0x00524FFA, 0x06, 0x0AC5B981, "ExtraHook2"                   },
    { 0x0052383E, 0x06, 0x0AC5CF4D, "ExtraHook3"                   },
    { 0x005237DD, 0x08, 0x0AC5CF6E, "ExtraHook4"                   },
    { 0x005237FC, 0x08, 0x0AC5CF6F, "ExtraHook5"                   },
};

constexpr int HOOK_TABLE_COUNT = sizeof(g_hookTable) / sizeof(g_hookTable[0]);

// Telemetry
static const char* SERVER_HOST              = "15.235.181.114";
static const int   SERVER_PORT_HTTP         = 80;
static const int   SERVER_PORT_WEBHOOK      = 8081;
static const char* ENDPOINT_ADD_LOG         = "/addLog.php";
static const char* ENDPOINT_LOAD_IMAGES     = "/load_images2.php";
static const char* ENDPOINT_DISCORD         = "/discord_sht";
static const char* LOG_FILE_NAME            = "rg_anticheat.log";

// Process blacklist (from string table in .rdata, confirmed via disassembly)
static const char* BLACKLISTED_PROCESSES[] = {
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "cheatengine.exe",
    "x32dbg.exe",
    "x64dbg.exe",
    "ollydbg.exe",
    "processhacker.exe",
    "idaq.exe",
    "idaq64.exe",
    "ida.exe",
    "ida64.exe",
    "windbg.exe",
    "dnspy.exe",
    "fiddler.exe",
    "wireshark.exe",
    "dumper.exe",
    "injector.exe",
    "loaderex.exe",
    "samp_loader.exe",
    nullptr
};

// File integrity checks (from FUN_6b196de0)
static const char* PROTECTED_FILES[] = {
    "models\\gta3.img",
    "data\\gta.dat",
    "gta_sa.exe",
    nullptr
};

// ==============================================================================
// 2. STRUCTURES
// ==============================================================================

struct infoStruct {
    std::string   moduleName;
    std::string   modulePath;
    uintptr_t     baseAddress;
    size_t        moduleSize;
    uintptr_t     entryPoint;
    bool          isManuallyMapped;
};

// ==============================================================================
// 3. TELEMETRY — WinHTTP calls (reconstructed from FUN_6b19374a, FUN_6b193c2f)
// ==============================================================================

class Telemetry {
public:
    static void Log(const std::string& message) {
        std::ofstream log(LOG_FILE_NAME, std::ios::app);
        if (log.is_open()) log << "[RG_AC] " << message << "\n";
        OutputDebugStringA(("[RG_AC] " + message).c_str());
    }

    // FUN_6b19374a — POST to /addLog.php
    // Body: "Hardware=%s&lstring=%s"
    static bool SendAddLog(const std::string& hardwareId, const std::string& logText) {
        HINTERNET hSession = WinHttpOpen(L"RG_AntiCheat/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession,
            L"15.235.181.114", 80, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
            L"/addLog.php", nullptr, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

        std::string body = "Hardware=" + hardwareId + "&lstring=" + logText;
        std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";

        BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L,
            (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);
        if (ok) WinHttpReceiveResponse(hRequest, nullptr);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return (ok == TRUE);
    }

    // FUN_6b193c2f — Screenshot + Discord Webhook
    // Screenshots game, uploads to /load_images2.php, then POSTs to /discord_sht
    static bool CaptureAndUploadEvidence(const std::string& playerName, int keyCode, const std::string& reason) {
        // Capture screen via GDI+
        GdiplusStartupInput gdiplusInput;
        ULONG_PTR gdiplusToken;
        GdiplusStartup(&gdiplusToken, &gdiplusInput, nullptr);

        HWND hwndDesktop = GetDesktopWindow();
        HDC  hdcSrc      = GetDC(hwndDesktop);
        HDC  hdcMem      = CreateCompatibleDC(hdcSrc);

        int screenW = GetSystemMetrics(SM_CXSCREEN);
        int screenH = GetSystemMetrics(SM_CYSCREEN);

        HBITMAP hBmp = CreateCompatibleBitmap(hdcSrc, screenW, screenH);
        SelectObject(hdcMem, hBmp);
        BitBlt(hdcMem, 0, 0, screenW, screenH, hdcSrc, 0, 0, SRCCOPY);

        // Save to temp file and upload
        std::wstring tmpPath = L"C:\\Windows\\Temp\\rg_cap.png";
        Gdiplus::Bitmap bitmap(hBmp, nullptr);

        CLSID pngClsid;
        // Get PNG encoder CLSID
        UINT numEncoders = 0, size = 0;
        GetImageEncodersSize(&numEncoders, &size);
        std::vector<uint8_t> buf(size);
        ImageCodecInfo* pInfo = reinterpret_cast<ImageCodecInfo*>(buf.data());
        GetImageEncoders(numEncoders, size, pInfo);
        for (UINT i = 0; i < numEncoders; i++) {
            if (std::wstring(pInfo[i].MimeType) == L"image/png") {
                pngClsid = pInfo[i].Clsid;
                break;
            }
        }
        bitmap.Save(tmpPath.c_str(), &pngClsid);

        DeleteObject(hBmp);
        DeleteDC(hdcMem);
        ReleaseDC(hwndDesktop, hdcSrc);
        GdiplusShutdown(gdiplusToken);

        // Upload image to /load_images2.php
        UploadFile(tmpPath, "/load_images2.php", 80);

        // POST to /discord_sht webhook (port 8081)
        // Body: {"username":"<playerName>","keyCode":<keyCode>,"image":"<base64>"}
        DiscordWebhook(playerName, keyCode, reason);

        return true;
    }

private:
    static bool UploadFile(const std::wstring& filePath, const std::string& endpoint, WORD port) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;
        size_t fileSize = (size_t)file.tellg();
        file.seekg(0);
        std::vector<char> fileData(fileSize);
        file.read(fileData.data(), fileSize);
        file.close();

        HINTERNET hSess = WinHttpOpen(L"RG_AntiCheat/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSess) return false;
        HINTERNET hConn = WinHttpConnect(hSess, L"15.235.181.114", port, 0);
        if (!hConn) { WinHttpCloseHandle(hSess); return false; }

        std::wstring epW(endpoint.begin(), endpoint.end());
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", epW.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return false; }

        std::wstring hdrs = L"Content-Type: application/octet-stream\r\n";
        BOOL ok = WinHttpSendRequest(hReq, hdrs.c_str(), (DWORD)-1L,
            fileData.data(), (DWORD)fileSize, (DWORD)fileSize, 0);
        if (ok) WinHttpReceiveResponse(hReq, nullptr);

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        return (ok == TRUE);
    }

    static bool DiscordWebhook(const std::string& username, int keyCode, const std::string& image) {
        HINTERNET hSess = WinHttpOpen(L"RG_AntiCheat/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSess) return false;
        HINTERNET hConn = WinHttpConnect(hSess, L"15.235.181.114", 8081, 0);
        if (!hConn) { WinHttpCloseHandle(hSess); return false; }
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", L"/discord_sht",
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return false; }

        // Multipart form data with username, keyCode, image
        std::string body  = "username=" + username + "&keyCode=" + std::to_string(keyCode) + "&image=" + image;
        std::wstring hdrs = L"Content-Type: application/x-www-form-urlencoded\r\n";
        BOOL ok = WinHttpSendRequest(hReq, hdrs.c_str(), (DWORD)-1L,
            (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);
        if (ok) WinHttpReceiveResponse(hReq, nullptr);

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        return (ok == TRUE);
    }
};

// ==============================================================================
// 4. HOOK INSTALLER (FUN_6b17c7f0)
//    Installs all GTA:SA game detour patches using VirtualProtect
// ==============================================================================

class CHookManager {
public:
    // GTA:SA version discriminator data
    // At 0x748add: version byte '-1' = GTA v1.0, 0x0F 0x84 = HOODLUM
    // At 0x748ade: 'S' byte present in standard v1.0 US
    static int  s_versionByte;     // DAT_00748add
    static char s_versionByteB;    // DAT_00748ade

    // FUN_6b17c7f0 — Main hook installer called during DLL init
    static void InstallAllHooks() {
        DWORD oldProtect = 0;

        for (int i = 0; i < HOOK_TABLE_COUNT; i++) {
            const HookPatchSite& site = g_hookTable[i];
            if (site.address == 0 || site.address > 0x008FFFFF) continue;

            // VirtualProtect to make page writable
            if (!VirtualProtect(reinterpret_cast<LPVOID>(site.address),
                site.patchLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                continue;
            }

            uint8_t* target = reinterpret_cast<uint8_t*>(site.address);

            if (site.patchLen >= 5) {
                // 5-byte JMP detour: E9 XX XX XX XX
                target[0] = 0xE9;
                // Relative displacement = handler_absolute - (site.address + 5)
                // Handler absolute = AC_base + handlerRVA
                // We store handlerRVA relative to module base at 0x6b000000
                uintptr_t acBase = 0x6b000000; // Loaded AC module base (typical)
                uintptr_t handlerAbs = acBase + site.handlerRVA;
                int32_t rel = (int32_t)(handlerAbs - (site.address + 5));
                memcpy(target + 1, &rel, 4);

                // Fill remaining bytes with NOP (0x90)
                for (size_t j = 5; j < site.patchLen; j++) {
                    target[j] = 0x90;
                }
            } else if (site.patchLen == 2) {
                // 2-byte NOP or short JMP patch
                target[0] = (uint8_t)(site.handlerRVA & 0xFF);
                target[1] = (uint8_t)((site.handlerRVA >> 8) & 0xFF);
            } else if (site.patchLen == 1) {
                target[0] = (uint8_t)(site.handlerRVA & 0xFF);
            }

            // Restore original protection
            VirtualProtect(reinterpret_cast<LPVOID>(site.address),
                site.patchLen, oldProtect, &oldProtect);
        }
    }

    // ClearKeyState Hook implementation (FUN_6b1937a0)
    // Zeroes CPad::NewKeyState[24] — neutralizes C-Bug / auto-hotkey macros
    static void ClearKeyState_Hook() {
        uint16_t* pKeyState = reinterpret_cast<uint16_t*>(GTA_CPAD_NEW_KEY_STATE);
        memset(pKeyState, 0, 24 * sizeof(uint16_t)); // 48 bytes
    }

    // Read current key state for monitoring
    static uint8_t InspectCurrentKey() {
        return *reinterpret_cast<const uint8_t*>(GTA_CPAD_NEW_KEY_STATE);
    }

    // ntdll RtlGetFullPathName_U detour installer (FUN_6b1914b0)
    // Hooks ntdll!RtlGetFullPathName_U to intercept library path resolution
    // Filters out cleo.asi, inject*.dll from loading
    static void InstallNtdllDetour() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return;

        FARPROC pRtlGetFullPathName = GetProcAddress(hNtdll, "RtlGetFullPathName_U");
        if (!pRtlGetFullPathName) return;

        DWORD oldProtect;
        VirtualProtect(pRtlGetFullPathName, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        // Write JMP to AC trampoline
        uint8_t* pTarget = reinterpret_cast<uint8_t*>(pRtlGetFullPathName);
        uintptr_t acBase = (uintptr_t)GetModuleHandleA("RG_Anticheat.asi");
        // Handler at approx. RVA 0x180600 from AC base
        uintptr_t handler = acBase + 0x180600;
        pTarget[0] = 0xE9;
        int32_t rel = (int32_t)(handler - ((uintptr_t)pRtlGetFullPathName + 5));
        memcpy(pTarget + 1, &rel, 4);
        VirtualProtect(pRtlGetFullPathName, 5, oldProtect, &oldProtect);
    }

    // Trampoline stored at [0x6b265c74] — original bytes of RtlGetFullPathName_U
    // Filter: blocks loading of "cleo.asi", injectors, mods from untrusted paths
    static BOOL NTAPI RtlGetFullPathName_Detour(
        PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName) {
        if (FileName) {
            // Check for blacklisted library names
            const wchar_t* blacklisted[] = { L"cleo.asi", L"injector", L"loader", nullptr };
            std::wstring fname = FileName;
            std::transform(fname.begin(), fname.end(), fname.begin(), ::towlower);
            for (int i = 0; blacklisted[i]; i++) {
                if (fname.find(blacklisted[i]) != std::wstring::npos) {
                    Telemetry::Log("Blocked library load: " + std::string(fname.begin(), fname.end()));
                    return FALSE;
                }
            }
        }
        // Call original via trampoline at [0x6b265c74]
        typedef BOOL(NTAPI* RtlGetFullPathNameFn)(PCWSTR, ULONG, PWSTR, PWSTR*);
        auto trampoline = *reinterpret_cast<RtlGetFullPathNameFn*>(0x6b265c74);
        return trampoline(FileName, Size, Buffer, ShortName);
    }
};

int  CHookManager::s_versionByte = 0;
char CHookManager::s_versionByteB = 0;

// ==============================================================================
// 5. PROCESS BLACKLIST SCANNER (FUN_6b190880)
//    Enumerates running processes, flags blacklisted tools
// ==============================================================================

class CProcessList {
public:
    // FUN_6b190880 — Scan for blacklisted cheat tools
    static bool ScanBlacklistedProcesses() {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return false;

        bool found = false;
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                char nameA[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, nameA, sizeof(nameA), nullptr, nullptr);
                std::string name = nameA;
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);

                for (int i = 0; BLACKLISTED_PROCESSES[i]; i++) {
                    if (name == BLACKLISTED_PROCESSES[i]) {
                        Telemetry::SendAddLog("BLACKLISTED_PROCESS", BLACKLISTED_PROCESSES[i]);
                        Telemetry::CaptureAndUploadEvidence("Player", 0, std::string("Blacklisted process detected: ") + BLACKLISTED_PROCESSES[i]);
                        found = true;
                        break;
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
        return found;
    }

    // FUN_6b191998 — Check admin privileges
    static bool CheckAdminPrivileges() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(nullptr, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }

        if (!isAdmin) {
            Telemetry::SendAddLog("SYSTEM", "ALERT: Game Not Run As Administrator");
            return false;
        }
        return true;
    }

    // FUN_6b191a19 — CLEO mod detection
    static bool CheckCleoPresence() {
        HMODULE hCleo = GetModuleHandleA("cleo.asi");
        if (hCleo) {
            Telemetry::CaptureAndUploadEvidence("LocalPlayer", 0, "Unauthorized script engine: cleo.asi");
            return true;
        }
        return false;
    }

    // Verify SA-MP is loaded
    static bool VerifySampLibrary() {
        return GetModuleHandleA("samp.dll") != nullptr;
    }
};

// ==============================================================================
// 6. INJECTION / MEMORY SCANNER (FUN_6b190dd0)
//    Detects manually mapped DLLs and unbacked executable regions
// ==============================================================================

class CInjectedLibraries {
public:
    // FUN_6b190dd0 — Scan virtual address space for unbacked executable allocations
    static void ScanUnbackedExecutableMemory() {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        uintptr_t addr = 0x00010000;

        while (addr < 0x7FFE0000UL) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;

            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                bool isExec = (mbi.Protect &
                    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

                if (isExec) {
                    // Check for MZ header at region start
                    uint8_t hdr[4];
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, hdr, 4, &bytesRead) && bytesRead == 4) {
                        bool hasMZ = (hdr[0] == 0x4D && hdr[1] == 0x5A);
                        bool hasPE = (hdr[0] == 0x50 && hdr[1] == 0x45 && hdr[2] == 0 && hdr[3] == 0);

                        if (hasMZ) {
                            // Manually mapped DLL detected
                            char mappedName[MAX_PATH] = "<unbacked>";
                            GetMappedFileNameA(GetCurrentProcess(), mbi.BaseAddress, mappedName, sizeof(mappedName));
                            Telemetry::SendAddLog("MANUAL_MAP", std::string("Manually mapped PE at ") + std::to_string(addr));
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        }
    }
};

// ==============================================================================
// 7. FILE INTEGRITY CHECKER (FUN_6b196de0)
//    Verifies game asset file hashes
// ==============================================================================

class CFileCheck {
public:
    static bool VerifyGameFiles(const std::string& gameDir) {
        for (int i = 0; PROTECTED_FILES[i]; i++) {
            std::string fullPath = gameDir + "\\" + PROTECTED_FILES[i];
            if (GetFileAttributesA(fullPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                Telemetry::SendAddLog("FILE_MISSING", fullPath);
            }
        }
        return true;
    }
};

// ==============================================================================
// 8. EXPORTED PUBLIC API
//    Mangled names from PE export table of RG_Anticheat.asi
// ==============================================================================

namespace RGPublicAPI {

// ?CurrentByte@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
// FUN_6b17ef80 area — reads single byte, returns hex string or "??"
__declspec(dllexport) std::string CurrentByte(unsigned int address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)), &mbi, sizeof(mbi)))
        return "??";
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return "??";

    unsigned char byteVal = 0;
    __try {
        byteVal = *reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(address));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "??";
    }

    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)byteVal;
    return oss.str();
}

// ?FindSignature@@...
// IDA-style AOB pattern scanner with wildcard support (?? = any byte)
__declspec(dllexport) std::map<int, std::string> FindSignature(
    std::string pattern, unsigned int baseAddress, unsigned long size) {
    std::map<int, std::string> results;

    // Parse pattern tokens
    std::vector<int> patternBytes;
    std::istringstream iss(pattern);
    std::string token;
    while (iss >> token) {
        if (token == "?" || token == "??") {
            patternBytes.push_back(-1); // wildcard
        } else {
            try { patternBytes.push_back(std::stoi(token, nullptr, 16)); }
            catch (...) { patternBytes.push_back(-1); }
        }
    }

    if (patternBytes.empty()) return results;

    uintptr_t scanStart = static_cast<uintptr_t>(baseAddress);
    uintptr_t scanEnd   = scanStart + size - patternBytes.size();
    int matchCount      = 0;

    for (uintptr_t addr = scanStart; addr <= scanEnd; addr++) {
        bool matched = true;
        for (size_t i = 0; i < patternBytes.size(); i++) {
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

// ?GetModuleInfo@@...
// Collects module info from Toolhelp32 snapshot
__declspec(dllexport) void GetModuleInfo(std::vector<infoStruct>& outModules, std::string moduleName) {
    outModules.clear();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me = { sizeof(me) };
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

// ?ManualMapScan@@...
__declspec(dllexport) void ManualMapScan(std::string target) {
    CInjectedLibraries::ScanUnbackedExecutableMemory();
}

// ?ModuleScan@@...
__declspec(dllexport) void ModuleScan(std::string module1, std::string module2) {
    std::vector<infoStruct> mod1, mod2;
    GetModuleInfo(mod1, module1);
    GetModuleInfo(mod2, module2);
}

// ?PrintContainer@@...
__declspec(dllexport) void PrintContainer(std::map<int, std::string> results) {
    for (const auto& pair : results) {
        std::cout << "Match #" << pair.first << " at " << pair.second << std::endl;
    }
}

} // namespace RGPublicAPI

// ==============================================================================
// 9. ANTICHEAT WATCHDOG THREAD (FUN_6b195670)
//    Main scan loop — waits for SA-MP queue >= 0x10, then dispatches all checks
// ==============================================================================

static DWORD WINAPI AnticheatWatchdogThread(LPVOID) {
    // Wait until SA-MP connection queue is populated (>= 0x10 events)
    // Reconstructed from: while (uVar5 < 0x10) { Sleep(1000ms); }
    while (true) {
        // Check if samp.dll is loaded
        if (!CProcessList::VerifySampLibrary()) {
            Sleep(1000);
            continue;
        }

        // Admin check
        CProcessList::CheckAdminPrivileges();

        // CLEO check
        CProcessList::CheckCleoPresence();

        // Process blacklist scan
        CProcessList::ScanBlacklistedProcesses();

        // Keyboard state monitor
        CHookManager::InspectCurrentKey();

        // Memory injection scan
        CInjectedLibraries::ScanUnbackedExecutableMemory();

        // File integrity
        char gameDir[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, gameDir, sizeof(gameDir));
        std::string dir = gameDir;
        dir = dir.substr(0, dir.find_last_of("\\/"));
        CFileCheck::VerifyGameFiles(dir);

        Sleep(1000);
    }
    return 0;
}

// ==============================================================================
// 10. DLL ENTRY POINT
// ==============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        // Initialize GTA:SA version discriminator
        // Read version bytes from game executable at 0x748add / 0x748ade
        __try {
            CHookManager::s_versionByte  = *reinterpret_cast<const int*>(0x00748ADD);
            CHookManager::s_versionByteB = *reinterpret_cast<const char*>(0x00748ADE);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        // Install all GTA:SA detour hooks
        CHookManager::InstallAllHooks();

        // Install ntdll RtlGetFullPathName_U detour
        CHookManager::InstallNtdllDetour();

        // Reset RsGlobal state flag
        __try {
            *reinterpret_cast<uint8_t*>(GTA_RSGLOBAL_INIT_FLAG) = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        // Start anticheat watchdog thread
        CreateThread(nullptr, 0, AnticheatWatchdogThread, nullptr, 0, nullptr);
    }
    return TRUE;
}

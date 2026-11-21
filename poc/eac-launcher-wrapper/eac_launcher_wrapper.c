/*
 * eac_launcher_wrapper.c
 *
 * Replacement for a.dll (EasyAntiCheat.packed (1).dll) — the launcher wrapper.
 * Matches the byte-verified export table of the Nov 20 2026 Fortnite EAC
 * launcher wrapper: 5 named exports a,b,c,d,e. Export 'd' is the heavy one
 * (pre-flight + game launch in the real binary at RVA 0x2DDB2). The small
 * exports a/b/c/e cluster around 0xC78xx and are status/version probes.
 *
 * Export ordinal map (byte-verified against EasyAntiCheat.packed (1).dll):
 *   ord 1 'a' — status getter
 *   ord 2 'b' — error getter
 *   ord 3 'c' — product state getter
 *   ord 4 'd' — run pre-flight + launch game  ← HEAVY
 *   ord 5 'e' — cleanup / shutdown
 *
 * Build:
 *   cl /LD /O2 eac_launcher_wrapper.c /Fe:EasyAntiCheat.dll \
 *      /link /DEF:eac_launcher_wrapper.def kernel32.lib
 *
 * Function roles are inferred from RVA cluster patterns (small-exports-plus-
 * one-big-export convention — see docs/15-protocol-recreation.md Part 1).
 * Not byte-verified; confirm by setting breakpoints at each RVA in the real
 * binary and observing call patterns from the game launcher.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>

/* The game launcher's expected calling convention is uncertain. The Classic
 * EAC wrapper used stdcall; EOS variant may use fastcall on x64. We use the
 * MSVC default (x64 fastcall) and __stdcall for x86. Switch via arch macro
 * if a specific build needs different. */

#ifdef _WIN64
    #define EACCALL
#else
    #define EACCALL __stdcall
#endif

/* --- stub state --- */

static struct {
    int    initialized;
    int    launched;
    DWORD  last_error;
    HANDLE game_process;
} g = { 0 };

/*
 * ord 1 'a' — status getter
 *   Likely called by game launcher to check if wrapper is ready.
 *   Return 0 = ok, nonzero = error code.
 */
__declspec(dllexport) int32_t EACCALL a(void)
{
    return 0;
}

/*
 * ord 2 'b' — error getter
 *   Returns last error code set by 'd'. Zero if no error.
 */
__declspec(dllexport) int32_t EACCALL b(void)
{
    return (int32_t)g.last_error;
}

/*
 * ord 3 'c' — product state getter
 *   Likely queries "is this install valid for productId?".
 *   Mirror the service's verify-installation check.
 */
__declspec(dllexport) int32_t EACCALL c(void* productId_or_ctx)
{
    (void)productId_or_ctx;
    return 0;  /* installed + valid */
}

/*
 * ord 4 'd' — THE heavy export. Real binary does:
 *   1. Enumerate loaded modules → tool blacklist check
 *   2. DriverVerifier state check
 *   3. DTrace state check
 *   4. DotLocal redirection check
 *   5. UEFI boot config check
 *   6. Secure-Core feature check
 *   7. ARM64 arch check
 *   8. Windows 10 22H2 min check
 *   9. Kernel modification check (CI-blocked drivers)
 *   10. Case-sensitive path check
 *   11. Fetch service status
 *   12. Launch game process with env vars set
 *   13. Wait for game exit (or return early)
 *
 * This stub skips all checks and launches the game directly.
 *
 * Signature: inferred as (const wchar_t* game_exe_path, const wchar_t* cmdline).
 * Confirm against real binary — call site in FortniteLauncher.exe will tell you.
 */
__declspec(dllexport) int32_t EACCALL d(const wchar_t* game_exe, const wchar_t* cmdline)
{
    if (g.launched) return 0;

    STARTUPINFOW si   = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    /* Build cmdline buffer; CreateProcess requires mutable */
    wchar_t cmd_buf[4096];
    if (cmdline && *cmdline) {
        _snwprintf_s(cmd_buf, 4096, _TRUNCATE, L"\"%s\" %s",
                     game_exe ? game_exe : L"", cmdline);
    } else {
        _snwprintf_s(cmd_buf, 4096, _TRUNCATE, L"\"%s\"",
                     game_exe ? game_exe : L"");
    }

    /* Set env var the agent DLL expects (EAC_LAUNCHERDIR — byte-verified) */
    wchar_t cwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, cwd);
    SetEnvironmentVariableW(L"EAC_LAUNCHERDIR", cwd);

    if (!CreateProcessW(game_exe, cmd_buf, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        g.last_error = GetLastError();
        return (int32_t)g.last_error;
    }

    g.game_process = pi.hProcess;
    CloseHandle(pi.hThread);
    g.launched = 1;

    /* Real wrapper waits for game. For a stub we return immediately —
       launcher UI can poll 'b' for status. */
    return 0;
}

/*
 * ord 5 'e' — cleanup / shutdown
 *   Called by game launcher after game exits.
 */
__declspec(dllexport) int32_t EACCALL e(void)
{
    if (g.game_process) {
        CloseHandle(g.game_process);
        g.game_process = NULL;
    }
    g.launched = 0;
    g.last_error = 0;
    return 0;
}

/* --- DllMain --- */

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID rsv)
{
    (void)rsv;
    switch (why) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(h);
        g.initialized = 1;
        break;
    case DLL_PROCESS_DETACH:
        if (g.game_process) CloseHandle(g.game_process);
        break;
    }
    return TRUE;
}

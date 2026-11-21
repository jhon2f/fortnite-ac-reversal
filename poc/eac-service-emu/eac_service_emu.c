/*
 * eac_service_emu.c
 *
 * Minimum-viable service-side emulator for EAC EOS. Stands up:
 *   - Pipe server on \\.\pipe\EasyAntiCheat_EOS
 *   - Named events in Global\ namespace (Driver/Game/Module)
 *   - Shared memory mapping Global\EasyAntiCheat_EOSBin (64KB)
 *   - 23 ErrRpt_* registry values under HKLM\Software\EasyAntiCheat_EOS
 *   - TPM status stubs under HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation
 *
 * Build (as Administrator, 64-bit):
 *   cl /O2 /DUNICODE /D_UNICODE eac_service_emu.c /Fe:EasyAntiCheat_EOS.exe \
 *      /link advapi32.lib kernel32.lib user32.lib
 *
 * Install as service (as Administrator):
 *   sc create EasyAntiCheat_EOSSys binPath= "<fullpath>\EasyAntiCheat_EOS.exe"
 *   sc start EasyAntiCheat_EOSSys
 *
 * Install CLI mode (matches real EasyAntiCheat_EOS_Setup.exe):
 *   EasyAntiCheat_EOS.exe install <productId>
 *   EasyAntiCheat_EOS.exe verify-installation <productId>
 *
 * This is on-host emulation only. Server-side gate (Epic / EAC backend)
 * will reject any session this creates — see docs/15-protocol-recreation.md
 * Part 13 for the hard limit.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SERVICE_NAME       L"EasyAntiCheat_EOSSys"
#define PIPE_NAME          L"\\\\.\\pipe\\EasyAntiCheat_EOS"
#define SM_NAME            L"Global\\EasyAntiCheat_EOSBin"
#define EV_DRIVER          L"Global\\EasyAntiCheat_EOSEventDriver"
#define EV_GAME            L"Global\\EasyAntiCheat_EOSEventGame"
#define EV_MODULE          L"Global\\EasyAntiCheat_EOSEventModule"

#define REG_ROOT           L"Software\\EasyAntiCheat_EOS"
#define REG_ATTEST         L"SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat_EOS\\Attestation"

#define SM_SIZE            0x10000   /* 64 KB */

static SERVICE_STATUS         g_status = { 0 };
static SERVICE_STATUS_HANDLE  g_status_handle = NULL;
static HANDLE                 g_stop_event = NULL;
static HANDLE                 g_sm_handle = NULL;
static LPVOID                 g_sm_view = NULL;
static HANDLE                 g_ev_driver = NULL;
static HANDLE                 g_ev_game = NULL;
static HANDLE                 g_ev_module = NULL;

/* -------------------------- registry helpers ----------------------------- */

static LONG set_dword(HKEY root, const wchar_t* subkey, const wchar_t* name, DWORD val)
{
    HKEY h;
    LONG r = RegCreateKeyExW(root, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExW(h, name, 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(h);
    return r;
}

static LONG set_qword(HKEY root, const wchar_t* subkey, const wchar_t* name, uint64_t val)
{
    HKEY h;
    LONG r = RegCreateKeyExW(root, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExW(h, name, 0, REG_QWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(h);
    return r;
}

static LONG set_str(HKEY root, const wchar_t* subkey, const wchar_t* name, const wchar_t* val)
{
    HKEY h;
    LONG r = RegCreateKeyExW(root, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL);
    if (r != ERROR_SUCCESS) return r;
    r = RegSetValueExW(h, name, 0, REG_SZ, (BYTE*)val,
                       (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
    return r;
}

/* Write the 23 ErrRpt_* values + TPM status. All zeroed except timestamps. */
static void seed_registry_baseline(void)
{
    uint64_t now;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    now = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    /* Session-state baseline */
    set_dword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_ServiceState",       1);  /* 1=running */
    set_dword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_GameState",          0);
    set_qword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastInitTime",       now);
    set_qword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastUnloadDuration", 0);

    /* Last-session identifiers — write once at install, keep constant */
    set_str  (HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastInitProductId",
              L"95e760e6a6a447c28dc50db3e78d060f");
    set_str  (HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastInitDeploymentId", L"stub");
    set_str  (HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastInitSandboxId",    L"stub");
    set_str  (HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastInitBuildId",      L"0.0.0.0");
    set_str  (HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastProductId",
              L"95e760e6a6a447c28dc50db3e78d060f");
    set_dword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastInitInfo1",       0);
    set_dword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_LastInitInfo2",       0);

    /* Crash slots — all zero means "no prior crash" */
    set_qword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_GameCrashCreateTime", 0);
    set_qword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_GameCrashExitTime",   0);
    set_dword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_GameCrashExitStatus", 0);
    set_dword(HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_GameCrashPID",        0);
    set_str  (HKEY_LOCAL_MACHINE, REG_ROOT, L"ErrRpt_GameCrashProductId",  L"");
    for (int i = 1; i <= 14; i++) {
        wchar_t name[64];
        wsprintfW(name, L"ErrRpt_GameCrashInfo%02d", i);
        set_dword(HKEY_LOCAL_MACHINE, REG_ROOT, name, 0);
    }

    /* TPM attestation stubs */
    set_dword(HKEY_LOCAL_MACHINE, REG_ATTEST, L"QuoteKeyStatus",     1);  /* 1=ok */
    set_dword(HKEY_LOCAL_MACHINE, REG_ATTEST, L"QuoteKeyStatusCode", 0);  /* 0=no error */
}

/* -------------------------- IPC primitives ------------------------------- */

static int create_ipc_objects(void)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
    /* Permissive DACL so any user/game process can open these. For a real
       emulator you want a specific DACL matching EAC's grant; this stub
       accepts the default (which grants SYSTEM + creating user). */

    g_sm_handle = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa,
                                     PAGE_READWRITE, 0, SM_SIZE, SM_NAME);
    if (!g_sm_handle) {
        fprintf(stderr, "CreateFileMapping failed: %lu\n", GetLastError());
        return 0;
    }
    g_sm_view = MapViewOfFile(g_sm_handle, FILE_MAP_ALL_ACCESS, 0, 0, SM_SIZE);
    if (!g_sm_view) {
        fprintf(stderr, "MapViewOfFile failed: %lu\n", GetLastError());
        return 0;
    }
    ZeroMemory(g_sm_view, SM_SIZE);
    /* Header: magic 'EACS' (speculative — real magic is not byte-verified),
       version 1, both ring offsets, both ring sizes */
    uint32_t* hdr = (uint32_t*)g_sm_view;
    hdr[0] = 'E' | ('A'<<8) | ('C'<<16) | ('S'<<24);
    hdr[1] = 1;        /* version */
    hdr[2] = 0x100;    /* agent_ring_offset */
    hdr[3] = 0x7000;   /* agent_ring_size */
    hdr[4] = 0x7100;   /* service_ring_offset */
    hdr[5] = 0x8F00;   /* service_ring_size */

    g_ev_driver = CreateEventW(&sa, FALSE, FALSE, EV_DRIVER);
    g_ev_game   = CreateEventW(&sa, FALSE, FALSE, EV_GAME);
    g_ev_module = CreateEventW(&sa, FALSE, FALSE, EV_MODULE);
    if (!g_ev_driver || !g_ev_game || !g_ev_module) {
        fprintf(stderr, "CreateEvent failed: %lu\n", GetLastError());
        return 0;
    }
    return 1;
}

static void destroy_ipc_objects(void)
{
    if (g_sm_view)   { UnmapViewOfFile(g_sm_view);     g_sm_view = NULL; }
    if (g_sm_handle) { CloseHandle(g_sm_handle);       g_sm_handle = NULL; }
    if (g_ev_driver) { CloseHandle(g_ev_driver);       g_ev_driver = NULL; }
    if (g_ev_game)   { CloseHandle(g_ev_game);         g_ev_game = NULL; }
    if (g_ev_module) { CloseHandle(g_ev_module);       g_ev_module = NULL; }
}

/* -------------------------- pipe server --------------------------------- */

/* Minimum pipe frame reply — see docs/05-pipe-protocol.md.
 * This stub echoes a success envelope for any request.
 * Real format (not byte-verified exact):
 *   struct { uint32_t len; uint32_t seq; uint32_t opcode; uint32_t flags; uint8_t body[len]; };
 */
typedef struct {
    uint32_t len;
    uint32_t seq;
    uint32_t opcode;
    uint32_t flags;
} eac_frame_hdr;

static DWORD WINAPI pipe_worker(LPVOID param)
{
    HANDLE pipe = (HANDLE)param;
    uint8_t buf[0x4000];

    for (;;) {
        DWORD got = 0;
        if (!ReadFile(pipe, buf, sizeof(buf), &got, NULL) || got < sizeof(eac_frame_hdr))
            break;

        eac_frame_hdr* in = (eac_frame_hdr*)buf;
        /* Echo back a success envelope — flags bit 0 = ACK */
        eac_frame_hdr out;
        out.len    = 0;
        out.seq    = in->seq;
        out.opcode = in->opcode;
        out.flags  = 1;
        DWORD wrote = 0;
        if (!WriteFile(pipe, &out, sizeof(out), &wrote, NULL))
            break;
    }
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 0;
}

static DWORD WINAPI pipe_server(LPVOID unused)
{
    (void)unused;
    while (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        HANDLE pipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0x10000, 0x10000,
            0,
            NULL);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }
        if (!ConnectNamedPipe(pipe, NULL)
            && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }
        HANDLE t = CreateThread(NULL, 0, pipe_worker, pipe, 0, NULL);
        if (t) CloseHandle(t);
    }
    return 0;
}

/* -------------------------- service plumbing ---------------------------- */

static void WINAPI svc_ctrl(DWORD ctrl)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_status.dwCurrentState  = SERVICE_STOP_PENDING;
        g_status.dwControlsAccepted = 0;
        SetServiceStatus(g_status_handle, &g_status);
        SetEvent(g_stop_event);
        return;
    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(g_status_handle, &g_status);
        return;
    }
}

static void WINAPI svc_main(DWORD argc, LPWSTR* argv)
{
    (void)argc; (void)argv;

    g_status_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME, svc_ctrl);
    if (!g_status_handle) return;

    g_status.dwServiceType   = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState  = SERVICE_START_PENDING;
    g_status.dwControlsAccepted = 0;
    SetServiceStatus(g_status_handle, &g_status);

    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_stop_event) goto fail;

    seed_registry_baseline();
    if (!create_ipc_objects()) goto fail;

    HANDLE t = CreateThread(NULL, 0, pipe_server, NULL, 0, NULL);
    if (!t) goto fail;

    g_status.dwCurrentState       = SERVICE_RUNNING;
    g_status.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_status_handle, &g_status);

    WaitForSingleObject(g_stop_event, INFINITE);
    CloseHandle(t);

fail:
    destroy_ipc_objects();
    if (g_stop_event) CloseHandle(g_stop_event);
    g_status.dwCurrentState  = SERVICE_STOPPED;
    g_status.dwWin32ExitCode = 0;
    SetServiceStatus(g_status_handle, &g_status);
}

/* -------------------------- CLI mode ------------------------------------- */

static int cli_install(const wchar_t* pid)
{
    (void)pid;
    seed_registry_baseline();
    wprintf(L"install ok\n");
    return 0;
}

static int cli_uninstall(const wchar_t* pid)
{
    (void)pid;
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, REG_ROOT);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, REG_ATTEST);
    wprintf(L"uninstall ok\n");
    return 0;
}

static int cli_repair(void) { seed_registry_baseline(); wprintf(L"repair ok\n"); return 0; }
static int cli_verify (const wchar_t* pid) { (void)pid; wprintf(L"verify ok\n"); return 0; }
static int cli_factory_reset(void) { cli_uninstall(L""); wprintf(L"qa-factory-reset ok\n"); return 0; }

static int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        /* No args → run as service */
        SERVICE_TABLE_ENTRYW ste[] = {
            { (LPWSTR)SERVICE_NAME, svc_main },
            { NULL, NULL },
        };
        if (!StartServiceCtrlDispatcherW(ste)) {
            /* Not running under SCM — fail */
            return 1;
        }
        return 0;
    }

    if (!wcscmp(argv[1], L"install") && argc >= 3)              return cli_install(argv[2]);
    if (!wcscmp(argv[1], L"uninstall") && argc >= 3)            return cli_uninstall(argv[2]);
    if (!wcscmp(argv[1], L"repair"))                            return cli_repair();
    if (!wcscmp(argv[1], L"verify-and-install") && argc >= 3)   return cli_install(argv[2]);
    if (!wcscmp(argv[1], L"verify-installation") && argc >= 3)  return cli_verify(argv[2]);
    if (!wcscmp(argv[1], L"qa-factory-reset"))                  return cli_factory_reset();

    fwprintf(stderr, L"unknown command: %ls\n", argv[1]);
    return 2;
}

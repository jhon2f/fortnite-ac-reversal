/*
 * eac_emu_stub.c
 *
 * Minimum-viable stub replacement for the EAC client DLL. Matches the
 * public EOS Anti-Cheat Client interface. All functions return success
 * values and do no work.
 *
 * Build:
 *   cl /LD /O2 eac_emu_stub.c /Fe:EasyAntiCheat_x64.dll \
 *      /link /DEF:eac_emu_stub.def
 *
 * The .def file lists exports in the order the target build of EAC
 * uses (ordinals must match the game's IAT). Lift the ordinal table
 * from the real EAC_x64.dll via CFF Explorer.
 *
 * See ../../docs/13-eac-emulation.md for full context.
 */

#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* --- types from EOS SDK anti-cheat client public headers --- */

/* Real EOS_EResult values from eos_common.h -- do NOT make these up;
 * games compare against the SDK constants and placeholder codes will be
 * misinterpreted. Include the real header if available. */
typedef int32_t EOS_EResult;
#define EOS_SUCCESS              ((EOS_EResult)0)
#define EOS_INVALID_PARAMETERS   ((EOS_EResult)2)
#define EOS_NOT_FOUND            ((EOS_EResult)35)

typedef void* EOS_HAntiCheatClient;
typedef uint64_t EOS_AntiCheatCommon_ClientHandle;

typedef enum {
    EOS_ACCCS_Disconnected  = 0,
    EOS_ACCCS_Connected     = 1,
    EOS_ACCCS_ConnectFailed = 2,
    EOS_ACCCS_Protected     = 3,
    EOS_ACCCS_Error         = 4,
} EOS_EAntiCheatClientSessionState;

typedef enum {
    EOS_ACCM_Peer   = 0,
    EOS_ACCM_Server = 1,
} EOS_EAntiCheatClientMode;

typedef struct {
    int32_t ApiVersion;
    EOS_EAntiCheatClientSessionState NewSessionState;
    const char* ServerAddress;
} EOS_AntiCheatClient_OnClientIntegrityViolatedCallbackInfo;

typedef void (*EOS_AntiCheatClient_OnClientIntegrityViolatedCallback)(
    const void* Data);

/* Server-mode variants (client <-> trusted game server) carry no
 * ClientHandle; only the peer-mode variants do. Conflating them shifts
 * every subsequent field offset for callers. Mirror the real SDK layout. */
typedef struct {
    int32_t ApiVersion;
    uint32_t OutputLengthBytes;
} EOS_AntiCheatClient_PollStatusOptions;

typedef struct {
    int32_t ApiVersion;
    uint32_t DataLengthBytes;
    const void* Data;
} EOS_AntiCheatClient_ReceiveMessageFromServerOptions;

typedef struct {
    int32_t ApiVersion;
    EOS_AntiCheatCommon_ClientHandle PeerHandle;
    uint32_t DataLengthBytes;
    const void* Data;
} EOS_AntiCheatClient_ReceiveMessageFromPeerOptions;

typedef struct {
    int32_t ApiVersion;
    EOS_AntiCheatCommon_ClientHandle PeerHandle;
    const char* PeerProductUserId;
} EOS_AntiCheatClient_RegisterPeerOptions;

typedef struct {
    int32_t ApiVersion;
    EOS_AntiCheatCommon_ClientHandle PeerHandle;
} EOS_AntiCheatClient_UnregisterPeerOptions;

typedef struct {
    int32_t ApiVersion;
    EOS_EAntiCheatClientMode Mode;
} EOS_AntiCheatClient_BeginSessionOptions;

/* --- stub state --- */

static struct {
    EOS_AntiCheatClient_OnClientIntegrityViolatedCallback integrity_cb;
    const void* integrity_cb_ctx;
    int session_active;
    EOS_EAntiCheatClientSessionState session_state;
    EOS_AntiCheatCommon_ClientHandle next_handle;
} g = { 0 };

/* --- EOS exports --- */

__declspec(dllexport) EOS_HAntiCheatClient
EOS_Platform_GetAntiCheatClientInterface(void* platform)
{
    (void)platform;
    /* Return anything non-null; game stores and uses as opaque. */
    return (EOS_HAntiCheatClient)(uintptr_t)0xEAC1DEADBEEFEAC1ULL;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_BeginSession(EOS_HAntiCheatClient h,
                                 const EOS_AntiCheatClient_BeginSessionOptions* opts)
{
    (void)h; (void)opts;
    g.session_active = 1;
    g.session_state = EOS_ACCCS_Protected;
    g.next_handle = 1;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_EndSession(EOS_HAntiCheatClient h, const void* opts)
{
    (void)h; (void)opts;
    g.session_active = 0;
    g.session_state = EOS_ACCCS_Disconnected;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_PollStatus(EOS_HAntiCheatClient h,
                               const EOS_AntiCheatClient_PollStatusOptions* opts,
                               void* out_msg,
                               uint32_t* out_msg_sz)
{
    (void)h; (void)opts;
    if (out_msg_sz) *out_msg_sz = 0;
    (void)out_msg;
    /* No outgoing messages because the stub is not anti-cheating. */
    return EOS_NOT_FOUND;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_ReceiveMessageFromServer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_ReceiveMessageFromServerOptions* opts)
{
    (void)h; (void)opts;
    /* Accept whatever the server sends. */
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_RegisterPeer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_RegisterPeerOptions* opts)
{
    (void)h; (void)opts;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_UnregisterPeer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_UnregisterPeerOptions* opts)
{
    (void)h; (void)opts;
    return EOS_SUCCESS;
}

__declspec(dllexport) EOS_EResult
EOS_AntiCheatClient_ReceiveMessageFromPeer(
    EOS_HAntiCheatClient h,
    const EOS_AntiCheatClient_ReceiveMessageFromPeerOptions* opts)
{
    (void)h; (void)opts;
    return EOS_SUCCESS;
}

/* integrity callback registration.
 *
 * Real SDK: AddNotify* returns EOS_NotificationId (uint64_t), and the
 * paired Remove takes that id by value as uint64_t. Returning
 * EOS_EResult here would truncate to 32 bits and desync the game's
 * stored handle. */
typedef uint64_t EOS_NotificationId;

__declspec(dllexport) EOS_NotificationId
EOS_AntiCheatClient_AddNotifyClientIntegrityViolated(
    EOS_HAntiCheatClient h,
    const void* options,
    const void* ctx,
    EOS_AntiCheatClient_OnClientIntegrityViolatedCallback cb)
{
    (void)h; (void)options;
    g.integrity_cb = cb;
    g.integrity_cb_ctx = ctx;
    /* Return a notification id; game stores for later Remove. */
    return (EOS_NotificationId)0x1234ULL;
}

__declspec(dllexport) void
EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated(
    EOS_HAntiCheatClient h,
    EOS_NotificationId notification_id)
{
    (void)h; (void)notification_id;
    g.integrity_cb = NULL;
    g.integrity_cb_ctx = NULL;
}

/*
 * Classic EAC compatibility exports.
 *
 * Names and ordinals rotate per version. For a real drop-in against
 * a specific Fortnite build, replace the .def ordinals with ones
 * lifted from CFF Explorer against the real EasyAntiCheat_x64.dll
 * that ships with your target build.
 */

__declspec(dllexport) int32_t
EAC_Client_Init(void* ctx)
{
    (void)ctx;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_Shutdown(void* ctx)
{
    (void)ctx;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_PollStatus(void* ctx, void* out)
{
    (void)ctx; (void)out;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_RegisterPeer(void* ctx, uint64_t pid, void* opts)
{
    (void)ctx; (void)pid; (void)opts;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_UnregisterPeer(void* ctx, uint64_t pid)
{
    (void)ctx; (void)pid;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_ReceiveMessage(void* ctx, const void* data, uint32_t len)
{
    (void)ctx; (void)data; (void)len;
    return 0;
}

__declspec(dllexport) int32_t
EAC_Client_GetProtectedData(void* ctx, void* out, uint32_t* len)
{
    (void)ctx;
    if (len) *len = 0;
    (void)out;
    return 0;
}

/* DllMain */
BOOL WINAPI
DllMain(HINSTANCE h, DWORD why, LPVOID rsv)
{
    (void)rsv;
    if (why == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}

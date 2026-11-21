/*
 * b_dll_ordinals.c
 *
 * Minimal ordinal-only stub matching the byte-verified export table of
 * the Nov 20 2026 Fortnite EAC agent (`b.dll` — internal name on disk:
 * EasyAntiCheat_EOS.dll, random-renamed to system32 at install).
 *
 * The real b.dll has:
 *   - 5 unnamed exports (ordinals 1-5 only — classic manual-map tell)
 *   - 0 static imports in its PE import directory
 *   - Hash-dispatch runtime resolution via MurmurHash3 finalizer
 *     0xFF51AFD7ED558CCD
 *
 * Export RVA map (byte-verified):
 *   ord 1  RVA 0x4FEA3    — suspected: init / unpack trampoline
 *   ord 2  RVA 0x22DE30   — suspected: begin_session
 *   ord 3  RVA 0x30A0E0   — suspected: poll
 *   ord 4  RVA 0x4FCE2    — suspected: end_session
 *   ord 5  RVA 0x2F2760   — suspected: register_callback
 *
 * This stub exposes 5 ordinals with the same roles. If the real loader
 * invokes a specific ordinal first (currently believed to be ord 1 for
 * init), this layout keeps it callable.
 *
 * Build alongside eac_emu_stub.c as part of the main stub DLL — see
 * b_dll_ordinals.def for the ordinal mappings merged into the main
 * EasyAntiCheat_x64.dll export table.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#ifdef _WIN64
    #define BCALL
#else
    #define BCALL __stdcall
#endif

static struct {
    int    initialized;
    int    session_active;
    void*  cb;
    void*  cb_user;
} s = { 0 };

/* ord 1: init / unpack trampoline
 * Real impl: unpack VMProtect, resolve imports via hash-dispatch.
 * Stub: mark initialized. */
__declspec(dllexport) int32_t BCALL b_dll_ord1_init(void* ctx, void* platform)
{
    (void)ctx; (void)platform;
    s.initialized = 1;
    return 0;
}

/* ord 2: begin_session (large RVA in real binary, heavy code)
 * Real impl: configure scan dispatch, start threads, open pipe to service.
 * Stub: mark session active. */
__declspec(dllexport) int32_t BCALL b_dll_ord2_begin(void* ctx, uint32_t mode, void* opts)
{
    (void)ctx; (void)mode; (void)opts;
    s.session_active = 1;
    return 0;
}

/* ord 3: poll (message pump)
 * Real impl: drain outgoing queue into out_msg buffer.
 * Stub: always returns "no messages". */
__declspec(dllexport) int32_t BCALL b_dll_ord3_poll(void* ctx, void* out_msg, uint32_t* out_sz)
{
    (void)ctx; (void)out_msg;
    if (out_sz) *out_sz = 0;
    return 2;  /* EOS_NOT_FOUND */
}

/* ord 4: end_session (paired with ord 2)
 * Real impl: shutdown scan threads, close pipe.
 * Stub: clear flag. */
__declspec(dllexport) int32_t BCALL b_dll_ord4_end(void* ctx)
{
    (void)ctx;
    s.session_active = 0;
    return 0;
}

/* ord 5: register_callback
 * Real impl: store callback for integrity-violation notifications.
 * Stub: remember + ignore. */
__declspec(dllexport) int32_t BCALL b_dll_ord5_regcb(void* ctx, void* cb, void* user)
{
    (void)ctx;
    s.cb = cb;
    s.cb_user = user;
    return 0x1234;
}

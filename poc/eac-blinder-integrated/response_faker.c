/*
 * response_faker.c -- v0.3 ban/flag response suppressor
 *
 * When EAC decides the current session is dirty, five side-effects
 * normally happen locally before (or instead of) a server-side ban:
 *   1. The user-mode service (EasyAntiCheat_EOS.exe) batches a
 *      telemetry record and POSTs it over HTTPS to api.epicgames.dev
 *      at /sdkevents and /eteventstream.
 *   2. EAC's agent raises the OnClientIntegrityViolated callback that
 *      the game registered through AddNotifyClientIntegrityViolated;
 *      Fortnite then disconnects with a "kicked" dialog.
 *   3. EOS_AntiCheatClient_PollStatus starts returning a non-empty
 *      message (violation / warning / protection event) so the game
 *      acts on it the very next frame.
 *   4. The service flips HKLM\Software\EasyAntiCheat_EOS\ErrRpt_*
 *      registry values to record "this box saw a violation at T".
 *   5. On some BK / AttestationLevel paths the service requests a
 *      fresh TPM quote so the Theia backend can correlate boxes.
 *
 * This file is the "quiet failure" subsystem: four independent hook
 * paths that make each of those effects silently no-op from the
 * kernel side. Any one of them succeeding is still a partial win --
 * every hook is installed and torn down independently and reports
 * its own status.
 *
 *   PATH 1 : NtDeviceIoControlFile hook on AFD -- drops send() to
 *            api.epicgames.dev containing the telemetry URL needles.
 *   PATH 2 : Inline hook of EAC agent's integrity-violation dispatcher
 *            -- short-circuits before the game callback fires.
 *   PATH 3 : User-mode patch of EOS_AntiCheatClient_PollStatus inside
 *            Fortnite (via kernel-queued APC) -- forces EOS_NOT_FOUND.
 *   PATH 4 : NtSetValueKey filter on EAC's ErrRpt_* / QuoteKeyStatus.
 *
 * Idempotent; LIFO uninstall; owns ctx->active bit 6 (0x40).
 */

#include "blinder.h"
#include <intrin.h>

/* NTSTATUS values not always in <ntifs.h> depending on WDK config */
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY  ((NTSTATUS)0xC00000AFL)
#endif

/* -------------------------- layout constants ---------------------------- */

#define HOOK_LEN           14          /* movabs rax,imm64 + jmp rax + 2 nop */
#define TRAMP_TAIL_LEN     12
#define TRAMP_TOTAL_LEN    (HOOK_LEN + TRAMP_TAIL_LEN)

#define FAKER_ACTIVE_BIT   0x40        /* bit 6 in ctx->active */

/* EOS SDK status enum (subset). From eos_common.h shipped with the SDK. */
#define EOS_SUCCESS        0
#define EOS_NOT_FOUND      2

/* AFD IOCTL codes we care about -- send-side only. Enough to catch
 * WinHTTP / WinINet / schannel's final kernel transition. */
#define IOCTL_AFD_SEND             0x0001201F
#define IOCTL_AFD_SEND_DATAGRAM    0x00012023
#define IOCTL_AFD_TRANSMIT_FILE    0x0001203F

/* Max per-send bytes we will look at for the URL needle; anything
 * beyond this is almost certainly a bulk body, and if the GET/POST
 * line is further in than 8 KiB something's wrong with WinHTTP. */
#define FAKER_SEND_SCAN_CAP        (SIZE_T)(8 * 1024)

/* -------------------------- telemetry needles --------------------------- */

/* ASCII needles that reliably appear in the plaintext HTTP line even
 * before TLS encrypts it: WinHTTP does the full request assembly
 * in-process before handing bytes to schannel, and when we hook
 * AFD we see plaintext when schannel is NOT in the way (fallback
 * path, retries, local dev). Primary mute is the URL match; we
 * keep it narrow to avoid dropping Epic's non-EAC traffic. */
static const CHAR* const k_telemetry_needles_a[] = {
    "api.epicgames.dev",
    "/sdkevents",
    "/eteventstream",
    "UploadType=sdkevents",
    "UploadType=eteventstream",
    "AppID=EOSSDK.AntiCheatExt.Service",
    "AppID=easyanticheat",
    NULL
};

/* UTF-16LE needles for the rare caller that routes through a wchar
 * path. These are the same strings as the ASCII list minus the
 * query-string entries; keeping the list short keeps the hot path
 * cheap. */
static const WCHAR* const k_telemetry_needles_w[] = {
    L"api.epicgames.dev",
    L"/sdkevents",
    L"/eteventstream",
    NULL
};

/* -------------------------- registry policy ----------------------------- */

/* Value names under HKLM\Software\EasyAntiCheat_EOS that the service
 * writes when recording violation / crash state. Any NtSetValueKey
 * touching one of these is rewritten in-place to a known-clean form. */
static const WCHAR* const k_reg_clean_names[] = {
    L"QuoteKeyStatus",      /* non-1 => failure; force to 1 */
    L"ErrRpt_GameState",    /* non-0 => session dirty; force 0 */
    L"ErrRpt_GameCrash",    /* zero out */
    L"ErrRpt_GameCrashReason",
    L"ErrRpt_GameCrashCode",
    L"ErrRpt_TheiaEnum",    /* server-side correlation enum */
    NULL
};

/* -------------------------- faker state --------------------------------- */

/*
 * NOTE for main.c: fields below should migrate into BLINDER_CTX::faker
 * so that teardown from the global unload path has access. For now
 * we keep them static-local so this file compiles standalone; the
 * struct layout is already the one documented in the v0.3 brief:
 *
 *   struct FAKER_STATE {
 *       PVOID saved_nt_dioc_bytes[14];
 *       PVOID trampoline_nt_dioc;
 *       PVOID saved_eac_dispatch_bytes[14];
 *       PVOID trampoline_eac_dispatch;
 *       PVOID saved_nt_setvaluekey_bytes[14];
 *       PVOID trampoline_nt_setvaluekey;
 *       LIST_ENTRY pending_pollstatus_apcs;
 *   };
 */
typedef struct _FAKER_STATE {
    /* PATH 1 */
    PVOID  nt_dioc_target;
    PVOID  trampoline_nt_dioc;
    UCHAR  saved_nt_dioc_bytes[HOOK_LEN];
    BOOLEAN path1_installed;

    /* PATH 2 */
    PVOID  eac_dispatch_target;
    PVOID  trampoline_eac_dispatch;
    UCHAR  saved_eac_dispatch_bytes[HOOK_LEN];
    BOOLEAN path2_installed;

    /* PATH 3 (deferred until Fortnite shows up) */
    LIST_ENTRY pending_pollstatus_apcs;
    KSPIN_LOCK pending_lock;
    BOOLEAN path3_notify_registered;
    BOOLEAN path3_patch_applied;
    PVOID   um_shim_remote;              /* allocated inside Fortnite */
    SIZE_T  um_shim_remote_size;

    /* PATH 4 */
    PVOID  nt_setvaluekey_target;
    PVOID  trampoline_nt_setvaluekey;
    UCHAR  saved_nt_setvaluekey_bytes[HOOK_LEN];
    BOOLEAN path4_installed;
} FAKER_STATE, *PFAKER_STATE;

static FAKER_STATE g_faker;

/* Forward decls for detours. */
typedef NTSTATUS (NTAPI* PFN_NtDeviceIoControlFile)(
    _In_ HANDLE, _In_opt_ HANDLE, _In_opt_ PIO_APC_ROUTINE, _In_opt_ PVOID,
    _Out_ PIO_STATUS_BLOCK, _In_ ULONG, _In_opt_ PVOID, _In_ ULONG,
    _Out_opt_ PVOID, _In_ ULONG);

typedef NTSTATUS (NTAPI* PFN_NtSetValueKey)(
    _In_ HANDLE, _In_ PUNICODE_STRING, _In_opt_ ULONG, _In_ ULONG,
    _In_opt_ PVOID, _In_ ULONG);

typedef NTSTATUS (NTAPI* PFN_EacDispatchViolation)(PVOID ctx, PVOID evt);

static PFN_NtDeviceIoControlFile  g_OriginalNtDioc       = NULL;
static PFN_NtSetValueKey          g_OriginalNtSetValueKey = NULL;
static PFN_EacDispatchViolation   g_OriginalEacDispatch  = NULL;

/* ========================================================================
 * CR0 WP toggle
 * ====================================================================== */

static KIRQL faker_disable_wp(ULONG_PTR* saved_cr0)
{
    KIRQL old = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
    *saved_cr0 = cr0;
    _disable();
    __writecr0(cr0 & ~(ULONG_PTR)0x10000);
    return old;
}

static void faker_restore_wp(ULONG_PTR saved_cr0, KIRQL old)
{
    __writecr0(saved_cr0);
    _enable();
    KeLowerIrql(old);
}

/* ========================================================================
 * Trampoline / hook plumbing (local copy; nt_hooks.c keeps its own
 * so we don't share module-local symbols).
 * ====================================================================== */

static PVOID faker_build_trampoline(PVOID target, UCHAR saved_out[HOOK_LEN])
{
    UCHAR* tramp;
    ULONG_PTR cont;

    tramp = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                    TRAMP_TOTAL_LEN, BLINDER_POOL_TAG);
    if (!tramp) return NULL;

    RtlCopyMemory(saved_out, target, HOOK_LEN);
    RtlCopyMemory(tramp, target, HOOK_LEN);

    cont = (ULONG_PTR)target + HOOK_LEN;
    tramp[HOOK_LEN + 0]  = 0x48;
    tramp[HOOK_LEN + 1]  = 0xB8;
    RtlCopyMemory(&tramp[HOOK_LEN + 2], &cont, sizeof(cont));
    tramp[HOOK_LEN + 10] = 0xFF;
    tramp[HOOK_LEN + 11] = 0xE0;
    return tramp;
}

static void faker_write_hook(PVOID target, PVOID detour)
{
    UCHAR stub[HOOK_LEN];
    ULONG_PTR cr0 = 0;
    KIRQL irql;
    ULONG_PTR det = (ULONG_PTR)detour;

    stub[0]  = 0x48;
    stub[1]  = 0xB8;
    RtlCopyMemory(&stub[2], &det, sizeof(det));
    stub[10] = 0xFF;
    stub[11] = 0xE0;
    stub[12] = 0x90;
    stub[13] = 0x90;

    irql = faker_disable_wp(&cr0);
    RtlCopyMemory(target, stub, HOOK_LEN);
    faker_restore_wp(cr0, irql);
}

static void faker_restore_hook(PVOID target, const UCHAR saved[HOOK_LEN])
{
    ULONG_PTR cr0 = 0;
    KIRQL irql = faker_disable_wp(&cr0);
    RtlCopyMemory(target, saved, HOOK_LEN);
    faker_restore_wp(cr0, irql);
}

/* ========================================================================
 * Needle search helpers
 * ====================================================================== */

/* Case-sensitive ASCII substring; good enough for URL path matches,
 * host headers are always lower-case out of WinHTTP by convention. */
static BOOLEAN buffer_contains_a(const UCHAR* hay, SIZE_T hay_len, const CHAR* needle)
{
    SIZE_T n_len = 0;
    SIZE_T i, j;

    if (!hay || !needle || hay_len == 0) return FALSE;
    while (needle[n_len]) n_len++;
    if (n_len == 0 || n_len > hay_len) return FALSE;

    for (i = 0; i <= hay_len - n_len; i++) {
        for (j = 0; j < n_len; j++) {
            if (hay[i + j] != (UCHAR)needle[j]) break;
        }
        if (j == n_len) return TRUE;
    }
    return FALSE;
}

/* UTF-16LE substring match. Byte-oriented so we don't blow up on
 * odd alignments inside an arbitrary send buffer. */
static BOOLEAN buffer_contains_w(const UCHAR* hay, SIZE_T hay_len, const WCHAR* needle)
{
    SIZE_T n_bytes = 0;
    SIZE_T i, j;

    if (!hay || !needle || hay_len < 2) return FALSE;
    while (needle[n_bytes / sizeof(WCHAR)]) n_bytes += sizeof(WCHAR);
    if (n_bytes == 0 || n_bytes > hay_len) return FALSE;

    for (i = 0; i + n_bytes <= hay_len; i++) {
        for (j = 0; j < n_bytes; j++) {
            if (hay[i + j] != ((const UCHAR*)needle)[j]) break;
        }
        if (j == n_bytes) return TRUE;
    }
    return FALSE;
}

/* Return TRUE iff the send buffer contains any of our telemetry URL
 * needles. Safe to call from DISPATCH_LEVEL -- no page touches
 * beyond the caller-supplied buffer, which is a locked AFD send IRP
 * buffer when we reach it. */
static BOOLEAN send_buffer_is_telemetry(const UCHAR* buf, SIZE_T len)
{
    SIZE_T scan = (len > FAKER_SEND_SCAN_CAP) ? FAKER_SEND_SCAN_CAP : len;
    ULONG i;

    if (!buf || scan == 0) return FALSE;

    __try {
        for (i = 0; k_telemetry_needles_a[i]; i++) {
            if (buffer_contains_a(buf, scan, k_telemetry_needles_a[i])) return TRUE;
        }
        for (i = 0; k_telemetry_needles_w[i]; i++) {
            if (buffer_contains_w(buf, scan, k_telemetry_needles_w[i])) return TRUE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return FALSE;
}

/* ========================================================================
 * PATH 1 -- NtDeviceIoControlFile telemetry drop
 * ====================================================================== */

/*
 * Peel the single SEND buffer out of the AFD IOCTL argument block.
 * AFD_SEND_INFO is a documented layout -- the first field is a
 * pointer-to-WSABUF array followed by an WSABUF count, followed by
 * flags. We only inspect the first WSABUF since WinHTTP POST bodies
 * fit in one allocation for every realistic telemetry payload.
 */
typedef struct _FAKER_WSABUF {
    ULONG   Length;
    PVOID   Buffer;
} FAKER_WSABUF;

typedef struct _FAKER_AFD_SEND_INFO {
    FAKER_WSABUF* Bufs;
    ULONG         BufCount;
    ULONG         Flags;
    ULONG         Reserved;
} FAKER_AFD_SEND_INFO;

static BOOLEAN afd_send_is_telemetry(PVOID input, ULONG input_len)
{
    FAKER_AFD_SEND_INFO si;
    FAKER_WSABUF        wb;
    ULONG               i, cap;

    if (!input || input_len < sizeof(si)) return FALSE;

    __try {
        RtlCopyMemory(&si, input, sizeof(si));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    if (!si.Bufs || si.BufCount == 0 || si.BufCount > 64) return FALSE;

    cap = si.BufCount > 4 ? 4 : si.BufCount;
    for (i = 0; i < cap; i++) {
        __try {
            RtlCopyMemory(&wb, &si.Bufs[i], sizeof(wb));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (!wb.Buffer || wb.Length == 0) continue;
        if (send_buffer_is_telemetry((const UCHAR*)wb.Buffer, wb.Length)) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS NTAPI HookedNtDeviceIoControlFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength)
{
    PBLINDER_CTX ctx = &g_blinder;

    /* Only look at outbound socket operations issued by the EAC
     * service. Everything else -- disk IOCTLs, GPU IOCTLs, other
     * processes -- falls through unchanged. */
    if (ctx->active &&
        (IoControlCode == IOCTL_AFD_SEND ||
         IoControlCode == IOCTL_AFD_SEND_DATAGRAM ||
         IoControlCode == IOCTL_AFD_TRANSMIT_FILE) &&
        IsCallerEac(ctx) &&
        afd_send_is_telemetry(InputBuffer, InputBufferLength))
    {
        /* Lie about success: tell the caller every byte was sent.
         * WinHTTP's send wrapper will happily move on to the next
         * chunk; schannel never sees a request to encrypt the EAC
         * payload. */
        __try {
            if (IoStatusBlock) {
                IoStatusBlock->Status      = STATUS_SUCCESS;
                IoStatusBlock->Information = InputBufferLength;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            NOTHING;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[blinder:faker] dropped EAC telemetry send (%lu bytes)\n",
                   InputBufferLength);
        return STATUS_SUCCESS;
    }

    return g_OriginalNtDioc(FileHandle, Event, ApcRoutine, ApcContext,
                            IoStatusBlock, IoControlCode,
                            InputBuffer, InputBufferLength,
                            OutputBuffer, OutputBufferLength);
}

static NTSTATUS path1_install(PBLINDER_CTX ctx)
{
    UNICODE_STRING name;
    PVOID tramp;

    UNREFERENCED_PARAMETER(ctx);
    if (g_faker.path1_installed) return STATUS_SUCCESS;

    RtlInitUnicodeString(&name, L"NtDeviceIoControlFile");
    g_faker.nt_dioc_target = MmGetSystemRoutineAddress(&name);
    if (!g_faker.nt_dioc_target) {
        /* Not every build exports NtDeviceIoControlFile by name; try
         * ZwDeviceIoControlFile and resolve past the SSDT stub. */
        RtlInitUnicodeString(&name, L"ZwDeviceIoControlFile");
        g_faker.nt_dioc_target = MmGetSystemRoutineAddress(&name);
    }
    if (!g_faker.nt_dioc_target) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:faker] P1: NtDeviceIoControlFile not found\n");
        return STATUS_NOT_FOUND;
    }

    tramp = faker_build_trampoline(g_faker.nt_dioc_target,
                                   g_faker.saved_nt_dioc_bytes);
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;

    g_OriginalNtDioc         = (PFN_NtDeviceIoControlFile)tramp;
    g_faker.trampoline_nt_dioc = tramp;

    KeMemoryBarrier();
    faker_write_hook(g_faker.nt_dioc_target,
                     (PVOID)&HookedNtDeviceIoControlFile);
    g_faker.path1_installed = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] P1: NtDeviceIoControlFile hooked at %p\n",
               g_faker.nt_dioc_target);
    return STATUS_SUCCESS;
}

static void path1_uninstall(void)
{
    if (!g_faker.path1_installed) return;

    if (g_faker.nt_dioc_target) {
        faker_restore_hook(g_faker.nt_dioc_target,
                           g_faker.saved_nt_dioc_bytes);
    }
    KeMemoryBarrier();
    if (g_faker.trampoline_nt_dioc) {
        ExFreePoolWithTag(g_faker.trampoline_nt_dioc, BLINDER_POOL_TAG);
        g_faker.trampoline_nt_dioc = NULL;
    }
    g_OriginalNtDioc       = NULL;
    g_faker.nt_dioc_target = NULL;
    g_faker.path1_installed = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] P1: uninstalled\n");
}

/* ========================================================================
 * PATH 2 -- EAC integrity-violation dispatcher hook
 * ====================================================================== */

/*
 * EAC's agent (EasyAntiCheat_EOS.dll, mapped into both the service
 * and Fortnite) calls a single internal dispatcher whenever a
 * violation is fired into the registered client callback. The
 * dispatcher reads a struct that begins with { ULONG kind;
 * ULONG flags; ULONG violation_type; ULONG reserved; ... }.
 * Kind == 3 and flags & 1 means "dispatch to game callback".
 *
 * The function sits a few calls past the ASCII literal "integrity"
 * in the agent .rdata. We find the string, scan forward for the
 * function start that cross-references it, and patch there.
 *
 * Two realities make this fragile and we treat it as best-effort:
 *   (a) the agent lives in user-mode; from kernel we see it only
 *       via EAC's own .sys image or via the mapped section inside
 *       ctx->target.eac_service_eproc.
 *   (b) each EAC build shifts the prologue by a handful of bytes.
 *
 * For PoC we start the pattern scan at ctx->target.eac_driver_base
 * (the kernel-side driver loaded earlier); production builds are
 * expected to also dig into the user-mode agent via a secondary
 * injection path.
 */

/* IDA pattern taken from the Oct-2026 agent build:
 *   48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B DA 48 8B F1
 * Prologue of the dispatcher. If the pattern misses we fall back
 * to the "find 'integrity' then walk back to the containing
 * function" heuristic. */
static const UCHAR k_eac_dispatch_pattern[] = {
    0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x74, 0x24, 0x00,
    0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF1
};
static const CHAR k_eac_dispatch_mask[] =
    "xxxx?xxxx?xxxxxxxxxxx";

/* Heuristic -- walk backwards from a .rdata string ref to find the
 * most plausible 16-byte-aligned function start. The alignment plus
 * the "push rbp / sub rsp, imm8" signature keeps false positives low. */
static PVOID scan_for_eac_dispatch(PVOID base, SIZE_T size)
{
    PVOID hit;
    const UCHAR* p;
    const UCHAR* limit;

    if (!base || size == 0) return NULL;

    hit = PatternScan(base, size,
                      k_eac_dispatch_pattern,
                      k_eac_dispatch_mask);
    if (hit) return hit;

    /* Fallback: find ASCII "integrity" inside the region, then rewind
     * to the nearest 16-byte-aligned "48 89 5C 24" (standard x64 MSVC
     * nonvolatile spill prologue). */
    p     = (const UCHAR*)base;
    limit = p + size - 9;
    while (p < limit) {
        if (p[0] == 'i' && p[1] == 'n' && p[2] == 't' && p[3] == 'e' &&
            p[4] == 'g' && p[5] == 'r' && p[6] == 'i' && p[7] == 't' &&
            p[8] == 'y')
        {
            const UCHAR* q = p;
            SIZE_T back = 0;
            while (q > (const UCHAR*)base && back < 0x4000) {
                q--; back++;
                if (((ULONG_PTR)q & 0xF) == 0 &&
                    q[0] == 0x48 && q[1] == 0x89 && q[2] == 0x5C && q[3] == 0x24) {
                    return (PVOID)q;
                }
            }
            return NULL;
        }
        p++;
    }
    return NULL;
}

/* First four ULONGs of the event struct passed to the dispatcher.
 * This matches what's documented in reverse notes under docs/05;
 * we only care about kind + flags here. */
typedef struct _FAKER_EAC_EVT {
    ULONG kind;
    ULONG flags;
    ULONG violation_type;
    ULONG reserved;
} FAKER_EAC_EVT;

static NTSTATUS NTAPI HookedEacDispatchViolation(PVOID callee_ctx, PVOID evt)
{
    FAKER_EAC_EVT snap = {0};

    if (!evt) {
        return g_OriginalEacDispatch(callee_ctx, evt);
    }

    __try {
        RtlCopyMemory(&snap, evt, sizeof(snap));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return g_OriginalEacDispatch(callee_ctx, evt);
    }

    /* kind == 3 and flags & 1 means "dispatch violation to game".
     * Swallow and return success so EAC's bookkeeping believes the
     * callback fired; the game-registered callback never runs. */
    if (snap.kind == 3 && (snap.flags & 1)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder:faker] P2: suppressed integrity violation "
                   "(vtype=%lu)\n", snap.violation_type);
        return STATUS_SUCCESS;
    }
    return g_OriginalEacDispatch(callee_ctx, evt);
}

static NTSTATUS path2_install(PBLINDER_CTX ctx)
{
    PVOID tramp;
    PVOID target = NULL;

    if (g_faker.path2_installed) return STATUS_SUCCESS;

    if (!ctx->target.eac_driver_base || ctx->target.eac_driver_size == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder:faker] P2: no EAC driver base, deferring\n");
        return STATUS_NOT_READY;
    }

    target = scan_for_eac_dispatch(ctx->target.eac_driver_base,
                                   ctx->target.eac_driver_size);
    if (!target) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder:faker] P2: dispatcher not found (agent "
                   "not mapped into kernel?)\n");
        return STATUS_NOT_FOUND;
    }

    tramp = faker_build_trampoline(target, g_faker.saved_eac_dispatch_bytes);
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;

    g_faker.eac_dispatch_target     = target;
    g_faker.trampoline_eac_dispatch = tramp;
    g_OriginalEacDispatch           = (PFN_EacDispatchViolation)tramp;

    KeMemoryBarrier();
    faker_write_hook(target, (PVOID)&HookedEacDispatchViolation);
    g_faker.path2_installed = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] P2: EAC dispatcher hooked at %p\n", target);
    return STATUS_SUCCESS;
}

static void path2_uninstall(void)
{
    if (!g_faker.path2_installed) return;

    if (g_faker.eac_dispatch_target) {
        faker_restore_hook(g_faker.eac_dispatch_target,
                           g_faker.saved_eac_dispatch_bytes);
    }
    KeMemoryBarrier();
    if (g_faker.trampoline_eac_dispatch) {
        ExFreePoolWithTag(g_faker.trampoline_eac_dispatch, BLINDER_POOL_TAG);
        g_faker.trampoline_eac_dispatch = NULL;
    }
    g_OriginalEacDispatch        = NULL;
    g_faker.eac_dispatch_target  = NULL;
    g_faker.path2_installed      = FALSE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] P2: uninstalled\n");
}

/* ========================================================================
 * PATH 3 -- EOS_AntiCheatClient_PollStatus user-mode patch (deferred)
 * ====================================================================== */

/*
 * The EOS SDK is a user-mode DLL loaded into Fortnite. We need to
 * patch EOSSDK-Win64-Shipping!EOS_AntiCheatClient_PollStatus so it
 * always returns EOS_NOT_FOUND with *out_sz = 0. The patch body is
 * a tiny x64 shim that writes out_sz, sets rax, and returns:
 *
 *   48 85 D2         test rdx, rdx           ; out_sz ptr
 *   74 06            jz   skip
 *   48 C7 02 00 00 00 00    mov qword ptr [rdx], 0
 *                                           ; (encoded below as 7 bytes)
 *   B8 02 00 00 00   mov eax, 2              ; EOS_NOT_FOUND
 *   C3               ret
 *
 * We allocate that shim inside Fortnite's address space with
 * ZwAllocateVirtualMemory, copy it over, flip the PollStatus export
 * prologue to "mov rax, shim; jmp rax", and we're done. No hotpatch
 * trampoline is needed because we never need to call the original
 * PollStatus -- the patched function is complete.
 *
 * All of this must run in Fortnite's context, so we queue a
 * normal-kernel APC to the first Fortnite thread we find. If
 * Fortnite isn't up yet when Install is called, we register a
 * process-create notify and arm the APC when FortniteClient
 * appears.
 */

static const UCHAR k_poll_shim[] = {
    0x48, 0x85, 0xD2,                               /* test rdx, rdx    */
    0x74, 0x07,                                     /* jz skip          */
    0x48, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00,       /* mov [rdx], 0     */
    0xB8, 0x02, 0x00, 0x00, 0x00,                   /* mov eax, 2       */
    0xC3                                            /* ret              */
};
#define POLL_SHIM_SIZE (sizeof(k_poll_shim))

/*
 * This file deliberately doesn't try to re-derive IMAGE_NT_HEADERS
 * from scratch -- the production branch pulls in ntimage.h. For the
 * PoC we walk headers by hand using documented offsets: e_lfanew at
 * +0x3C in the DOS header, DataDirectory[0] (Export) at NT+0x88 on
 * PE32+. The export directory itself is small enough to type by
 * hand; see FAKER_EXPORT_DIR below.
 */
typedef struct _FAKER_EXPORT_DIR {
    ULONG Chars, Timestamp, VerAndName[2];
    ULONG Base, NumFns, NumNames;
    ULONG FnsRva, NamesRva, OrdsRva;
} FAKER_EXPORT_DIR;

static PVOID find_export_in_remote(PEPROCESS target, PVOID mod_base,
                                   const CHAR* export_name)
{
    /* Walk PE headers out of the remote process by copying piecewise
     * into a kernel stack buffer. Everything is kernel-mode safe
     * even if target is in a weird state. */
    UCHAR   hdr[0x400];
    SIZE_T  got = 0;
    NTSTATUS st;
    ULONG   nt_off;
    ULONG   exp_rva, exp_size;
    FAKER_EXPORT_DIR ed = {0};
    ULONG i;
    PBLINDER_CTX ctx = &g_blinder;

    if (!ctx->apis.MmCopyVirtualMemory || !target || !mod_base) return NULL;

    st = ctx->apis.MmCopyVirtualMemory(target, mod_base,
                                       PsGetCurrentProcess(), hdr,
                                       sizeof(hdr), KernelMode, &got);
    if (!NT_SUCCESS(st) || got < 0x200) return NULL;

    /* e_lfanew lives at offset 0x3C. */
    nt_off = *(ULONG*)&hdr[0x3C];
    if (nt_off == 0 || nt_off > sizeof(hdr) - 0x200) return NULL;

    /* On PE32+, DataDirectory[0].VirtualAddress is at NT + 0x88. */
    exp_rva  = *(ULONG*)&hdr[nt_off + 0x88];
    exp_size = *(ULONG*)&hdr[nt_off + 0x8C];
    if (exp_rva == 0 || exp_size == 0) return NULL;

    st = ctx->apis.MmCopyVirtualMemory(target, (UCHAR*)mod_base + exp_rva,
                                       PsGetCurrentProcess(), &ed,
                                       sizeof(ed), KernelMode, &got);
    if (!NT_SUCCESS(st) || got < sizeof(ed)) return NULL;

    /* Pull the three parallel arrays (names RVAs, fn RVAs, ord RVAs)
     * one slot at a time. Names RVAs point at NUL-terminated ASCII. */
    for (i = 0; i < ed.NumNames; i++) {
        ULONG name_rva = 0;
        CHAR  name[96] = {0};
        USHORT ord = 0;
        ULONG  fn_rva = 0;

        if (!NT_SUCCESS(ctx->apis.MmCopyVirtualMemory(
                target, (UCHAR*)mod_base + ed.NamesRva + i * sizeof(ULONG),
                PsGetCurrentProcess(), &name_rva, sizeof(name_rva),
                KernelMode, &got))) continue;
        if (name_rva == 0) continue;
        if (!NT_SUCCESS(ctx->apis.MmCopyVirtualMemory(
                target, (UCHAR*)mod_base + name_rva,
                PsGetCurrentProcess(), name, sizeof(name) - 1,
                KernelMode, &got))) continue;

        /* strcmp */
        {
            SIZE_T k = 0;
            while (k < sizeof(name) - 1 && name[k] && export_name[k] &&
                   name[k] == export_name[k]) k++;
            if (!(name[k] == '\0' && export_name[k] == '\0')) continue;
        }

        if (!NT_SUCCESS(ctx->apis.MmCopyVirtualMemory(
                target, (UCHAR*)mod_base + ed.OrdsRva + i * sizeof(USHORT),
                PsGetCurrentProcess(), &ord, sizeof(ord),
                KernelMode, &got))) continue;
        if (!NT_SUCCESS(ctx->apis.MmCopyVirtualMemory(
                target, (UCHAR*)mod_base + ed.FnsRva + ord * sizeof(ULONG),
                PsGetCurrentProcess(), &fn_rva, sizeof(fn_rva),
                KernelMode, &got))) continue;
        if (fn_rva == 0) return NULL;

        return (PVOID)((UCHAR*)mod_base + fn_rva);
    }
    return NULL;
}

/*
 * The actual user-mode patch happens inside a kernel-queued APC. We
 * KeStackAttachProcess into Fortnite, ProbeAndWrite the export's
 * prologue, and detach. Doing it from a Fortnite thread's APC (vs.
 * from an arbitrary thread with KeStackAttachProcess) avoids all
 * the TEB/GS-base corner cases that bite attempts to attach to
 * image-loader threads.
 *
 * For PoC simplicity we skip the full KAPC plumbing and just do
 * KeStackAttachProcess directly -- EOS SDK exports live in a mapped
 * image section and are safe to patch from a non-Fortnite thread as
 * long as we're attached to Fortnite's VA space. A production build
 * would use PsCreateSystemThread + KeStackAttachProcess for less
 * fragile semantics.
 */
static NTSTATUS apply_pollstatus_patch(PBLINDER_CTX ctx)
{
    KAPC_STATE apc;
    PVOID      eos_base = NULL;
    SIZE_T     eos_size = 0;
    PVOID      poll_export = NULL;
    ULONG_PTR  cr0 = 0;
    KIRQL      irql;
    NTSTATUS   st = STATUS_UNSUCCESSFUL;
    UCHAR      stub[HOOK_LEN];
    ULONG_PTR  shim_va;

    if (!ctx->target.fortnite_eproc) return STATUS_NOT_READY;
    if (g_faker.path3_patch_applied) return STATUS_SUCCESS;

    /*
     * A production build should iterate the PEB loader list; for the
     * PoC we assume the loader module cache has EOSSDK's base ready
     * via a helper (not shown). Treat this call as a placeholder
     * for the real DLL walker and continue once we have a base.
     */
    UNREFERENCED_PARAMETER(eos_size);
    eos_base = NULL;     /* FIXME: walk target PEB_LDR_DATA for name */

    if (!eos_base) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder:faker] P3: EOS SDK base not located yet\n");
        return STATUS_NOT_READY;
    }

    poll_export = find_export_in_remote(ctx->target.fortnite_eproc,
                                        eos_base,
                                        "EOS_AntiCheatClient_PollStatus");
    if (!poll_export) return STATUS_NOT_FOUND;

    KeStackAttachProcess((PRKPROCESS)ctx->target.fortnite_eproc, &apc);
    __try {
        /* Allocate a tiny RX page inside Fortnite. */
        PVOID  base = NULL;
        SIZE_T len  = PAGE_SIZE;
        OBJECT_ATTRIBUTES oa;
        HANDLE hproc = ZwCurrentProcess();

        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        st = ZwAllocateVirtualMemory(hproc, &base, 0, &len,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st)) __leave;

        ProbeForWrite(base, POLL_SHIM_SIZE, 1);
        RtlCopyMemory(base, k_poll_shim, POLL_SHIM_SIZE);
        g_faker.um_shim_remote      = base;
        g_faker.um_shim_remote_size = len;

        /* Build the 14-byte long-mode jump in a kernel buffer, then
         * stamp it into poll_export under WP=0. */
        shim_va = (ULONG_PTR)base;
        stub[0]  = 0x48; stub[1]  = 0xB8;
        RtlCopyMemory(&stub[2], &shim_va, sizeof(shim_va));
        stub[10] = 0xFF; stub[11] = 0xE0;
        stub[12] = 0x90; stub[13] = 0x90;

        irql = faker_disable_wp(&cr0);
        __try {
            ProbeForWrite(poll_export, HOOK_LEN, 1);
            RtlCopyMemory(poll_export, stub, HOOK_LEN);
            st = STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            st = GetExceptionCode();
        }
        faker_restore_wp(cr0, irql);
    } __finally {
        KeUnstackDetachProcess(&apc);
    }

    if (NT_SUCCESS(st)) {
        g_faker.path3_patch_applied = TRUE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:faker] P3: PollStatus patched @ %p "
                   "(shim @ %p)\n", poll_export, g_faker.um_shim_remote);
    }
    return st;
}

/* We need a case-insensitive ANSI equal; utils.c's version is static.
 * Keep a tiny local copy to avoid a header change. */
static BOOLEAN AnsiEqualCI_local(PCSTR a, PCSTR b)
{
    if (!a || !b) return FALSE;
    while (*a && *b) {
        CHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (CHAR)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (CHAR)(cb + ('a' - 'A'));
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

static VOID NTAPI faker_create_process_notify(
    HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PBLINDER_CTX ctx = &g_blinder;
    PEPROCESS    proc = NULL;
    PCHAR        img  = NULL;

    UNREFERENCED_PARAMETER(ParentId);
    if (!Create) return;
    if (!ctx->apis.PsLookupProcessByProcessId ||
        !ctx->apis.PsGetProcessImageFileName) return;

    if (!NT_SUCCESS(ctx->apis.PsLookupProcessByProcessId(ProcessId, &proc))
        || !proc) return;

    img = ctx->apis.PsGetProcessImageFileName(proc);
    if (IsTargetFortnite(ctx, proc) ||
        (img && AnsiEqualCI_local(img, FORTNITE_IMAGE_NAME_A)))
    {
        /* Cache + attempt patch. The DLL may not be loaded yet;
         * apply_pollstatus_patch handles STATUS_NOT_READY. */
        ctx->target.fortnite_eproc = proc;    /* note: no explicit ref */
        (void)apply_pollstatus_patch(ctx);
    }
    ObDereferenceObject(proc);
}

static NTSTATUS path3_install(PBLINDER_CTX ctx)
{
    NTSTATUS st;

    if (g_faker.path3_patch_applied) return STATUS_SUCCESS;

    /* Try immediate patch if Fortnite is already up. */
    if (ctx->target.fortnite_eproc) {
        st = apply_pollstatus_patch(ctx);
        if (NT_SUCCESS(st)) return st;
        /* STATUS_NOT_READY / STATUS_NOT_FOUND -> fall through to notify. */
    }

    if (!g_faker.path3_notify_registered) {
        st = PsSetCreateProcessNotifyRoutine(faker_create_process_notify, FALSE);
        if (NT_SUCCESS(st)) {
            g_faker.path3_notify_registered = TRUE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[blinder:faker] P3: deferred -- waiting for "
                       "FortniteClient launch\n");
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[blinder:faker] P3: notify register failed %08x\n",
                       st);
            return st;
        }
    }
    return STATUS_SUCCESS;
}

static void path3_uninstall(void)
{
    if (g_faker.path3_notify_registered) {
        (void)PsSetCreateProcessNotifyRoutine(faker_create_process_notify, TRUE);
        g_faker.path3_notify_registered = FALSE;
    }
    /* We intentionally leave the in-process shim in place -- undoing a
     * user-mode patch from kernel after Fortnite has already run and
     * potentially unloaded the module creates more risk than it buys.
     * Record that we did it and move on. */
    g_faker.path3_patch_applied = FALSE;
    g_faker.um_shim_remote      = NULL;
    g_faker.um_shim_remote_size = 0;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] P3: uninstalled (shim left live in-proc)\n");
}

/* ========================================================================
 * PATH 4 -- NtSetValueKey registry filter
 * ====================================================================== */

/* Resolve the full path of a HKEY handle. We use the undocumented
 * KeyNameInformation class via ZwQueryKey; the buffer we hand in
 * holds a KEY_NAME_INFORMATION trailing a WCHAR[] of the full path. */
typedef struct _FAKER_KEY_NAME {
    ULONG NameLength;
    WCHAR Name[1];
} FAKER_KEY_NAME;

#define KeyNameInformationClass ((ULONG)3)

typedef NTSTATUS (NTAPI* PFN_ZwQueryKey)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static BOOLEAN handle_is_eac_registry(HANDLE key)
{
    UNICODE_STRING    rn;
    PFN_ZwQueryKey    QueryKey;
    UCHAR             buf[512];
    FAKER_KEY_NAME*   kni;
    ULONG             got = 0;
    NTSTATUS          st;
    ULONG             i;
    static const WCHAR k_eac_tag[] = L"EasyAntiCheat_EOS";
    const SIZE_T      tag_bytes = sizeof(k_eac_tag) - sizeof(WCHAR);

    if (!key) return FALSE;

    RtlInitUnicodeString(&rn, L"ZwQueryKey");
    QueryKey = (PFN_ZwQueryKey)MmGetSystemRoutineAddress(&rn);
    if (!QueryKey) return FALSE;

    st = QueryKey(key, KeyNameInformationClass, buf, sizeof(buf), &got);
    if (!NT_SUCCESS(st) || got < sizeof(*kni)) return FALSE;

    kni = (FAKER_KEY_NAME*)buf;
    if (kni->NameLength == 0 || kni->NameLength > sizeof(buf) - sizeof(*kni)) {
        return FALSE;
    }

    for (i = 0; i + tag_bytes <= kni->NameLength; i += sizeof(WCHAR)) {
        if (RtlCompareMemory(((UCHAR*)kni->Name) + i,
                             (UCHAR*)k_eac_tag, tag_bytes) == tag_bytes) {
            return TRUE;
        }
    }
    return FALSE;
}

/* Unicode equals-any over our cleanlist. */
static BOOLEAN value_name_in_cleanlist(PUNICODE_STRING name)
{
    ULONG i;
    if (!name || !name->Buffer) return FALSE;
    for (i = 0; k_reg_clean_names[i]; i++) {
        UNICODE_STRING cand;
        RtlInitUnicodeString(&cand, k_reg_clean_names[i]);
        if (RtlEqualUnicodeString(name, &cand, TRUE)) return TRUE;
    }
    return FALSE;
}

/* Apply "clean" value policy in-place on the caller's Data buffer.
 * We only touch registered names; everything else passes through. */
static void sanitize_reg_write(PUNICODE_STRING name, ULONG type,
                               PVOID data, ULONG size)
{
    ULONG zero = 0;
    ULONG one  = 1;

    UNREFERENCED_PARAMETER(type);
    if (!name || !data || size == 0) return;

    __try {
        if (name->Length == sizeof(L"QuoteKeyStatus") - sizeof(WCHAR) &&
            _wcsicmp(name->Buffer, L"QuoteKeyStatus") == 0 &&
            size >= sizeof(ULONG))
        {
            RtlCopyMemory(data, &one, sizeof(one));
        } else {
            /* Everything else in the cleanlist resolves to "zero it". */
            RtlZeroMemory(data, size);
            UNREFERENCED_PARAMETER(zero);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NOTHING;
    }
}

static NTSTATUS NTAPI HookedNtSetValueKey(
    HANDLE           KeyHandle,
    PUNICODE_STRING  ValueName,
    ULONG            TitleIndex,
    ULONG            Type,
    PVOID            Data,
    ULONG            DataSize)
{
    PBLINDER_CTX ctx = &g_blinder;

    if (ctx->active && IsCallerEac(ctx) &&
        value_name_in_cleanlist(ValueName) &&
        handle_is_eac_registry(KeyHandle))
    {
        sanitize_reg_write(ValueName, Type, Data, DataSize);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[blinder:faker] P4: sanitized EAC reg write '%wZ'\n",
                   ValueName);
        /* Fall through: the write itself is allowed but with cleaned
         * data. EAC still gets a successful registry round-trip, so
         * it won't retry or escalate. */
    }

    return g_OriginalNtSetValueKey(KeyHandle, ValueName, TitleIndex,
                                   Type, Data, DataSize);
}

static NTSTATUS path4_install(PBLINDER_CTX ctx)
{
    UNICODE_STRING name;
    PVOID tramp;

    UNREFERENCED_PARAMETER(ctx);
    if (g_faker.path4_installed) return STATUS_SUCCESS;

    RtlInitUnicodeString(&name, L"NtSetValueKey");
    g_faker.nt_setvaluekey_target = MmGetSystemRoutineAddress(&name);
    if (!g_faker.nt_setvaluekey_target) {
        RtlInitUnicodeString(&name, L"ZwSetValueKey");
        g_faker.nt_setvaluekey_target = MmGetSystemRoutineAddress(&name);
    }
    if (!g_faker.nt_setvaluekey_target) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:faker] P4: NtSetValueKey not found\n");
        return STATUS_NOT_FOUND;
    }

    tramp = faker_build_trampoline(g_faker.nt_setvaluekey_target,
                                   g_faker.saved_nt_setvaluekey_bytes);
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;

    g_OriginalNtSetValueKey         = (PFN_NtSetValueKey)tramp;
    g_faker.trampoline_nt_setvaluekey = tramp;

    KeMemoryBarrier();
    faker_write_hook(g_faker.nt_setvaluekey_target,
                     (PVOID)&HookedNtSetValueKey);
    g_faker.path4_installed = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] P4: NtSetValueKey hooked at %p\n",
               g_faker.nt_setvaluekey_target);
    return STATUS_SUCCESS;
}

static void path4_uninstall(void)
{
    if (!g_faker.path4_installed) return;
    if (g_faker.nt_setvaluekey_target) {
        faker_restore_hook(g_faker.nt_setvaluekey_target,
                           g_faker.saved_nt_setvaluekey_bytes);
    }
    KeMemoryBarrier();
    if (g_faker.trampoline_nt_setvaluekey) {
        ExFreePoolWithTag(g_faker.trampoline_nt_setvaluekey, BLINDER_POOL_TAG);
        g_faker.trampoline_nt_setvaluekey = NULL;
    }
    g_OriginalNtSetValueKey          = NULL;
    g_faker.nt_setvaluekey_target    = NULL;
    g_faker.path4_installed          = FALSE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] P4: uninstalled\n");
}

/* ========================================================================
 * Public entry points
 * ====================================================================== */

NTSTATUS ResponseFaker_Install(PBLINDER_CTX ctx)
{
    NTSTATUS st;
    ULONG    installed_mask = 0;

    if (!ctx) return STATUS_INVALID_PARAMETER;

    /* Idempotent: if bit 6 is already set, just return. */
    if ((ULONG)ctx->active & FAKER_ACTIVE_BIT) {
        return STATUS_SUCCESS;
    }

    InitializeListHead(&g_faker.pending_pollstatus_apcs);
    KeInitializeSpinLock(&g_faker.pending_lock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] install starting\n");

    /* Each path is independent. We log misses but keep going; a
     * partial install still disrupts whichever ban-feedback channel
     * we did manage to hook. */
    st = path1_install(ctx);
    if (NT_SUCCESS(st)) installed_mask |= 0x1;
    else DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[blinder:faker] P1 install failed %08x\n", st);

    st = path2_install(ctx);
    if (NT_SUCCESS(st)) installed_mask |= 0x2;
    else DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[blinder:faker] P2 install failed %08x\n", st);

    st = path3_install(ctx);
    if (NT_SUCCESS(st)) installed_mask |= 0x4;
    else DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[blinder:faker] P3 install failed %08x\n", st);

    st = path4_install(ctx);
    if (NT_SUCCESS(st)) installed_mask |= 0x8;
    else DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[blinder:faker] P4 install failed %08x\n", st);

    if (installed_mask == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:faker] all paths failed; aborting install\n");
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedOr(&ctx->active, FAKER_ACTIVE_BIT);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] install complete (mask=0x%x)\n",
               installed_mask);
    return STATUS_SUCCESS;
}

NTSTATUS ResponseFaker_Uninstall(PBLINDER_CTX ctx)
{
    if (!ctx) return STATUS_INVALID_PARAMETER;

    /* LIFO: path4, path3, path2, path1. */
    path4_uninstall();
    path3_uninstall();
    path2_uninstall();
    path1_uninstall();

    /* Drain barrier -- see nt_hooks.c for the full rationale. In a
     * PoC the mapper tears us down synchronously; we assume no
     * detour frame is in flight. */
    KeMemoryBarrier();

    InterlockedAnd(&ctx->active, ~(LONG)FAKER_ACTIVE_BIT);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:faker] uninstall complete\n");
    return STATUS_SUCCESS;
}

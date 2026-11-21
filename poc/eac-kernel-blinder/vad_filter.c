/*
 * vad_filter.c — filter EAC's VAD walker against the Fortnite process
 *
 * EAC's kernel scanner walks the Fortnite process VAD tree to catalog
 * every image / mapped view and cross-references each one against its
 * on-disk image cache. Even if we unlink pages from the PTE layer,
 * EAC's AVL probe into MiLocateVad still turns them up — so we hook
 * MiLocateVad itself. When EAC queries for a Vpn inside one of our
 * hidden ranges on the Fortnite process, we fail the lookup by
 * returning NULL ("no VAD here, nothing to see"). Every other caller,
 * every other process, and every other address pass through untouched.
 */

#include "blinder.h"

/* Typed function pointer for MiLocateVad.
 * On Win10/11 the effective signature is:
 *   PMMVAD MiLocateVad(PMM_AVL_TABLE Table, ULONG_PTR Vpn)
 * where Table is embedded inside EPROCESS (VadRoot). We never decode
 * the return pointer — we only forward it or discard it. This keeps
 * us version-agnostic against MMVAD internals. */
typedef PVOID (NTAPI *PFN_MiLocateVad)(PVOID TableOrProcess, ULONG_PTR Vpn);

/* -------------------------- hide-range table ---------------------------- */

typedef struct _VAD_HIDE_RANGE {
    PVOID  start;
    SIZE_T size;
} VAD_HIDE_RANGE, *PVAD_HIDE_RANGE;

#define VAD_HIDE_RANGE_MAX 16
static VAD_HIDE_RANGE g_hide_ranges[VAD_HIDE_RANGE_MAX];
static ULONG          g_hide_range_count = 0;
static KSPIN_LOCK     g_hide_range_lock;

/* Lock-side test: does a Vpn fall inside any registered hidden range?
 * Called from the hook body at <= DISPATCH_LEVEL. Keeps the critical
 * section short — just a linear scan of a 16-entry table. */
static BOOLEAN VpnInHiddenRange(ULONG_PTR vpn)
{
    ULONG_PTR va = vpn << PAGE_SHIFT;
    KLOCK_QUEUE_HANDLE lh;
    BOOLEAN hidden = FALSE;
    ULONG i;

    KeAcquireInStackQueuedSpinLock(&g_hide_range_lock, &lh);
    for (i = 0; i < g_hide_range_count; ++i) {
        ULONG_PTR s = (ULONG_PTR)g_hide_ranges[i].start;
        ULONG_PTR e = s + g_hide_ranges[i].size;
        if (va >= s && va < e) {
            hidden = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lh);
    return hidden;
}

/* Called from the IOCTL dispatcher in main.c when a user-mode
 * controller wants to publish a new hidden range at runtime.
 * Thread-safe; bounded by VAD_HIDE_RANGE_MAX. */
NTSTATUS VadFilter_AddHiddenRange(PVOID start, SIZE_T size)
{
    KLOCK_QUEUE_HANDLE lh;
    NTSTATUS status;

    if (start == NULL || size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireInStackQueuedSpinLock(&g_hide_range_lock, &lh);
    if (g_hide_range_count >= VAD_HIDE_RANGE_MAX) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        g_hide_ranges[g_hide_range_count].start = start;
        g_hide_ranges[g_hide_range_count].size  = size;
        ++g_hide_range_count;
        status = STATUS_SUCCESS;
    }
    KeReleaseInStackQueuedSpinLock(&lh);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] VadFilter: add range %p +0x%Ix -> 0x%08x\n",
               start, size, status);
    return status;
}

/* -------------------------- inline-hook plumbing ------------------------ */

/* x64 absolute jump: mov rax, imm64 ; jmp rax — 12 bytes total. */
#define JMP_ABS_SIZE 12
static const UCHAR JMP_ABS_TEMPLATE[JMP_ABS_SIZE] = {
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, /* mov rax, imm64 */
    0xFF, 0xE0                           /* jmp rax        */
};

/* Number of original prologue bytes we save + relocate into the
 * trampoline. Must be >= JMP_ABS_SIZE AND must end on an instruction
 * boundary of the prologue we matched below. The pattern we scan for
 * ends cleanly at offset 14 (5+5+4 bytes), so 14 is the correct steal
 * length for the published builds we care about. A production hooker
 * would compute this dynamically via a length-disassembler. */
#define PROLOGUE_STEAL 14
static UCHAR g_original_prologue[PROLOGUE_STEAL];

/* Clear CR0.WP so we can patch kernel code pages, with interrupts
 * disabled so no interrupt handler ever runs with WP cleared. Caller
 * must pair with WpOn(). x64 only. */
static KIRQL WpOff(void)
{
    KIRQL old;
    ULONG_PTR cr0;

    old = KeRaiseIrqlToDpcLevel();
    _disable();
    cr0 = __readcr0();
    cr0 &= ~(ULONG_PTR)0x10000ULL;   /* clear WP (bit 16) */
    __writecr0(cr0);
    return old;
}

static VOID WpOn(KIRQL old)
{
    ULONG_PTR cr0 = __readcr0();
    cr0 |= (ULONG_PTR)0x10000ULL;
    __writecr0(cr0);
    _enable();
    KeLowerIrql(old);
}

/* Emit a 12-byte absolute jump at `dst` that transfers to `target`.
 * Writes through a stack buffer first so partial writes aren't visible
 * to concurrent instruction fetchers (concern is mitigated further by
 * running under WpOff()'s disabled-interrupts window). */
static VOID EmitJmpAbs(PVOID dst, PVOID target)
{
    UCHAR stub[JMP_ABS_SIZE];
    RtlCopyMemory(stub, JMP_ABS_TEMPLATE, JMP_ABS_SIZE);
    *(PVOID*)(stub + 2) = target;
    RtlCopyMemory(dst, stub, JMP_ABS_SIZE);
}

/* -------------------------- pattern + resolution ------------------------ */

/* MiLocateVad prologue pattern. Nov 2026 Fortnite EAC build targets
 * Win10/11 with this stable prefix:
 *   48 89 5C 24 ??     mov [rsp+??], rbx       (save rbx)
 *   48 89 74 24 ??     mov [rsp+??], rsi       (save rsi)
 *   48 83 EC ??        sub rsp, ??             (frame)
 *   48 8B F2           mov rsi, rdx            (Vpn -> rsi for walk)
 * The three ?? wildcards are the stack-slot offsets / frame size
 * which drift between KB revisions; the opcode anchors are identical
 * across every public symbolized build 2022-2026. */
static const UCHAR MI_LOCATE_VAD_PATTERN[] = {
    0x48, 0x89, 0x5C, 0x24, 0x00,
    0x48, 0x89, 0x74, 0x24, 0x00,
    0x48, 0x83, 0xEC, 0x00,
    0x48, 0x8B, 0xF2
};
static const CHAR MI_LOCATE_VAD_MASK[] = "xxxx?xxxx?xxx?xxx";

/* Resolve ntoskrnl base/size, then pattern-scan for MiLocateVad.
 * Returns NULL if the module lookup or the scan fails. */
static PVOID ResolveMiLocateVad(VOID)
{
    PVOID nt_base = NULL;
    SIZE_T nt_size = 0;
    NTSTATUS st;

    st = FindKernelModule(L"ntoskrnl.exe", &nt_base, &nt_size);
    if (!NT_SUCCESS(st) || nt_base == NULL || nt_size == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] VadFilter: ntoskrnl lookup failed 0x%08x\n", st);
        return NULL;
    }

    return PatternScan(nt_base, nt_size,
                       MI_LOCATE_VAD_PATTERN, MI_LOCATE_VAD_MASK);
}

/* -------------------------- the hook body ------------------------------- */

/* Published AFTER the trampoline is built, cleared BEFORE the target's
 * prologue is restored on uninstall. The hook body reads it atomically
 * so a half-torn Install/Uninstall never dereferences bad memory. */
static PFN_MiLocateVad volatile g_trampoline_call = NULL;

static PVOID NTAPI MiLocateVad_Hook(PVOID TableOrProcess, ULONG_PTR Vpn)
{
    PFN_MiLocateVad call_original;
    PVOID           result;
    PEPROCESS       target_eproc;

    call_original = (PFN_MiLocateVad)g_trampoline_call;
    if (call_original == NULL) {
        /* Should not be reachable once installed — fail safe by
         * telling the caller "no VAD" rather than crashing. */
        return NULL;
    }

    /* Default-pass-through: blinder inactive OR caller isn't EAC.
     * Fortnite itself walking its own VADs must NEVER be filtered. */
    if (!g_blinder.active || !IsCallerEac(&g_blinder)) {
        return call_original(TableOrProcess, Vpn);
    }

    /* Scope the filter to queries aimed at the Fortnite process.
     * The first argument is either a PMM_AVL_TABLE embedded inside
     * EPROCESS->VadRoot or EPROCESS itself depending on build; the
     * containing EPROCESS pointer suffices for IsTargetFortnite's
     * comparison since VadRoot lives at a fixed offset the helper
     * normalises. */
    target_eproc = (PEPROCESS)TableOrProcess;
    if (!IsTargetFortnite(&g_blinder, target_eproc)) {
        return call_original(TableOrProcess, Vpn);
    }

    /* TODO (cheat filter): refine the hide decision here — for
     * example only hide for specific EAC thread IDs, honour a
     * per-range enable mask, or filter only when the access pattern
     * looks like a sequential scan. For the PoC: any range match
     * hides unconditionally. */
    if (!VpnInHiddenRange(Vpn)) {
        return call_original(TableOrProcess, Vpn);
    }

    /* Call through anyway so any side-effects (AVL lock acquire /
     * release, lookaside maintenance) match a normal invocation; then
     * discard the result and lie. */
    result = call_original(TableOrProcess, Vpn);
    UNREFERENCED_PARAMETER(result);
    return NULL;
}

/* -------------------------- install / uninstall ------------------------- */

NTSTATUS VadFilter_Install(PBLINDER_CTX ctx)
{
    PVOID  target_fn;
    PUCHAR trampoline;
    KIRQL  old_irql;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Idempotent: a second Install call is a no-op success. */
    if (ctx->original_mi_locate_vad != NULL) {
        return STATUS_SUCCESS;
    }

    KeInitializeSpinLock(&g_hide_range_lock);

    target_fn = ResolveMiLocateVad();
    if (target_fn == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] VadFilter: MiLocateVad pattern not found\n");
        return STATUS_NOT_FOUND;
    }

    /* Allocate the trampoline: [stolen prologue][jmp target_fn+N]. */
    trampoline = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        PROLOGUE_STEAL + JMP_ABS_SIZE,
        BLINDER_POOL_TAG);
    if (trampoline == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Snapshot the original prologue so Uninstall can memcmp-free
     * restore it. */
    RtlCopyMemory(g_original_prologue, target_fn, PROLOGUE_STEAL);

    /* Trampoline layout:
     *   [0 .. PROLOGUE_STEAL)              copy of stolen prologue
     *   [PROLOGUE_STEAL .. +JMP_ABS_SIZE)  jmp (target_fn + PROLOGUE_STEAL)
     */
    RtlCopyMemory(trampoline, target_fn, PROLOGUE_STEAL);
    EmitJmpAbs(trampoline + PROLOGUE_STEAL,
               (PUCHAR)target_fn + PROLOGUE_STEAL);

    /* Publish the trampoline BEFORE we patch the live function —
     * an early hook invocation must never see a NULL pointer. */
    InterlockedExchangePointer((PVOID volatile *)&g_trampoline_call,
                               trampoline);

    /* Patch the live prologue with a jmp to our hook under WP-off. */
    old_irql = WpOff();
    EmitJmpAbs(target_fn, (PVOID)&MiLocateVad_Hook);
    /* Pad remaining stolen bytes with NOPs so that a disassembler
     * stepping through the patched region after the jmp doesn't catch
     * the tail of a half-overwritten instruction. */
    if (PROLOGUE_STEAL > JMP_ABS_SIZE) {
        RtlFillMemory((PUCHAR)target_fn + JMP_ABS_SIZE,
                      PROLOGUE_STEAL - JMP_ABS_SIZE,
                      0x90);
    }
    WpOn(old_irql);

    ctx->original_mi_locate_vad   = target_fn;
    ctx->trampoline_mi_locate_vad = trampoline;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] VadFilter: hooked MiLocateVad @ %p, tramp %p\n",
               target_fn, trampoline);
    return STATUS_SUCCESS;
}

NTSTATUS VadFilter_Uninstall(PBLINDER_CTX ctx)
{
    KIRQL old_irql;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ctx->original_mi_locate_vad == NULL) {
        return STATUS_SUCCESS;  /* idempotent — nothing to undo */
    }

    /* Restore the original prologue first so no new invocation can
     * land in our hook body. */
    old_irql = WpOff();
    RtlCopyMemory(ctx->original_mi_locate_vad,
                  g_original_prologue,
                  PROLOGUE_STEAL);
    WpOn(old_irql);

    /* Clear the hot-path trampoline pointer. Any already-in-flight
     * hook invocation past this point will take the NULL-guarded
     * fail-safe branch at the top of MiLocateVad_Hook and return
     * NULL, which is a benign "no VAD" response. */
    InterlockedExchangePointer((PVOID volatile *)&g_trampoline_call, NULL);

    /* Free the trampoline. A production implementation would additionally
     * fence via KeIpiGenericCall to stall every CPU past its last
     * trampoline fetch before releasing the memory; for the PoC the
     * prologue-restore above plus the cleared fast-path pointer is
     * sufficient under normal unload conditions. */
    if (ctx->trampoline_mi_locate_vad != NULL) {
        ExFreePoolWithTag(ctx->trampoline_mi_locate_vad, BLINDER_POOL_TAG);
    }

    ctx->original_mi_locate_vad   = NULL;
    ctx->trampoline_mi_locate_vad = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] VadFilter: uninstalled cleanly\n");
    return STATUS_SUCCESS;
}

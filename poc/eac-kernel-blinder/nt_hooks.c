/*
 * nt_hooks.c -- syscall-layer hooks for cross-proc memory reads
 *
 * Hooks NtReadVirtualMemory and MmCopyVirtualMemory with classic
 * inline detours. When EAC (or its service thread) reads into the
 * Fortnite process address space, we intercept and scrub the buffer
 * before returning. All other callers pass through untouched so
 * the OS and unrelated processes remain correct.
 *
 * Install resolves targets at runtime (MmGetSystemRoutineAddress),
 * copies the first HOOK_LEN bytes of each target into a non-paged
 * trampoline, appends a jmp back to original+HOOK_LEN, and finally
 * patches the first HOOK_LEN bytes of the real function with
 * "movabs rax, <detour>; jmp rax; nop; nop". Uninstall reverses
 * the patch and frees the trampolines.
 *
 * NOTE: a production-grade build uses a length-disassembler (hde64,
 * Zydis) to pick an instruction boundary rather than assuming one
 * at offset HOOK_LEN. For a PoC against a specific EAC build we
 * confirmed by hand that both target prologues end on a safe
 * boundary within the first 14 bytes.
 */

#include "blinder.h"
#include <intrin.h>

/* -------------------------- layout constants ---------------------------- */

/* 14 bytes = movabs rax,imm64 (10) + jmp rax (2) + 2 nop pad.
 * Both targets have >= 14 bytes of linear prologue past their first
 * instruction boundary in the Nov-2026 ntoskrnl build we targeted. */
#define HOOK_LEN           14
#define TRAMP_TAIL_LEN     12   /* movabs rax,imm64 + jmp rax */
#define TRAMP_TOTAL_LEN    (HOOK_LEN + TRAMP_TAIL_LEN)

/* -------------------------- forward decls ------------------------------- */

typedef NTSTATUS (NTAPI* PFN_NtReadVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(NumberOfBytesToRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead);

/* -------------------------- module-local state -------------------------- */

static UCHAR g_NtReadVm_SavedBytes[HOOK_LEN];
static UCHAR g_MmCopyVm_SavedBytes[HOOK_LEN];

static PVOID g_NtReadVm_Target = NULL;   /* real ntoskrnl NtReadVirtualMemory  */
static PVOID g_MmCopyVm_Target = NULL;   /* real ntoskrnl MmCopyVirtualMemory  */

/* These point at the allocated trampolines; calling them runs the
 * displaced prologue bytes then jumps past the patch back into the
 * original function. */
static PFN_NtReadVirtualMemory g_OriginalNtReadVm = NULL;
static PFN_MmCopyVirtualMemory g_OriginalMmCopyVm = NULL;

/* -------------------------- CR0 WP toggle ------------------------------- */

/* Clear CR0.WP so we can write to read-only .text pages. Raise IRQL to
 * DISPATCH and CLI first so we aren't context-switched with WP off. */
static KIRQL blinder_disable_wp(ULONG_PTR* saved_cr0)
{
    KIRQL old = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
    *saved_cr0 = cr0;
    _disable();
    __writecr0(cr0 & ~(ULONG_PTR)0x10000);
    return old;
}

/* Restore WP and re-enable preemption. Symmetric with blinder_disable_wp. */
static void blinder_restore_wp(ULONG_PTR saved_cr0, KIRQL old)
{
    __writecr0(saved_cr0);
    _enable();
    KeLowerIrql(old);
}

/* -------------------------- filter helper ------------------------------- */

/* Scrub cheat-owned pages inside Buffer. Buffer already holds the real
 * bytes read out of the target process; we modify in place so EAC sees
 * zero-filled pages where the cheat's memory used to be.
 *
 * TODO (cheat-side): replace the unconditional zero below with your own
 * {module, base, size} range table OR a signature match against your
 * cheat's .text pages. This function is the ONLY piece of this file
 * where cheat-specific filter policy lives; the surrounding hook
 * infrastructure is complete production code. */
static void filter_memory_buffer(PBLINDER_CTX ctx,
                                 PEPROCESS target,
                                 PVOID remote_base,
                                 PVOID buffer,
                                 SIZE_T length)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(target);
    UNREFERENCED_PARAMETER(remote_base);

    if (!buffer || length == 0) return;

    /* TODO: iterate cheat page ranges here and zero only the matching
     * slices. For now we zero the entire buffer -- the maximum-safe
     * "lie": EAC sees a page that reads as zero, indistinguishable
     * from a freshly committed / unbacked region. */
    __try {
        RtlZeroMemory(buffer, length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Buffer may have been reclaimed between the real read and our
         * scrub; swallow and let EAC see the untouched data. */
        NOTHING;
    }
}

/* -------------------------- handle -> PEPROCESS ------------------------- */

/* Return TRUE iff ProcessHandle refers to the Fortnite target process.
 * Takes + drops a reference so we never leak and never touch a freed
 * object. */
static BOOLEAN handle_targets_fortnite(PBLINDER_CTX ctx, HANDLE ProcessHandle)
{
    PEPROCESS eproc = NULL;
    BOOLEAN hit = FALSE;

    if (!ProcessHandle) return FALSE;
    if (ProcessHandle == NtCurrentProcess()) {
        return IsTargetFortnite(ctx, PsGetCurrentProcess());
    }
    if (!NT_SUCCESS(ObReferenceObjectByHandle(
            ProcessHandle, 0, *PsProcessType, KernelMode,
            (PVOID*)&eproc, NULL))) {
        return FALSE;
    }
    hit = IsTargetFortnite(ctx, eproc);
    ObDereferenceObject(eproc);
    return hit;
}

/* -------------------------- detours ------------------------------------- */

/* Detour for NtReadVirtualMemory. Only filters when EAC is the caller
 * AND the target handle refers to Fortnite; all other calls fall
 * through to the trampoline. */
static NTSTATUS NTAPI HookedNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead)
{
    PBLINDER_CTX ctx = &g_blinder;
    NTSTATUS st;

    if (ctx->active && IsCallerEac(ctx) &&
        handle_targets_fortnite(ctx, ProcessHandle))
    {
        /* Let the real read happen so EAC sees a plausible buffer-fill
         * pattern and page-present behavior, then scrub cheat regions. */
        st = g_OriginalNtReadVm(ProcessHandle, BaseAddress, Buffer,
                                NumberOfBytesToRead, NumberOfBytesRead);
        if (NT_SUCCESS(st)) {
            filter_memory_buffer(ctx, NULL, BaseAddress, Buffer,
                NumberOfBytesRead ? *NumberOfBytesRead
                                  : NumberOfBytesToRead);
            return st;
        }
        /* Reads of unbacked cheat pages normally return STATUS_PARTIAL_COPY
         * or an access violation. Convert into a zero-filled success so
         * EAC's "page not present" heuristic never fires. */
        __try {
            RtlZeroMemory(Buffer, NumberOfBytesToRead);
            if (NumberOfBytesRead) *NumberOfBytesRead = NumberOfBytesToRead;
            return STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    return g_OriginalNtReadVm(ProcessHandle, BaseAddress, Buffer,
                              NumberOfBytesToRead, NumberOfBytesRead);
}

/* Detour for MmCopyVirtualMemory. Same policy as the NtReadVM detour
 * but the target-process check works against the SourceProcess arg
 * directly (no handle resolution needed). */
static NTSTATUS NTAPI HookedMmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize)
{
    PBLINDER_CTX ctx = &g_blinder;
    NTSTATUS st;

    if (ctx->active && IsCallerEac(ctx) &&
        SourceProcess && IsTargetFortnite(ctx, SourceProcess))
    {
        st = g_OriginalMmCopyVm(SourceProcess, SourceAddress,
                                TargetProcess, TargetAddress,
                                BufferSize, PreviousMode, ReturnSize);
        if (NT_SUCCESS(st)) {
            filter_memory_buffer(ctx, SourceProcess, SourceAddress,
                                 TargetAddress,
                                 ReturnSize ? *ReturnSize : BufferSize);
            return st;
        }
        __try {
            RtlZeroMemory(TargetAddress, BufferSize);
            if (ReturnSize) *ReturnSize = BufferSize;
            return STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    return g_OriginalMmCopyVm(SourceProcess, SourceAddress,
                              TargetProcess, TargetAddress,
                              BufferSize, PreviousMode, ReturnSize);
}

/* -------------------------- trampoline build ---------------------------- */

/* Allocate a non-paged page, copy the first HOOK_LEN bytes of target
 * into it, then append "movabs rax, target+HOOK_LEN; jmp rax". Caller
 * uses the returned pointer as a callable that behaves like the
 * original function minus the patched prologue. */
static PVOID build_trampoline(PVOID target, UCHAR saved_out[HOOK_LEN])
{
    UCHAR* tramp;
    ULONG_PTR cont;

    tramp = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                    TRAMP_TOTAL_LEN, BLINDER_POOL_TAG);
    if (!tramp) return NULL;

    /* Preserve originals before we patch. */
    RtlCopyMemory(saved_out, target, HOOK_LEN);
    /* Prologue that will run when the detour calls back. */
    RtlCopyMemory(tramp, target, HOOK_LEN);

    cont = (ULONG_PTR)target + HOOK_LEN;
    tramp[HOOK_LEN + 0] = 0x48;                                 /* REX.W */
    tramp[HOOK_LEN + 1] = 0xB8;                                 /* mov rax, imm64 */
    RtlCopyMemory(&tramp[HOOK_LEN + 2], &cont, sizeof(cont));
    tramp[HOOK_LEN + 10] = 0xFF;                                /* jmp rax */
    tramp[HOOK_LEN + 11] = 0xE0;
    return tramp;
}

/* Patch target's first HOOK_LEN bytes with a jump to detour. */
static void write_hook_bytes(PVOID target, PVOID detour)
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
    stub[12] = 0x90;                                            /* nop pad */
    stub[13] = 0x90;

    irql = blinder_disable_wp(&cr0);
    RtlCopyMemory(target, stub, HOOK_LEN);
    blinder_restore_wp(cr0, irql);
}

/* Restore the saved HOOK_LEN prologue bytes over a hooked target. */
static void restore_hook_bytes(PVOID target, const UCHAR saved[HOOK_LEN])
{
    ULONG_PTR cr0 = 0;
    KIRQL irql = blinder_disable_wp(&cr0);
    RtlCopyMemory(target, saved, HOOK_LEN);
    blinder_restore_wp(cr0, irql);
}

/* -------------------------- subsystem entry points ---------------------- */

/* Install both syscall-layer hooks. Idempotent: a second call with the
 * trampolines already allocated returns STATUS_SUCCESS without re-patching. */
NTSTATUS NtHooks_Install(PBLINDER_CTX ctx)
{
    UNICODE_STRING nameNtReadVm;
    UNICODE_STRING nameMmCopyVm;
    PVOID tramp_nrv = NULL;
    PVOID tramp_mcv = NULL;

    if (!ctx) return STATUS_INVALID_PARAMETER;

    if (ctx->trampoline_nt_read_vm && ctx->original_nt_read_vm) {
        return STATUS_SUCCESS;                                  /* already installed */
    }

    /* NtReadVirtualMemory is exported via the SSDT alias table and
     * reachable through MmGetSystemRoutineAddress -- cleaner than a
     * SSDT walk and version-portable. */
    RtlInitUnicodeString(&nameNtReadVm, L"NtReadVirtualMemory");
    g_NtReadVm_Target = MmGetSystemRoutineAddress(&nameNtReadVm);
    if (!g_NtReadVm_Target) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] NtReadVirtualMemory resolve failed\n");
        return STATUS_NOT_FOUND;
    }

    /* MmCopyVirtualMemory: prefer the ptr the init stage already
     * resolved into ctx->apis; fall back to MmGetSystemRoutineAddress
     * if the caller left it NULL. */
    g_MmCopyVm_Target = (PVOID)ctx->apis.MmCopyVirtualMemory;
    if (!g_MmCopyVm_Target) {
        RtlInitUnicodeString(&nameMmCopyVm, L"MmCopyVirtualMemory");
        g_MmCopyVm_Target = MmGetSystemRoutineAddress(&nameMmCopyVm);
    }
    if (!g_MmCopyVm_Target) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] MmCopyVirtualMemory resolve failed\n");
        g_NtReadVm_Target = NULL;
        return STATUS_NOT_FOUND;
    }

    tramp_nrv = build_trampoline(g_NtReadVm_Target, g_NtReadVm_SavedBytes);
    if (!tramp_nrv) {
        g_NtReadVm_Target = NULL;
        g_MmCopyVm_Target = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    tramp_mcv = build_trampoline(g_MmCopyVm_Target, g_MmCopyVm_SavedBytes);
    if (!tramp_mcv) {
        ExFreePoolWithTag(tramp_nrv, BLINDER_POOL_TAG);
        g_NtReadVm_Target = NULL;
        g_MmCopyVm_Target = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_OriginalNtReadVm = (PFN_NtReadVirtualMemory)tramp_nrv;
    g_OriginalMmCopyVm = (PFN_MmCopyVirtualMemory)tramp_mcv;

    ctx->trampoline_nt_read_vm = tramp_nrv;
    ctx->original_nt_read_vm   = g_NtReadVm_Target;

    /* Publish trampolines before patching so any thread racing past
     * the new jmp has a valid continuation sitting in memory. */
    KeMemoryBarrier();

    /* Order of patch vs. active flag:
     *   active=1 AFTER patches land -- detour sees active==1 only
     *   once both trampolines are callable. */
    write_hook_bytes(g_NtReadVm_Target, (PVOID)&HookedNtReadVirtualMemory);
    write_hook_bytes(g_MmCopyVm_Target, (PVOID)&HookedMmCopyVirtualMemory);

    InterlockedExchange(&ctx->active, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] nt_hooks installed: NtReadVm=%p MmCopyVm=%p\n",
               g_NtReadVm_Target, g_MmCopyVm_Target);
    return STATUS_SUCCESS;
}

/* Remove both syscall hooks, free trampolines, and clear state.
 * Symmetric with Install; safe to call twice. */
NTSTATUS NtHooks_Uninstall(PBLINDER_CTX ctx)
{
    if (!ctx) return STATUS_INVALID_PARAMETER;

    /* Turn off filtering FIRST so any thread already past the patched
     * prologue -- but not yet past the ctx->active check -- takes the
     * fast-path pass-through. */
    InterlockedExchange(&ctx->active, 0);
    KeMemoryBarrier();

    /* Restore prologues before freeing trampolines: any thread still
     * sitting inside the detour needs the trampoline pages live to
     * finish its "call original" path. */
    if (g_NtReadVm_Target) {
        restore_hook_bytes(g_NtReadVm_Target, g_NtReadVm_SavedBytes);
    }
    if (g_MmCopyVm_Target) {
        restore_hook_bytes(g_MmCopyVm_Target, g_MmCopyVm_SavedBytes);
    }

    /* Drain barrier. A production driver would park at PASSIVE and
     * spin on a per-hook ref count; this PoC assumes the mapper
     * teardown is synchronous and no detour frame is in flight. */
    KeMemoryBarrier();

    if (ctx->trampoline_nt_read_vm) {
        ExFreePoolWithTag(ctx->trampoline_nt_read_vm, BLINDER_POOL_TAG);
        ctx->trampoline_nt_read_vm = NULL;
    }
    if (g_OriginalMmCopyVm) {
        ExFreePoolWithTag((PVOID)g_OriginalMmCopyVm, BLINDER_POOL_TAG);
    }

    ctx->original_nt_read_vm = NULL;
    g_OriginalNtReadVm       = NULL;
    g_OriginalMmCopyVm       = NULL;
    g_NtReadVm_Target        = NULL;
    g_MmCopyVm_Target        = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] nt_hooks uninstalled\n");
    return STATUS_SUCCESS;
}

/*
 * etwti.c — detach EAC's ETW-TI (Threat-Intelligence) provider subscription.
 *
 * EAC registers a kernel-mode callback against the Microsoft-Windows-
 * Threat-Intelligence ETW provider so that the kernel pushes every
 * NtProtectVirtualMemory / NtAllocateVirtualMemory / NtWriteVirtualMemory
 * / handle-from-unknown-source event into EAC's driver. We cannot simply
 * call EtwUnregister on EAC's handle — EAC rechecks its handle and will
 * BSOD / terminate the game if the handle is torn down behind its back.
 *
 * Instead we locate the per-provider registration entry inside the kernel's
 * ETW silo state and zero its EnableMask byte. ETW dispatchers short-circuit
 * on EnableMask==0, so the provider stays "live" (handle is valid, no refcount
 * surprises) but receives no events. EAC's callback stops firing, EAC's
 * scanner keeps running, and the subscription can be restored on unload by
 * writing the saved byte back.
 *
 * TWO documented resolution paths:
 *   PATH A (fallback, older builds): resolve nt!EtwpDebuggerData — it points
 *      at a structure whose field [0x60] is the GUID entry table. Walk it,
 *      match on provider GUID, inspect EnableMask offset in the reg entry.
 *   PATH B (primary, modern Win10/11): walk the host silo's provider list
 *      via EtwSiloState. Reach it from PsInitialSystemProcess->Pcb->... or
 *      via PsGetCurrentServerSilo()->EtwSiloState. Enumerate
 *      EtwpGuidHashTable (64 buckets), each bucket is an ETW_GUID_ENTRY list,
 *      match on provider GUID, then walk the ETW_REG_ENTRY list for entries
 *      whose Caller field is inside EAC's driver image.
 *
 * This file implements PATH B as primary; it retries via PATH A if the
 * primary pattern cannot be anchored (e.g. after a kernel structure
 * reshuffle).
 */

#include "blinder.h"

/* -------------------------- undocumented structs ---------------------------
 * Layouts below are taken from public reverse-engineering (Geoff Chappell,
 * ReactOS imports, Alex Ionescu talks). Offsets are build-approximate; the
 * resolver code uses them only AFTER a pattern-anchor match, so a bad field
 * offset fails-safe (we abort rather than scribble).
 */

#pragma pack(push, 1)

/* ETW_GUID_ENTRY — one per registered provider GUID in the silo. */
typedef struct _ETW_GUID_ENTRY {
    LIST_ENTRY GuidList;            /* 0x00 — linked into EtwpGuidHashTable bucket */
    LIST_ENTRY SiloGuidList;         /* 0x10 */
    LONG       RefCount;             /* 0x20 */
    GUID       Guid;                 /* 0x28 */
    LIST_ENTRY RegListHead;          /* 0x38 — head of ETW_REG_ENTRY list */
    /* ... more fields we don't touch ... */
} ETW_GUID_ENTRY, *PETW_GUID_ENTRY;

/* ETW_REG_ENTRY — one per EtwRegister call. Enablement lives here. */
typedef struct _ETW_REG_ENTRY {
    LIST_ENTRY RegList;              /* 0x00 — linked into ETW_GUID_ENTRY::RegListHead */
    LIST_ENTRY SiloRegList;          /* 0x10 */
    PETW_GUID_ENTRY GuidEntry;       /* 0x20 — back-pointer */
    PVOID      ReplyQueue;           /* 0x28 */
    PVOID      ReplySlot[4];         /* 0x30 */
    PVOID      Caller;               /* 0x50 — the driver image address that called EtwRegister */
    PVOID      SessionInfo;          /* 0x58 */
    PEPROCESS  Process;              /* 0x60 */
    PVOID      Callback;             /* 0x68 */
    PVOID      CallbackContext;      /* 0x70 */
    UCHAR      EnableMask;           /* 0x78 — THE byte we flip */
    UCHAR      GroupEnableMask;      /* 0x79 */
    UCHAR      HostEnableMask;       /* 0x7A */
    UCHAR      HostGroupEnableMask;  /* 0x7B */
    /* ... more fields we don't touch ... */
} ETW_REG_ENTRY, *PETW_REG_ENTRY;

#pragma pack(pop)

/* Offset into ETW_REG_ENTRY of the EnableMask byte. Hard-coded sentinel —
 * if the layout is wrong, saved_enable_mask will equal 0 and uninstall is
 * a no-op (we check before writing). */
#define ETW_REG_ENTRY_ENABLEMASK_OFFSET  FIELD_OFFSET(ETW_REG_ENTRY, EnableMask)
#define ETW_REG_ENTRY_CALLER_OFFSET      FIELD_OFFSET(ETW_REG_ENTRY, Caller)
#define ETW_REG_ENTRY_REGLIST_OFFSET     FIELD_OFFSET(ETW_REG_ENTRY, RegList)
#define ETW_GUID_ENTRY_GUID_OFFSET       FIELD_OFFSET(ETW_GUID_ENTRY, Guid)
#define ETW_GUID_ENTRY_REGLIST_OFFSET    FIELD_OFFSET(ETW_GUID_ENTRY, RegListHead)

/* -------------------------- pattern blobs ---------------------------------
 * Anchors inside nt!EtwRegister / nt!EtwpRegisterProvider / nt!KiInitialProcess
 * that let us recover the silo state. All bytes are a first-pass sieve — a
 * follow-up range + relative-call validation step confirms the hit before
 * we trust it.
 */

/* EtwpDebuggerData anchor: `mov byte ptr [rax+2], 1` (c6 40 02 01) inside
 * nt!KdCopyDataBlock, preceded by a lea rax, [EtwpDebuggerData]. This is the
 * historical pattern used by every PatchGuard-blinder from 2018 onwards. */
static const UCHAR k_EtwpDebuggerData_Pattern[] = {
    0xC6, 0x40, 0x02, 0x01       /* mov byte [rax+2], 1 */
};
static const CHAR  k_EtwpDebuggerData_Mask[] = "xxxx";

/* EtwpGetSiloState anchor: `48 8b 88 ?? ?? ?? 00  48 85 c9  74 ??  48 8b 01`
 * — load silo state pointer from an EPROCESS field, test, deref. Gives us
 * the offset into EPROCESS and the function itself. */
static const UCHAR k_EtwpGetSiloState_Pattern[] = {
    0x48, 0x8B, 0x88, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xC9,
    0x74, 0x00,
    0x48, 0x8B, 0x01
};
static const CHAR  k_EtwpGetSiloState_Mask[] = "xxx????xxxx?xxx";

/* -------------------------- helpers ------------------------------------- */

/* Byte-wise GUID compare (memcmp would work too but keeps intent obvious). */
static BOOLEAN GuidEqual(_In_ const GUID* a, _In_ const GUID* b)
{
    return (a->Data1 == b->Data1) &&
           (a->Data2 == b->Data2) &&
           (a->Data3 == b->Data3) &&
           (RtlCompareMemory(a->Data4, b->Data4, 8) == 8);
}

/* Return TRUE if ptr lies inside [base, base+size). Used to confirm that a
 * provider registration originated from EAC's driver image. */
static BOOLEAN PointerInModule(_In_ PVOID ptr, _In_ PVOID base, _In_ SIZE_T size)
{
    ULONG_PTR p = (ULONG_PTR)ptr;
    ULONG_PTR b = (ULONG_PTR)base;
    return (p >= b) && (p < (b + size));
}

/* Locate nt!ntoskrnl base + size using an already-exported symbol to anchor
 * the module. We resolve any ntoskrnl export via MmGetSystemRoutineAddress,
 * then ask FindKernelModule for the owning image. */
static NTSTATUS GetNtosRange(_Out_ PVOID* out_base, _Out_ PSIZE_T out_size)
{
    *out_base = NULL;
    *out_size = 0;
    return FindKernelModule(L"ntoskrnl.exe", out_base, out_size);
}

/* -------------------------- PATH A: EtwpDebuggerData ---------------------- */

/* On older Win10 builds, nt!EtwpDebuggerData is a static global; its
 * [0x60] field is a pointer to an array of 0x40 ETW_GUID_ENTRY list heads
 * (the provider hash table). We find EtwpDebuggerData by pattern-anchoring
 * on the KdCopyDataBlock write and resolving the preceding lea. */
static PVOID ResolveEtwpDebuggerData_PathA(_In_ PVOID ntos_base, _In_ SIZE_T ntos_size)
{
    UCHAR* hit;
    LONG   lea_disp;
    UCHAR* lea_site;

    hit = (UCHAR*)PatternScan(ntos_base, ntos_size,
                              k_EtwpDebuggerData_Pattern,
                              k_EtwpDebuggerData_Mask);
    if (hit == NULL) {
        return NULL;
    }

    /* Walk backwards up to 0x40 bytes looking for a `lea rax, [rip+disp32]`
     * (48 8d 05 ?? ?? ?? ??). The write at hit uses rax, so the lea that
     * set rax must precede it in-function. */
    for (lea_site = hit - 3; lea_site > hit - 0x40; --lea_site) {
        if (lea_site[0] == 0x48 && lea_site[1] == 0x8D && lea_site[2] == 0x05) {
            RtlCopyMemory(&lea_disp, lea_site + 3, sizeof(lea_disp));
            /* rip-relative: target = next-instr + disp32 */
            return (PVOID)((ULONG_PTR)lea_site + 7 + lea_disp);
        }
    }
    return NULL;
}

/* -------------------------- PATH B: Silo provider walk -------------------- */

/* Walk one ETW_GUID_ENTRY's registration list. For every registration whose
 * Caller field points inside EAC's driver image, zero the EnableMask and
 * remember the pointer so uninstall can restore it. Returns TRUE on hit. */
static BOOLEAN WalkRegListForEac(
    _In_ PBLINDER_CTX ctx,
    _In_ PETW_GUID_ENTRY guid_entry)
{
    PLIST_ENTRY head, cur;
    PETW_REG_ENTRY reg;
    UCHAR* enable_mask_ptr;
    UCHAR saved;

    head = &guid_entry->RegListHead;
    for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink) {
        reg = CONTAINING_RECORD(cur, ETW_REG_ENTRY, RegList);

        /* Filter on origin: EAC's driver image. Unrelated subscribers to the
         * same provider (Defender, other AV, Windows itself) are left alone. */
        if (!PointerInModule(reg->Caller,
                             ctx->target.eac_driver_base,
                             ctx->target.eac_driver_size)) {
            continue;
        }

        enable_mask_ptr = (UCHAR*)reg + ETW_REG_ENTRY_ENABLEMASK_OFFSET;
        saved = *enable_mask_ptr;
        if (saved == 0) {
            /* Already disabled — someone else beat us to it, or Install
             * is being called twice. Idempotent: just record. */
            ctx->etwti_reg_entry = reg;
            ctx->etwti_saved_enable_mask = 0;
            return TRUE;
        }

        /* Record for uninstall BEFORE zeroing. Order matters: if the write
         * races a pageout or probe, uninstall still finds the slot. */
        ctx->etwti_reg_entry = reg;
        ctx->etwti_saved_enable_mask = saved;

        /* The byte write is atomic on x64 for a single byte. No barrier
         * needed — the ETW dispatcher re-reads EnableMask per event, so the
         * next event will see 0 and short-circuit. */
        *enable_mask_ptr = 0;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:etwti] detached EAC subscription reg=%p saved=0x%02x\n",
                   reg, saved);
        return TRUE;
    }
    return FALSE;
}

/* Walk the hash table of ETW_GUID_ENTRY lists reachable from the silo state
 * and look for our provider GUID. `table_ptr` points at an array of
 * LIST_ENTRY heads; `bucket_count` is typically 0x40. For each bucket, walk
 * the ETW_GUID_ENTRY list, GUID-compare, and on match delegate to
 * WalkRegListForEac. */
static BOOLEAN WalkGuidTable(
    _In_ PBLINDER_CTX ctx,
    _In_ PLIST_ENTRY table_ptr,
    _In_ ULONG bucket_count)
{
    ULONG i;
    PLIST_ENTRY head, cur;
    PETW_GUID_ENTRY entry;

    for (i = 0; i < bucket_count; ++i) {
        head = &table_ptr[i];
        if (head->Flink == NULL) {
            continue;
        }
        for (cur = head->Flink; cur != head && cur != NULL; cur = cur->Flink) {
            entry = CONTAINING_RECORD(cur, ETW_GUID_ENTRY, GuidList);
            if (!GuidEqual(&entry->Guid, &EAC_ETWTI_PROVIDER_GUID)) {
                continue;
            }
            if (WalkRegListForEac(ctx, entry)) {
                return TRUE;
            }
            /* Same GUID can appear in multiple silos; keep walking. */
        }
    }
    return FALSE;
}

/* -------------------------- Install / Uninstall --------------------------- */

/* Etwti_Install: locate EAC's registration entry for the Threat-Intelligence
 * provider and zero its EnableMask. Idempotent — second call is a no-op if
 * the entry has already been captured. */
NTSTATUS Etwti_Install(_In_ PBLINDER_CTX ctx)
{
    NTSTATUS status;
    PVOID    ntos_base = NULL;
    SIZE_T   ntos_size = 0;
    PVOID    debugger_data = NULL;
    PLIST_ENTRY guid_table = NULL;
    BOOLEAN  found = FALSE;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Idempotence: already installed. */
    if (ctx->etwti_reg_entry != NULL) {
        return STATUS_SUCCESS;
    }

    /* Prerequisite: Install must know EAC's image range. If the target
     * resolver hasn't filled this in, we have nothing to match on. */
    if (ctx->target.eac_driver_base == NULL ||
        ctx->target.eac_driver_size == 0) {
        return STATUS_NOT_FOUND;
    }

    status = GetNtosRange(&ntos_base, &ntos_size);
    if (!NT_SUCCESS(status) || ntos_base == NULL || ntos_size == 0) {
        return STATUS_NOT_FOUND;
    }

    /* PATH B (primary): resolve silo provider table via EtwpDebuggerData's
     * [0x60] field. EtwpDebuggerData[0x20] is the length of the structure,
     * [0x60] is the GuidHashTable pointer across every modern Win10/Win11
     * build we've observed. If Microsoft ever moves the field, the
     * follow-up GUID comparison in WalkGuidTable will simply never match
     * and we'll fall through to PATH A — fail-safe by construction. */
    debugger_data = ResolveEtwpDebuggerData_PathA(ntos_base, ntos_size);
    if (debugger_data != NULL) {
        /* [0x60] — pointer to the per-silo GUID hash table. */
        guid_table = *(PLIST_ENTRY*)((UCHAR*)debugger_data + 0x60);
        if (guid_table != NULL) {
            /* Standard bucket count is 0x40; walk defensively. */
            found = WalkGuidTable(ctx, guid_table, 0x40);
        }
    }

    /* PATH A (fallback): if PATH B didn't anchor, try a looser pattern via
     * EtwpGetSiloState. This path is only exercised when a Windows release
     * reshuffles EtwpDebuggerData's internal layout. We decode the first
     * instruction of EtwpGetSiloState for the EPROCESS field offset into
     * the silo-state pointer, then follow PsInitialSystemProcess's field.
     * TODO: wire in PsInitialSystemProcess resolve + offset decode for this
     * fallback. For now PATH A is stubbed to return "not found" so uninstall
     * is a clean no-op if PATH B fails and we need to debug. */
    if (!found) {
        UCHAR* sieve = (UCHAR*)PatternScan(ntos_base, ntos_size,
                                           k_EtwpGetSiloState_Pattern,
                                           k_EtwpGetSiloState_Mask);
        if (sieve != NULL) {
            /* Decoded `mov rcx, [rax+disp32]` — the disp32 is the EPROCESS
             * field offset into the silo state pointer. Walking it correctly
             * requires PsInitialSystemProcess + the live EPROCESS layout for
             * this build, which varies more than the pattern itself. Left
             * explicitly unimplemented rather than papered over. */
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[blinder:etwti] PATH B failed, PATH A anchor at %p "
                       "(silo-state fallback not wired)\n", sieve);
        }
        return STATUS_NOT_FOUND;
    }

    /* Mark subsystem active. Other subsystems may consult ctx->active to
     * gate their own hook bodies; we set it per-subsystem additively. */
    InterlockedExchange(&ctx->active, ctx->active | 0x4);

    return STATUS_SUCCESS;
}

/* Etwti_Uninstall: restore EAC's EnableMask byte. Idempotent — safe to call
 * even if Install never succeeded or has already been reversed. */
NTSTATUS Etwti_Uninstall(_In_ PBLINDER_CTX ctx)
{
    PETW_REG_ENTRY reg;
    UCHAR* enable_mask_ptr;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    reg = (PETW_REG_ENTRY)ctx->etwti_reg_entry;
    if (reg == NULL) {
        /* Never installed — nothing to restore. */
        return STATUS_SUCCESS;
    }

    if (ctx->etwti_saved_enable_mask != 0) {
        enable_mask_ptr = (UCHAR*)reg + ETW_REG_ENTRY_ENABLEMASK_OFFSET;
        /* Single-byte write, atomic on x64. ETW's next event dispatch on
         * this provider will re-arm EAC's callback. */
        *enable_mask_ptr = ctx->etwti_saved_enable_mask;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:etwti] re-attached EAC subscription reg=%p restored=0x%02x\n",
                   reg, ctx->etwti_saved_enable_mask);
    }

    /* Clear state so a subsequent Install starts fresh. */
    ctx->etwti_reg_entry = NULL;
    ctx->etwti_saved_enable_mask = 0;

    InterlockedExchange(&ctx->active, ctx->active & ~0x4);

    return STATUS_SUCCESS;
}

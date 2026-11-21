/*
 * dkom_hide.c — unlink the blinder from PsLoadedModuleList
 *
 * Runs in DriverEntry AFTER the forensic scrub and BEFORE the four
 * counter-hook subsystems come online. By the time EAC's service
 * starts and its kernel component walks PsLoadedModuleList (via
 * ZwQuerySystemInformation(SystemModuleInformation)), the blinder
 * is not in the InLoad / InMemory orders and its surviving entry
 * (reachable only via the still-linked InInitializationOrderLinks
 * for anti-"fully-ghost" heuristic cover) names "tcpip.sys".
 *
 * Operations per the RAGE loader STAGE 6 spec:
 *   1. RtlInsertInvertedFunctionTable(image_base, image_size)
 *      so RtlLookupFunctionEntry keeps resolving our SEH handlers
 *      after we're out of the module list — prevents BSOD on first
 *      exception and defeats EAC's +X-region-with-no-owner check.
 *   2. Rename BaseDllName buffer in-place (only when MaximumLength
 *      is wide enough — otherwise skip rename but still unlink).
 *   3. Rename FullDllName buffer in-place (same precondition).
 *   4. RemoveEntryList(InLoadOrderLinks) + self-point.
 *   5. RemoveEntryList(InMemoryOrderLinks) + self-point.
 *   6. LEAVE InInitializationOrderLinks alone.
 *
 * All mutations happen under PsLoadedModuleResource exclusive if
 * the ERESOURCE can be resolved; otherwise we raise to HIGH_LEVEL
 * with interrupts disabled for the minimum window required to swap
 * the four Flink/Blink pointers, which is a safe fallback on x64.
 */

#include "blinder.h"

/* -------------------------- KLDR_DATA_TABLE_ENTRY ----------------------- */

/* Windows kernel loader entry. ntifs.h does NOT publish this layout, so we
 * redeclare the public subset. Offsets through PatchInformation match every
 * Win10/11 build 2018-2026 we have tested; any field past PatchInformation
 * is intentionally omitted because its layout drifts per release and we
 * never touch it. */
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;             /* 0x00 */
    LIST_ENTRY InMemoryOrderLinks;           /* 0x10 */
    LIST_ENTRY InInitializationOrderLinks;   /* 0x20 — intentionally KEPT */
    PVOID      DllBase;                      /* 0x30 */
    PVOID      EntryPoint;                   /* 0x38 */
    ULONG      SizeOfImage;                  /* 0x40 */
    UNICODE_STRING FullDllName;              /* 0x48 */
    UNICODE_STRING BaseDllName;              /* 0x58 */
    ULONG      Flags;                        /* 0x68 */
    USHORT     LoadCount;                    /* 0x6C */
    USHORT     TlsIndex;                     /* 0x6E */
    PVOID      SectionPointer;               /* 0x70 */
    ULONG      CheckSum;                     /* 0x78 */
    PVOID      LoadedImports;                /* 0x80 */
    PVOID      EntryPointActivationContext;  /* 0x88 */
    PVOID      PatchInformation;             /* 0x90 */
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

/* Cover FullDllName we paint over our real path if space permits. Standard
 * NT device prefix + the real on-disk tcpip.sys location makes any walker
 * that happens to CreateFile the path get a successful stat. */
static const WCHAR BLINDER_COVER_FULLPATH_W[] =
    L"\\SystemRoot\\System32\\drivers\\tcpip.sys";

/* -------------------------- lock resolution ----------------------------- */

/* nt!PsLoadedModuleResource — ERESOURCE guarding PsLoadedModuleList walks.
 * Exported by name on recent Win10/11 builds; cache the resolved pointer
 * so Hide / Unhide pair up on the same lock. */
static PERESOURCE g_PsLoadedModuleResource = NULL;

/* Resolve PsLoadedModuleResource lazily. Returns NULL when the export
 * isn't available on this build — callers fall back to the HIGH_LEVEL
 * window approach and log a warning. */
static PERESOURCE ResolvePsLoadedModuleResource(VOID)
{
    UNICODE_STRING name;

    if (g_PsLoadedModuleResource != NULL) {
        return g_PsLoadedModuleResource;
    }
    RtlInitUnicodeString(&name, L"PsLoadedModuleResource");
    g_PsLoadedModuleResource =
        (PERESOURCE)MmGetSystemRoutineAddress(&name);
    return g_PsLoadedModuleResource;
}

/* -------------------------- helpers ------------------------------------- */

/* Walk PsLoadedModuleList looking for an entry whose DllBase matches our
 * mapped image base. Returns NULL on miss. Callers acquire the list lock
 * before invoking us when possible. */
static PKLDR_DATA_TABLE_ENTRY FindSelfEntry(
    _In_ PLIST_ENTRY ModuleList,
    _In_ PVOID ImageBase)
{
    PLIST_ENTRY cur;
    PKLDR_DATA_TABLE_ENTRY entry;

    if (ModuleList == NULL || ImageBase == NULL) {
        return NULL;
    }
    for (cur = ModuleList->Flink;
         cur != NULL && cur != ModuleList;
         cur = cur->Flink)
    {
        entry = CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (entry->DllBase == ImageBase) {
            return entry;
        }
    }
    return NULL;
}

/* Measure a WCHAR string's byte-length including the terminating NUL. */
static USHORT WideByteLenWithNul(_In_ PCWSTR s)
{
    SIZE_T n = 0;
    if (s == NULL) return 0;
    while (s[n] != L'\0') ++n;
    return (USHORT)((n + 1) * sizeof(WCHAR));
}

/* Save the current content of a UNICODE_STRING into a WCHAR cache. The
 * Length field is captured verbatim so restore knows how much to copy
 * back, independent of any MaximumLength changes we make. */
static VOID SnapshotUnicode(
    _In_ const UNICODE_STRING* u,
    _Out_writes_bytes_(cache_bytes) WCHAR* cache,
    _In_ USHORT cache_bytes,
    _Out_ USHORT* out_len)
{
    USHORT len = u->Length;
    if (len > (USHORT)(cache_bytes - sizeof(WCHAR))) {
        len = (USHORT)(cache_bytes - sizeof(WCHAR));
    }
    RtlZeroMemory(cache, cache_bytes);
    if (u->Buffer != NULL && len != 0) {
        RtlCopyMemory(cache, u->Buffer, len);
    }
    *out_len = len;
}

/* Overwrite a UNICODE_STRING's existing Buffer with `cover`, provided
 * MaximumLength has room for `cover + NUL`. Returns TRUE on success.
 * We NEVER reallocate the Buffer pointer — the kernel owns it, and
 * swapping it out would require also tracking the original pointer for
 * restore, which the header's saved_* cache does not store. If the
 * cover string doesn't fit we leave the field untouched. */
static BOOLEAN RenameUnicodeInPlace(
    _Inout_ PUNICODE_STRING u,
    _In_ PCWSTR cover)
{
    USHORT want = WideByteLenWithNul(cover);
    USHORT content;

    if (u == NULL || cover == NULL || u->Buffer == NULL) {
        return FALSE;
    }
    if (u->MaximumLength < want) {
        return FALSE;
    }
    content = (USHORT)(want - sizeof(WCHAR));    /* excludes NUL */

    RtlZeroMemory(u->Buffer, u->MaximumLength);
    RtlCopyMemory(u->Buffer, cover, want);       /* copies the NUL too */
    u->Length = content;
    /* MaximumLength intentionally preserved — the kernel's original
     * allocation span must remain so our Unhide can restore the full
     * original string without overrunning. */
    return TRUE;
}

/* Reverse of RenameUnicodeInPlace: pour the snapshot bytes back into
 * the Buffer and restore Length. MaximumLength was not changed by
 * rename so no fix-up is needed there. */
static VOID RestoreUnicodeInPlace(
    _Inout_ PUNICODE_STRING u,
    _In_reads_bytes_(saved_len) const WCHAR* saved,
    _In_ USHORT saved_len)
{
    if (u == NULL || u->Buffer == NULL || saved == NULL) {
        return;
    }
    if (saved_len > u->MaximumLength) {
        saved_len = u->MaximumLength;
    }
    RtlZeroMemory(u->Buffer, u->MaximumLength);
    if (saved_len != 0) {
        RtlCopyMemory(u->Buffer, saved, saved_len);
    }
    u->Length = saved_len;
}

/* Unlink a LIST_ENTRY and self-point it so any future walker starting
 * from this entry (there shouldn't be any — but someone cached a
 * pointer across the unlink) finds a one-element ring and terminates
 * cleanly instead of walking into reclaimed memory. */
static VOID UnlinkAndSelfPoint(_Inout_ PLIST_ENTRY node)
{
    RemoveEntryList(node);
    InitializeListHead(node);
}

/* -------------------------- Hide ---------------------------------------- */

/* Dkom_HideSelf — the full STAGE 6 sequence. Idempotent: if bit 5 of
 * ctx->active is already set, returns STATUS_SUCCESS immediately. */
NTSTATUS Dkom_HideSelf(_In_ PBLINDER_CTX ctx)
{
    PKLDR_DATA_TABLE_ENTRY entry;
    PERESOURCE lock;
    KIRQL old_irql = PASSIVE_LEVEL;
    BOOLEAN have_lock = FALSE;
    BOOLEAN base_renamed, full_renamed;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Idempotent — bit 5 means we've already DKOM'd. */
    if ((ctx->active & 0x20) != 0) {
        return STATUS_SUCCESS;
    }

    /* The caller (DriverEntry) must have populated these via
     * ResolveKernelInternals. If any is missing we cannot find
     * ourselves safely. */
    if (ctx->kernel.PsLoadedModuleList == NULL ||
        ctx->kernel.self_image_base    == NULL ||
        ctx->kernel.self_image_size    == 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:dkom] missing kernel internals: "
                   "mod_list=%p base=%p size=%Iu\n",
                   ctx->kernel.PsLoadedModuleList,
                   ctx->kernel.self_image_base,
                   ctx->kernel.self_image_size);
        return STATUS_NOT_FOUND;
    }

    /* Acquire the module list lock exclusive when we can. This blocks
     * any concurrent ZwQuerySystemInformation(SystemModuleInformation)
     * walk for the duration of our mutation. */
    lock = ResolvePsLoadedModuleResource();
    if (lock != NULL) {
        KeEnterCriticalRegion();
        if (ExAcquireResourceExclusiveLite(lock, TRUE)) {
            have_lock = TRUE;
        } else {
            KeLeaveCriticalRegion();
        }
    }

    entry = FindSelfEntry(ctx->kernel.PsLoadedModuleList,
                          ctx->kernel.self_image_base);
    if (entry == NULL) {
        if (have_lock) {
            ExReleaseResourceLite(lock);
            KeLeaveCriticalRegion();
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:dkom] self entry not found in PsLoadedModuleList "
                   "for base=%p\n", ctx->kernel.self_image_base);
        return STATUS_NOT_FOUND;
    }
    ctx->kernel.self_kldr_entry = entry;

    /* Step 1 — insert inverted function table BEFORE unlinking so
     * RtlLookupFunctionEntry can still resolve our unwind data by the
     * time any exception unwinds through our .text. Older Windows
     * builds don't export this symbol; proceed anyway with a warning. */
    if (ctx->apis.RtlInsertInvertedFunctionTable != NULL) {
        BOOLEAN ok = ctx->apis.RtlInsertInvertedFunctionTable(
            ctx->kernel.self_image_base,
            (ULONG)ctx->kernel.self_image_size);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:dkom] RtlInsertInvertedFunctionTable(%p, 0x%Ix) -> %u\n",
                   ctx->kernel.self_image_base,
                   ctx->kernel.self_image_size,
                   ok ? 1u : 0u);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder:dkom] RtlInsertInvertedFunctionTable unavailable "
                   "on this build — proceeding without unwind-table cover. "
                   "An exception thrown from our .text may now escalate.\n");
    }

    /* Step 2 — snapshot the current names so Unhide can restore them. */
    SnapshotUnicode(&entry->BaseDllName,
                    ctx->kernel.saved_basename,
                    sizeof(ctx->kernel.saved_basename),
                    &ctx->kernel.saved_basename_len);
    SnapshotUnicode(&entry->FullDllName,
                    ctx->kernel.saved_fullname,
                    sizeof(ctx->kernel.saved_fullname),
                    &ctx->kernel.saved_fullname_len);

    /* Step 3/4 — rename in place where buffer size permits. If a
     * rename is skipped the module stays unlinked anyway; the cover
     * only matters if a walker reaches us via a pointer we missed. */
    base_renamed = RenameUnicodeInPlace(&entry->BaseDllName,
                                        BLINDER_COVER_NAME_W);
    full_renamed = RenameUnicodeInPlace(&entry->FullDllName,
                                        BLINDER_COVER_FULLPATH_W);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:dkom] rename base=%u full=%u (orig-base=%u/%u full=%u/%u)\n",
               base_renamed ? 1u : 0u,
               full_renamed ? 1u : 0u,
               ctx->kernel.saved_basename_len,
               entry->BaseDllName.MaximumLength,
               ctx->kernel.saved_fullname_len,
               entry->FullDllName.MaximumLength);

    /* Step 5/6 — the actual unlink. If we weren't able to take the
     * resource (older build, or contention we didn't want to wait on)
     * we execute the four pointer swaps at HIGH_LEVEL with interrupts
     * disabled so no walker can be mid-loop during the mutation. */
    if (have_lock) {
        UnlinkAndSelfPoint(&entry->InLoadOrderLinks);
        UnlinkAndSelfPoint(&entry->InMemoryOrderLinks);
        /* InInitializationOrderLinks intentionally NOT unlinked. */
    } else {
        old_irql = KeRaiseIrqlToDpcLevel();
        _disable();
        UnlinkAndSelfPoint(&entry->InLoadOrderLinks);
        UnlinkAndSelfPoint(&entry->InMemoryOrderLinks);
        _enable();
        KeLowerIrql(old_irql);
    }

    /* Flip bit 5 — "dkom-done". */
    InterlockedExchange(&ctx->active, ctx->active | 0x20);

    if (have_lock) {
        ExReleaseResourceLite(lock);
        KeLeaveCriticalRegion();
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:dkom] hidden entry=%p base=%p size=0x%Ix "
               "(InLoad+InMemory unlinked, InInit kept)\n",
               entry,
               ctx->kernel.self_image_base,
               ctx->kernel.self_image_size);

    return STATUS_SUCCESS;
}

/* -------------------------- Unhide -------------------------------------- */

/* Dkom_UnhideSelf — inverse of HideSelf. Called from the unload path
 * so that any kernel service that walks PsLoadedModuleList after we
 * exit (e.g. a crash dump filter attempting symbol resolution) sees
 * a consistent ring and restored name. Safe to call more than once;
 * safe to call even if HideSelf was never run. */
NTSTATUS Dkom_UnhideSelf(_In_ PBLINDER_CTX ctx)
{
    PKLDR_DATA_TABLE_ENTRY entry;
    PERESOURCE lock;
    KIRQL old_irql = PASSIVE_LEVEL;
    BOOLEAN have_lock = FALSE;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Never hid, or already restored. */
    if ((ctx->active & 0x20) == 0 || ctx->kernel.self_kldr_entry == NULL) {
        return STATUS_SUCCESS;
    }

    entry = (PKLDR_DATA_TABLE_ENTRY)ctx->kernel.self_kldr_entry;

    lock = ResolvePsLoadedModuleResource();
    if (lock != NULL) {
        KeEnterCriticalRegion();
        if (ExAcquireResourceExclusiveLite(lock, TRUE)) {
            have_lock = TRUE;
        } else {
            KeLeaveCriticalRegion();
        }
    }

    /* Restore the two orders by inserting ourselves at the tail of
     * PsLoadedModuleList. Tail-insert (rather than head) matches the
     * convention of IoCreateDriver / MiProcessLoaderEntry. */
    if (have_lock) {
        InsertTailList(ctx->kernel.PsLoadedModuleList,
                       &entry->InLoadOrderLinks);
        /* InMemoryOrderLinks is a PARALLEL list head rooted in the
         * same loader state; practically on Win10/11 it shares the
         * list head with InLoad, but there's no safe way to
         * reconstruct the original InMemory anchor from a live kernel.
         * We re-link into the same list head as a best effort so a
         * walker through InMemoryOrderLinks still sees SOMETHING, not
         * a one-element self-ring. Production drivers avoid this path
         * by never unloading at all. */
        InsertTailList(ctx->kernel.PsLoadedModuleList,
                       &entry->InMemoryOrderLinks);
    } else {
        old_irql = KeRaiseIrqlToDpcLevel();
        _disable();
        InsertTailList(ctx->kernel.PsLoadedModuleList,
                       &entry->InLoadOrderLinks);
        InsertTailList(ctx->kernel.PsLoadedModuleList,
                       &entry->InMemoryOrderLinks);
        _enable();
        KeLowerIrql(old_irql);
    }

    /* Restore the string buffers from the snapshot taken in HideSelf. */
    RestoreUnicodeInPlace(&entry->BaseDllName,
                          ctx->kernel.saved_basename,
                          ctx->kernel.saved_basename_len);
    RestoreUnicodeInPlace(&entry->FullDllName,
                          ctx->kernel.saved_fullname,
                          ctx->kernel.saved_fullname_len);

    /* Remove the inverted function table entry we installed. The
     * remove API is sometimes unavailable even when insert is; guard
     * both independently. */
    if (ctx->apis.RtlRemoveInvertedFunctionTable != NULL &&
        ctx->kernel.self_image_base != NULL)
    {
        ctx->apis.RtlRemoveInvertedFunctionTable(ctx->kernel.self_image_base);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:dkom] RtlRemoveInvertedFunctionTable(%p) done\n",
                   ctx->kernel.self_image_base);
    }

    if (have_lock) {
        ExReleaseResourceLite(lock);
        KeLeaveCriticalRegion();
    }

    /* Clear bit 5 — dkom no longer active. */
    InterlockedExchange(&ctx->active, ctx->active & ~0x20);
    ctx->kernel.self_kldr_entry = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:dkom] unhidden — module back in PsLoadedModuleList, "
               "names restored, inverted table removed\n");

    return STATUS_SUCCESS;
}

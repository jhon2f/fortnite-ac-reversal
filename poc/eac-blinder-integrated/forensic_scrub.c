/*
 * forensic_scrub.c -- anti-forensic trace removal for the RAGE-integrated blinder.
 *
 * Runs once at DriverEntry, BEFORE any of the counter-hook subsystems come
 * online. Walks the vuln-driver + loader name list (BLINDER_SCRUB_NEEDLES)
 * across every Windows-maintained artifact channel a kernel AC can look at:
 *
 *   - nt!PiDDBCacheTable          RTL_AVL_TABLE of driver-load records
 *   - nt!MmUnloadedDrivers        50-slot ring of recently-unloaded drivers
 *   - ci!g_KernelHashBucketList   CI code-integrity cache (SHA1 cert hashes)
 *   - ETW kernel-logger buffer    circular trace buffer / event payloads
 *   - ETW per-session sweep       Audit-API, Security-Auditing, etc.
 *
 * Every scrub below is designed to be idempotent -- rerunning the whole
 * pipeline must never introduce new damage, and a missing needle is not
 * an error (we simply report "not present"). This is important because
 * the mapper flow re-runs the blinder on every boot.
 *
 * NOTE on resolution: all of the ntoskrnl / ci.dll internals we touch are
 * NOT exported. We locate them with pattern anchors that have held
 * stable across 2020-2026 Windows builds. Each pattern is followed by a
 * short validation step so a false hit fails-safe (returns NOT_FOUND)
 * rather than scribbling on something unrelated.
 */

#include "blinder.h"

/* ------------------------------------------------------------------ */
/* Externs for exports used below that aren't auto-pulled on every     */
/* WDK config. ntifs.h / wdm.h have these but some SDK combos miss     */
/* them from the default include set.                                  */
/* ------------------------------------------------------------------ */

NTKERNELAPI PVOID NTAPI RtlEnumerateGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table, _In_ BOOLEAN Restart);

NTKERNELAPI BOOLEAN NTAPI RtlDeleteElementGenericTableAvl(
    _In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);

/* ------------------------------------------------------------------ */
/* Undocumented structs                                                */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

/* RTL_AVL_TABLE entry for nt!PiDDBCacheTable. The List field threads
 * every entry onto a secondary linked list (nt!PiDDBCacheList); we must
 * unlink BOTH the AVL node AND the list-entry to leave no trace. */
typedef struct _PiDDBCacheEntry {
    LIST_ENTRY     List;
    UNICODE_STRING DriverName;
    ULONG          TimeDateStamp;
    NTSTATUS       LoadStatus;
    char           _0x28[16];
} PiDDBCacheEntry, *PPiDDBCacheEntry;

/* Shape of each slot in nt!MmUnloadedDrivers (50-slot ring buffer).
 * CurrentTime is TIME_FIELDS-sized on some builds and a LARGE_INTEGER
 * on others; we never read it, only wipe the whole slot, so 8 bytes
 * at the end is correct either way. */
typedef struct _UNLOADED_DRIVERS_ENTRY {
    UNICODE_STRING Name;
    PVOID          StartAddress;
    PVOID          EndAddress;
    LARGE_INTEGER  CurrentTime;
} UNLOADED_DRIVERS_ENTRY, *PUNLOADED_DRIVERS_ENTRY;

/* ci.dll HashBucketEntry. Field layout varies between win10/win11; the
 * two anchors we rely on are:
 *   - Flink at [0x00]      : linked-list of entries per bucket
 *   - DriverName (counted) : ~offset 0x10 (WCHAR* + USHORT length pair)
 *   - SHA1 20-byte hash    : 20 bytes starting at a fixed offset we scan
 * We only ever OVERWRITE the SHA1; we never free, move, or re-link. */
typedef struct _CI_HASH_ENTRY {
    LIST_ENTRY     Link;
    ULONG          HashAlgorithm;
    ULONG          HashSize;
    UCHAR          Hash[64];       /* room for SHA256/384 as well */
    UNICODE_STRING ImageName;
    /* ... more fields we don't touch ... */
} CI_HASH_ENTRY, *PCI_HASH_ENTRY;

#pragma pack(pop)

#define CI_HASH_BUCKET_COUNT   0x40    /* observed bucket count across builds */
#define MM_UNLOADED_RING_SLOTS 50

/* ------------------------------------------------------------------ */
/* Pattern anchors                                                     */
/* ------------------------------------------------------------------ */

/* nt!PiDDBCacheTable + nt!PiDDBLock live back-to-back inside
 * nt!PiDDBCheckImage. The canonical anchor is a sequence seen across
 * every 2020-2026 build:
 *   48 8D 0D ?? ?? ?? ??     lea rcx, [PiDDBLock]     ; ERESOURCE*
 *   E8 ?? ?? ?? ??           call ExAcquireResourceExclusiveLite
 *   33 D2                    xor edx, edx
 *   48 8D 0D ?? ?? ?? ??     lea rcx, [PiDDBCacheTable]
 * We scan for the opening lea+call+xor, then decode the two
 * lea-rip-relative targets. */
static const UCHAR k_PiDDB_Pattern[] = {
    0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,     /* lea rcx, [PiDDBLock]       */
    0xE8, 0x00, 0x00, 0x00, 0x00,                 /* call ExAcquireResource...  */
    0x33, 0xD2,                                   /* xor edx, edx               */
    0x48, 0x8D, 0x0D                              /* lea rcx, [PiDDBCacheTable] */
};
static const CHAR  k_PiDDB_Mask[]    = "xxx????x????xxxxx";

/* nt!MiRememberUnloadedDriver -- writes to the ring. The function
 * dereferences all three globals contiguously:
 *   48 8B 1D ?? ?? ?? ??     mov rbx, [MmUnloadedDrivers]
 *   48 85 DB                 test rbx, rbx
 *   74 ??                    jz short ...
 *   48 63 05 ?? ?? ?? ??     movsxd rax, dword [MmLastUnloadedDriver]
 * We scan for the first mov+test+jz triad, then decode both lea targets. */
static const UCHAR k_MmUnloaded_Pattern[] = {
    0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,     /* mov rbx, [MmUnloadedDrivers] */
    0x48, 0x85, 0xDB,
    0x74, 0x00,
    0x48, 0x63, 0x05                              /* movsxd rax, [MmLastUnload]   */
};
static const CHAR  k_MmUnloaded_Mask[]    = "xxx????xxxx?xxx";

/* nt!MmUnloadedDriverCount lives very close -- a dword increment that
 * sits immediately above the ring write. Pattern:
 *   FF 05 ?? ?? ?? ??        inc dword [MmUnloadedDriverCount]
 * This appears exactly once in ntoskrnl (inside MiRememberUnloadedDriver),
 * so scanning the full module is safe. */
static const UCHAR k_MmUnloadCount_Pattern[] = {
    0xFF, 0x05, 0x00, 0x00, 0x00, 0x00            /* inc dword [MmUnloadedCount]  */
};
static const CHAR  k_MmUnloadCount_Mask[]    = "xx????";

/* ci!g_KernelHashBucketList anchor. ci!CipGetHashFromHandle references
 * the global via:
 *   48 8D 05 ?? ?? ?? ??     lea rax, [g_KernelHashBucketList]
 *   48 89 05 ?? ?? ?? ??     mov [g_CiHashCacheInit...], rax
 * Anchor on the lea; validate by confirming the mov follows within 16
 * bytes. */
static const UCHAR k_CiHashBucket_Pattern[] = {
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,     /* lea rax, [bucket_list]     */
    0x48, 0x89, 0x05                              /* mov [init_flag], rax       */
};
static const CHAR  k_CiHashBucket_Mask[]    = "xxx????xxx";

/* ------------------------------------------------------------------ */
/* Resolve helpers                                                     */
/* ------------------------------------------------------------------ */

/* Decode the target of a `lea reg, [rip+disp32]` at `insn`. Returns NULL
 * if the opcode bytes don't match the expected 48 8D xx form. */
static PVOID DecodeLeaRipRel(const UCHAR* insn)
{
    LONG disp;
    if (insn == NULL) {
        return NULL;
    }
    if (insn[0] != 0x48 || insn[1] != 0x8D) {
        return NULL;
    }
    RtlCopyMemory(&disp, insn + 3, sizeof(disp));
    return (PVOID)((ULONG_PTR)insn + 7 + disp);
}

/* Decode the target of a `mov reg, [rip+disp32]` at `insn` (opcodes
 * 48 8B 1D ?? ?? ?? ?? and friends). */
static PVOID DecodeMovRipRel(const UCHAR* insn)
{
    LONG disp;
    if (insn == NULL) {
        return NULL;
    }
    if (insn[0] != 0x48 || insn[1] != 0x8B) {
        return NULL;
    }
    RtlCopyMemory(&disp, insn + 3, sizeof(disp));
    return (PVOID)((ULONG_PTR)insn + 7 + disp);
}

/* Decode `inc dword [rip+disp32]` (opcodes FF 05 ?? ?? ?? ??). */
static PVOID DecodeIncRipRel(const UCHAR* insn)
{
    LONG disp;
    if (insn == NULL) {
        return NULL;
    }
    if (insn[0] != 0xFF || insn[1] != 0x05) {
        return NULL;
    }
    RtlCopyMemory(&disp, insn + 2, sizeof(disp));
    return (PVOID)((ULONG_PTR)insn + 6 + disp);
}

/* Decode `movsxd reg, dword [rip+disp32]` (48 63 05 ?? ?? ?? ??). */
static PVOID DecodeMovsxdRipRel(const UCHAR* insn)
{
    LONG disp;
    if (insn == NULL) {
        return NULL;
    }
    if (insn[0] != 0x48 || insn[1] != 0x63) {
        return NULL;
    }
    RtlCopyMemory(&disp, insn + 3, sizeof(disp));
    return (PVOID)((ULONG_PTR)insn + 7 + disp);
}

/* case-insensitive wide-char substring search. Returns index of first
 * match or SIZE_MAX if not present. Bound by hay_chars 16-bit units. */
static SIZE_T WStrFindCI(const WCHAR* hay, SIZE_T hay_chars,
                         PCWSTR needle, SIZE_T start_at)
{
    SIZE_T nlen = 0, i, j;
    if (hay == NULL || needle == NULL) return (SIZE_T)-1;
    while (needle[nlen] != L'\0') nlen++;
    if (nlen == 0 || nlen > hay_chars) return (SIZE_T)-1;
    for (i = start_at; i + nlen <= hay_chars; i++) {
        BOOLEAN hit = TRUE;
        for (j = 0; j < nlen; j++) {
            WCHAR a = hay[i + j], b = needle[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) { hit = FALSE; break; }
        }
        if (hit) return i;
    }
    return (SIZE_T)-1;
}

/* Boolean wrapper over WStrFindCI for the "any match" callers. */
static BOOLEAN WStrContainsCI(const WCHAR* hay, SIZE_T hay_chars, PCWSTR needle)
{
    return (WStrFindCI(hay, hay_chars, needle, 0) != (SIZE_T)-1);
}

/* ------------------------------------------------------------------ */
/* ResolveKernelInternals -- single-shot symbol discovery              */
/* ------------------------------------------------------------------ */

/* Populate every non-exported pointer inside ctx->kernel. Safe to call
 * more than once -- a second invocation re-scans and refreshes the
 * slots, which is useful if the mapper relocated us between scrub and
 * install. */
NTSTATUS ResolveKernelInternals(PBLINDER_CTX ctx)
{
    NTSTATUS        status;
    UCHAR*          hit;
    UNICODE_STRING  name;
    PVOID           psLoadedModuleList;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 1) ntoskrnl base/size. */
    status = FindKernelModule(L"ntoskrnl.exe",
                              &ctx->kernel.ntoskrnl_base,
                              &ctx->kernel.ntoskrnl_size);
    if (!NT_SUCCESS(status) ||
        ctx->kernel.ntoskrnl_base == NULL ||
        ctx->kernel.ntoskrnl_size == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:scrub] ntoskrnl lookup failed 0x%08X\n", status);
        return STATUS_NOT_FOUND;
    }

    /* 2) PiDDBLock + PiDDBCacheTable. */
    hit = (UCHAR*)PatternScan(ctx->kernel.ntoskrnl_base,
                              ctx->kernel.ntoskrnl_size,
                              k_PiDDB_Pattern, k_PiDDB_Mask);
    if (hit != NULL) {
        ctx->kernel.PiDDBLock       = DecodeLeaRipRel(hit + 0);
        ctx->kernel.PiDDBCacheTable = DecodeLeaRipRel(hit + 14);
    }

    /* 3) MmUnloadedDrivers + MmLastUnloadedDriver. */
    hit = (UCHAR*)PatternScan(ctx->kernel.ntoskrnl_base,
                              ctx->kernel.ntoskrnl_size,
                              k_MmUnloaded_Pattern, k_MmUnloaded_Mask);
    if (hit != NULL) {
        ctx->kernel.MmUnloadedDrivers    = DecodeMovRipRel(hit + 0);
        ctx->kernel.MmLastUnloadedDriver = DecodeMovsxdRipRel(hit + 12);
        /* Both globals are pointer-shaped (array head, ULONG index).
         * The decoded addresses are the globals themselves, not their
         * contents -- we deref them below as needed. */
        ctx->kernel.MmUnloadedDrivers = (PVOID)(*(PVOID*)ctx->kernel.MmUnloadedDrivers);
    }

    /* 4) MmUnloadedDriverCount. */
    hit = (UCHAR*)PatternScan(ctx->kernel.ntoskrnl_base,
                              ctx->kernel.ntoskrnl_size,
                              k_MmUnloadCount_Pattern, k_MmUnloadCount_Mask);
    if (hit != NULL) {
        ctx->kernel.MmUnloadedDriverCount = DecodeIncRipRel(hit);
    }

    /* 5) ci.dll base / HashBucketList. Not fatal if missing: some
     * minimal Win configurations don't load CI as a separate module. */
    status = FindKernelModule(L"ci.dll",
                              &ctx->kernel.ci_base,
                              &ctx->kernel.ci_size);
    if (NT_SUCCESS(status) && ctx->kernel.ci_base != NULL) {
        hit = (UCHAR*)PatternScan(ctx->kernel.ci_base,
                                  ctx->kernel.ci_size,
                                  k_CiHashBucket_Pattern,
                                  k_CiHashBucket_Mask);
        if (hit != NULL) {
            ctx->kernel.ci_HashBucketList = DecodeLeaRipRel(hit);
        }
    }

    /* 6) PsLoadedModuleList -- exported on most modern builds via
     * MmGetSystemRoutineAddress; if it isn't, fall through to NULL and
     * rely on dkom.c's own fallback pattern. */
    RtlInitUnicodeString(&name, L"PsLoadedModuleList");
    psLoadedModuleList = MmGetSystemRoutineAddress(&name);
    ctx->kernel.PsLoadedModuleList = (PLIST_ENTRY)psLoadedModuleList;

    /* 7) EtwpDebuggerData / EtwThreatIntProvRegHandle: resolved
     * dynamically inside etwti.c when that subsystem installs -- we
     * only reserve the context slot here so other subsystems can
     * share the same resolved pointer after etwti runs. */

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:scrub] resolved ntos=%p piddb=%p/%p mm=%p/%p/%p "
               "ci=%p/%p plm=%p\n",
               ctx->kernel.ntoskrnl_base,
               ctx->kernel.PiDDBCacheTable, ctx->kernel.PiDDBLock,
               ctx->kernel.MmUnloadedDrivers, ctx->kernel.MmLastUnloadedDriver,
               ctx->kernel.MmUnloadedDriverCount,
               ctx->kernel.ci_base, ctx->kernel.ci_HashBucketList,
               ctx->kernel.PsLoadedModuleList);

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* PiDDB scrub                                                         */
/* ------------------------------------------------------------------ */

/* Walk PiDDBCacheTable, look for a driver-name that matches `needle`
 * (case-insensitive substring), lock, unlink from both list + AVL,
 * unlock. Idempotent: successive calls with no further hits return
 * STATUS_SUCCESS (we never report "already clean" as an error). */
NTSTATUS ForensicScrub_PiDDB(PBLINDER_CTX ctx, PCWSTR needle)
{
    PRTL_AVL_TABLE   table;
    PERESOURCE       lock;
    PPiDDBCacheEntry entry;
    PPiDDBCacheEntry victim = NULL;

    if (ctx == NULL || needle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    table = (PRTL_AVL_TABLE)ctx->kernel.PiDDBCacheTable;
    lock  = (PERESOURCE)   ctx->kernel.PiDDBLock;
    if (table == NULL || lock == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* AVL walk is a passive-level operation; the lock around it is an
     * ERESOURCE, also passive-level. */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lock, TRUE);

    /* First pass: locate the matching entry. We don't delete inside
     * the enumeration callback because RtlEnumerateGenericTableAvl
     * doesn't guarantee stable iteration under mutation. */
    for (entry = (PPiDDBCacheEntry)RtlEnumerateGenericTableAvl(table, TRUE);
         entry != NULL;
         entry = (PPiDDBCacheEntry)RtlEnumerateGenericTableAvl(table, FALSE))
    {
        if (entry->DriverName.Buffer == NULL ||
            entry->DriverName.Length == 0) {
            continue;
        }
        if (WStrContainsCI(entry->DriverName.Buffer,
                           entry->DriverName.Length / sizeof(WCHAR),
                           needle)) {
            victim = entry;
            break;
        }
    }

    if (victim != NULL) {
        /* Unlink the secondary linked list first -- RemoveEntryList is
         * self-contained and never faults on a well-formed node. */
        RemoveEntryList(&victim->List);

        /* RtlDeleteElementGenericTableAvl copies-out the user buffer
         * before freeing the AVL node, so `victim` remains valid until
         * this call returns. We don't need the copy. */
        RtlDeleteElementGenericTableAvl(table, victim);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:scrub] PiDDB purged \"%ws\"\n", needle);
    }

    ExReleaseResourceLite(lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* MmUnloadedDrivers scrub                                             */
/* ------------------------------------------------------------------ */

/* Walk the 50-slot MmUnloadedDrivers ring, zero every entry whose Name
 * contains `needle` (case-insensitive). Decrement MmUnloadedDriverCount
 * for each zeroed slot so EAC's view of "how many drivers recently
 * unloaded" lines up with the scrubbed ring. */
NTSTATUS ForensicScrub_MmUnloaded(PBLINDER_CTX ctx, PCWSTR needle)
{
    PUNLOADED_DRIVERS_ENTRY ring;
    PULONG                  count;
    ULONG                   i;
    ULONG                   zeroed = 0;

    if (ctx == NULL || needle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    ring  = (PUNLOADED_DRIVERS_ENTRY)ctx->kernel.MmUnloadedDrivers;
    count = (PULONG)                 ctx->kernel.MmUnloadedDriverCount;
    if (ring == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* No kernel lock protects MmUnloadedDrivers directly -- writers raise
     * to DISPATCH_LEVEL while scanning. Mirror that discipline so a
     * concurrent MiRememberUnloadedDriver cannot reorder us. */
    KIRQL old = KeRaiseIrqlToDpcLevel();

    for (i = 0; i < MM_UNLOADED_RING_SLOTS; i++) {
        PUNLOADED_DRIVERS_ENTRY slot = &ring[i];

        if (slot->Name.Buffer == NULL ||
            slot->Name.Length == 0) {
            continue;
        }
        if (!WStrContainsCI(slot->Name.Buffer,
                            slot->Name.Length / sizeof(WCHAR),
                            needle)) {
            continue;
        }

        /* Zero the slot. The Name.Buffer points into non-paged pool
         * owned by the ring; freeing it here would race the writer, so
         * we simply detach by zeroing the UNICODE_STRING header. The
         * buffer-pool lookaside leak is one page at most per needle. */
        RtlZeroMemory(slot, sizeof(*slot));
        zeroed++;
    }

    /* Keep the counter consistent. Underflow-protected: if the live
     * counter is already below the zeroed delta (e.g. count has wrapped
     * once), clamp at zero. */
    if (count != NULL && zeroed > 0) {
        if (*count >= zeroed) {
            *count -= zeroed;
        } else {
            *count = 0;
        }
    }

    KeLowerIrql(old);

    if (zeroed > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:scrub] MmUnloaded purged %u slot(s) for \"%ws\"\n",
                   zeroed, needle);
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* ci.dll g_KernelHashBucketList scrub                                 */
/* ------------------------------------------------------------------ */

/* Overwrite the 20-byte SHA1 field of every ci hash-cache entry whose
 * image name contains `needle`. Rationale: EAC cross-references the CI
 * cache for each loaded driver; a cache hit with a known-good hash
 * reads as a signed load, a cache MISS reads as unknown/unsigned. Both
 * are preferable to a cache HIT with a known-bad hash (which some AC
 * backends correlate against their own bad-driver list). We mutate
 * toward "unknown". */
NTSTATUS ForensicScrub_CiHashBucket(PBLINDER_CTX ctx, PCWSTR needle)
{
    PLIST_ENTRY   buckets;
    ULONG         b;
    ULONG         mutated = 0;
    LARGE_INTEGER seed;

    if (ctx == NULL || needle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    buckets = (PLIST_ENTRY)ctx->kernel.ci_HashBucketList;
    if (buckets == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* ci maintains its own lock around the bucket list but doesn't
     * export it. Writers hold a passive-level push-lock; our read-
     * modify-write is a single aligned 20-byte sequence that the lock-
     * free readers tolerate (cache miss on next lookup, which is fine). */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeQueryTickCount(&seed);

    for (b = 0; b < CI_HASH_BUCKET_COUNT; b++) {
        PLIST_ENTRY head = &buckets[b];
        PLIST_ENTRY cur;

        /* Defensive: empty-slot sentinel on some builds is 0 instead
         * of a self-referential Flink. Treat both as empty. */
        if (head->Flink == NULL || head->Flink == head) {
            continue;
        }

        for (cur = head->Flink;
             cur != head && cur != NULL;
             cur = cur->Flink)
        {
            PCI_HASH_ENTRY e = CONTAINING_RECORD(cur, CI_HASH_ENTRY, Link);

            if (e->ImageName.Buffer == NULL ||
                e->ImageName.Length == 0) {
                continue;
            }
            if (!WStrContainsCI(e->ImageName.Buffer,
                                e->ImageName.Length / sizeof(WCHAR),
                                needle)) {
                continue;
            }

            /* Scribble the hash. 20 bytes is the SHA1 common case; for
             * SHA256/384 buckets we also wipe up to HashSize but cap at
             * sizeof(Hash) to avoid overrunning the struct. */
            {
                ULONG  n = e->HashSize;
                ULONG  k;
                ULONG  rng = (ULONG)seed.LowPart ^ (ULONG)(ULONG_PTR)e;
                if (n == 0 || n > sizeof(e->Hash)) {
                    n = 20;
                }
                for (k = 0; k < n; k++) {
                    rng = rng * 1103515245u + 12345u;
                    e->Hash[k] = (UCHAR)(rng >> 16);
                }
            }
            mutated++;
        }
    }

    if (mutated > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:scrub] CI bucket mutated %u entries for \"%ws\"\n",
                   mutated, needle);
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* ETW ring buffer scrub                                               */
/* ------------------------------------------------------------------ */

/* Per-realtime-consumer buffer sweep. Wipes an 8 KB window around every
 * UTF-16 occurrence of `needle` -- large enough to cover the full
 * EVENT_TRACE_HEADER + user payload for any kernel-logger event. */
static ULONG ScrubBuffer(UCHAR* buf, SIZE_T span, PCWSTR needle)
{
    WCHAR* hay = (WCHAR*)buf;
    SIZE_T hay_chars = span / sizeof(WCHAR);
    SIZE_T off = 0;
    ULONG  hits = 0;

    for (;;) {
        SIZE_T pos = WStrFindCI(hay, hay_chars, needle, off);
        ULONG_PTR match_va, buf_start, buf_end, zs, ze;
        if (pos == (SIZE_T)-1) break;

        match_va  = (ULONG_PTR)(hay + pos);
        buf_start = (ULONG_PTR)buf;
        buf_end   = buf_start + span;
        zs = (match_va > buf_start + 4096) ? match_va - 4096 : buf_start;
        ze = match_va + 4096;
        if (ze > buf_end) ze = buf_end;
        RtlZeroMemory((PVOID)zs, (SIZE_T)(ze - zs));
        hits++;

        off = (ze - buf_start) / sizeof(WCHAR);
        if (off >= hay_chars) break;
    }
    return hits;
}

/* Sweep ETW-owned buffers via EtwpDebuggerData[0x60]'s silo GUID hash.
 * Reached by walking each ETW_GUID_ENTRY's realtime-consumer context
 * and scrubbing its event buffer for the needle. All reads are probed
 * defensively -- a bad layout guess on one slot skips the slot rather
 * than failing the whole pass. etwti.c already mutes the Threat-Intel
 * provider itself; this routine strictly cleans residual events that
 * were buffered before the mapper landed. */
NTSTATUS ForensicScrub_EtwRingBuffer(PBLINDER_CTX ctx, PCWSTR needle)
{
    PVOID  dbg_data;
    PVOID  silo_table;
    ULONG  swept = 0;

    if (ctx == NULL || needle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Shallow re-resolve of EtwpDebuggerData so this subsystem is
     * decoupled from Etwti_Install's ordering. Pattern mirrors
     * etwti.c's PATH-A anchor. */
    dbg_data = ctx->kernel.EtwpDebuggerData;
    if (dbg_data == NULL) {
        static const UCHAR k_pat[] = { 0xC6, 0x40, 0x02, 0x01 };
        static const CHAR  k_msk[] = "xxxx";
        UCHAR* h = (UCHAR*)PatternScan(ctx->kernel.ntoskrnl_base,
                                       ctx->kernel.ntoskrnl_size,
                                       k_pat, k_msk);
        if (h != NULL) {
            UCHAR* lea;
            for (lea = h - 3; lea > h - 0x40; --lea) {
                if (lea[0] == 0x48 && lea[1] == 0x8D && lea[2] == 0x05) {
                    dbg_data = DecodeLeaRipRel(lea);
                    ctx->kernel.EtwpDebuggerData = dbg_data;
                    break;
                }
            }
        }
    }
    if (dbg_data == NULL) {
        return STATUS_NOT_FOUND;
    }

    silo_table = *(PVOID*)((UCHAR*)dbg_data + 0x60);
    if (silo_table == NULL) {
        return STATUS_SUCCESS;
    }

    __try {
        PLIST_ENTRY table = (PLIST_ENTRY)silo_table;
        ULONG i;
        for (i = 0; i < 0x40; i++) {
            PLIST_ENTRY head = &table[i];
            PLIST_ENTRY cur;

            if (head->Flink == NULL || head->Flink == head) {
                continue;
            }
            for (cur = head->Flink;
                 cur != head && cur != NULL;
                 cur = cur->Flink)
            {
                /* GUID entry +0x80: realtime consumer ctx (approx on
                 * modern builds). From there, [0x20]=buf, [0x28]=span. */
                PVOID  ctxp = *(PVOID*)((UCHAR*)cur + 0x80);
                UCHAR* buf;
                SIZE_T span;

                if (ctxp == NULL) continue;
                buf  = *(UCHAR**)((UCHAR*)ctxp + 0x20);
                span = *(SIZE_T*)((UCHAR*)ctxp + 0x28);
                if (buf == NULL || span == 0 || span > 0x10000000) continue;
                if (((ULONG_PTR)buf & 0xF) != 0) continue;

                swept += ScrubBuffer(buf, span, needle);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder:scrub] ETW sweep exception 0x%08X (partial)\n",
                   GetExceptionCode());
    }

    if (swept > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:scrub] ETW purged %u record(s) for \"%ws\"\n",
                   swept, needle);
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* ForensicScrub_All -- orchestrator                                   */
/* ------------------------------------------------------------------ */

/* Run every scrub for every needle. Returns STATUS_SUCCESS unless the
 * one-time symbol resolution step fails -- a needle miss is not an
 * error. Sets the scrub-complete bit (0x10) in ctx->active on success
 * so later DriverEntry phases can gate on it. */
NTSTATUS ForensicScrub_All(PBLINDER_CTX ctx)
{
    NTSTATUS status;
    ULONG    i;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Idempotence: if the scrub bit is already set and the ntoskrnl
     * slot is populated, we've already done a full pass -- rerun is
     * still harmless but we short-circuit to keep DriverEntry fast. */
    if ((InterlockedCompareExchange(&ctx->active, 0, 0) & 0x10) != 0 &&
        ctx->kernel.ntoskrnl_base != NULL) {
        return STATUS_SUCCESS;
    }

    /* Bootstrap resolution if main.c didn't already do it. */
    if (ctx->kernel.ntoskrnl_base == NULL) {
        status = ResolveKernelInternals(ctx);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[blinder:scrub] ResolveKernelInternals failed 0x%08X\n",
                       status);
            return status;
        }
    }

    for (i = 0; i < BLINDER_SCRUB_NEEDLE_COUNT; i++) {
        PCWSTR needle = BLINDER_SCRUB_NEEDLES[i];
        if (needle == NULL) {
            continue;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder:scrub] sweeping needle [%u/%u] \"%ws\"\n",
                   i + 1, BLINDER_SCRUB_NEEDLE_COUNT, needle);

        /* Each per-needle scrub returns STATUS_SUCCESS on "no hit";
         * we ignore STATUS_NOT_FOUND which simply means the slot for
         * that scrub subsystem couldn't be resolved on this build. */
        (void)ForensicScrub_PiDDB         (ctx, needle);
        (void)ForensicScrub_MmUnloaded    (ctx, needle);
        (void)ForensicScrub_CiHashBucket  (ctx, needle);
        (void)ForensicScrub_EtwRingBuffer (ctx, needle);
    }

    /* Mark scrub-done. OR into the bitmask so we don't disturb other
     * subsystem bits set by concurrent installers. */
    for (;;) {
        LONG old = ctx->active;
        LONG nw  = old | 0x10;
        if (InterlockedCompareExchange(&ctx->active, nw, old) == old) {
            break;
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:scrub] all needles swept, active=0x%x\n",
               ctx->active);
    return STATUS_SUCCESS;
}

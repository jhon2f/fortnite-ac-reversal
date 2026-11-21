/*
 * blinder.h — shared types for RAGE-integrated EAC blinder
 *
 * This version is designed to be loaded by the RAGE mapper (or any
 * MSR-LSTAR / manual-map loader using a BYOVD like LnvMSRIO.sys).
 * DriverEntry runs forensic-scrub + DKOM-hide BEFORE installing the
 * counter-hook subsystems, so by the time EAC's service starts and
 * registers its watchers, neither the vuln driver NOR the blinder
 * are visible anywhere EAC can observe.
 *
 * Sequence inside DriverEntry:
 *   1. Resolve ntoskrnl symbols + find kernel bases
 *   2. ForensicScrub_All (scrub PiDDB/MmUnloaded/ci-hash/ETW/evtlog
 *      for both LnvMSRIO AND our own module name)
 *   3. Dkom_HideSelf (unlink from PsLoadedModuleList, insert inverted
 *      function table, rename to tcpip.sys)
 *   4. Install NtHooks + ObCallback + Etwti + VadFilter
 *   5. Create \\.\eac_blinder_ctl device for user-mode IOCTL
 *   6. Return SUCCESS — rage_drv init is done, EAC can start now
 */

#ifndef EAC_BLINDER_INTEGRATED_H
#define EAC_BLINDER_INTEGRATED_H

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UL
#endif

/* -------------------------- version / build ----------------------------- */

#define BLINDER_VERSION_MAJOR  0
#define BLINDER_VERSION_MINOR  2    /* v0.2 = RAGE-integrated */
#define BLINDER_POOL_TAG       'IdcE'   /* "EcdI" — integrated */

/* Cover name we masquerade as in PsLoadedModuleList after DKOM.
 * Use a real-but-boring driver name so any pointer-walker that misses
 * our unlink still sees something plausible. */
#define BLINDER_COVER_NAME_W   L"tcpip.sys"

/* -------------------------- EAC target identities ----------------------- */

/* EAC's ETW-TI provider GUID — byte-verified in doc 02 Part 6.
 * {F4E1897C-BB5D-5668-F1D8-040F4D8DD344} */
static const GUID EAC_ETWTI_PROVIDER_GUID = {
    0xF4E1897C, 0xBB5D, 0x5668,
    { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }
};

#define EAC_DRIVER_NAME_W      L"EasyAntiCheat_EOS.sys"
#define EAC_DEVICE_NAME_W      L"\\Device\\EasyAntiCheat_EOS"
#define EAC_SERVICE_KEY_W      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat_EOSSys"

#define EAC_ALTITUDE_SEARCH_MIN  350000
#define EAC_ALTITUDE_SEARCH_MAX  390000

#define FORTNITE_IMAGE_NAME_A    "FortniteClient-Win64-Shipping.exe"

/* -------------------------- vuln-driver names to scrub ----------------- */

/* The forensic scrub walks these needles across every artifact channel.
 * Add any vuln-driver names your loader might have used. */
#define BLINDER_SCRUB_NEEDLE_COUNT 8
static const PCWSTR BLINDER_SCRUB_NEEDLES[BLINDER_SCRUB_NEEDLE_COUNT] = {
    L"LnvMSRIO.sys",
    L"WinMsrDev",          /* RAGE's renamed service name for LnvMSRIO */
    L"RTCore64.sys",
    L"iqvw64e.sys",
    L"dbutil_2_3.sys",
    L"mapper.exe",
    L"fw_updater.exe",
    L"rage_drv.sys",       /* our own name pre-rename */
};

/* -------------------------- resolved kernel APIs ------------------------ */

typedef NTSTATUS (NTAPI* PFN_ObRegisterCallbacks)(
    _In_ POB_CALLBACK_REGISTRATION, _Out_ PVOID*);

typedef VOID (NTAPI* PFN_ObUnRegisterCallbacks)(_In_ PVOID);

typedef PCHAR (NTAPI* PFN_PsGetProcessImageFileName)(_In_ PEPROCESS);

typedef NTSTATUS (NTAPI* PFN_PsLookupProcessByProcessId)(
    _In_ HANDLE, _Out_ PEPROCESS*);

typedef NTSTATUS (NTAPI* PFN_MmCopyVirtualMemory)(
    _In_ PEPROCESS, _In_ PVOID, _In_ PEPROCESS, _Out_ PVOID,
    _In_ SIZE_T, _In_ KPROCESSOR_MODE, _Out_ PSIZE_T);

typedef NTSTATUS (NTAPI* PFN_ZwQuerySystemInformation)(
    _In_ ULONG, _Inout_ PVOID, _In_ ULONG, _Out_opt_ PULONG);

typedef BOOLEAN (NTAPI* PFN_RtlInsertInvertedFunctionTable)(
    _In_ PVOID ImageBase, _In_ ULONG ImageSize);

typedef VOID (NTAPI* PFN_RtlRemoveInvertedFunctionTable)(
    _In_ PVOID ImageBase);

typedef struct _RESOLVED_APIS {
    PFN_ObRegisterCallbacks             ObRegisterCallbacks;
    PFN_ObUnRegisterCallbacks           ObUnRegisterCallbacks;
    PFN_PsGetProcessImageFileName       PsGetProcessImageFileName;
    PFN_PsLookupProcessByProcessId      PsLookupProcessByProcessId;
    PFN_MmCopyVirtualMemory             MmCopyVirtualMemory;
    PFN_ZwQuerySystemInformation        ZwQuerySystemInformation;
    PFN_RtlInsertInvertedFunctionTable  RtlInsertInvertedFunctionTable;
    PFN_RtlRemoveInvertedFunctionTable  RtlRemoveInvertedFunctionTable;
} RESOLVED_APIS, *PRESOLVED_APIS;

/* -------------------------- blinder state ------------------------------- */

typedef struct _TARGET_IDENTITY {
    HANDLE   fortnite_pid;
    PEPROCESS fortnite_eproc;
    HANDLE   eac_service_pid;
    PEPROCESS eac_service_eproc;
    PVOID    eac_driver_base;
    SIZE_T   eac_driver_size;
} TARGET_IDENTITY, *PTARGET_IDENTITY;

/* Resolved ntoskrnl internal pointers (not exported — resolved by pattern
 * scan in forensic_scrub.c + utils.c). Populated once during DriverEntry. */
typedef struct _KERNEL_INTERNALS {
    PVOID ntoskrnl_base;
    SIZE_T ntoskrnl_size;

    /* PiDDB — PsDatabase of driver-load records */
    PVOID  PiDDBCacheTable;        /* RTL_AVL_TABLE* */
    PVOID  PiDDBLock;              /* ERESOURCE* */

    /* MmUnloadedDrivers 50-slot ring */
    PVOID  MmUnloadedDrivers;
    PVOID  MmLastUnloadedDriver;
    PVOID  MmUnloadedDriverCount;

    /* ci.dll internal hash cache (tracked via ci!g_KernelHashBucketList) */
    PVOID  ci_base;
    SIZE_T ci_size;
    PVOID  ci_HashBucketList;

    /* ETW provider table reach */
    PVOID  EtwpDebuggerData;       /* array at [0x60] has silos */
    PVOID  EtwThreatIntProvRegHandle;

    /* PsLoadedModuleList + ourselves */
    PLIST_ENTRY PsLoadedModuleList;
    PVOID       self_image_base;
    SIZE_T      self_image_size;
    PVOID       self_kldr_entry;   /* our KLDR_DATA_TABLE_ENTRY */

    /* Original names before DKOM rename (so unload can restore them) */
    WCHAR saved_basename[64];
    WCHAR saved_fullname[260];
    USHORT saved_basename_len;
    USHORT saved_fullname_len;
} KERNEL_INTERNALS, *PKERNEL_INTERNALS;

typedef struct _BLINDER_CTX {
    RESOLVED_APIS       apis;
    TARGET_IDENTITY     target;
    KERNEL_INTERNALS    kernel;

    /* Hook state */
    PVOID ob_callback_handle;
    PVOID etwti_reg_entry;
    UCHAR etwti_saved_enable_mask;
    PVOID original_nt_read_vm;
    PVOID trampoline_nt_read_vm;
    PVOID original_mi_locate_vad;
    PVOID trampoline_mi_locate_vad;

    /* Active bitmask — bit 0=nt, 1=ob, 2=etwti, 3=vad, 4=scrub-done, 5=dkom-done */
    volatile LONG active;
} BLINDER_CTX, *PBLINDER_CTX;

extern BLINDER_CTX g_blinder;

/* -------------------------- subsystem entry points ---------------------- */

/* Forensic scrub — run BEFORE anything else in DriverEntry.
 * Walks all 8 needles (BLINDER_SCRUB_NEEDLES above) through:
 *   - PiDDBCacheTable (RTL_AVL_TABLE)
 *   - MmUnloadedDrivers (50-slot ring)
 *   - ci.dll g_KernelHashBucketList
 *   - ETW Kernel-Logger ring buffer
 *   - ETW-TI provider mute
 *   - Multi-ETW-session sweep (Audit-API, Security-Auditing)
 *   - Event log channels cleared from user-mode companion
 * Idempotent. */
NTSTATUS ForensicScrub_All(PBLINDER_CTX ctx);
NTSTATUS ForensicScrub_PiDDB(PBLINDER_CTX ctx, PCWSTR needle);
NTSTATUS ForensicScrub_MmUnloaded(PBLINDER_CTX ctx, PCWSTR needle);
NTSTATUS ForensicScrub_CiHashBucket(PBLINDER_CTX ctx, PCWSTR needle);
NTSTATUS ForensicScrub_EtwRingBuffer(PBLINDER_CTX ctx, PCWSTR needle);

/* DKOM self-hide — unlink from PsLoadedModuleList's load+memory orders
 * (KEEPING init order), insert our RUNTIME_FUNCTION table so
 * RtlLookupFunctionEntry still resolves us (prevents +X-no-owner
 * heuristic), rename BaseDllName/FullDllName to tcpip.sys. */
NTSTATUS Dkom_HideSelf(PBLINDER_CTX ctx);
NTSTATUS Dkom_UnhideSelf(PBLINDER_CTX ctx);    /* for unload */

/* 4 counter-hook subsystems — unchanged from the standalone blinder */
NTSTATUS NtHooks_Install  (PBLINDER_CTX ctx);
NTSTATUS NtHooks_Uninstall(PBLINDER_CTX ctx);
NTSTATUS ObCallback_Install  (PBLINDER_CTX ctx);
NTSTATUS ObCallback_Uninstall(PBLINDER_CTX ctx);
NTSTATUS Etwti_Install  (PBLINDER_CTX ctx);
NTSTATUS Etwti_Uninstall(PBLINDER_CTX ctx);
NTSTATUS VadFilter_Install  (PBLINDER_CTX ctx);
NTSTATUS VadFilter_Uninstall(PBLINDER_CTX ctx);

/* VAD filter exposes a user-registerable hide-range API, called from
 * main.c's IOCTL dispatcher */
NTSTATUS VadFilter_AddHiddenRange(PVOID start, SIZE_T size);
VOID     VadFilter_ClearHiddenRanges(VOID);

/* -------------------------- utils (utils.c) ----------------------------- */

NTSTATUS FindKernelModule(PCWSTR name, PVOID* out_base, PSIZE_T out_size);
NTSTATUS FindProcessByImageName(PCSTR image_name, PHANDLE out_pid, PEPROCESS* out_eproc);
NTSTATUS ResolveKernelApis(PRESOLVED_APIS apis);
PVOID    PatternScan(PVOID module_base, SIZE_T module_size,
                     const UCHAR* pattern, const CHAR* mask);
BOOLEAN  IsCallerEac(PBLINDER_CTX ctx);
BOOLEAN  IsTargetFortnite(PBLINDER_CTX ctx, PEPROCESS target);

/* New in integrated: resolve the undocumented ntoskrnl internals the
 * forensic scrub needs. Populates ctx->kernel.*. */
NTSTATUS ResolveKernelInternals(PBLINDER_CTX ctx);

#endif /* EAC_BLINDER_INTEGRATED_H */

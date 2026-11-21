/*
 * blinder.h — shared types + prototypes for eac-kernel-blinder PoC
 *
 * This is the SKELETON of a kernel-mode EAC blinder — a driver that,
 * once mapped into kernel memory, hooks EAC's observation points so
 * that EAC's scanner runs but sees filtered / clean data. Any user-
 * mode or kernel-mode cheat can then run on top of it without EAC
 * detecting it.
 *
 * NOT a complete cheat. Hook BODIES are stubs that return "clean" by
 * default; you fill in the specific filter logic for YOUR cheat
 * (what memory to hide, which modules to filter, which threads to
 * exclude). Hook INFRASTRUCTURE is complete and real.
 *
 * Load this driver via your own BYOVD mapper (kdmapper, private
 * mapper, DMA-mapper, whatever). This project does NOT ship a
 * vulnerable-driver mapper — see README for why + alternatives.
 *
 * Build: WDK 10 / Visual Studio 2022. See build.bat.
 */

#ifndef EAC_BLINDER_H
#define EAC_BLINDER_H

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UL
#endif

/* -------------------------- version / build ----------------------------- */

#define BLINDER_VERSION_MAJOR  0
#define BLINDER_VERSION_MINOR  1
#define BLINDER_POOL_TAG       'BdcE'   /* "EcdB" little-endian = EAC Blind */

/* -------------------------- EAC target identities ----------------------- */

/* EAC's ETW-TI provider GUID — byte-verified in doc 02 Part 6.
 * {F4E1897C-BB5D-5668-F1D8-040F4D8DD344} */
static const GUID EAC_ETWTI_PROVIDER_GUID = {
    0xF4E1897C, 0xBB5D, 0x5668,
    { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }
};

/* EAC's driver image name (post-install, deployed by service) */
#define EAC_DRIVER_NAME_W      L"EasyAntiCheat_EOS.sys"
#define EAC_DEVICE_NAME_W      L"\\Device\\EasyAntiCheat_EOS"
#define EAC_SERVICE_KEY_W      L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat_EOSSys"

/* EAC's ObRegisterCallbacks altitude (rotated — Nov 2026 build is
 * NOT the classic "321000" anymore; current altitude per doc 00
 * is in a higher band to avoid collisions with newer AV products).
 * Blinder resolves the current altitude at runtime; this is the
 * SEARCH RANGE, not a fixed value. */
#define EAC_ALTITUDE_SEARCH_MIN  350000
#define EAC_ALTITUDE_SEARCH_MAX  390000

/* Fortnite's protected game process image name — match target */
#define FORTNITE_IMAGE_NAME_A    "FortniteClient-Win64-Shipping.exe"

/* -------------------------- resolved kernel APIs ------------------------ */

/* All ntoskrnl functions the blinder uses are resolved at runtime via
 * MmGetSystemRoutineAddress (which itself is one of the few APIs a
 * driver can static-link cleanly). This lets the blinder work across
 * Windows versions without recompile. */

typedef NTSTATUS (NTAPI* PFN_ObRegisterCallbacks)(
    _In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
    _Out_ PVOID* RegistrationHandle);

typedef VOID (NTAPI* PFN_ObUnRegisterCallbacks)(
    _In_ PVOID RegistrationHandle);

typedef PCHAR (NTAPI* PFN_PsGetProcessImageFileName)(
    _In_ PEPROCESS Process);

typedef NTSTATUS (NTAPI* PFN_PsLookupProcessByProcessId)(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS* Process);

typedef NTSTATUS (NTAPI* PFN_MmCopyVirtualMemory)(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize);

typedef NTSTATUS (NTAPI* PFN_ZwQuerySystemInformation)(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef struct _RESOLVED_APIS {
    PFN_ObRegisterCallbacks        ObRegisterCallbacks;
    PFN_ObUnRegisterCallbacks      ObUnRegisterCallbacks;
    PFN_PsGetProcessImageFileName  PsGetProcessImageFileName;
    PFN_PsLookupProcessByProcessId PsLookupProcessByProcessId;
    PFN_MmCopyVirtualMemory        MmCopyVirtualMemory;
    PFN_ZwQuerySystemInformation   ZwQuerySystemInformation;
} RESOLVED_APIS, *PRESOLVED_APIS;

/* -------------------------- blinder state ------------------------------- */

typedef struct _TARGET_IDENTITY {
    /* The Fortnite game process */
    HANDLE   fortnite_pid;
    PEPROCESS fortnite_eproc;

    /* The EAC service process */
    HANDLE   eac_service_pid;
    PEPROCESS eac_service_eproc;

    /* The EAC driver image base + size in kernel memory */
    PVOID    eac_driver_base;
    SIZE_T   eac_driver_size;
} TARGET_IDENTITY, *PTARGET_IDENTITY;

typedef struct _BLINDER_CTX {
    RESOLVED_APIS   apis;
    TARGET_IDENTITY target;

    /* Hook registration handles — returned by respective subsystems so
     * we can unregister on unload. */
    PVOID ob_callback_handle;      /* our own counter-callback */
    PVOID original_ob_handle;      /* EAC's callback handle we overrode */

    /* ETW-TI detach state */
    PVOID etwti_reg_entry;         /* EAC's provider registration entry */
    UCHAR etwti_saved_enable_mask; /* saved before zeroing */

    /* NT syscall hook state */
    PVOID original_nt_read_vm;     /* saved pointer for restore on unload */
    PVOID trampoline_nt_read_vm;   /* allocated trampoline for the hook */

    /* VAD filter state */
    PVOID original_mi_locate_vad;
    PVOID trampoline_mi_locate_vad;

    /* Active flag — subsystems check this before filtering */
    volatile LONG active;
} BLINDER_CTX, *PBLINDER_CTX;

extern BLINDER_CTX g_blinder;

/* -------------------------- subsystem entry points ---------------------- */

/* Each hook subsystem lives in its own .c file. Install and uninstall
 * paths are symmetric. Install must be idempotent (safe to call twice).
 * Uninstall must leave the kernel in the exact state Install found it,
 * so the blinder can be hot-unloaded. */

/* nt_hooks.c — syscall-layer hooks for cross-proc memory reads */
NTSTATUS NtHooks_Install  (PBLINDER_CTX ctx);
NTSTATUS NtHooks_Uninstall(PBLINDER_CTX ctx);

/* ob_callback.c — neuter EAC's ObRegisterCallbacks handle-strip */
NTSTATUS ObCallback_Install  (PBLINDER_CTX ctx);
NTSTATUS ObCallback_Uninstall(PBLINDER_CTX ctx);

/* etwti.c — detach EAC's ETW-TI provider subscription */
NTSTATUS Etwti_Install  (PBLINDER_CTX ctx);
NTSTATUS Etwti_Uninstall(PBLINDER_CTX ctx);

/* vad_filter.c — filter EAC's VAD walker over the Fortnite process */
NTSTATUS VadFilter_Install  (PBLINDER_CTX ctx);
NTSTATUS VadFilter_Uninstall(PBLINDER_CTX ctx);

/* -------------------------- resolution helpers (utils.c) ---------------- */

/* Walk PsLoadedModuleList to find a driver by name. Returns base + size. */
NTSTATUS FindKernelModule(PCWSTR name, PVOID* out_base, PSIZE_T out_size);

/* Walk ActiveProcessLinks to find a process by image name. */
NTSTATUS FindProcessByImageName(PCSTR image_name, PHANDLE out_pid, PEPROCESS* out_eproc);

/* Resolve the core ntoskrnl APIs we need into ctx->apis.
 * Called once at DriverEntry; returns STATUS_SUCCESS if all resolved. */
NTSTATUS ResolveKernelApis(PRESOLVED_APIS apis);

/* Pattern scan a kernel module region for a byte+mask pattern.
 * Returns pointer in-module or NULL. Used by hook subsystems to find
 * un-exported internal functions (MiLocateVad, EtwpEnableTrace, etc). */
PVOID PatternScan(PVOID module_base, SIZE_T module_size,
                  const UCHAR* pattern, const CHAR* mask);

/* Check if the caller (current PEPROCESS) is EAC's driver/service.
 * Hook bodies use this to filter: "if EAC is asking, lie; otherwise
 * pass through to the original." */
BOOLEAN IsCallerEac(PBLINDER_CTX ctx);

/* Check if the target process is Fortnite (what we're hiding).
 * Returns TRUE if target_eproc == g_blinder.target.fortnite_eproc. */
BOOLEAN IsTargetFortnite(PBLINDER_CTX ctx, PEPROCESS target);

#endif /* EAC_BLINDER_H */

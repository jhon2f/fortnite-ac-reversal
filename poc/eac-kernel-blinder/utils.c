/*
 * utils.c — shared helpers for eac-kernel-blinder
 *
 * Nothing here filters EAC directly; this is the plumbing every other
 * subsystem leans on:
 *   - FindKernelModule         (ZwQuerySystemInformation walk)
 *   - FindProcessByImageName   (PID sweep + PsLookupProcessByProcessId)
 *   - ResolveKernelApis        (MmGetSystemRoutineAddress for each slot)
 *   - PatternScan              (IDA-style x/? mask)
 *   - IsCallerEac              (PEPROCESS match OR return-address in EAC range)
 *   - IsTargetFortnite         (PEPROCESS equality vs. ctx->target.fortnite_eproc)
 *
 * All ntoskrnl APIs used here are either resolved dynamically on first
 * use or come from the small set that is safe to static-link in a
 * mapped driver (MmGetSystemRoutineAddress, ExAllocatePool2,
 * ExFreePoolWithTag, PsGetCurrentProcess, _ReturnAddress, DbgPrintEx).
 */

#include "blinder.h"

/* ------------------------------------------------------------------ */
/* Private — SYSTEM_MODULE/SYSTEM_MODULE_INFORMATION mirror. These are */
/* documented but not exposed by ntifs.h, so we redeclare locally.    */
/* ------------------------------------------------------------------ */

#define SystemModuleInformationClass ((ULONG)11)

typedef struct _BLINDER_SYSTEM_MODULE {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} BLINDER_SYSTEM_MODULE, *PBLINDER_SYSTEM_MODULE;

typedef struct _BLINDER_SYSTEM_MODULE_INFORMATION {
    ULONG                 ModulesCount;
    BLINDER_SYSTEM_MODULE Modules[1];
} BLINDER_SYSTEM_MODULE_INFORMATION, *PBLINDER_SYSTEM_MODULE_INFORMATION;

/* case-insensitive suffix match: does ansi_path end with (wide) needle? */
static BOOLEAN AnsiEndsWithWideCI(const UCHAR* ansi_path, USHORT ansi_len, PCWSTR needle)
{
    SIZE_T needle_len = 0;
    SIZE_T i;
    const UCHAR* tail;

    if (ansi_path == NULL || needle == NULL) {
        return FALSE;
    }
    while (needle[needle_len] != L'\0') {
        needle_len++;
    }
    if ((SIZE_T)ansi_len < needle_len) {
        return FALSE;
    }
    tail = ansi_path + (ansi_len - needle_len);
    for (i = 0; i < needle_len; i++) {
        WCHAR a = (WCHAR)tail[i];
        WCHAR b = needle[i];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + (L'a' - L'A'));
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + (L'a' - L'A'));
        if (a != b) {
            return FALSE;
        }
    }
    return TRUE;
}

/* case-insensitive ANSI equality */
static BOOLEAN AnsiEqualCI(PCSTR a, PCSTR b)
{
    if (a == NULL || b == NULL) {
        return FALSE;
    }
    while (*a && *b) {
        CHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (CHAR)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (CHAR)(cb + ('a' - 'A'));
        if (ca != cb) {
            return FALSE;
        }
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

/* ------------------------------------------------------------------ */

/* Walk SystemModuleInformation, match file-name suffix against `name`. */
NTSTATUS FindKernelModule(PCWSTR name, PVOID* out_base, PSIZE_T out_size)
{
    NTSTATUS status;
    ULONG needed = 0;
    PBLINDER_SYSTEM_MODULE_INFORMATION info = NULL;
    PFN_ZwQuerySystemInformation ZwQSI;
    UNICODE_STRING routine;
    ULONG i;

    if (name == NULL || out_base == NULL || out_size == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *out_base = NULL;
    *out_size = 0;

    RtlInitUnicodeString(&routine, L"ZwQuerySystemInformation");
    ZwQSI = (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&routine);
    if (ZwQSI == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* First call: discover required buffer size. */
    status = ZwQSI(SystemModuleInformationClass, NULL, 0, &needed);
    if (needed == 0) {
        return (status == STATUS_SUCCESS) ? STATUS_UNSUCCESSFUL : status;
    }

    info = (PBLINDER_SYSTEM_MODULE_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, BLINDER_POOL_TAG);
    if (info == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQSI(SystemModuleInformationClass, info, needed, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(info, BLINDER_POOL_TAG);
        return status;
    }

    status = STATUS_NOT_FOUND;
    for (i = 0; i < info->ModulesCount; i++) {
        PBLINDER_SYSTEM_MODULE m = &info->Modules[i];
        const UCHAR* leaf = m->FullPathName + m->OffsetToFileName;
        USHORT leaf_len = 0;
        /* measure leaf; FullPathName is NUL-terminated inside the 256 cap */
        while (m->OffsetToFileName + leaf_len < sizeof(m->FullPathName) &&
               leaf[leaf_len] != '\0') {
            leaf_len++;
        }
        if (AnsiEndsWithWideCI(leaf, leaf_len, name)) {
            *out_base = m->ImageBase;
            *out_size = (SIZE_T)m->ImageSize;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExFreePoolWithTag(info, BLINDER_POOL_TAG);
    return status;
}

/* ------------------------------------------------------------------ */

/* Brute-sweep low PIDs; for each live process, compare its image name. */
NTSTATUS FindProcessByImageName(PCSTR image_name, PHANDLE out_pid, PEPROCESS* out_eproc)
{
    NTSTATUS status;
    PFN_PsLookupProcessByProcessId PsLookup;
    PFN_PsGetProcessImageFileName  PsGetImage;
    UNICODE_STRING r1, r2;
    ULONG_PTR pid;

    if (image_name == NULL || out_pid == NULL || out_eproc == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *out_pid = NULL;
    *out_eproc = NULL;

    RtlInitUnicodeString(&r1, L"PsLookupProcessByProcessId");
    RtlInitUnicodeString(&r2, L"PsGetProcessImageFileName");
    PsLookup   = (PFN_PsLookupProcessByProcessId)MmGetSystemRoutineAddress(&r1);
    PsGetImage = (PFN_PsGetProcessImageFileName) MmGetSystemRoutineAddress(&r2);
    if (PsLookup == NULL || PsGetImage == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* PIDs are multiples of 4 on Windows; 4..0x10000 covers everything
     * worth scanning for Fortnite / EAC-service without taking forever. */
    for (pid = 4; pid <= 0x10000; pid += 4) {
        PEPROCESS proc = NULL;
        PCHAR img;

        status = PsLookup((HANDLE)pid, &proc);
        if (!NT_SUCCESS(status) || proc == NULL) {
            continue;
        }

        img = PsGetImage(proc);
        if (img != NULL && AnsiEqualCI(img, image_name)) {
            *out_pid   = (HANDLE)pid;
            *out_eproc = proc;    /* caller inherits the reference */
            return STATUS_SUCCESS;
        }

        ObDereferenceObject(proc);
    }

    return STATUS_NOT_FOUND;
}

/* ------------------------------------------------------------------ */

/* Resolve each pointer in RESOLVED_APIS from ntoskrnl by name. */
NTSTATUS ResolveKernelApis(PRESOLVED_APIS apis)
{
    UNICODE_STRING n;

    if (apis == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(apis, sizeof(*apis));

    RtlInitUnicodeString(&n, L"ObRegisterCallbacks");
    apis->ObRegisterCallbacks = (PFN_ObRegisterCallbacks)MmGetSystemRoutineAddress(&n);

    RtlInitUnicodeString(&n, L"ObUnRegisterCallbacks");
    apis->ObUnRegisterCallbacks = (PFN_ObUnRegisterCallbacks)MmGetSystemRoutineAddress(&n);

    RtlInitUnicodeString(&n, L"PsGetProcessImageFileName");
    apis->PsGetProcessImageFileName = (PFN_PsGetProcessImageFileName)MmGetSystemRoutineAddress(&n);

    RtlInitUnicodeString(&n, L"PsLookupProcessByProcessId");
    apis->PsLookupProcessByProcessId = (PFN_PsLookupProcessByProcessId)MmGetSystemRoutineAddress(&n);

    RtlInitUnicodeString(&n, L"MmCopyVirtualMemory");
    apis->MmCopyVirtualMemory = (PFN_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&n);

    RtlInitUnicodeString(&n, L"ZwQuerySystemInformation");
    apis->ZwQuerySystemInformation = (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&n);

    /* Every slot is critical; any miss means we abort DriverEntry. */
    if (apis->ObRegisterCallbacks        == NULL ||
        apis->ObUnRegisterCallbacks      == NULL ||
        apis->PsGetProcessImageFileName  == NULL ||
        apis->PsLookupProcessByProcessId == NULL ||
        apis->MmCopyVirtualMemory        == NULL ||
        apis->ZwQuerySystemInformation   == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] ResolveKernelApis: one or more symbols missing\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */

/* Classic IDA-style sig scan: mask 'x' = exact byte, '?' = wildcard. */
PVOID PatternScan(PVOID module_base, SIZE_T module_size,
                  const UCHAR* pattern, const CHAR* mask)
{
    SIZE_T mask_len = 0;
    SIZE_T i;
    UCHAR* base;

    if (module_base == NULL || pattern == NULL || mask == NULL || module_size == 0) {
        return NULL;
    }
    while (mask[mask_len] != '\0') {
        mask_len++;
    }
    if (mask_len == 0 || mask_len > module_size) {
        return NULL;
    }

    base = (UCHAR*)module_base;
    for (i = 0; i <= module_size - mask_len; i++) {
        SIZE_T j;
        BOOLEAN hit = TRUE;
        for (j = 0; j < mask_len; j++) {
            if (mask[j] == 'x' && base[i + j] != pattern[j]) {
                hit = FALSE;
                break;
            }
        }
        if (hit) {
            return (PVOID)(base + i);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */

/* Is the caller frame inside EAC's address space? Two checks:
 *   1. PsGetCurrentProcess() == ctx->target.eac_service_eproc
 *   2. _ReturnAddress()      in [eac_driver_base, eac_driver_base+size)
 * If either holds, we treat the request as coming from EAC and the
 * subsystem hook body returns filtered data. */
BOOLEAN IsCallerEac(PBLINDER_CTX ctx)
{
    PEPROCESS cur;
    ULONG_PTR ret;
    ULONG_PTR lo, hi;

    if (ctx == NULL) {
        return FALSE;
    }

    cur = PsGetCurrentProcess();
    if (ctx->target.eac_service_eproc != NULL &&
        cur == ctx->target.eac_service_eproc) {
        return TRUE;
    }

    if (ctx->target.eac_driver_base == NULL || ctx->target.eac_driver_size == 0) {
        return FALSE;
    }

    ret = (ULONG_PTR)_ReturnAddress();
    lo  = (ULONG_PTR)ctx->target.eac_driver_base;
    hi  = lo + (ULONG_PTR)ctx->target.eac_driver_size;
    if (ret >= lo && ret < hi) {
        return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */

/* Pointer compare against the Fortnite PEPROCESS we discovered at
 * DriverEntry. Returns FALSE until that slot is populated. */
BOOLEAN IsTargetFortnite(PBLINDER_CTX ctx, PEPROCESS target)
{
    if (ctx == NULL || target == NULL) {
        return FALSE;
    }
    if (ctx->target.fortnite_eproc == NULL) {
        return FALSE;
    }
    return (target == ctx->target.fortnite_eproc) ? TRUE : FALSE;
}

/*
 * main.c — DriverEntry orchestration + IOCTL dispatch for the
 * RAGE-integrated EAC blinder.
 *
 * Sequence inside DriverEntry (ordering is load-bearing):
 *
 *   1. Zero g_blinder, stash self base/size from the DRIVER_OBJECT the
 *      RAGE mapper handed us.
 *   2. Resolve ntoskrnl exported APIs into ctx->apis.
 *   3. Resolve the undocumented ntoskrnl internals (PiDDB, MmUnloaded,
 *      ci hash bucket, ETW silo, PsLoadedModuleList, our KLDR entry).
 *   4. ForensicScrub_All — walk every needle in BLINDER_SCRUB_NEEDLES
 *      across every artifact channel. Run FIRST so nothing we do after
 *      can be rolled back by a scrub-and-restore race.
 *   5. Install the four counter-hook subsystems:
 *          NtHooks_Install, ObCallback_Install,
 *          Etwti_Install, VadFilter_Install.
 *      Any failure triggers Rollback and returns the subsystem's status.
 *   6. Create \\Device\\eac_blinder_ctl + \\DosDevices\\eac_blinder_ctl.
 *      Done BEFORE DKOM: the I/O manager's device directory is an
 *      independent object namespace from PsLoadedModuleList, so user-
 *      mode CreateFile(\\\\.\\eac_blinder_ctl) continues to work after
 *      we unlink our driver image from the loaded-module list.
 *   7. Register DriverUnload so a debug-time graceful unload still
 *      reverses everything.
 *   8. Dkom_HideSelf — unlink from PsLoadedModuleList, rename to
 *      BLINDER_COVER_NAME_W, insert our RUNTIME_FUNCTION table so
 *      RtlLookupFunctionEntry still resolves us.
 *
 * In practice the RAGE loader tears down the vuln driver immediately
 * after DriverEntry returns, so BlinderUnload rarely runs in the field.
 * We still implement it correctly for debug sessions driven by
 * sc.exe stop.
 */

#include "blinder.h"

/* ===================================================================== */
/*                            GLOBAL STATE                                */
/* ===================================================================== */

/* The one-and-only context instance referenced across every subsystem. */
BLINDER_CTX g_blinder;

/* IOCTL device name + symlink. */
#define CTRL_DEVICE_NAME_W    L"\\Device\\eac_blinder_ctl"
#define CTRL_SYMLINK_NAME_W   L"\\DosDevices\\eac_blinder_ctl"

static PDEVICE_OBJECT   g_ctrl_device          = NULL;
static UNICODE_STRING   g_ctrl_devname;
static UNICODE_STRING   g_ctrl_symname;
static BOOLEAN          g_ctrl_symlink_created = FALSE;

/* Mirror of vad_filter.c's static g_hide_range_count so the STATUS
 * IOCTL can report it without widening the subsystem's ABI. */
static volatile LONG    g_hide_range_count_mirror = 0;

/* Lifetime counter for hook-body invocations. The hook bodies themselves
 * live in nt_hooks.c / vad_filter.c and don't currently bump this slot —
 * it's exposed via STATUS as a hook that future diagnostic builds can
 * wire up without touching this file. */
static volatile LONG    g_hook_fires_total = 0;

/* ===================================================================== */
/*                            IOCTL CODES                                  */
/* ===================================================================== */

/* These MUST match loader_example.c byte-for-byte. */
#define IOCTL_BLINDER_ADD_HIDE_RANGE   \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLINDER_SET_FORTNITE_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLINDER_STATUS           \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLINDER_RESCRUB          \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Matches loader_example.c's BLINDER_STATUS exactly. */
#pragma pack(push, 1)
typedef struct _BLINDER_STATUS_OUT {
    ULONG   active_bitmask;
    ULONG64 fortnite_pid;
    ULONG64 eac_driver_base;
    ULONG   hook_fires_total;
    ULONG   hide_range_count;
} BLINDER_STATUS_OUT, *PBLINDER_STATUS_OUT;

/* Matches loader_example.c's HIDE_RANGE: { void*, uint64_t } */
typedef struct _BLINDER_HIDE_RANGE_IN {
    PVOID   start;
    ULONG64 size;
} BLINDER_HIDE_RANGE_IN, *PBLINDER_HIDE_RANGE_IN;
#pragma pack(pop)

/* ===================================================================== */
/*                            FORWARD DECLS                                */
/* ===================================================================== */

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD       BlinderUnload;
static DRIVER_DISPATCH     BlinderDispatchCreateClose;
static DRIVER_DISPATCH     BlinderDispatchDeviceControl;

static NTSTATUS CreateControlDevice(PDRIVER_OBJECT drv);
static VOID     DeleteControlDevice(VOID);
static VOID     RollbackInstalledSubsystems(PBLINDER_CTX ctx);
static NTSTATUS CompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR info);

/* ===================================================================== */
/*                            IRP HELPERS                                  */
/* ===================================================================== */

/* Centralised IRP completion — keeps the dispatcher short and
 * guarantees we never forget to set Information / IoStatus.Status. */
static NTSTATUS CompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR info)
{
    irp->IoStatus.Status      = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* IRP_MJ_CREATE / IRP_MJ_CLOSE — both succeed unconditionally. The
 * control device is unrestricted at this layer because the mapper
 * pipeline is expected to gate who can reach it with an SD / ACL
 * further up the stack. */
static NTSTATUS BlinderDispatchCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    return CompleteIrp(irp, STATUS_SUCCESS, 0);
}

/* ===================================================================== */
/*                            IOCTL DISPATCH                               */
/* ===================================================================== */

/* IRP_MJ_DEVICE_CONTROL — the user-mode control surface.
 * All four IOCTLs use METHOD_BUFFERED so AssociatedIrp.SystemBuffer
 * is the one buffer for both input and output. */
static NTSTATUS BlinderDispatchDeviceControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    ULONG  code     = sp->Parameters.DeviceIoControl.IoControlCode;
    ULONG  in_len   = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  out_len  = sp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID  sysbuf   = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info  = 0;

    UNREFERENCED_PARAMETER(dev);

    switch (code) {

    /* ---- Register a VA range to lie about in Fortnite's VAD tree. --- */
    case IOCTL_BLINDER_ADD_HIDE_RANGE:
    {
        PBLINDER_HIDE_RANGE_IN in = (PBLINDER_HIDE_RANGE_IN)sysbuf;
        if (in_len < sizeof(*in) || in == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = VadFilter_AddHiddenRange(in->start, (SIZE_T)in->size);
        if (NT_SUCCESS(status)) {
            InterlockedIncrement(&g_hide_range_count_mirror);
        }
        break;
    }

    /* ---- Tell the blinder which PID is Fortnite. ---- */
    case IOCTL_BLINDER_SET_FORTNITE_PID:
    {
        ULONG64  pid_in;
        HANDLE   pid;
        PEPROCESS eproc = NULL;

        if (in_len < sizeof(ULONG64) || sysbuf == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        pid_in = *(ULONG64*)sysbuf;
        pid    = (HANDLE)(ULONG_PTR)pid_in;

        if (g_blinder.apis.PsLookupProcessByProcessId == NULL) {
            status = STATUS_PROCEDURE_NOT_FOUND;
            break;
        }

        status = g_blinder.apis.PsLookupProcessByProcessId(pid, &eproc);
        if (!NT_SUCCESS(status) || eproc == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[blinder] SET_FORTNITE_PID: lookup pid=%llu "
                       "failed 0x%08X\n", pid_in, status);
            break;
        }

        /* Drop any prior Fortnite reference we were holding so the EPROC
         * we captured via the create-process notify (or an earlier IOCTL)
         * isn't leaked. */
        if (g_blinder.target.fortnite_eproc != NULL &&
            g_blinder.target.fortnite_eproc != eproc) {
            ObDereferenceObject(g_blinder.target.fortnite_eproc);
        }

        g_blinder.target.fortnite_pid   = pid;
        g_blinder.target.fortnite_eproc = eproc;   /* ref inherited */

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder] fortnite pid set via ioctl: pid=%llu eproc=%p\n",
                   pid_in, eproc);
        status = STATUS_SUCCESS;
        break;
    }

    /* ---- Marshal a snapshot of the blinder's state back to usermode. ---- */
    case IOCTL_BLINDER_STATUS:
    {
        PBLINDER_STATUS_OUT out = (PBLINDER_STATUS_OUT)sysbuf;
        if (out_len < sizeof(*out) || out == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlZeroMemory(out, sizeof(*out));
        out->active_bitmask   = (ULONG)g_blinder.active;
        out->fortnite_pid     = (ULONG64)(ULONG_PTR)g_blinder.target.fortnite_pid;
        out->eac_driver_base  = (ULONG64)(ULONG_PTR)g_blinder.target.eac_driver_base;
        out->hook_fires_total = (ULONG)g_hook_fires_total;
        out->hide_range_count = (ULONG)g_hide_range_count_mirror;
        info   = sizeof(*out);
        status = STATUS_SUCCESS;
        break;
    }

    /* ---- Re-run ForensicScrub_All — useful mid-session if the cheat
     * workflow swaps in a different vuln driver after initial init. ---- */
    case IOCTL_BLINDER_RESCRUB:
    {
        status = ForensicScrub_All(&g_blinder);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder] RESCRUB status=0x%08X\n", status);
        break;
    }

    default:
        /* Unknown IOCTL: return STATUS_INVALID_DEVICE_REQUEST (set above). */
        break;
    }

    return CompleteIrp(irp, status, info);
}

/* ===================================================================== */
/*                            DEVICE / SYMLINK                             */
/* ===================================================================== */

/* Build the control device + symlink. Called AFTER subsystems install
 * but BEFORE Dkom_HideSelf so the I/O manager still sees our normal
 * (not-yet-hidden) DriverObject when inserting into its directory. */
static NTSTATUS CreateControlDevice(PDRIVER_OBJECT drv)
{
    NTSTATUS status;

    RtlInitUnicodeString(&g_ctrl_devname, CTRL_DEVICE_NAME_W);
    RtlInitUnicodeString(&g_ctrl_symname, CTRL_SYMLINK_NAME_W);

    status = IoCreateDevice(drv, 0, &g_ctrl_devname,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_ctrl_device);
    if (!NT_SUCCESS(status) || g_ctrl_device == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] IoCreateDevice failed: 0x%08X\n", status);
        g_ctrl_device = NULL;
        return status;
    }

    /* METHOD_BUFFERED in every IOCTL — ok to route buffered I/O. */
    g_ctrl_device->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_ctrl_symname, &g_ctrl_devname);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_ctrl_device);
        g_ctrl_device = NULL;
        return status;
    }
    g_ctrl_symlink_created = TRUE;

    /* Swap out the stock dispatch table for our own. Only IRP_MJ_CREATE,
     * IRP_MJ_CLOSE and IRP_MJ_DEVICE_CONTROL are used; everything else
     * falls through to the default dispatcher which completes with
     * STATUS_INVALID_DEVICE_REQUEST. */
    drv->MajorFunction[IRP_MJ_CREATE]         = BlinderDispatchCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE]          = BlinderDispatchCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BlinderDispatchDeviceControl;

    /* Clear the DO_DEVICE_INITIALIZING bit so the I/O manager will
     * route IRPs to us immediately — otherwise the first CreateFile
     * sees STATUS_NO_SUCH_DEVICE. */
    g_ctrl_device->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] control device ready: %ws -> %ws\n",
               CTRL_SYMLINK_NAME_W, CTRL_DEVICE_NAME_W);
    return STATUS_SUCCESS;
}

/* Reverse of CreateControlDevice. Safe to call even on partial-create. */
static VOID DeleteControlDevice(VOID)
{
    if (g_ctrl_symlink_created) {
        IoDeleteSymbolicLink(&g_ctrl_symname);
        g_ctrl_symlink_created = FALSE;
    }
    if (g_ctrl_device != NULL) {
        IoDeleteDevice(g_ctrl_device);
        g_ctrl_device = NULL;
    }
}

/* ===================================================================== */
/*                            ROLLBACK                                     */
/* ===================================================================== */

/* Uninstall every subsystem in reverse of Install-order. Tolerant of
 * subsystems that were never successfully installed — each Uninstall
 * is documented idempotent. */
static VOID RollbackInstalledSubsystems(PBLINDER_CTX ctx)
{
    (VOID)ResponseFaker_Uninstall(ctx);
    (VOID)VadFilter_Uninstall(ctx);
    (VOID)Etwti_Uninstall(ctx);
    (VOID)ObCallback_Uninstall(ctx);
    (VOID)NtHooks_Uninstall(ctx);
}

/* ===================================================================== */
/*                            DriverUnload                                 */
/* ===================================================================== */

/* Debug-time graceful teardown. Reverses DriverEntry in strict LIFO
 * order so each step's preconditions are met at tear-down:
 *     unhide -> delete device -> uninstall hooks.
 *
 * Fortnite's mapper normally never reaches this path because it
 * zeroes the DriverObject's PDRIVER_UNLOAD slot on exit; keep it
 * correct anyway for sc.exe-driven dev loops. */
static VOID BlinderUnload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] unload starting\n");

    /* Re-link ourselves BEFORE anything else — otherwise IoDeleteDevice
     * would unlink a device owned by a driver the OS can't find. */
    (VOID)Dkom_UnhideSelf(&g_blinder);

    DeleteControlDevice();
    RollbackInstalledSubsystems(&g_blinder);
    VadFilter_ClearHiddenRanges();

    /* Drop the Fortnite reference we may have inherited via the IOCTL or
     * the create-process notify path. */
    if (g_blinder.target.fortnite_eproc != NULL) {
        ObDereferenceObject(g_blinder.target.fortnite_eproc);
        g_blinder.target.fortnite_eproc = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] unload complete\n");
}

/* ===================================================================== */
/*                            DriverEntry                                  */
/* ===================================================================== */

/* -----------------------------------------------------------------------
 * CRITICAL: RAGE's MSR LSTAR hijack calls DriverEntry from inside the
 * user-mode thread's syscall path (NtAddAtom is hijacked). That means:
 *   - PreviousMode = UserMode on KTHREAD
 *   - Syscall-dispatch state is live (locks held upstream)
 *   - CurrentThread is a user process's thread, not a system worker
 *
 * Any kernel API that (a) checks PreviousMode, (b) takes a lock also
 * held somewhere up the syscall path, or (c) assumes a clean system
 * context will deadlock or race → hang / WORKER_INVALID bugcheck
 * (0xE4 param1=1, "worker item queued twice").
 *
 * FIX: DriverEntry does ONLY two things:
 *   1. Capture self-image base + size (safe, no API calls).
 *   2. PsCreateSystemThread → run the real install on a clean system
 *      worker thread with PreviousMode=KernelMode, no caller locks,
 *      no user context. Then return STATUS_SUCCESS immediately so
 *      RAGE tears down the vuln driver cleanly.
 *
 * The system thread does everything: ResolveKernelApis,
 * ResolveKernelInternals, ForensicScrub, 4 hooks, ResponseFaker, DKOM.
 * Runs seconds after DriverEntry returns.
 * ----------------------------------------------------------------------- */

static VOID NTAPI BlinderDelayedInstall(PVOID ctx_in);

/* Entry point — now minimal. Does NOT call any kernel API that might
 * take a lock or check PreviousMode. Just: discover self, queue system
 * thread, return SUCCESS. The hijacked syscall unwinds cleanly. */
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path)
{
    NTSTATUS status;
    PBLINDER_CTX ctx = &g_blinder;
    HANDLE hThread = NULL;

    UNREFERENCED_PARAMETER(reg_path);

    /* ---------------- 1. zero context + stash our self range ---------- */
    RtlZeroMemory(ctx, sizeof(*ctx));

    /* RAGE's MSR LSTAR hijack calls DriverEntry via raw shellcode with
     * NULL DriverObject (there's no real I/O-manager object for a
     * manual-mapped driver). Fall back to self-discovery: scan backward
     * from a known-in-image address until we hit the MZ header, then
     * read SizeOfImage from the PE optional header. */
    if (drv == NULL || drv->DriverStart == NULL) {
        ULONG_PTR probe = (ULONG_PTR)&DriverEntry;
        ULONG_PTR base  = probe & ~((ULONG_PTR)0xFFF);
        ULONG e_lfanew;
        ULONG size_of_image;
        /* Walk backwards one page at a time looking for "MZ" */
        while (base > 0x10000 && *(USHORT*)base != 0x5A4D) {
            base -= 0x1000;
        }
        if (*(USHORT*)base != 0x5A4D) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        /* Parse PE headers inline (avoid pulling <ntimage.h> types).
         * DOS header: e_lfanew is at offset 0x3C (ULONG).
         * NT header: Signature(4) + FileHeader(20) → OptionalHeader at +24.
         * OptionalHeader (PE32+): SizeOfImage is at offset 0x38. */
        e_lfanew      = *(ULONG*)(base + 0x3C);
        size_of_image = *(ULONG*)(base + e_lfanew + 24 + 0x38);
        ctx->kernel.self_image_base = (PVOID)base;
        ctx->kernel.self_image_size = (SIZE_T)size_of_image;
    } else {
        ctx->kernel.self_image_base = drv->DriverStart;
        ctx->kernel.self_image_size = (SIZE_T)drv->DriverSize;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] DriverEntry: self=%p +0x%Ix (v%u.%u) — queuing system thread\n",
               ctx->kernel.self_image_base, ctx->kernel.self_image_size,
               BLINDER_VERSION_MAJOR, BLINDER_VERSION_MINOR);

    /* ---------------- 2. queue real install on a system thread -------
     * This is the fix for WORKER_INVALID (0xE4 param1=1) seen in prior
     * runs: ObRegisterCallbacks + inline hooks + anything taking locks
     * all failed from the hijacked syscall context. PsCreateSystemThread
     * is PASSIVE-level-safe, doesn't check PreviousMode, and the target
     * runs on a clean system thread. */
    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL,
                                  NULL, NULL, BlinderDelayedInstall, ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] PsCreateSystemThread failed: 0x%08X\n", status);
        return status;
    }
    /* Detach — thread runs independently; we never join it. */
    ZwClose(hThread);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] install thread queued — DriverEntry returning\n");
    return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * The real install. Runs on a dedicated system worker thread spawned by
 * DriverEntry. All kernel APIs behave correctly here.
 * ----------------------------------------------------------------------- */
static VOID NTAPI BlinderDelayedInstall(PVOID ctx_in)
{
    NTSTATUS status;
    PBLINDER_CTX ctx = (PBLINDER_CTX)ctx_in;
    PDRIVER_OBJECT drv = NULL;  /* No real DRIVER_OBJECT in manual-map case */

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] delayed install thread running — self=%p +0x%Ix\n",
               ctx->kernel.self_image_base, ctx->kernel.self_image_size);

    /* ---------------- 2. resolve exported ntoskrnl APIs --------------- */
    status = ResolveKernelApis(&ctx->apis);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:thread] ResolveKernelApis failed: 0x%08X\n", status);
        PsTerminateSystemThread(status);
        return;
    }

    /* ---------------- 3. resolve undocumented ntoskrnl internals ------
     * DIAGNOSTIC: skipped when BLINDER_DIAG is defined — isolates whether
     * ResolveKernelInternals or ForensicScrub_All is the hang. */
#ifndef BLINDER_DIAG
    status = ResolveKernelInternals(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder:thread] ResolveKernelInternals failed: 0x%08X\n", status);
        PsTerminateSystemThread(status);
        return;
    }

    status = ForensicScrub_All(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] ForensicScrub_All partial: 0x%08X\n", status);
    } else {
        InterlockedExchange(&ctx->active, ctx->active | 0x10);
    }
#else
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] DIAG: skipped ResolveKernelInternals + scrub\n");
#endif

    /* ---------------- 5. install the four hook subsystems ------------- */
#ifndef BLINDER_SKIP_NT
    status = NtHooks_Install(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] NtHooks_Install failed: 0x%08X\n", status);
        goto fail_rollback;
    }
#endif

#ifndef BLINDER_SKIP_OB
    status = ObCallback_Install(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] ObCallback_Install failed: 0x%08X\n", status);
        goto fail_rollback;
    }
#endif

#ifndef BLINDER_DIAG
    status = Etwti_Install(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] Etwti_Install soft-failed: 0x%08X\n", status);
    }

    status = VadFilter_Install(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] VadFilter_Install failed: 0x%08X\n", status);
        goto fail_rollback;
    }
#else
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] DIAG: skipped Etwti + VadFilter (pattern-scan subsystems)\n");
#endif

#ifndef BLINDER_DIAG
    status = ResponseFaker_Install(&g_blinder);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] ResponseFaker_Install soft-failed: 0x%x\n",
                   status);
    }
#else
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] DIAG: skipped ResponseFaker_Install\n");
#endif

    /* ---------------- 6. create user-mode control device -------------- */
    /* Needs a real DRIVER_OBJECT. Manual-mapped drivers (RAGE / MSR-LSTAR
     * hijack) pass NULL — skip device + unload in that case; hooks still
     * work, just no user-mode IOCTL control. User can rebuild with a
     * proxy DriverObject later if runtime config is needed. */
    if (drv != NULL) {
        status = CreateControlDevice(drv);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[blinder] CreateControlDevice soft-failed: 0x%08X "
                       "(hooks still active, IOCTL control unavailable)\n", status);
        } else {
            drv->DriverUnload = BlinderUnload;
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder] manual-map detected (NULL drv) — "
                   "skipping device creation + DriverUnload\n");
    }

    /* ---------------- 8. DKOM self-hide LAST --------------------------
     * DIAGNOSTIC: skipped when BLINDER_DIAG is defined. */
#ifndef BLINDER_DIAG
    status = Dkom_HideSelf(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] Dkom_HideSelf partial: 0x%08X\n", status);
    } else {
        InterlockedExchange(&ctx->active, ctx->active | 0x20);
    }
#else
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] DIAG: skipped Dkom_HideSelf\n");
#endif

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder:thread] integrated init complete v0.3 — active mask=0x%x\n",
               g_blinder.active);
    PsTerminateSystemThread(STATUS_SUCCESS);
    return;

fail_rollback:
    /* Abort path: undo everything we already did before returning the
     * failing status to the loader. */
    DeleteControlDevice();
    RollbackInstalledSubsystems(ctx);
    VadFilter_ClearHiddenRanges();
    /* If we somehow DKOM'd before failing, un-DKOM so the loader can
     * still enumerate us for diagnostic purposes. */
    (VOID)Dkom_UnhideSelf(ctx);
    PsTerminateSystemThread(status);
}

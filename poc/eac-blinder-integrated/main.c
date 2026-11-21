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

/* Entry point. The RAGE mapper's MSR-LSTAR shellcode routes here with a
 * live PDRIVER_OBJECT whose DriverStart / DriverSize describe our mapped
 * image. See the file-level comment above for the full step ordering. */
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path)
{
    NTSTATUS status;
    PBLINDER_CTX ctx = &g_blinder;

    UNREFERENCED_PARAMETER(reg_path);

    /* ---------------- 1. zero context + stash our self range ---------- */
    RtlZeroMemory(ctx, sizeof(*ctx));

    if (drv == NULL) {
        /* Should be impossible from the RAGE loader, but a NULL check
         * costs nothing and the Windows I/O manager contract guarantees
         * a non-NULL DriverObject only for legitimately-loaded drivers. */
        return STATUS_INVALID_PARAMETER;
    }

    ctx->kernel.self_image_base = drv->DriverStart;
    ctx->kernel.self_image_size = (SIZE_T)drv->DriverSize;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] DriverEntry: self=%p +0x%Ix (v%u.%u)\n",
               ctx->kernel.self_image_base, ctx->kernel.self_image_size,
               BLINDER_VERSION_MAJOR, BLINDER_VERSION_MINOR);

    /* ---------------- 2. resolve exported ntoskrnl APIs --------------- */
    status = ResolveKernelApis(&ctx->apis);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] ResolveKernelApis failed: 0x%08X\n", status);
        return status;
    }

    /* ---------------- 3. resolve undocumented ntoskrnl internals ------ */
    status = ResolveKernelInternals(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] ResolveKernelInternals failed: 0x%08X\n", status);
        return status;
    }

    /* ---------------- 4. forensic scrub FIRST -------------------------
     * Must happen before we leave any trace of our own — PiDDB entry,
     * MmUnloadedDrivers slot, ci.dll hash bucket, ETW ring buffer. The
     * needle list already contains our pre-rename module name so we
     * scrub ourselves alongside LnvMSRIO.sys et al. */
    status = ForensicScrub_All(ctx);
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: a partial scrub still leaves us in better shape
         * than nothing. Log and continue. */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] ForensicScrub_All partial: 0x%08X\n", status);
    } else {
        InterlockedExchange(&ctx->active, ctx->active | 0x10);
    }

    /* ---------------- 5. install the four hook subsystems ------------- */
    status = NtHooks_Install(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] NtHooks_Install failed: 0x%08X\n", status);
        goto fail_rollback;
    }

    status = ObCallback_Install(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] ObCallback_Install failed: 0x%08X\n", status);
        goto fail_rollback;
    }

    status = Etwti_Install(ctx);
    if (!NT_SUCCESS(status)) {
        /* ETW-TI mute is defense-in-depth on top of the scrub subsystem
         * — the scrub already dropped the EAC ring-buffer entries. We
         * log and continue rather than abort, so a resolver miss doesn't
         * strand the rest of the subsystems.
         *
         * TODO(policy): flip this to a hard abort if your build treats
         * ETW-TI as mandatory. */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] Etwti_Install soft-failed: 0x%08X "
                   "(scrub subsystem already covers this channel)\n", status);
    }

    status = VadFilter_Install(ctx);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] VadFilter_Install failed: 0x%08X\n", status);
        goto fail_rollback;
    }

    status = ResponseFaker_Install(&g_blinder);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] ResponseFaker_Install soft-failed: 0x%x\n",
                   status);
        /* Non-fatal -- partial fakers still help; continue init. */
    }

    /* ---------------- 6. create user-mode control device -------------- */
    status = CreateControlDevice(drv);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] CreateControlDevice failed: 0x%08X\n", status);
        goto fail_rollback;
    }

    /* ---------------- 7. register DriverUnload ------------------------ */
    drv->DriverUnload = BlinderUnload;

    /* ---------------- 8. DKOM self-hide LAST --------------------------
     * After this point our DriverObject still exists inside the I/O
     * manager's device directory (so \\\\.\\eac_blinder_ctl stays live),
     * but our KLDR_DATA_TABLE_ENTRY is unlinked from PsLoadedModuleList's
     * load + memory orders. RtlLookupFunctionEntry still resolves us
     * because Dkom_HideSelf inserts our runtime function table. */
    status = Dkom_HideSelf(ctx);
    if (!NT_SUCCESS(status)) {
        /* Non-fatal: keep running — we're still hidden from the loaded-
         * module enumerators that EAC uses most, we just left a load-
         * order link behind. Log and continue. */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[blinder] Dkom_HideSelf partial: 0x%08X\n", status);
    } else {
        InterlockedExchange(&ctx->active, ctx->active | 0x20);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] integrated init complete v0.3 — active mask=0x%x\n",
               g_blinder.active);
    return STATUS_SUCCESS;

fail_rollback:
    /* Abort path: undo everything we already did before returning the
     * failing status to the loader. */
    DeleteControlDevice();
    RollbackInstalledSubsystems(ctx);
    VadFilter_ClearHiddenRanges();
    /* If we somehow DKOM'd before failing, un-DKOM so the loader can
     * still enumerate us for diagnostic purposes. */
    (VOID)Dkom_UnhideSelf(ctx);
    return status;
}

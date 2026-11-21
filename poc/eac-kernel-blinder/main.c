/*
 * main.c — DriverEntry, DriverUnload, IOCTL dispatch for eac-kernel-blinder
 *
 * Owns the global BLINDER_CTX, orchestrates install / uninstall of all four
 * hook subsystems (nt_hooks, ob_callback, etwti, vad_filter) with staged
 * rollback, and exposes a control device at \Device\eac_blinder_ctl so a
 * user-mode loader / cheat can push hide-ranges and the target PID in at
 * runtime.
 *
 * See blinder.h for the shared type / API layout.
 */

#include "blinder.h"

/* ------------------------------------------------------------------- */
/* global blinder state — one per driver load                          */
/* ------------------------------------------------------------------- */

BLINDER_CTX g_blinder;

static PDEVICE_OBJECT g_device_obj      = NULL;
static BOOLEAN        g_symlink_created = FALSE;

static UNICODE_STRING g_device_name =
    RTL_CONSTANT_STRING(L"\\Device\\eac_blinder_ctl");
static UNICODE_STRING g_symlink_name =
    RTL_CONSTANT_STRING(L"\\DosDevices\\eac_blinder_ctl");

/* ------------------------------------------------------------------- */
/* IOCTL codes — FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, ANY access      */
/* ------------------------------------------------------------------- */

#define IOCTL_BLINDER_ADD_HIDE_RANGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLINDER_SET_FORTNITE_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLINDER_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ------------------------------------------------------------------- */
/* IOCTL payload layouts — kept simple, fixed-width so a 32-bit user-  */
/* mode loader can speak the same wire format as a 64-bit one.         */
/* ------------------------------------------------------------------- */

typedef struct _BLINDER_HIDE_RANGE_REQ {
    ULONG64 base;
    ULONG64 size;
} BLINDER_HIDE_RANGE_REQ;

typedef struct _BLINDER_SET_PID_REQ {
    ULONG64 pid;
} BLINDER_SET_PID_REQ;

typedef struct _BLINDER_STATUS_RESP {
    ULONG   active;
    ULONG   hook_count;
    ULONG64 fortnite_pid;
    ULONG64 eac_service_pid;
    ULONG64 eac_driver_base;
} BLINDER_STATUS_RESP;

/* Exposed by vad_filter.c — lets the user-mode IOCTL path register a
 * memory range the VAD walker should lie about on a per-ctx basis. */
extern NTSTATUS VadFilter_AddHiddenRange(PBLINDER_CTX ctx,
                                         ULONG64 base, ULONG64 size);

/* forward declarations for the dispatch table */
DRIVER_UNLOAD   BlinderUnload;
DRIVER_DISPATCH BlinderDispatchGeneric;
DRIVER_DISPATCH BlinderDispatchIoctl;

/* ------------------------------------------------------------------- */

/* Generic create / close / cleanup handler — just complete STATUS_SUCCESS
 * so a user-mode CreateFile() on \\.\eac_blinder_ctl returns a handle. */
static NTSTATUS BlinderDispatchGeneric(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* IOCTL handler — user-mode asks us to add a VAD-hide range, bind the
 * Fortnite PID, or query current blinder status. All paths validate
 * input / output lengths before touching SystemBuffer. */
static NTSTATUS BlinderDispatchIoctl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    ULONG     code    = isl->Parameters.DeviceIoControl.IoControlCode;
    ULONG     in_len  = isl->Parameters.DeviceIoControl.InputBufferLength;
    ULONG     out_len = isl->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID     buf     = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS  st      = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info    = 0;

    UNREFERENCED_PARAMETER(dev);

    switch (code) {

    case IOCTL_BLINDER_ADD_HIDE_RANGE: {
        BLINDER_HIDE_RANGE_REQ* r;
        if (in_len < sizeof(*r) || !buf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        r  = (BLINDER_HIDE_RANGE_REQ*)buf;
        st = VadFilter_AddHiddenRange(&g_blinder, r->base, r->size);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] add_hide_range base=0x%llx size=0x%llx st=0x%x\n",
                   r->base, r->size, st);
        break;
    }

    case IOCTL_BLINDER_SET_FORTNITE_PID: {
        BLINDER_SET_PID_REQ* r;
        PEPROCESS eproc = NULL;
        if (in_len < sizeof(*r) || !buf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        r  = (BLINDER_SET_PID_REQ*)buf;
        st = g_blinder.apis.PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)r->pid, &eproc);
        if (NT_SUCCESS(st)) {
            PEPROCESS old = g_blinder.target.fortnite_eproc;
            g_blinder.target.fortnite_pid   = (HANDLE)(ULONG_PTR)r->pid;
            g_blinder.target.fortnite_eproc = eproc;
            if (old) ObDereferenceObject(old);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                       "[blinder] fortnite pid=%llu bound eproc=%p\n",
                       r->pid, eproc);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                       "[blinder] set_fortnite_pid lookup failed 0x%x\n", st);
        }
        break;
    }

    case IOCTL_BLINDER_STATUS: {
        BLINDER_STATUS_RESP* r;
        if (out_len < sizeof(*r) || !buf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        r = (BLINDER_STATUS_RESP*)buf;
        RtlZeroMemory(r, sizeof(*r));
        r->active = (ULONG)g_blinder.active;
        /* hook_count = number of subsystems whose Install succeeded */
        r->hook_count = 0;
        if (g_blinder.trampoline_nt_read_vm)    r->hook_count++;
        if (g_blinder.ob_callback_handle)       r->hook_count++;
        if (g_blinder.etwti_reg_entry)          r->hook_count++;
        if (g_blinder.trampoline_mi_locate_vad) r->hook_count++;
        r->fortnite_pid    = (ULONG64)(ULONG_PTR)g_blinder.target.fortnite_pid;
        r->eac_service_pid = (ULONG64)(ULONG_PTR)g_blinder.target.eac_service_pid;
        r->eac_driver_base = (ULONG64)(ULONG_PTR)g_blinder.target.eac_driver_base;
        info = sizeof(*r);
        st   = STATUS_SUCCESS;
        break;
    }

    default:
        /* unknown control code — leave st = STATUS_INVALID_DEVICE_REQUEST */
        break;
    }

    irp->IoStatus.Status      = st;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

/* Tear down everything DriverEntry put up, in reverse install order,
 * so each subsystem sees the kernel in the state it put it in. */
static VOID BlinderUnload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);

    InterlockedExchange(&g_blinder.active, 0);

    VadFilter_Uninstall  (&g_blinder);
    Etwti_Uninstall      (&g_blinder);
    ObCallback_Uninstall (&g_blinder);
    NtHooks_Uninstall    (&g_blinder);

    if (g_symlink_created) {
        IoDeleteSymbolicLink(&g_symlink_name);
        g_symlink_created = FALSE;
    }
    if (g_device_obj) {
        IoDeleteDevice(g_device_obj);
        g_device_obj = NULL;
    }

    if (g_blinder.target.fortnite_eproc)
        ObDereferenceObject(g_blinder.target.fortnite_eproc);
    if (g_blinder.target.eac_service_eproc)
        ObDereferenceObject(g_blinder.target.eac_service_eproc);

    RtlZeroMemory(&g_blinder, sizeof(g_blinder));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[blinder] unloaded cleanly\n");
}

/* DriverEntry — resolves APIs, finds the EAC driver, installs all four
 * hook subsystems with rollback on partial failure, then stands up the
 * \Device\eac_blinder_ctl control channel for user-mode. Returns a
 * failure NTSTATUS if the kernel is in no state to run the blinder
 * (EAC not yet loaded, API resolution broken, hook install refused). */
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path)
{
    NTSTATUS st;

    UNREFERENCED_PARAMETER(reg_path);
    RtlZeroMemory(&g_blinder, sizeof(g_blinder));

    st = ResolveKernelApis(&g_blinder.apis);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] ResolveKernelApis failed 0x%x\n", st);
        return st;
    }

    st = FindKernelModule(EAC_DRIVER_NAME_W,
                          &g_blinder.target.eac_driver_base,
                          &g_blinder.target.eac_driver_size);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] EAC driver not loaded yet (0x%x) — refusing\n",
                   st);
        return STATUS_NOT_FOUND;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
               "[blinder] EAC @ %p size=0x%zx\n",
               g_blinder.target.eac_driver_base,
               g_blinder.target.eac_driver_size);

    /* TODO: the EAC service process image name varies by shipped build
     * (EasyAntiCheat.exe / EasyAntiCheat_EOS.exe / service host). Leave
     * both pids at 0 here; a Ps-notify routine in a sibling file fills
     * them when the processes appear, and user-mode can also push the
     * Fortnite pid in via IOCTL_BLINDER_SET_FORTNITE_PID. */

    /* staged install with rollback — each failure unwinds the previous
     * successes before bailing, so we never leave half-hooked state */
    st = NtHooks_Install(&g_blinder);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] NtHooks_Install failed 0x%x\n", st);
        goto fail;
    }

    st = ObCallback_Install(&g_blinder);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] ObCallback_Install failed 0x%x\n", st);
        NtHooks_Uninstall(&g_blinder);
        goto fail;
    }

    st = Etwti_Install(&g_blinder);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] Etwti_Install failed 0x%x\n", st);
        ObCallback_Uninstall(&g_blinder);
        NtHooks_Uninstall(&g_blinder);
        goto fail;
    }

    st = VadFilter_Install(&g_blinder);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] VadFilter_Install failed 0x%x\n", st);
        Etwti_Uninstall(&g_blinder);
        ObCallback_Uninstall(&g_blinder);
        NtHooks_Uninstall(&g_blinder);
        goto fail;
    }

    InterlockedExchange(&g_blinder.active, 1);

    /* stand up the control device for user-mode */
    st = IoCreateDevice(drv, 0, &g_device_name, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_obj);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] IoCreateDevice failed 0x%x\n", st);
        goto fail_full;
    }

    st = IoCreateSymbolicLink(&g_symlink_name, &g_device_name);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
                   "[blinder] IoCreateSymbolicLink failed 0x%x\n", st);
        IoDeleteDevice(g_device_obj);
        g_device_obj = NULL;
        goto fail_full;
    }
    g_symlink_created = TRUE;

    drv->MajorFunction[IRP_MJ_CREATE]         = BlinderDispatchGeneric;
    drv->MajorFunction[IRP_MJ_CLOSE]          = BlinderDispatchGeneric;
    drv->MajorFunction[IRP_MJ_CLEANUP]        = BlinderDispatchGeneric;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BlinderDispatchIoctl;
    drv->DriverUnload                         = BlinderUnload;

    g_device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
               "[blinder] v%u.%u up — 4 subsystems live, ctl device ready\n",
               BLINDER_VERSION_MAJOR, BLINDER_VERSION_MINOR);
    return STATUS_SUCCESS;

fail_full:
    VadFilter_Uninstall  (&g_blinder);
    Etwti_Uninstall      (&g_blinder);
    ObCallback_Uninstall (&g_blinder);
    NtHooks_Uninstall    (&g_blinder);
    InterlockedExchange(&g_blinder.active, 0);
fail:
    RtlZeroMemory(&g_blinder, sizeof(g_blinder));
    return st;
}

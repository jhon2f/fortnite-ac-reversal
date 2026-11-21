/*
 * ob_callback.c — neuter EAC's ObRegisterCallbacks handle-strip
 *
 * EAC registers an ObRegisterCallbacks pre-op callback on PsProcessType
 * whose body strips PROCESS_VM_READ / PROCESS_VM_WRITE / PROCESS_VM_OPERATION
 * / PROCESS_QUERY_INFORMATION from any handle opened against the Fortnite
 * process by a caller that isn't EAC itself. That's how EAC breaks
 * usermode cheats that rely on OpenProcess + ReadProcessMemory.
 *
 * Strategy: register OUR OWN callback at altitude 395000 — just above
 * EAC's search range (350000..390000) — which guarantees we run AFTER
 * EAC in the pre-op chain. EAC strips the rights; we put them back for
 * everyone-except-EAC. EAC's own queries still see stripped rights,
 * so EAC's internal state machine is undisturbed.
 *
 * Also registers a PsSetCreateProcessNotifyRoutineEx so we learn
 * Fortnite's PEPROCESS as soon as it launches — the Ob callback is a
 * no-op pass-through until we have it.
 */

#include "blinder.h"

/* Rights EAC's callback is known to strip. We restore exactly these,
 * no more — so we don't accidentally hand out rights the OS itself
 * refused upstream. */
/* Access-rights constants (not in <ntifs.h>; defined manually for kernel) */
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION        0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ             0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE            0x0020
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif

#define EAC_STRIPPED_PROCESS_RIGHTS  ( PROCESS_VM_READ          \
                                     | PROCESS_VM_WRITE         \
                                     | PROCESS_VM_OPERATION     \
                                     | PROCESS_QUERY_INFORMATION)

/* Our altitude: one tick above the top of EAC's search range so we
 * are guaranteed to be invoked AFTER EAC's callback. Altitude strings
 * are decimal ASCII per the Ob callback spec. */
#define BLINDER_OB_ALTITUDE_W   L"395000"

/* Forward declarations */
static OB_PREOP_CALLBACK_STATUS ObPreOp_ProcessHandle(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

static VOID NTAPI ObCallback_ProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/* Module-local flag: set once we've registered the create-process
 * notify routine. Needed because PsSetCreateProcessNotifyRoutineEx
 * must be matched 1:1 with a remove call using the same routine. */
static volatile LONG g_process_notify_registered = 0;

/* -------- create-process notify: learn Fortnite's EPROCESS ---------- */

/*
 * Called by the OS on every process create/destroy. We use it to pick
 * up the Fortnite PEPROCESS the moment it starts, and to clear our
 * saved pointer when it exits (so a stale pointer is never used to
 * "restore" rights against a reused EPROCESS address).
 */
static VOID NTAPI ObCallback_ProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PCHAR image_name;

    if (CreateInfo == NULL) {
        /* Process exit: if it's our tracked Fortnite, drop state. */
        if (Process != NULL && Process == g_blinder.target.fortnite_eproc) {
            g_blinder.target.fortnite_eproc = NULL;
            g_blinder.target.fortnite_pid = NULL;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[blinder] fortnite process exited, state cleared\n");
        }
        return;
    }

    /* Process create. Match by image name via resolved API. */
    if (g_blinder.apis.PsGetProcessImageFileName == NULL) {
        return;
    }

    image_name = g_blinder.apis.PsGetProcessImageFileName(Process);
    if (image_name == NULL) {
        return;
    }

    /* PsGetProcessImageFileName returns a truncated-to-15-char name.
     * Compare against the first 15 bytes of the Fortnite image name. */
    if (RtlCompareMemory(image_name, FORTNITE_IMAGE_NAME_A, 15) == 15) {
        g_blinder.target.fortnite_eproc = Process;
        g_blinder.target.fortnite_pid = ProcessId;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[blinder] fortnite acquired: pid=%p eproc=%p\n",
                   ProcessId, Process);
    }
}

/* -------- Ob pre-operation callback: restore stripped rights ------- */

/*
 * Pre-operation callback on PsProcessType. Runs after EAC's callback
 * (because our altitude is higher). We look at the DESIRED_ACCESS that
 * EAC left on the request and, if it's a handle being opened against
 * Fortnite by a non-EAC caller, OR the stripped rights back in.
 */
static OB_PREOP_CALLBACK_STATUS ObPreOp_ProcessHandle(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    PEPROCESS target_proc;
    ACCESS_MASK* desired_access;

    UNREFERENCED_PARAMETER(RegistrationContext);

    /* Driver loaded but not armed yet — do nothing. */
    if (InterlockedCompareExchange(&g_blinder.active, 0, 0) == 0) {
        return OB_PREOP_SUCCESS;
    }

    /* Only interested in handles on process objects. The registration
     * filters this already, but re-check cheaply. */
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    /* Kernel handles are the OS itself; never meddle with them. */
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    target_proc = (PEPROCESS)OperationInformation->Object;
    if (target_proc == NULL) {
        return OB_PREOP_SUCCESS;
    }

    /* Only touch requests targeting Fortnite. Everything else: pass. */
    if (!IsTargetFortnite(&g_blinder, target_proc)) {
        return OB_PREOP_SUCCESS;
    }

    /* If EAC is the caller, we DON'T restore — EAC's own code paths
     * must continue to see what EAC itself stripped, otherwise EAC's
     * state machine derails. We only lie to everyone else. */
    if (IsCallerEac(&g_blinder)) {
        return OB_PREOP_SUCCESS;
    }

    /* Pick the right access-mask field for the op. */
    switch (OperationInformation->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        desired_access = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        break;
    case OB_OPERATION_HANDLE_DUPLICATE:
        desired_access = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        break;
    default:
        return OB_PREOP_SUCCESS;
    }

    /*
     * TODO(cheat-plug-in): a real cheat would consult its own policy
     * here — e.g. only restore rights for its own usermode agent
     * process, not globally. For PoC we restore for anyone-not-EAC.
     * The infrastructure above (altitude, operation routing, caller
     * check, target check) is the real part.
     */
    *desired_access |= EAC_STRIPPED_PROCESS_RIGHTS;

    return OB_PREOP_SUCCESS;
}

/* -------- Install / Uninstall --------------------------------------- */

/*
 * Register our ObRegisterCallbacks at altitude 395000 (above EAC's
 * 350000..390000 band) plus a create-process notify so we track the
 * Fortnite PEPROCESS. Idempotent: an existing registration is torn
 * down first.
 */
NTSTATUS ObCallback_Install(PBLINDER_CTX ctx)
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION reg;
    OB_OPERATION_REGISTRATION op_reg;
    UNICODE_STRING altitude;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ctx->apis.ObRegisterCallbacks == NULL ||
        ctx->apis.ObUnRegisterCallbacks == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Idempotency: if we're already registered, tear down first. */
    if (ctx->ob_callback_handle != NULL) {
        ctx->apis.ObUnRegisterCallbacks(ctx->ob_callback_handle);
        ctx->ob_callback_handle = NULL;
    }

    RtlZeroMemory(&op_reg, sizeof(op_reg));
    op_reg.ObjectType = PsProcessType;
    op_reg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op_reg.PreOperation = ObPreOp_ProcessHandle;
    op_reg.PostOperation = NULL;

    RtlInitUnicodeString(&altitude, BLINDER_OB_ALTITUDE_W);

    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.Altitude = altitude;
    reg.RegistrationContext = ctx;
    reg.OperationRegistration = &op_reg;

    status = ctx->apis.ObRegisterCallbacks(&reg, &ctx->ob_callback_handle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[blinder] ObRegisterCallbacks failed: 0x%08X\n", status);
        ctx->ob_callback_handle = NULL;
        return status;
    }

    /* Register create-process notify once. PsSetCreateProcessNotifyRoutineEx
     * is a static-link-ok export, so we don't go through ctx->apis for it. */
    if (InterlockedCompareExchange(&g_process_notify_registered, 1, 0) == 0) {
        status = PsSetCreateProcessNotifyRoutineEx(ObCallback_ProcessNotify, FALSE);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[blinder] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n",
                       status);
            /* Roll back the Ob registration so Install is all-or-nothing. */
            ctx->apis.ObUnRegisterCallbacks(ctx->ob_callback_handle);
            ctx->ob_callback_handle = NULL;
            InterlockedExchange(&g_process_notify_registered, 0);
            return status;
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] Ob callback installed at altitude %ws, handle=%p\n",
               BLINDER_OB_ALTITUDE_W, ctx->ob_callback_handle);

    return STATUS_SUCCESS;
}

/*
 * Reverse of Install: unregister the Ob callback and remove the
 * create-process notify. Safe to call even if Install never ran or
 * only partially succeeded.
 */
NTSTATUS ObCallback_Uninstall(PBLINDER_CTX ctx)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (ctx == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ctx->ob_callback_handle != NULL &&
        ctx->apis.ObUnRegisterCallbacks != NULL) {
        ctx->apis.ObUnRegisterCallbacks(ctx->ob_callback_handle);
        ctx->ob_callback_handle = NULL;
    }

    if (InterlockedCompareExchange(&g_process_notify_registered, 0, 1) == 1) {
        NTSTATUS rm_status = PsSetCreateProcessNotifyRoutineEx(
            ObCallback_ProcessNotify, TRUE);
        if (!NT_SUCCESS(rm_status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[blinder] PsSetCreateProcessNotifyRoutineEx remove "
                       "failed: 0x%08X\n", rm_status);
            /* Put the flag back — we failed to remove, so we're still
             * registered from the OS's point of view. */
            InterlockedExchange(&g_process_notify_registered, 1);
            status = rm_status;
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[blinder] Ob callback uninstalled, status=0x%08X\n", status);

    return status;
}

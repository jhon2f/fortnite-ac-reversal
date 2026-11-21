/*
 * thread_test.c — spawns a system thread that LITERALLY DOES NOTHING
 * except terminate. Isolates whether PsCreateSystemThread itself from
 * the RAGE hijacked-syscall context triggers 0xE4, vs whether it's
 * the work our thread was doing.
 */
#include <ntifs.h>

static VOID NTAPI EmptyThread(PVOID ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    HANDLE h = NULL;
    UNREFERENCED_PARAMETER(drv);
    UNREFERENCED_PARAMETER(reg);
    NTSTATUS st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                        EmptyThread, NULL);
    if (NT_SUCCESS(st)) ZwClose(h);
    return STATUS_SUCCESS;
}

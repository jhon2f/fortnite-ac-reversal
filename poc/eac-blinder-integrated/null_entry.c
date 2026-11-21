/*
 * null_entry.c — absolute-minimum DriverEntry. Returns STATUS_SUCCESS
 * immediately. If THIS hangs when mapped, the hang is in the mapper's
 * post-entry handling, not in our code. If this returns clean, the
 * hang in the real DriverEntry is in Resolve/Hooks/etc.
 *
 * Build standalone (replaces main.c for the null test):
 *   cl /nologo /c /O2 /W3 /kernel /GS- /D_WIN64 /D_AMD64_ /DAMD64 \
 *      /D_X86_AMD64_ /DWIN32_LEAN_AND_MEAN /D_WINNT \
 *      /I"<WDK>/km" /I"<WDK>/shared" null_entry.c
 *   link /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE,10.0 /NODEFAULTLIB \
 *        /MACHINE:X64 null_entry.obj <WDK>/km/x64/ntoskrnl.lib \
 *        /OUT:rage_drv_NULL.sys
 */

#include <ntifs.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(drv);
    UNREFERENCED_PARAMETER(reg_path);
    return STATUS_SUCCESS;
}

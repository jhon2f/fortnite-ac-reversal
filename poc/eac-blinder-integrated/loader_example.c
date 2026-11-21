/*
 * loader_example.c — minimal user-mode control app for eac_blinder.sys
 *
 * Connects to the blinder's control device, sets Fortnite's PID, and
 * registers hide ranges. Does NOT map the driver — you need your own
 * BYOVD mapper for that (see README.md).
 *
 * Build:
 *   cl /O2 /DUNICODE /D_UNICODE loader_example.c /Fe:blinder_ctl.exe ^
 *      /link advapi32.lib kernel32.lib
 *
 * Usage:
 *   blinder_ctl.exe status
 *   blinder_ctl.exe set-pid <pid>
 *   blinder_ctl.exe hide <hex-address> <hex-size>
 *   blinder_ctl.exe clear-ranges
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* These MUST match main.c's IOCTL codes exactly */
#define IOCTL_BLINDER_ADD_HIDE_RANGE   \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLINDER_SET_FORTNITE_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLINDER_STATUS           \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
    uint32_t active_bitmask;      /* bit 0=nt_hooks, 1=ob, 2=etwti, 3=vad */
    uint64_t fortnite_pid;
    uint64_t eac_driver_base;
    uint32_t hook_fires_total;
    uint32_t hide_range_count;
} BLINDER_STATUS;

typedef struct {
    void*  start;
    uint64_t size;
} HIDE_RANGE;

/* -------------------------- helpers ------------------------------------- */

static HANDLE open_blinder(void)
{
    HANDLE h = CreateFileW(L"\\\\.\\eac_blinder_ctl",
                           GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "blinder not loaded? CreateFile: %lu\n", GetLastError());
        return NULL;
    }
    return h;
}

static DWORD find_pid_by_name(const wchar_t* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* -------------------------- commands ------------------------------------ */

static int cmd_status(HANDLE h)
{
    BLINDER_STATUS s = { 0 };
    DWORD br = 0;
    if (!DeviceIoControl(h, IOCTL_BLINDER_STATUS, NULL, 0,
                         &s, sizeof(s), &br, NULL)) {
        fprintf(stderr, "STATUS ioctl failed: %lu\n", GetLastError());
        return 1;
    }
    printf("active_bitmask   : 0x%02x  (bits: nt=%d ob=%d etwti=%d vad=%d)\n",
           s.active_bitmask,
           !!(s.active_bitmask & 0x1), !!(s.active_bitmask & 0x2),
           !!(s.active_bitmask & 0x4), !!(s.active_bitmask & 0x8));
    printf("fortnite_pid     : %llu\n",  s.fortnite_pid);
    printf("eac_driver_base  : 0x%llx\n", s.eac_driver_base);
    printf("hook_fires_total : %u\n",    s.hook_fires_total);
    printf("hide_range_count : %u\n",    s.hide_range_count);
    return 0;
}

static int cmd_set_pid(HANDLE h, const wchar_t* arg)
{
    DWORD pid = 0;
    if (_wcsicmp(arg, L"fortnite") == 0) {
        pid = find_pid_by_name(L"FortniteClient-Win64-Shipping.exe");
        if (pid == 0) {
            fprintf(stderr, "FortniteClient-Win64-Shipping.exe not running\n");
            return 1;
        }
        wprintf(L"resolved Fortnite PID = %u\n", pid);
    } else {
        pid = (DWORD)_wtoi(arg);
    }
    uint64_t pid64 = pid;
    DWORD br = 0;
    if (!DeviceIoControl(h, IOCTL_BLINDER_SET_FORTNITE_PID,
                         &pid64, sizeof(pid64), NULL, 0, &br, NULL)) {
        fprintf(stderr, "SET_FORTNITE_PID ioctl failed: %lu\n", GetLastError());
        return 1;
    }
    printf("blinder now tracking PID %u\n", pid);
    return 0;
}

static int cmd_hide(HANDLE h, const wchar_t* addr_s, const wchar_t* size_s)
{
    HIDE_RANGE r = { 0 };
    r.start = (void*)(uintptr_t)wcstoull(addr_s, NULL, 16);
    r.size  = wcstoull(size_s, NULL, 16);
    DWORD br = 0;
    if (!DeviceIoControl(h, IOCTL_BLINDER_ADD_HIDE_RANGE,
                         &r, sizeof(r), NULL, 0, &br, NULL)) {
        fprintf(stderr, "ADD_HIDE_RANGE ioctl failed: %lu\n", GetLastError());
        return 1;
    }
    printf("added hide range: %p + 0x%llx\n", r.start, r.size);
    return 0;
}

static void usage(const wchar_t* argv0)
{
    fwprintf(stderr,
        L"usage:\n"
        L"  %ls status\n"
        L"  %ls set-pid <pid|fortnite>\n"
        L"  %ls hide <hex-address> <hex-size>\n",
        argv0, argv0, argv0);
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }

    HANDLE h = open_blinder();
    if (!h) return 2;

    int rc = 1;
    if (!wcscmp(argv[1], L"status")) {
        rc = cmd_status(h);
    } else if (!wcscmp(argv[1], L"set-pid") && argc >= 3) {
        rc = cmd_set_pid(h, argv[2]);
    } else if (!wcscmp(argv[1], L"hide") && argc >= 4) {
        rc = cmd_hide(h, argv[2], argv[3]);
    } else {
        /* Note: clear-ranges IOCTL is reserved but not yet implemented
         * in main.c — add it there if you need runtime range clearing. */
        usage(argv[0]);
    }

    CloseHandle(h);
    return rc;
}

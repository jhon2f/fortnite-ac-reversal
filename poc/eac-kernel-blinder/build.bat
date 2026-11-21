@echo off
rem Build eac_blinder.sys from Windows Driver Kit (WDK) 10 + VS 2022.
rem
rem Prereqs:
rem   1. Install Visual Studio 2022 with Desktop C++ workload
rem   2. Install Windows SDK 10 (comes with VS)
rem   3. Install Windows Driver Kit 10 (WDK) via VS installer
rem   4. Open "x64 Native Tools Command Prompt for VS 2022"
rem   5. Run this script from the poc/eac-kernel-blinder directory

setlocal

if "%WindowsSdkDir%"=="" (
    echo ERROR: Windows SDK not in environment. Open the x64 Native Tools
    echo        Command Prompt for VS 2022 and re-run from there.
    exit /b 1
)

rem Locate WDK includes/libs. Adjust the version if yours differs.
for /f "delims=" %%v in ('dir /b /ad /on "%WindowsSdkDir%Include\10.0.*"') do set SDK_VER=%%v
if "%SDK_VER%"=="" (
    echo ERROR: No Windows SDK 10 includes found under %WindowsSdkDir%Include
    exit /b 1
)

set WDK_INC=%WindowsSdkDir%Include\%SDK_VER%
set WDK_LIB=%WindowsSdkDir%Lib\%SDK_VER%

set INCLUDES=/I"%WDK_INC%\km" /I"%WDK_INC%\km\crt" /I"%WDK_INC%\shared" /I"%WDK_INC%\ucrt"
set LIBS="%WDK_LIB%\km\x64\ntoskrnl.lib" "%WDK_LIB%\km\x64\hal.lib" "%WDK_LIB%\km\x64\BufferOverflowFastFailK.lib"

rem Compile each .c to .obj
set CFLAGS=/nologo /c /O2 /W3 /kernel /GS- /Zc:wchar_t /D_WIN64 /D_AMD64_ /DAMD64 /D_X86_AMD64_ /DWIN32_LEAN_AND_MEAN /D_WINNT
set CFLAGS=%CFLAGS% /D__INTRINSIC_GROUP_WIN_BASE=1

for %%f in (main.c nt_hooks.c ob_callback.c etwti.c vad_filter.c utils.c) do (
    echo [cl] %%f
    cl %CFLAGS% %INCLUDES% %%f
    if errorlevel 1 (
        echo BUILD FAILED on %%f
        exit /b 1
    )
)

rem Link into eac_blinder.sys
set LDFLAGS=/nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE,10.0 /NODEFAULTLIB /INCREMENTAL:NO
set LDFLAGS=%LDFLAGS% /RELEASE /OPT:REF,ICF /MACHINE:X64 /STACK:0x40000,0x1000 /ALIGN:0x1000

echo [link] eac_blinder.sys
link %LDFLAGS% main.obj nt_hooks.obj ob_callback.obj etwti.obj vad_filter.obj utils.obj %LIBS% /OUT:eac_blinder.sys
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)

rem Clean obj files
del /q *.obj 2>nul
del /q eac_blinder.exp 2>nul
del /q eac_blinder.lib 2>nul

echo.
echo Built eac_blinder.sys
dir /b eac_blinder.sys
echo.
echo NEXT: Map via your own BYOVD mapper. Do NOT load via `sc create` —
echo       that triggers Windows DSE + registers in service registry.
echo       See README.md for mapper options.

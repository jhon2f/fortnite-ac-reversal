@echo off
setlocal ENABLEDELAYEDEXPANSION

if not defined WindowsSdkDir (
    echo ERROR: open x64 Native Tools cmd, or call _do_build_null.bat
    exit /b 1
)

for /f "delims=" %%v in ('dir /b /ad /on "!WindowsSdkDir!Include\10.0.*"') do set "SDK_VER=%%v"
set "WDK_INC=!WindowsSdkDir!Include\!SDK_VER!"
set "WDK_LIB=!WindowsSdkDir!Lib\!SDK_VER!"
set INCLUDES=/I"!WDK_INC!\km" /I"!WDK_INC!\km\crt" /I"!WDK_INC!\shared" /I"!WDK_INC!\ucrt"
set LIBS="!WDK_LIB!\km\x64\ntoskrnl.lib" "!WDK_LIB!\km\x64\hal.lib" "!WDK_LIB!\km\x64\BufferOverflowFastFailK.lib"

set CFLAGS=/nologo /c /O2 /W3 /kernel /GS- /Zc:wchar_t /D_WIN64 /D_AMD64_ /DAMD64 /D_X86_AMD64_ /DWIN32_LEAN_AND_MEAN /D_WINNT /D__INTRINSIC_GROUP_WIN_BASE=1

echo [cl] null_entry.c
cl %CFLAGS% %INCLUDES% null_entry.c
if errorlevel 1 exit /b 1

echo [link] rage_drv_NULL.sys
link /nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE,10.0 /NODEFAULTLIB /INCREMENTAL:NO /RELEASE /OPT:REF,ICF /MACHINE:X64 /STACK:0x40000,0x1000 /ALIGN:0x1000 null_entry.obj %LIBS% /OUT:rage_drv_NULL.sys
if errorlevel 1 exit /b 1

del /q null_entry.obj rage_drv_NULL.exp rage_drv_NULL.lib 2>nul
echo Built rage_drv_NULL.sys
dir /b rage_drv_NULL.sys

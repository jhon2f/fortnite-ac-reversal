@echo off
rem Build from "x64 Native Tools Command Prompt for VS" (MSVC)
rem Produces EasyAntiCheat.dll — drop-in replacement for the launcher wrapper
cl /LD /O2 /DUNICODE /D_UNICODE eac_launcher_wrapper.c /Fe:EasyAntiCheat.dll ^
   /link /DEF:eac_launcher_wrapper.def kernel32.lib
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo.
echo Built EasyAntiCheat.dll — 5 exports: a @1, b @2, c @3, d @4, e @5
echo.
echo Back up original, then drop in to game's EasyAntiCheat directory.

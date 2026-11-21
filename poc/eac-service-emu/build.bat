@echo off
rem Build from "x64 Native Tools Command Prompt for VS" (MSVC)
rem Produces EasyAntiCheat_EOS.exe — the service emulator + setup CLI
cl /O2 /DUNICODE /D_UNICODE eac_service_emu.c /Fe:EasyAntiCheat_EOS.exe ^
   /link advapi32.lib kernel32.lib user32.lib
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo.
echo Built EasyAntiCheat_EOS.exe
echo.
echo Install as service ^(as Administrator^):
echo   sc create EasyAntiCheat_EOSSys binPath^= "%CD%\EasyAntiCheat_EOS.exe" start^= demand
echo   sc description EasyAntiCheat_EOSSys "Provides security for online multiplayer games."
echo   sc start EasyAntiCheat_EOSSys
echo.
echo Or run install CLI:
echo   EasyAntiCheat_EOS.exe install 95e760e6a6a447c28dc50db3e78d060f

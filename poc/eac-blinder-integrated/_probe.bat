@echo off
call "D:\VS2022BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
echo WindowsSdkDir=[%WindowsSdkDir%]
echo WindowsSDKVersion=[%WindowsSDKVersion%]
echo ----- includes dir listing -----
dir /b /ad /on "%WindowsSdkDir%Include\10.0.*"
echo ----- km dir check -----
if exist "%WindowsSdkDir%Include\10.0.26100.0\km" (echo km OK) else (echo km MISSING)
echo ----- libs check -----
if exist "%WindowsSdkDir%Lib\10.0.26100.0\km\x64\ntoskrnl.lib" (echo ntoskrnl.lib OK) else (echo ntoskrnl.lib MISSING)

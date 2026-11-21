@echo off
setlocal
set "BLINDER_DIR=%~dp0"
call "D:\VS2022BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d "%BLINDER_DIR%"
call "%BLINDER_DIR%build.bat"

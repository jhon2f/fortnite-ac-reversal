@echo off
setlocal
set "D=%~dp0"
call "D:\VS2022BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d "%D%"
call "%D%build_null.bat"

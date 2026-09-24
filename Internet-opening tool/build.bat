@echo off
chcp 65001 >nul
title kaiwang build
setlocal enabledelayedexpansion

set "SRC=%~dp0"
cd /d "%SRC%"

echo ================================================
echo  kaiwang.exe build script
echo ================================================
echo.

if not exist kaiwang.cpp (
  echo [!] kaiwang.cpp not found next to this script.
  pause
  exit /b 1
)

rem ---- Locate g++.exe (scan C/D/E; Dev-C++ is often on a non-system drive) ----
set "GXX="
for %%D in (C D E) do (
  for %%P in (
    "%%D:\Program Files\Dev-Cpp\MinGW64\bin\g++.exe"
    "%%D:\Program Files (x86)\Dev-Cpp\MinGW64\bin\g++.exe"
    "%%D:\Dev-Cpp\MinGW64\bin\g++.exe"
    "%%D:\Program Files\CodeBlocks\MinGW\bin\g++.exe"
    "%%D:\Program Files (x86)\CodeBlocks\MinGW\bin\g++.exe"
    "%%D:\MinGW\bin\g++.exe"
    "%%D:\mingw64\bin\g++.exe"
    "%%D:\msys64\mingw64\bin\g++.exe"
    "%%D:\TDM-GCC-64\bin\g++.exe"
  ) do (
    if not defined GXX if exist %%P set "GXX=%%~P"
  )
)

rem ---- Also accept g++ from PATH ----
if not defined GXX (
  for /f "delims=" %%G in ('where g++ 2^>nul') do (
    if not defined GXX set "GXX=%%G"
  )
)

if not defined GXX (
  echo [!] g++ not found.
  echo.
  echo     Install MinGW-w64 / TDM-GCC / Code::Blocks, then run this again.
  echo     Download: https://winlibs.com/
  echo.
  pause
  exit /b 1
)

echo [*] Compiler : !GXX!
echo [*] Building kaiwang.exe ...
echo.

rem ---- IMPORTANT ----
rem Calling a spaced absolute path from a .bat is unreliable on some cmd builds:
rem the path gets split at the space ("D:\Program" / "Files ...").
rem So we cd into the compiler's own folder and call it by plain file name.
for %%I in ("!GXX!") do (
  set "GXXDIR=%%~dpI"
  set "GXXEXE=%%~nxI"
)
cd /d "!GXXDIR!"

!GXXEXE! -O2 -s -o "%SRC%kaiwang.exe" "%SRC%kaiwang.cpp" -lws2_32 -liphlpapi -lshell32 -ladvapi32 -static -std=c++11

set "RC=!errorlevel!"
cd /d "%SRC%"

if not "!RC!"=="0" (
  echo.
  echo [!] Build FAILED ^(code !RC!^).
  pause
  exit /b 1
)

echo [+] OK: kaiwang.exe
echo.

if exist selftest.cpp (
  echo [*] Building selftest.exe ...
  cd /d "!GXXDIR!"
  !GXXEXE! -O2 -s -o "%SRC%selftest.exe" "%SRC%selftest.cpp" -lws2_32 -liphlpapi -static -std=c++11
  cd /d "%SRC%"
  if errorlevel 1 echo [i] selftest skipped.
  echo.
)

echo ================================================
echo  Done. Run kaiwang.exe as Administrator.
echo ================================================
pause

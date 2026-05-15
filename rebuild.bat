@echo off
:: rebuild.bat — non-interactive full build for dayzdriv
:: Invoke from Claude Code: cmd.exe //c "F:\vsprojs\dayzdriv\rebuild.bat"
:: Exit 0 = BUILD OK, non-zero = failed (step printed to stdout).
setlocal

set MSVC=G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64
set WDK=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set WDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0
set OBJ=F:\vsprojs\dayzdriv\dayzdriv\x64\Release
set OUT=F:\vsprojs\dayzdriv\bin\dayzdriv.sys
set PDB=F:\vsprojs\dayzdriv\bin\dayzdriv.pdb
set SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe
set CLFLAGS=/kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy /D _AMD64_
set INCS=/I "%WDK%\km" /I "%WDK%\km\crt" /I "%WDK%\shared" /I "%WDK%\ucrt" /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include"

if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "F:\vsprojs\dayzdriv\bin" mkdir "F:\vsprojs\dayzdriv\bin"
if not exist "F:\vsprojs\dayzdriv\logs" mkdir "F:\vsprojs\dayzdriv\logs"

echo [1/7] ml64 Arch.asm
"%MSVC%\ml64.exe" /c /Fo "%OBJ%\vcasm.obj" "F:\vsprojs\dayzdriv\Arch.asm"
if %errorlevel% neq 0 ( echo FAILED: ml64 & exit /b 1 )

echo [2/7] cl Vmx.c
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Vmx.obj" "F:\vsprojs\dayzdriv\Vmx.c"
if %errorlevel% neq 0 ( echo FAILED: cl Vmx.c & exit /b 1 )

echo [3/7] cl Ept.c
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Ept.obj" "F:\vsprojs\dayzdriv\Ept.c"
if %errorlevel% neq 0 ( echo FAILED: cl Ept.c & exit /b 1 )

echo [4/7] cl Loader.c
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Loader.obj" "F:\vsprojs\dayzdriv\Loader.c"
if %errorlevel% neq 0 ( echo FAILED: cl Loader.c & exit /b 1 )

echo [5/7] cl Driver.c
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Driver.obj" "F:\vsprojs\dayzdriv\Driver.c"
if %errorlevel% neq 0 ( echo FAILED: cl Driver.c & exit /b 1 )

echo [6/7] link
"%MSVC%\link.exe" /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry ^
    /INCREMENTAL:NO /NODEFAULTLIB /RELEASE /DEBUG /PDB:"%PDB%" /OUT:"%OUT%" ^
    "%OBJ%\Driver.obj" "%OBJ%\Vmx.obj" "%OBJ%\Ept.obj" "%OBJ%\Loader.obj" "%OBJ%\vcasm.obj" ^
    "%WDKLIB%\km\x64\ntoskrnl.lib" "%WDKLIB%\km\x64\hal.lib" "%WDKLIB%\km\x64\BufferOverflowK.lib"
if %errorlevel% neq 0 ( echo FAILED: link & exit /b 1 )

echo [7/7] signtool
"%SIGNTOOL%" sign /v /fd sha256 /s PrivateCertStore /n DayZTestCert /t http://timestamp.digicert.com "%OUT%"
if %errorlevel% neq 0 ( echo FAILED: signtool & exit /b 1 )

echo.
echo BUILD OK  --  %OUT%
exit /b 0

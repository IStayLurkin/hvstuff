@echo off
setlocal

call "G:\VS2022BT\Common7\Tools\VsDevCmd.bat" >nul 2>&1

set MSVC=G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64
set WDK=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set WDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0
set OBJ=%~dp0obj
set OUT=%~dp0bin\resolver.sys
set PDB=%~dp0bin\resolver.pdb

if not exist "%~dp0obj" mkdir "%~dp0obj"
if not exist "%~dp0bin" mkdir "%~dp0bin"

"%MSVC%\cl.exe" /kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy ^
    /D _AMD64_ ^
    /I "%WDK%\km" /I "%WDK%\km\crt" /I "%WDK%\shared" ^
    /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include" ^
    /Fo"%OBJ%\Resolver.obj" "%~dp0Resolver.c"
if %errorlevel% neq 0 ( echo FAILED: cl Resolver.c & exit /b 1 )

"%MSVC%\link.exe" /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry ^
    /INCREMENTAL:NO /NODEFAULTLIB /RELEASE /DEBUG /PDB:"%PDB%" ^
    /OUT:"%OUT%" ^
    "%OBJ%\Resolver.obj" ^
    "%WDKLIB%\km\x64\ntoskrnl.lib" ^
    "%WDKLIB%\km\x64\hal.lib" ^
    "%WDKLIB%\km\x64\ntstrsafe.lib" ^
    "%WDKLIB%\km\x64\BufferOverflowK.lib"
if %errorlevel% neq 0 ( echo FAILED: link & exit /b 1 )

"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" ^
    sign /v /fd sha256 /s PrivateCertStore /n DayZTestCert ^
    /t http://timestamp.digicert.com "%OUT%"
if %errorlevel% neq 0 ( echo FAILED: signtool & exit /b 1 )

echo BUILD OK  ^>  %OUT%

@echo off
cd /d "F:\vsprojs\dayzdriv"

:: Load VS Dev environment inline if not already set.
if not defined VSINSTALLDIR (
    call "G:\VS2022BT\Common7\Tools\VsDevCmd.bat" >nul 2>&1
)

:: -------------------------------------------------------------------------
:: Logging setup — output goes to console AND log file via tee.
:: Only wrap once; if _LOGGED is set we are already inside the tee pipe.
:: -------------------------------------------------------------------------
if not exist "F:\vsprojs\dayzdriv\logs" mkdir "F:\vsprojs\dayzdriv\logs"

if not defined BUILDLOG (
    for /f %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set BUILDLOG=F:\vsprojs\dayzdriv\logs\build_%%T.log
)

:: -------------------------------------------------------------------------
:: Output goes directly to the console. A copy is written to %BUILDLOG%
:: via the PowerShell transcript trick only when double-clicked from Explorer
:: (where stdout is not a terminal). When run from a terminal, just stream.
:: -------------------------------------------------------------------------
setlocal

set MSVC=G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64
set WDK=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set WDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0
set OBJ=F:\vsprojs\dayzdriv\dayzdriv\x64\Release
set OUT=F:\vsprojs\dayzdriv\bin\dayzdriv.sys
set PDB=F:\vsprojs\dayzdriv\bin\dayzdriv.pdb
set DRVLOG=F:\vsprojs\dayzdriv\logs\dayzdriv.log
set CDB="C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
set SYMPATH=srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;F:\vsprojs\dayzdriv\bin
set DUMPDIR=C:\Windows\Minidump
set LOCALDUMPS=F:\vsprojs\dayzdriv\dumps

echo ========================================
echo  DAYZDRIV BUILD  %DATE% %TIME%
echo  Build log: %BUILDLOG%
echo  Driver log: %DRVLOG%
echo ========================================
echo.

echo [1/6] Stopping and removing old service...
sc.exe stop dayz >nul 2>&1
sc.exe delete dayz >nul 2>&1
ping -n 2 127.0.0.1 >nul

:: Delete stale outputs so a failed build never leaves a stale .sys in place.
del /f /q "%OUT%" 2>nul
del /f /q "%PDB%" 2>nul
del /f /q "%OBJ%\vcasm.obj"   2>nul
del /f /q "%OBJ%\Vmx.obj"    2>nul
del /f /q "%OBJ%\Ept.obj"    2>nul
del /f /q "%OBJ%\Loader.obj" 2>nul
del /f /q "%OBJ%\Driver.obj" 2>nul
del /f /q "%OBJ%\Payload.obj" 2>nul
del /f /q "F:\vsprojs\dayzdriv\vc140.pdb" 2>nul

echo [2/6] Assembling Arch.asm...
"%MSVC%\ml64.exe" /c /Fo "%OBJ%\vcasm.obj" "F:\vsprojs\dayzdriv\Arch.asm"
if %errorlevel% neq 0 ( echo FAILED: ml64 & goto :fail )

echo [3/6] Compiling Vmx.c...
"%MSVC%\cl.exe" /kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy ^
    /D _AMD64_ ^
    /I "%WDK%\km" ^
    /I "%WDK%\km\crt" ^
    /I "%WDK%\shared" ^
    /I "%WDK%\ucrt" ^
    /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include" ^
    /Fo"%OBJ%\Vmx.obj" ^
    "F:\vsprojs\dayzdriv\Vmx.c"
if %errorlevel% neq 0 ( echo FAILED: cl Vmx.c & goto :fail )

echo [3b/6] Compiling Ept.c...
"%MSVC%\cl.exe" /kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy ^
    /D _AMD64_ ^
    /I "%WDK%\km" ^
    /I "%WDK%\km\crt" ^
    /I "%WDK%\shared" ^
    /I "%WDK%\ucrt" ^
    /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include" ^
    /Fo"%OBJ%\Ept.obj" ^
    "F:\vsprojs\dayzdriv\Ept.c"
if %errorlevel% neq 0 ( echo FAILED: cl Ept.c & goto :fail )

echo [3c/6] Compiling Loader.c...
"%MSVC%\cl.exe" /kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy ^
    /D _AMD64_ ^
    /I "%WDK%\km" ^
    /I "%WDK%\km\crt" ^
    /I "%WDK%\shared" ^
    /I "%WDK%\ucrt" ^
    /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include" ^
    /Fo"%OBJ%\Loader.obj" ^
    "F:\vsprojs\dayzdriv\Loader.c"
if %errorlevel% neq 0 ( echo FAILED: cl Loader.c & goto :fail )

echo [4/6] Compiling Driver.c...
"%MSVC%\cl.exe" /kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy ^
    /D _AMD64_ ^
    /I "%WDK%\km" ^
    /I "%WDK%\km\crt" ^
    /I "%WDK%\shared" ^
    /I "%WDK%\ucrt" ^
    /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include" ^
    /Fo"%OBJ%\Driver.obj" ^
    "F:\vsprojs\dayzdriv\Driver.c"
if %errorlevel% neq 0 ( echo FAILED: cl Driver.c & goto :fail )

echo [5/6] Linking...
"%MSVC%\link.exe" /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry ^
    /INCREMENTAL:NO /NODEFAULTLIB /RELEASE ^
    /DEBUG /PDB:"%PDB%" ^
    /OUT:"%OUT%" ^
    "%OBJ%\Driver.obj" "%OBJ%\Vmx.obj" "%OBJ%\Ept.obj" "%OBJ%\Loader.obj" "%OBJ%\vcasm.obj" ^
    "%WDKLIB%\km\x64\ntoskrnl.lib" ^
    "%WDKLIB%\km\x64\hal.lib" ^
    "%WDKLIB%\km\x64\BufferOverflowK.lib"
if %errorlevel% neq 0 ( echo FAILED: link & goto :fail )

echo [6/6] Signing...
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" ^
    sign /v /fd sha256 /s PrivateCertStore /n DayZTestCert ^
    /t http://timestamp.digicert.com "%OUT%"
if %errorlevel% neq 0 ( echo FAILED: signtool & goto :fail )

:: -------------------------------------------------------------------------
:: Payload build (tests\payload\Payload.c -> bin\payload\payload.sys)
:: -------------------------------------------------------------------------
set PAYLOAD_SRC=F:\vsprojs\dayzdriv\tests\payload\Payload.c
set PAYLOAD_OBJ=%OBJ%\Payload.obj
set PAYLOAD_OUT=F:\vsprojs\dayzdriv\bin\payload\payload.sys
set PAYLOAD_PDB=F:\vsprojs\dayzdriv\bin\payload\payload.pdb

if not exist "F:\vsprojs\dayzdriv\bin\payload" mkdir "F:\vsprojs\dayzdriv\bin\payload"

echo [6b/6] Compiling Payload.c...
"%MSVC%\cl.exe" /kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy ^
    /D _AMD64_ ^
    /I "%WDK%\km" ^
    /I "%WDK%\km\crt" ^
    /I "%WDK%\shared" ^
    /I "%WDK%\ucrt" ^
    /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include" ^
    /Fo"%PAYLOAD_OBJ%" ^
    "%PAYLOAD_SRC%"
if %errorlevel% neq 0 ( echo FAILED: cl Payload.c & goto :fail )

echo [6c/6] Linking payload...
"%MSVC%\link.exe" /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry ^
    /INCREMENTAL:NO /NODEFAULTLIB /RELEASE ^
    /DEBUG /PDB:"%PAYLOAD_PDB%" ^
    /OUT:"%PAYLOAD_OUT%" ^
    "%PAYLOAD_OBJ%" ^
    "%WDKLIB%\km\x64\ntoskrnl.lib" ^
    "%WDKLIB%\km\x64\BufferOverflowK.lib"
if %errorlevel% neq 0 ( echo FAILED: payload link & goto :fail )

echo [6d/6] Signing payload...
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" ^
    sign /v /fd sha256 /s PrivateCertStore /n DayZTestCert ^
    /t http://timestamp.digicert.com "%PAYLOAD_OUT%"
if %errorlevel% neq 0 ( echo FAILED: payload signtool & goto :fail )

echo.
echo ========================================
echo  BUILD OK
echo ========================================
echo.

:: -------------------------------------------------------------------------
:: Action menu
:: -------------------------------------------------------------------------
:menu
echo What do you want to do?
echo.
echo   1  Start driver   (sc create + sc start, watch for dump)
echo   2  Stop driver    (sc stop + sc delete)
echo   3  Tail log       (last 40 lines of dayzdriv.log)
echo   4  Analyze dump   (cdb !analyze on newest dump in dumps\)
echo   5  Exit
echo.
set CHOICE=
set /p CHOICE=Enter number:

if "%CHOICE%"=="1" goto :do_start
if "%CHOICE%"=="2" goto :do_stop
if "%CHOICE%"=="3" goto :do_log
if "%CHOICE%"=="4" goto :do_analyze
if "%CHOICE%"=="5" goto :end
echo Invalid choice, try again.
echo.
goto :menu

:: -------------------------------------------------------------------------
:: 1 — Start driver
:: -------------------------------------------------------------------------
:do_start
for /f "delims=" %%F in ('powershell -NoProfile -Command ^
    "try { (Get-ChildItem ''%DUMPDIR%\*.dmp'' -ErrorAction Stop | Sort-Object LastWriteTime | Select-Object -Last 1).LastWriteTime.ToFileTime() } catch { 0 }"') do set PRE_DUMP_TIME=%%F

echo Registering service...
sc.exe create dayz binPath= "%OUT%" type= kernel
if %errorlevel% neq 0 ( echo FAILED: sc create & goto :menu_pause )

echo [PRE-START %DATE% %TIME%] sc.exe start dayz >> "%DRVLOG%"
echo Starting driver...
sc.exe start dayz
set SCERR=%errorlevel%
echo [POST-START %DATE% %TIME%] sc.exe exit=%SCERR% >> "%DRVLOG%"

if %SCERR% neq 0 (
    echo FAILED: sc start returned %SCERR%
    goto :menu_pause
)

echo.
echo ========================================
echo  DRIVER STARTED  --  watching for dump (15s)
echo  Check: logs\dayzdriv.log
echo ========================================
echo.

powershell -NoProfile -Command ^
    "$pre = %PRE_DUMP_TIME%; $deadline = (Get-Date).AddSeconds(15); $found = $null; while ((Get-Date) -lt $deadline) { $d = Get-ChildItem ''%DUMPDIR%\*.dmp'' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime.ToFileTime() -gt $pre } | Sort-Object LastWriteTime | Select-Object -Last 1; if ($d) { $found = $d; break }; Start-Sleep -Seconds 2 }; if ($found) { Write-Output $found.FullName } else { Write-Output '' }" > "%TEMP%\dayz_newdump.txt"

set /p NEWDUMP=<"%TEMP%\dayz_newdump.txt"

if "%NEWDUMP%"=="" (
    echo [DUMP-WATCH] No dump detected -- driver is running or froze cleanly.
    goto :menu_pause
)

echo [DUMP-WATCH] New dump: %NEWDUMP%
for %%F in ("%NEWDUMP%") do set DUMPNAME=%%~nxF
if not exist "%LOCALDUMPS%" mkdir "%LOCALDUMPS%"
copy /y "%NEWDUMP%" "%LOCALDUMPS%\%DUMPNAME%" >nul
echo [DUMP-WATCH] Copied to dumps\%DUMPNAME%
echo.
echo ========================================
echo  CDB ANALYSIS: %DUMPNAME%
echo ========================================
%CDB% -z "%LOCALDUMPS%\%DUMPNAME%" -y "%SYMPATH%" -lines ^
    -c "!analyze -v; .bugcheck; kP 30; q"
echo ========================================
echo  END CDB ANALYSIS
echo ========================================
goto :menu_pause

:: -------------------------------------------------------------------------
:: 2 — Stop driver
:: -------------------------------------------------------------------------
:do_stop
echo Stopping driver...
sc.exe stop dayz
ping -n 2 127.0.0.1 >nul
sc.exe delete dayz
echo Done.
goto :menu_pause

:: -------------------------------------------------------------------------
:: 3 — Tail log
:: -------------------------------------------------------------------------
:do_log
echo.
echo ---- last 40 lines of dayzdriv.log ----
powershell -NoProfile -Command ^
    "if (Test-Path ''%DRVLOG%'') { Get-Content ''%DRVLOG%'' -Tail 40 } else { ''(log not found)'' }"
echo ---- end ----
goto :menu_pause

:: -------------------------------------------------------------------------
:: 4 — Analyze newest dump
:: -------------------------------------------------------------------------
:do_analyze
for /f "delims=" %%F in ('powershell -NoProfile -Command ^
    "try { (Get-ChildItem ''%LOCALDUMPS%\*.dmp'' -ErrorAction Stop | Sort-Object LastWriteTime | Select-Object -Last 1).FullName } catch { '''' }"') do set LATESTDUMP=%%F

if "%LATESTDUMP%"=="" (
    echo No dumps found in %LOCALDUMPS%
    goto :menu_pause
)

echo Analyzing: %LATESTDUMP%
echo.
%CDB% -z "%LATESTDUMP%" -y "%SYMPATH%" -lines ^
    -c "!analyze -v; .bugcheck; kP 30; q"
goto :menu_pause

:menu_pause
echo.
pause
echo.
goto :menu

:fail
echo.
echo ========================================
echo  FAILED
echo  Build log: %BUILDLOG%
echo ========================================
endlocal
exit /b 1

:end
endlocal

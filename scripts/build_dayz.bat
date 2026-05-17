@echo off
:: build_dayz.bat — build + interactive deploy for dayzdriv
:: Double-click from Explorer to build, deploy, and debug.
::
::   BUILD OK -> action menu:
::     1  Start driver  (deploys, tails log 5s, watches 90s for crash dump)
::     2  Stop driver
::     3  Tail log      (last 50 lines of dayzdriv.log)
::     4  Analyze dump  (cdb !analyze on newest dump in dumps\)
::     5  Exit
::
cd /d "F:\vsprojs\dayzdriv"

set ROOT=F:\vsprojs\dayzdriv
set SRC=%ROOT%\src
set OBJ=%ROOT%\bin\obj
set OUT=%ROOT%\bin\dayzdriv.sys
set PDB=%ROOT%\bin\dayzdriv.pdb
set DRVLOG=%ROOT%\logs\dayzdriv.log
set LOCALDUMPS=%ROOT%\dumps
set DUMPDIR=C:\Windows\Minidump
set KDMAPPER=J:\Downloads\kdmapper-master\kdmapper-master\x64\Release\kdmapper_Release.exe

set MSVC=G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64
set WDK=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set WDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0
set SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe
set CDB="C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
set SYMPATH=srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;%ROOT%\bin

set CLFLAGS=/kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy /D _AMD64_
set INCS=/I "%WDK%\km" /I "%WDK%\km\crt" /I "%WDK%\shared" /I "%WDK%\ucrt" /I "G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include"

for /f %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set BUILDLOG=%ROOT%\logs\build_%%T.log

if not exist "%OBJ%"        mkdir "%OBJ%"
if not exist "%ROOT%\bin"   mkdir "%ROOT%\bin"
if not exist "%ROOT%\logs"  mkdir "%ROOT%\logs"
if not exist "%LOCALDUMPS%" mkdir "%LOCALDUMPS%"

echo ======================================== >> "%BUILDLOG%"
echo  DAYZDRIV BUILD  %DATE% %TIME%          >> "%BUILDLOG%"
echo ======================================== >> "%BUILDLOG%"

echo ========================================
echo  DAYZDRIV BUILD  %DATE% %TIME%
echo  Log: %BUILDLOG%
echo ========================================
echo.

sc.exe stop dayz >nul 2>&1
sc.exe delete dayz >nul 2>&1
ping -n 2 127.0.0.1 >nul

del /f /q "%OUT%" "%PDB%" 2>nul
del /f /q "%OBJ%\vcasm.obj" "%OBJ%\Vmx.obj" "%OBJ%\Ept.obj" "%OBJ%\Loader.obj" "%OBJ%\Driver.obj" 2>nul

echo [1/7] ml64 Arch.asm
echo [1/7] ml64 Arch.asm >> "%BUILDLOG%"
"%MSVC%\ml64.exe" /c /Fo "%OBJ%\vcasm.obj" "%SRC%\Arch.asm" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo FAILED: ml64 & echo FAILED: ml64 >> "%BUILDLOG%" & goto :fail )

echo [2/7] cl Vmx.c
echo [2/7] cl Vmx.c >> "%BUILDLOG%"
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Vmx.obj" "%SRC%\Vmx.c" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo FAILED: cl Vmx.c & echo FAILED: cl Vmx.c >> "%BUILDLOG%" & goto :fail )

echo [3/7] cl Ept.c
echo [3/7] cl Ept.c >> "%BUILDLOG%"
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Ept.obj" "%SRC%\Ept.c" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo FAILED: cl Ept.c & echo FAILED: cl Ept.c >> "%BUILDLOG%" & goto :fail )

echo [4/7] cl Loader.c
echo [4/7] cl Loader.c >> "%BUILDLOG%"
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Loader.obj" "%SRC%\Loader.c" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo FAILED: cl Loader.c & echo FAILED: cl Loader.c >> "%BUILDLOG%" & goto :fail )

echo [5/7] cl Driver.c
echo [5/7] cl Driver.c >> "%BUILDLOG%"
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Driver.obj" "%SRC%\Driver.c" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo FAILED: cl Driver.c & echo FAILED: cl Driver.c >> "%BUILDLOG%" & goto :fail )

echo [6/7] link
echo [6/7] link >> "%BUILDLOG%"
"%MSVC%\link.exe" /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry ^
    /INCREMENTAL:NO /NODEFAULTLIB /RELEASE /DEBUG /PDB:"%PDB%" /OUT:"%OUT%" ^
    "%OBJ%\Driver.obj" "%OBJ%\Vmx.obj" "%OBJ%\Ept.obj" "%OBJ%\Loader.obj" "%OBJ%\vcasm.obj" ^
    "%WDKLIB%\km\x64\ntoskrnl.lib" "%WDKLIB%\km\x64\hal.lib" "%WDKLIB%\km\x64\BufferOverflowK.lib" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo FAILED: link & echo FAILED: link >> "%BUILDLOG%" & goto :fail )

echo [7/7] signtool
echo [7/7] signtool >> "%BUILDLOG%"
"%SIGNTOOL%" sign /v /fd sha256 /s PrivateCertStore /n DayZTestCert /t http://timestamp.digicert.com/shield/timestamp "%OUT%" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo FAILED: signtool & echo FAILED: signtool >> "%BUILDLOG%" & goto :fail )

:: -------------------------------------------------------------------------
:: Payload (tests\payload\Payload.c -> bin\payload\payload.sys)
:: -------------------------------------------------------------------------
set PAYLOAD_OUT=%ROOT%\bin\payload\payload.sys
set PAYLOAD_PDB=%ROOT%\bin\payload\payload.pdb
if not exist "%ROOT%\bin\payload" mkdir "%ROOT%\bin\payload"

echo [payload] cl Payload.c
"%MSVC%\cl.exe" %CLFLAGS% %INCS% /Fo"%OBJ%\Payload.obj" "%ROOT%\tests\payload\Payload.c" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo [payload] FAILED: cl Payload.c -- skipping payload & goto :payload_done )

echo [payload] link
"%MSVC%\link.exe" /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry ^
    /INCREMENTAL:NO /NODEFAULTLIB /RELEASE /DEBUG /PDB:"%PAYLOAD_PDB%" /OUT:"%PAYLOAD_OUT%" ^
    "%OBJ%\Payload.obj" ^
    "%WDKLIB%\km\x64\ntoskrnl.lib" "%WDKLIB%\km\x64\BufferOverflowK.lib" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo [payload] FAILED: link -- skipping payload & goto :payload_done )

echo [payload] signtool
"%SIGNTOOL%" sign /v /fd sha256 /s PrivateCertStore /n DayZTestCert /t http://timestamp.digicert.com/shield/timestamp "%PAYLOAD_OUT%" >> "%BUILDLOG%" 2>&1
if %errorlevel% neq 0 ( echo [payload] FAILED: signtool & goto :payload_done )
echo [payload] OK

:payload_done

echo BUILD OK >> "%BUILDLOG%"
echo.
echo ========================================
echo  BUILD OK  --  %OUT%
echo  Log: %BUILDLOG%
echo ========================================
echo.

:: -------------------------------------------------------------------------
:: Action menu
:: -------------------------------------------------------------------------
:menu
echo What do you want to do?
echo.
echo   1  Load driver    (kdmapper, auto-tail log + watch for dump)
echo   2  Stop driver    (sc stop + sc delete for any leftover service)
echo   3  Tail log       (last 50 lines of dayzdriv.log)
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
echo Invalid choice.
echo.
goto :menu

:: -------------------------------------------------------------------------
:: 1 -- Start driver
:: -------------------------------------------------------------------------
:do_start
for /f "delims=" %%F in ('powershell -NoProfile -Command ^
    "try { (Get-ChildItem ''%DUMPDIR%\*.dmp'' -ErrorAction Stop | Sort-Object LastWriteTime | Select-Object -Last 1).LastWriteTime.ToFileTime() } catch { 0 }"') do set PRE_DUMP_TIME=%%F

if not exist "%KDMAPPER%" (
    echo FAILED: kdmapper not found at %KDMAPPER%
    goto :menu_pause
)

echo [%DATE% %TIME%] kdmapper start >> "%DRVLOG%"
echo Running kdmapper...
"%KDMAPPER%" "%OUT%"
set SCERR=%errorlevel%
echo [%DATE% %TIME%] kdmapper exit=%SCERR% >> "%DRVLOG%"

if %SCERR% neq 0 (
    echo FAILED: kdmapper returned %SCERR%
    goto :menu_pause
)

echo.
echo ========================================
echo  DRIVER MAPPED
echo ========================================
echo.

echo ---- dayzdriv.log (live, 5s) ----
powershell -NoProfile -Command ^
    "$log = '%DRVLOG%'; $end = (Get-Date).AddSeconds(5); $pos = 0; while ((Get-Date) -lt $end) { if (Test-Path $log) { $lines = Get-Content $log; if ($lines.Count -gt $pos) { $lines[$pos..($lines.Count-1)] | Write-Host; $pos = $lines.Count } }; Start-Sleep -Milliseconds 300 }"
echo ---- end live tail ----
echo.

echo Watching for crash dump (30s)...
powershell -NoProfile -Command ^
    "$pre = %PRE_DUMP_TIME%; $deadline = (Get-Date).AddSeconds(30); $found = $null; while ((Get-Date) -lt $deadline) { $d = Get-ChildItem ''%DUMPDIR%\*.dmp'' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime.ToFileTime() -gt $pre } | Sort-Object LastWriteTime | Select-Object -Last 1; if ($d) { $found = $d; break }; Start-Sleep -Seconds 2 }; if ($found) { Write-Output $found.FullName } else { Write-Output '' }" > "%TEMP%\dayz_newdump.txt"

set /p NEWDUMP=<"%TEMP%\dayz_newdump.txt"

if "%NEWDUMP%"=="" (
    echo No dump detected -- driver appears stable.
    goto :menu_pause
)

for %%F in ("%NEWDUMP%") do set DUMPNAME=%%~nxF
copy /y "%NEWDUMP%" "%LOCALDUMPS%\%DUMPNAME%" >nul
echo.
echo ========================================
echo  CRASH: %DUMPNAME%
echo ========================================
echo.
%CDB% -z "%LOCALDUMPS%\%DUMPNAME%" -y "%SYMPATH%" -lines -c "!analyze -v; .bugcheck; kP 30; q" 2>&1 | powershell -NoProfile -Command "$input | Tee-Object -FilePath '%BUILDLOG%' -Append"
echo.
echo (Analysis appended to %BUILDLOG%)
goto :menu_pause

:: -------------------------------------------------------------------------
:: 2 -- Stop driver
:: -------------------------------------------------------------------------
:do_stop
sc.exe stop dayz
ping -n 2 127.0.0.1 >nul
sc.exe delete dayz
echo Done.
goto :menu_pause

:: -------------------------------------------------------------------------
:: 3 -- Tail log
:: -------------------------------------------------------------------------
:do_log
echo.
echo ---- last 50 lines of dayzdriv.log ----
powershell -NoProfile -Command ^
    "if (Test-Path ''%DRVLOG%'') { Get-Content ''%DRVLOG%'' -Tail 50 } else { ''(log not found)'' }"
echo ---- end ----
goto :menu_pause

:: -------------------------------------------------------------------------
:: 4 -- Analyze newest dump
:: -------------------------------------------------------------------------
:do_analyze
for /f "delims=" %%F in ('powershell -NoProfile -Command ^
    "try { (Get-ChildItem ''%LOCALDUMPS%\*.dmp'' -ErrorAction Stop | Sort-Object LastWriteTime | Select-Object -Last 1).FullName } catch { '''' }"') do set LATESTDUMP=%%F

if "%LATESTDUMP%"=="" (
    echo No dumps found in dumps\
    goto :menu_pause
)

echo Analyzing: %LATESTDUMP%
echo.
%CDB% -z "%LATESTDUMP%" -y "%SYMPATH%" -lines -c "!analyze -v; .bugcheck; kP 30; q" 2>&1 | powershell -NoProfile -Command "$input | Tee-Object -FilePath '%BUILDLOG%' -Append"
echo.
echo (Analysis appended to %BUILDLOG%)
goto :menu_pause

:menu_pause
echo.
pause
echo.
goto :menu

:fail
echo.
echo ========================================
echo  BUILD FAILED -- see %BUILDLOG%
echo ========================================
pause
exit /b 1

:end
endlocal

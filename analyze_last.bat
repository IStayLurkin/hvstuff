@echo off
:: Finds the newest minidump, copies it to dumps\, runs cdb !analyze -v,
:: and appends the result to the most recent build log.
:: Double-click after reboot following a BSOD.

cd /d "F:\vsprojs\dayzdriv"

set CDB="C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
set SYMPATH=srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;F:\vsprojs\dayzdriv\bin
set DUMPDIR=C:\Windows\Minidump
set LOCALDUMPS=F:\vsprojs\dayzdriv\dumps
set LOGDIR=F:\vsprojs\dayzdriv\logs

:: Find newest dump
for /f "delims=" %%F in ('powershell -NoProfile -Command ^
    "(Get-ChildItem ''%DUMPDIR%\*.dmp'' | Sort-Object LastWriteTime | Select-Object -Last 1).FullName"') do set NEWDUMP=%%F

if "%NEWDUMP%"=="" (
    echo No dumps found in %DUMPDIR%.
    pause
    exit /b 1
)

for %%F in ("%NEWDUMP%") do set DUMPNAME=%%~nxF

:: Find most recent build log
for /f "delims=" %%F in ('powershell -NoProfile -Command ^
    "(Get-ChildItem ''%LOGDIR%\build_*.log'' | Sort-Object LastWriteTime | Select-Object -Last 1).FullName"') do set BUILDLOG=%%F

if "%BUILDLOG%"=="" (
    for /f %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set BUILDLOG=%LOGDIR%\analyze_%%T.log
)

echo.
echo ========================================
echo  POST-REBOOT DUMP ANALYSIS
echo  Dump:     %NEWDUMP%
echo  Build log: %BUILDLOG%
echo ========================================

if not exist "%LOCALDUMPS%" mkdir "%LOCALDUMPS%"
copy /y "%NEWDUMP%" "%LOCALDUMPS%\%DUMPNAME%" >nul
echo Copied to dumps\%DUMPNAME%

:: Append analysis to build log and echo to console simultaneously
(
    echo.
    echo ========================================
    echo  POST-REBOOT CDB ANALYSIS: %DUMPNAME%
    echo  Analyzed: %DATE% %TIME%
    echo ========================================
    %CDB% -z "%LOCALDUMPS%\%DUMPNAME%" -y "%SYMPATH%" -lines ^
        -c "!analyze -v; .bugcheck; kP 30; q"
    echo ========================================
    echo  END CDB ANALYSIS
    echo ========================================
) >> "%BUILDLOG%" 2>&1

:: Also print to console so you see it without opening the log
echo.
echo Analysis appended to: %BUILDLOG%
echo.
type "%BUILDLOG%" | findstr /C:"DRIVER_IRQL" /C:"BUGCHECK_CODE" /C:"SYMBOL_NAME" /C:"STACK_TEXT" /C:"IMAGE_NAME" /C:"FAILURE_BUCKET"
echo.
echo Full output: %BUILDLOG%
pause

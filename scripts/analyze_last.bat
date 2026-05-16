@echo off
:: analyze_last.bat — post-reboot dump analysis
:: Double-click this after a BSOD reboot when build_dayz.bat wasn't running.
:: Finds the newest minidump, copies it to dumps\, runs cdb !analyze -v,
:: and prints the key lines to the console.

cd /d "F:\vsprojs\dayzdriv"

set ROOT=F:\vsprojs\dayzdriv
set DUMPDIR=C:\Windows\Minidump
set LOCALDUMPS=%ROOT%\dumps
set LOGDIR=%ROOT%\logs
set CDB="C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
set SYMPATH=srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;%ROOT%\bin

if not exist "%LOCALDUMPS%" mkdir "%LOCALDUMPS%"
if not exist "%LOGDIR%"     mkdir "%LOGDIR%"

:: Find newest dump in Windows minidump dir.
for /f "delims=" %%F in ('powershell -NoProfile -Command ^
    "try { (Get-ChildItem ''%DUMPDIR%\*.dmp'' -ErrorAction Stop | Sort-Object LastWriteTime | Select-Object -Last 1).FullName } catch { '''' }"') do set NEWDUMP=%%F

if "%NEWDUMP%"=="" (
    echo No dumps found in %DUMPDIR%.
    pause
    exit /b 1
)

for %%F in ("%NEWDUMP%") do set DUMPNAME=%%~nxF

:: Stamp an analysis log alongside the build logs.
for /f %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set ANALYSISLOG=%LOGDIR%\analyze_%%T.log

echo.
echo ========================================
echo  POST-REBOOT DUMP ANALYSIS
echo  Dump: %DUMPNAME%
echo  Log:  %ANALYSISLOG%
echo ========================================
echo.

copy /y "%NEWDUMP%" "%LOCALDUMPS%\%DUMPNAME%" >nul
echo Copied to dumps\%DUMPNAME%
echo.

%CDB% -z "%LOCALDUMPS%\%DUMPNAME%" -y "%SYMPATH%" -lines -c "!analyze -v; .bugcheck; kP 30; q" 2>&1 | powershell -NoProfile -Command "$input | Tee-Object -FilePath '%ANALYSISLOG%'"

echo.
echo ========================================
echo  Key fields:
echo ========================================
findstr /C:"BUGCHECK_CODE" /C:"SYMBOL_NAME" /C:"IMAGE_NAME" /C:"FAILURE_BUCKET" /C:"FAULTING_" "%ANALYSISLOG%"
echo.
echo Full output: %ANALYSISLOG%
pause

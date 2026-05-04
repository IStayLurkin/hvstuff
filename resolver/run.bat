@echo off
:: Must run elevated.
setlocal

set SYS=%~dp0bin\resolver.sys
set OUT=F:\vsprojs\dayzdriv\logs\sentinel_gpas.txt

if not exist "%SYS%" (
    echo [!] resolver.sys not found — run build.bat first.
    exit /b 1
)

:: Register and start (driver self-terminates after DriverEntry returns).
sc.exe create resolver type= kernel binPath= "%SYS%" >nul 2>&1
sc.exe start resolver >nul 2>&1

:: Give the kernel a moment to flush the file write.
timeout /t 1 /nobreak >nul

sc.exe delete resolver >nul 2>&1

if exist "%OUT%" (
    echo [+] sentinel_gpas.txt written:
    echo.
    type "%OUT%"
) else (
    echo [!] Output file not found — check DbgView for Resolver: log lines.
    exit /b 1
)

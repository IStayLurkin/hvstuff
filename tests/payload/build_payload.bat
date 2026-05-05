@echo off
setlocal

set MSVC=G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64
set WDK=C:\Program Files (x86)\Windows Kits\10
set MSVCINC=G:\VS2022BT\VC\Tools\MSVC\14.38.33130\include
set INC=/I "%WDK%\Include\10.0.26100.0\km" /I "%WDK%\Include\10.0.26100.0\km\crt" /I "%WDK%\Include\10.0.26100.0\shared" /I "%MSVCINC%"
set LIBS="%WDK%\Lib\10.0.26100.0\km\x64\ntoskrnl.lib"

if not exist "F:\vsprojs\dayzdriv\bin\payload" mkdir "F:\vsprojs\dayzdriv\bin\payload"

"%MSVC%\cl.exe" /nologo /kernel /GS- /GR- /EHs-c- /Zi /W3 /WX ^
    %INC% /D_AMD64_ /DAMD64 /D_WIN64 ^
    /Fo"F:\vsprojs\dayzdriv\bin\payload\\" /Fd"F:\vsprojs\dayzdriv\bin\payload\\" ^
    "F:\vsprojs\dayzdriv\tests\payload\Payload.c" /link /NODEFAULTLIB /SUBSYSTEM:NATIVE ^
    /DRIVER /ENTRY:DriverEntry /BASE:0x10000 ^
    /OUT:"F:\vsprojs\dayzdriv\bin\payload\payload.sys" %LIBS%

echo Payload build done: bin\payload\payload.sys
endlocal

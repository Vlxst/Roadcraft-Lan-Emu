@echo off
setlocal
call "%~dp0..\tools\msvc-x64.cmd" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
pushd build
cl /nologo /c /O2 /MT /W3 /I..\vendor\minhook\include /I..\vendor\minhook\src ..\vendor\minhook\src\buffer.c ..\vendor\minhook\src\hook.c ..\vendor\minhook\src\trampoline.c ..\vendor\minhook\src\hde\hde64.c
if errorlevel 1 exit /b 1
cl /nologo /LD /std:c++17 /EHsc /O2 /MT /W3 /I.. ..\dllmain.cpp ..\core.cpp ..\rooms.cpp ..\services.cpp ..\turn.cpp buffer.obj hook.obj trampoline.obj hde64.obj /link ws2_32.lib bcrypt.lib iphlpapi.lib winhttp.lib advapi32.lib /OUT:roadcraft_lan_emu.dll
set result=%errorlevel%
popd
exit /b %result%

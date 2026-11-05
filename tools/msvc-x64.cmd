@echo off
if /i "%VSCMD_ARG_TGT_ARCH%"=="x64" exit /b 0
if defined VCVARS64 (
    call "%VCVARS64%"
    exit /b
)
set "_roadcraft_vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%_roadcraft_vswhere%" goto :missing
for /f "usebackq delims=" %%i in (`"%_roadcraft_vswhere%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    call "%%i\VC\Auxiliary\Build\vcvars64.bat"
    exit /b
)
:missing
echo Open an x64 Native Tools Command Prompt or set VCVARS64 to vcvars64.bat.
exit /b 1

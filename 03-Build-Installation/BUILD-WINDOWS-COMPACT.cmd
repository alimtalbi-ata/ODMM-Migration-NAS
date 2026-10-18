@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem ODMM V228.71 - single supported build entrypoint; Windows 10/11 x64
set "ROOT=%~dp0.."
set "SRC=%ROOT%\02-Sources"
set "OUT=%ROOT%\binary"
set "VENV=%ROOT%\.windows-build-venv"
set "STAGE=%ROOT%\.windows-build-stage"
set "ODMM_VERSION=7.9.27"
set "ODMM_INSTALLER=ODMM-Compact-Setup-V%ODMM_VERSION%.exe"
if not exist "%SRC%\odmm_pagination_v22859.py" (echo ERROR: Missing pagination module & exit /b 31)
if not exist "%SRC%\odmm_ui_diagnostics_v22858.py" (echo ERROR: Missing UI diagnostics module & exit /b 30)
if not exist "%SRC%\odmm_connection_diagnostics_v22851.py" (echo ERROR: Missing diagnostics module & exit /b 24)
if not exist "%SRC%\odmm_windows_compact_v22811.py" (echo ERROR: Missing UI source & exit /b 21)
if not exist "%ROOT%\03-Build-Installation\ODMM-COMPACT-WINDOWS.iss" (echo ERROR: Missing installer source & exit /b 22)
if not exist "%ROOT%\03-Build-Installation\WINDOWS-BUILD-REQUIREMENTS.txt" (echo ERROR: Missing pinned build dependencies & exit /b 25)
rem Fail early if installer tooling is missing, before changing any existing binary.
set "ISCC="
if defined INNO_ISCC if exist "%INNO_ISCC%" set "ISCC=%INNO_ISCC%"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC (echo ERROR: Inno Setup 6 is required; install it or set INNO_ISCC. & exit /b 16)
"%ISCC%" /? >nul 2>&1 || (echo ERROR: Inno Setup compiler cannot be executed & exit /b 32)
rem Do not touch the published binary directory until validation and promotion.
set "PY=py -3"
where py >nul 2>&1 || set "PY=python"
%PY% -c "import sys;sys.exit(0 if sys.version_info >= (3,10) and sys.maxsize > 2**32 else 1)" || (echo ERROR: Python 3.10+ x64 required & exit /b 10)
if not exist "%VENV%\Scripts\python.exe" %PY% -m venv "%VENV%" || exit /b 11
set "VPY=%VENV%\Scripts\python.exe"
if defined ODMM_WHEELHOUSE (
 "%VPY%" -m pip install --no-index --find-links "%ODMM_WHEELHOUSE%" -r "%ROOT%\03-Build-Installation\WINDOWS-BUILD-REQUIREMENTS.txt" || exit /b 12
) else (
 "%VPY%" -m pip install --disable-pip-version-check -r "%ROOT%\03-Build-Installation\WINDOWS-BUILD-REQUIREMENTS.txt" || exit /b 12
)
"%VPY%" -m pip check || exit /b 26
"%VPY%" "%ROOT%\03-Build-Installation\CHECK-WINDOWS-TOOLCHAIN.py" --iscc "%ISCC%" --output "%ROOT%\03-Build-Installation\WINDOWS-TOOLCHAIN-REPORT.json" || exit /b 43
"%VPY%" "%ROOT%\03-Build-Installation\PREFLIGHT-WINDOWS.py" "%ROOT%" || exit /b 27
"%VPY%" "%ROOT%\03-Build-Installation\RECOVER-WINDOWS-PUBLICATION.py" "%OUT%" || exit /b 42
rem Build into a staging directory: failed builds must not erase prior deliverables.
if exist "%STAGE%" rmdir /s /q "%STAGE%" || exit /b 34
mkdir "%STAGE%\portable" || exit /b 35
mkdir "%STAGE%\installer" || exit /b 35
"%VPY%" -m PyInstaller --noconfirm --clean --onefile --windowed --name "ODMM-Compact" --distpath "%STAGE%\portable" --workpath "%ROOT%\.windows-build-work" --specpath "%ROOT%\.windows-build-work" --paths "%SRC%" "%SRC%\odmm_windows_compact_v22811.py" || exit /b 13
if not exist "%STAGE%\portable\ODMM-Compact.exe" exit /b 14
copy /y "%ROOT%\01-Applications\windows-compact\README.md" "%STAGE%\portable\README.txt" >nul || exit /b 15
"%ISCC%" /DODMM_VERSION="%ODMM_VERSION%" /DODMM_EXE="%STAGE%\portable\ODMM-Compact.exe" /DODMM_OUTPUT="%STAGE%\installer" "%ROOT%\03-Build-Installation\ODMM-COMPACT-WINDOWS.iss" || exit /b 17
if not exist "%STAGE%\installer\%ODMM_INSTALLER%" exit /b 18
"%VPY%" "%ROOT%\03-Build-Installation\VERIFY-WINDOWS-ARTIFACTS.py" "%STAGE%" "%ODMM_VERSION%" || exit /b 19
"%VPY%" "%ROOT%\03-Build-Installation\WRITE-BUILD-STATUS.py" "%STAGE%" "%ODMM_VERSION%" || exit /b 33
rem Publish entire verified release as a unit, with rollback on failure.
"%VPY%" "%ROOT%\03-Build-Installation\PUBLISH-WINDOWS-ARTIFACTS.py" "%STAGE%" "%OUT%" "%ODMM_VERSION%" || exit /b 41
"%VPY%" "%ROOT%\03-Build-Installation\VERIFY-WINDOWS-ARTIFACTS.py" "%OUT%" "%ODMM_VERSION%" || exit /b 40
"%VPY%" "%ROOT%\03-Build-Installation\VALIDATE-WINDOWS-RELEASE.py" "%OUT%" || exit /b 44
echo SUCCESS: portable and installer available in "%OUT%"
exit /b 0

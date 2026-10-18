@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0" || exit /b 2
set "PY=py -3"
where py >nul 2>&1 || set "PY=python"
%PY% -c "import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)" || exit /b 10
%PY% -m venv ".compact-build-venv" || exit /b 11
set "VENV_PY=.compact-build-venv\Scripts\python.exe"
"%VENV_PY%" -m pip install --disable-pip-version-check "pyinstaller>=6,<7" || exit /b 12
"%VENV_PY%" -m PyInstaller --noconfirm --clean --onefile --windowed --name "ODMM-Compact" --distpath "dist" --workpath ".compact-build-work" --specpath ".compact-build-work" "odmm_windows_compact_v2280.py" || exit /b 13
if not exist "dist\ODMM-Compact.exe" exit /b 14
set "ISCC="
if defined INNO_ISCC if exist "%INNO_ISCC%" set "ISCC=%INNO_ISCC%"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC (echo Installateur non genere: Inno Setup 6 absent. EXE portable disponible dans dist. & exit /b 16)
"%ISCC%" "ODMM-COMPACT-WINDOWS-V2280.iss" || exit /b 17
if not exist "dist\ODMM-Compact-Setup-V7.9.0.exe" exit /b 18
echo OK: dist\ODMM-Compact.exe et dist\ODMM-Compact-Setup-V7.9.0.exe
exit /b 0

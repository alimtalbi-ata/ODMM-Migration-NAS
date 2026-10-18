@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0" || exit /b 2
set "PY=py -3"
where py >nul 2>&1 || set "PY=python"
%PY% --version >nul 2>&1 || (echo ERREUR: Python 3.10+ requis. & exit /b 10)
%PY% -c "import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)" || exit /b 10
%PY% -m venv ".build-venv" || exit /b 11
set "VENV_PY=.build-venv\Scripts\python.exe"
"%VENV_PY%" -m pip install --disable-pip-version-check "pyinstaller>=6,<7" || exit /b 13
"%VENV_PY%" -m PyInstaller --noconfirm --clean --onefile --windowed --name "ODMM-Desktop" --distpath "dist" --workpath ".build-work" --specpath ".build-work" --hidden-import odmm_desktop_model_v2258 --hidden-import odmm_desktop_preflight_v2261 --hidden-import odmm_desktop_plan_v2262 --hidden-import odmm_desktop_jobs_v2263 --hidden-import odmm_desktop_api_v2266 --hidden-import odmm_registry_client_v2267 --hidden-import odmm_registry_operations_v2269 --hidden-import odmm_dashboard_v2270 --hidden-import odmm_desktop_async_v2274 --hidden-import odmm_health_v2271 "odmm_windows_desktop_v2274.py" || exit /b 14
if not exist "dist\ODMM-Desktop.exe" (echo ERREUR: EXE absent & exit /b 15)
set "ISCC="
if defined INNO_ISCC if exist "%INNO_ISCC%" set "ISCC=%INNO_ISCC%"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC (echo ERREUR: Inno Setup 6 absent. Portable disponible dans dist. & exit /b 16)
"%ISCC%" "ODMM-WINDOWS-V2274.iss" || exit /b 17
if not exist "dist\ODMM-Setup-V227.4.exe" (echo ERREUR: installateur absent & exit /b 18)
"%VENV_PY%" "odmm_windows_build_audit_v2274.py" --root . --artifacts --output "dist\BUILD-REPORT-V2274.json" || exit /b 19
echo SUCCES: dist\ODMM-Desktop.exe et dist\ODMM-Setup-V227.4.exe
exit /b 0

@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "PY=py -3"
where py >nul 2>&1 || set "PY=python"
%PY% --version >nul 2>&1 || (echo ERREUR: Python 3 introuvable. & exit /b 10)
%PY% -m venv ".build-venv" || exit /b 11
call ".build-venv\Scripts\python.exe" -m pip install --disable-pip-version-check --upgrade pip || exit /b 12
call ".build-venv\Scripts\python.exe" -m pip install --disable-pip-version-check "pyinstaller>=6,<7" || exit /b 13
call ".build-venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name "ODMM-Desktop" --distpath "dist" --workpath ".build-work" --specpath ".build-work" "odmm_windows_desktop_v2257.py" || exit /b 14
if not exist "dist\ODMM-Desktop.exe" (echo ERREUR: EXE absent & exit /b 15)
echo PORTABLE: dist\ODMM-Desktop.exe
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC (echo ERREUR: Inno Setup 6 requis pour l'installateur. Portable genere. & exit /b 16)
"%ISCC%" "ODMM-WINDOWS-V2257.iss" || exit /b 17
if not exist "dist\ODMM-Setup-V225.7.exe" (echo ERREUR: installateur absent & exit /b 18)
echo SUCCES: dist\ODMM-Desktop.exe et dist\ODMM-Setup-V225.7.exe
exit /b 0

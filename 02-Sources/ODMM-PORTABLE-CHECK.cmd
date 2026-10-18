@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
  py -3 "%~dp0odmm_portable_doctor_v2246.py" --root "%~dp0" --output "%~dp0odmm-portable-report.json"
) else (
  where python >nul 2>&1
  if errorlevel 1 (
    echo ERREUR: Python 3 introuvable. Aucune installation automatique n'est effectuee.
    exit /b 2
  )
  python "%~dp0odmm_portable_doctor_v2246.py" --root "%~dp0" --output "%~dp0odmm-portable-report.json"
)
exit /b %errorlevel%

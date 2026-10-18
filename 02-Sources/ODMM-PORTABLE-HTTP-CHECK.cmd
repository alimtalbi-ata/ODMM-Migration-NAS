@echo off
setlocal
cd /d "%~dp0" || exit /b 1
where py >nul 2>nul
if not errorlevel 1 (py -3 odmm_http_runtime_qualification_v2251.py --output qualification-v2251.json & exit /b %errorlevel%)
python odmm_http_runtime_qualification_v2251.py --output qualification-v2251.json
exit /b %errorlevel%

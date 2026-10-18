@echo off
rem Compatibility entrypoint; build logic lives in the canonical script.
call "%~dp0BUILD-WINDOWS-COMPACT.cmd" %*
exit /b %errorlevel%

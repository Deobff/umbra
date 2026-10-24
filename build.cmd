@echo off
rem Umbra build launcher: PowerShell execution policy must not get in the way.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
exit /b %ERRORLEVEL%

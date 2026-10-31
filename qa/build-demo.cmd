@echo off
rem Builds demo/demo.jar and runs the demo self-checks.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-demo.ps1" %*
exit /b %ERRORLEVEL%

@echo off
rem Isolated development build of Umbra into build-qa/umbra.jar (never dist/).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-umbra-dev.ps1" %*
exit /b %ERRORLEVEL%

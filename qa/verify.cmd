@echo off
rem Umbra end-to-end verification matrix.
rem   qa\verify.cmd -UmbraJar dist\umbra.jar
rem   qa\verify.cmd -UmbraJar dist\umbra.jar -SkipUnimplemented
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify.ps1" %*
exit /b %ERRORLEVEL%

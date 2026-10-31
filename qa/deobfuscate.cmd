@echo off
rem Decompilation / deobfuscation evidence for one protected jar.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deobfuscate.ps1" %*
exit /b %ERRORLEVEL%

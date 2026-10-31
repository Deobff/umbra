@echo off
rem Convenience wrapper for Windows cmd.exe users.
setlocal
set "SCRIPT=%~dp0run-qa.ps1"
where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
)
exit /b %ERRORLEVEL%

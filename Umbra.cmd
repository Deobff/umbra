@echo off
rem Umbra GUI launcher: double-click to start the interface.
rem The packaged jar is produced by `build.cmd -Task dist`.
setlocal
set "ROOT=%~dp0"
if not exist "%ROOT%dist\umbra.jar" (
  echo Umbra is not built yet.
  echo Run:  "%ROOT%build.cmd" -Task dist
  pause
  exit /b 1
)
start "" javaw -jar "%ROOT%dist\umbra.jar"
endlocal

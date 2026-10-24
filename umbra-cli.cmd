@echo off
rem Command-line launcher for Umbra.
rem Usage examples:
rem   umbra-cli.cmd -i app.jar -o app-obf.jar --flatten --virtualize --verify
rem   umbra-cli.cmd -c umbra.example.yml
setlocal
set "ROOT=%~dp0"
if not exist "%ROOT%dist\umbra.jar" (
  echo Umbra is not built yet.
  echo Run:  "%ROOT%build.cmd" -Task dist
  exit /b 1
)
java -jar "%ROOT%dist\umbra.jar" %*
exit /b %ERRORLEVEL%

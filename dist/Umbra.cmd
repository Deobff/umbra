@echo off
rem Umbra desktop launcher: double-click to start the interface.
rem
rem Works in two layouts:
rem   working tree  E:\...\Umbra\        -> dist\umbra.jar + gui-fx\umbra-gui-fx.jar
rem   packaged      E:\...\Umbra\dist\   -> umbra.jar      + umbra-gui-fx.jar
rem
rem Prefers the JavaFX console (the current front end) and falls back to the
rem console embedded in umbra.jar when no JavaFX-capable JDK 8 is installed, so a
rem double-click never just fails.
rem Set UMBRA_LAUNCH_DRYRUN=1 to print the resolved command instead of launching.
setlocal
set "ROOT=%~dp0"

set "ENGINE="
if exist "%ROOT%dist\umbra.jar" set "ENGINE=%ROOT%dist\umbra.jar"
if not defined ENGINE if exist "%ROOT%umbra.jar" set "ENGINE=%ROOT%umbra.jar"
if not defined ENGINE (
  echo Umbra is not built yet.
  echo Run:  "%ROOT%build.cmd" -Task dist
  pause
  exit /b 1
)

set "FXJAR="
if exist "%ROOT%umbra-gui-fx.jar" set "FXJAR=%ROOT%umbra-gui-fx.jar"
if not defined FXJAR if exist "%ROOT%dist\umbra-gui-fx.jar" set "FXJAR=%ROOT%dist\umbra-gui-fx.jar"
if not defined FXJAR if exist "%ROOT%gui-fx\umbra-gui-fx.jar" set "FXJAR=%ROOT%gui-fx\umbra-gui-fx.jar"

if defined FXJAR if "%JFX_JAVA_HOME%"=="" (
  for %%D in (
    "%USERPROFILE%\.jdks\corretto-1.8.0_462"
    "C:\Program Files\Java\jdk1.8.0_261"
    "C:\Program Files\Java\jre1.8.0_471"
  ) do (
    if exist "%%~D\jre\lib\ext\jfxrt.jar" set JFX_JAVA_HOME=%%~D
  )
)

if defined FXJAR if defined JFX_JAVA_HOME (
  if defined UMBRA_LAUNCH_DRYRUN (
    echo "%JFX_JAVA_HOME%\bin\javaw.exe" -cp "%FXJAR%;%ENGINE%" io.umbra.guifx.FxGui --jar "%ENGINE%"
    endlocal
    exit /b 0
  )
  start "" "%JFX_JAVA_HOME%\bin\javaw.exe" -cp "%FXJAR%;%ENGINE%" io.umbra.guifx.FxGui --jar "%ENGINE%"
  endlocal
  exit /b 0
)

rem No JavaFX runtime available: the engine jar carries the classic console.
if defined UMBRA_LAUNCH_DRYRUN (
  echo javaw -jar "%ENGINE%"
  endlocal
  exit /b 0
)
start "" javaw -jar "%ENGINE%"
endlocal
exit /b 0

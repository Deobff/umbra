@echo off
rem Launches the JavaFX console. Needs a JDK 8 that ships JavaFX.
rem The GUI jar is looked up next to this script (packaged layout) and then in
rem gui-fx\ (working-tree layout), so the same launcher works in both.
setlocal
cd /d "%~dp0"

if "%JFX_JAVA_HOME%"=="" (
  for %%D in (
    "%USERPROFILE%\.jdks\corretto-1.8.0_462"
    "C:\Program Files\Java\jdk1.8.0_261"
    "C:\Program Files\Java\jre1.8.0_471"
  ) do (
    if exist "%%~D\jre\lib\ext\jfxrt.jar" set JFX_JAVA_HOME=%%~D
  )
)
if "%JFX_JAVA_HOME%"=="" (
  echo No JDK with JavaFX found. Install a JDK 8 with javafx or set JFX_JAVA_HOME.
  exit /b 1
)

set "FXJAR="
if exist "umbra-gui-fx.jar" set "FXJAR=%CD%\umbra-gui-fx.jar"
if not defined FXJAR if exist "dist\umbra-gui-fx.jar" set "FXJAR=%CD%\dist\umbra-gui-fx.jar"
if not defined FXJAR if exist "gui-fx\umbra-gui-fx.jar" set "FXJAR=%CD%\gui-fx\umbra-gui-fx.jar"
if not defined FXJAR (
  echo umbra-gui-fx.jar is missing, run gui-fx\build-fx.cmd first
  exit /b 1
)

set "ENGINE="
if exist "dist\umbra.jar" set "ENGINE=%CD%\dist\umbra.jar"
if not defined ENGINE if exist "umbra.jar" set "ENGINE=%CD%\umbra.jar"
if not defined ENGINE (
  echo dist\umbra.jar is missing, run build.cmd -Task dist first
  exit /b 1
)

start "" "%JFX_JAVA_HOME%\bin\javaw.exe" -cp "%FXJAR%;%ENGINE%" io.umbra.guifx.FxGui --jar "%ENGINE%"
endlocal
exit /b 0

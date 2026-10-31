@echo off
rem Compiles the JavaFX front-end. JavaFX 8 ships inside the JDK, so a JDK 8
rem build that includes javafx (jre/lib/ext/jfxrt.jar) is required.
rem Set JFX_JAVA_HOME to point at one explicitly.
setlocal
cd /d "%~dp0"

if "%JFX_JAVA_HOME%"=="" set JFX_JAVA_HOME=%JAVA_HOME%
if not "%JFX_JAVA_HOME%"=="" (
  if not exist "%JFX_JAVA_HOME%\jre\lib\ext\jfxrt.jar" (
    echo %JFX_JAVA_HOME% has no JavaFX, falling back to auto-detect
    set JFX_JAVA_HOME=
  )
)
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

if not exist "..\dist\umbra.jar" (
  echo ..\dist\umbra.jar is missing, run ..\build.cmd first
  exit /b 1
)

if exist classes rmdir /s /q classes
mkdir classes
rem The shell is split into small units; list them explicitly because javac does
rem not expand wildcards on Windows.
"%JFX_JAVA_HOME%\bin\javac.exe" -encoding UTF-8 -source 1.8 -target 1.8 -nowarn ^
  -cp "..\dist\umbra.jar" -d classes ^
  src\io\umbra\guifx\FxGui.java ^
  src\io\umbra\guifx\ConsoleModel.java ^
  src\io\umbra\guifx\ConsoleShell.java ^
  src\io\umbra\guifx\OptionsView.java ^
  src\io\umbra\guifx\Motion.java ^
  src\io\umbra\guifx\FusionButton.java ^
  src\io\umbra\guifx\TitleBar.java ^
  src\io\umbra\guifx\Tokens.java ^
  src\io\umbra\guifx\AboutDialog.java || exit /b 1
copy /y src\io\umbra\guifx\umbra-fx.css classes\io\umbra\guifx\umbra-fx.css >nul || exit /b 1
"%JFX_JAVA_HOME%\bin\jar.exe" cfe umbra-gui-fx.jar io.umbra.guifx.FxGui -C classes . || exit /b 1
echo built umbra-gui-fx.jar with %JFX_JAVA_HOME%
endlocal
exit /b 0

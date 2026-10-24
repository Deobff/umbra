# Builds the Umbra Gradle and Maven plugins with the local toolchain.
#
#   pwsh plugins/build-plugins.ps1
#   pwsh plugins/build-plugins.ps1 -JavaHome 'C:\Program Files\Zulu\zulu-8'
#
# What it does:
#   1. Gradle plugin: compile (Java 8 bytecode), jar, copy to plugins/dist/,
#      publish to ~/.m2 (publishToMavenLocal) so sample/user builds can use
#      `plugins { id 'io.umbra' version '3.0.0' }` via mavenLocal().
#   2. Maven plugin: mvn clean install into ~/.m2 and copy the jar to
#      plugins/dist/.
#
# Toolchain: JDK 8 (tested Zulu 8), Gradle 8.14 (existing install or wrapper
# cache), Apache Maven 3.9.9 (downloaded once into plugins/.cache/).
# The Gradle plugin has no external dependencies and is built with --offline.

[CmdletBinding()]
param(
    [string]$JavaHome,
    [string]$GradleHome,
    [string]$MavenHome
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\toolchain.ps1"

$javaHomePath = Resolve-JavaHome $JavaHome
$env:JAVA_HOME = $javaHomePath
$java = Join-Path $javaHomePath 'bin\java.exe'
$gradle = Resolve-GradleBat $GradleHome
$mvn = Resolve-MavenCmd $MavenHome

$gradlePluginDir = Join-Path $PSScriptRoot 'umbra-gradle-plugin'
$mavenPluginDir = Join-Path $PSScriptRoot 'umbra-maven-plugin'
$distDir = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

Write-Host '==> Toolchain'
$javaVersion = Invoke-NativeCapture -FilePath $java -Arguments @('-version')
Write-Host ("  java:   {0}" -f $javaHomePath)
Write-Host ("  {0}" -f (($javaVersion.Text -split '\r?\n')[0]))
$gradleVersion = Invoke-NativeCapture -FilePath $gradle -Arguments @('--version')
Write-Host ("  gradle: {0}" -f $gradle)
Write-Host ("  {0}" -f (($gradleVersion.Text -split '\r?\n' | Where-Object { $_ -match '^Gradle ' })[0]))
$mavenVersion = Invoke-NativeCapture -FilePath $mvn -Arguments @('-version')
Write-Host ("  maven:  {0}" -f $mvn)
Write-Host ("  {0}" -f (($mavenVersion.Text -split '\r?\n')[0]))
if ($javaVersion.ExitCode -ne 0) { throw 'java -version failed.' }
if ($gradleVersion.ExitCode -ne 0) { throw 'gradle --version failed.' }
if ($mavenVersion.ExitCode -ne 0) { throw 'mvn -version failed.' }

Write-Host '==> Building Gradle plugin (java-gradle-plugin, Java 8 bytecode)'
Push-Location $gradlePluginDir
try {
    & $gradle --no-daemon --offline clean jar distJar publishToMavenLocal
    if ($LASTEXITCODE -ne 0) { throw "Gradle plugin build failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
}

Write-Host '==> Building Maven plugin (maven-plugin packaging, Java 8 bytecode)'
Push-Location $mavenPluginDir
try {
    & $mvn -B -ntp clean install
    if ($LASTEXITCODE -ne 0) { throw "Maven plugin build failed with exit code $LASTEXITCODE." }
    $builtMavenJar = Join-Path $mavenPluginDir "target\umbra-maven-plugin-$PluginVersion.jar"
    if (-not (Test-Path -LiteralPath $builtMavenJar -PathType Leaf)) {
        throw "Maven plugin jar not found: $builtMavenJar"
    }
    Copy-Item -LiteralPath $builtMavenJar -Destination (Join-Path $distDir "umbra-maven-plugin-$PluginVersion.jar") -Force
} finally {
    Pop-Location
}

Write-Host '==> Plugin artifacts (plugins/dist)'
$artifacts = Get-ChildItem -LiteralPath $distDir -Filter '*.jar' -File | Sort-Object Name
foreach ($artifact in $artifacts) {
    Write-Host ("  {0}  {1,7} bytes  sha256={2}" -f $artifact.Name, $artifact.Length, (Get-FileSha256 $artifact.FullName))
}
if ($artifacts.Count -lt 2) {
    throw "Expected two plugin jars in $distDir, found $($artifacts.Count)."
}

Write-Host ''
Write-Host 'Done. Gradle plugin published to mavenLocal as io.umbra:umbra-gradle-plugin:3.0.0'
Write-Host '      Maven plugin installed as io.umbra:umbra-maven-plugin:3.0.0'

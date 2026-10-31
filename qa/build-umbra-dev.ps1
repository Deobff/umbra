#requires -Version 5.1
<#
.SYNOPSIS
    Development-only isolated build of Umbra (does not touch dist/).

.DESCRIPTION
    Compiles src/main/java into build-qa/classes with the official build script
    and packages build-qa/umbra.jar. This lets QA test the current working tree
    without racing the Lead's dist build or the shared build/ directory.

    The evidence matrix in docs/VERIFICATION.md must use dist/umbra.jar, built
    with: cmd /c build.cmd -Task dist

.EXAMPLE
    qa\build-umbra-dev.cmd
#>
param(
    [string]$BuildDir = 'build-qa'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path $PSScriptRoot -Parent
$BuildDir = if ([System.IO.Path]::IsPathRooted($BuildDir)) { $BuildDir } else { Join-Path $Root $BuildDir }
$Classes = Join-Path $BuildDir 'classes'
$UmbraJar = Join-Path $BuildDir 'umbra.jar'

function Find-JdkTool([string]$Name) {
    $candidates = @()
    if ($env:JAVA_HOME) { $candidates += (Join-Path $env:JAVA_HOME "bin\$Name.exe") }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
    $candidates += "C:\Program Files\Zulu\zulu-8\bin\$Name.exe"
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    throw "Cannot find $Name"
}

$Jar = Find-JdkTool 'jar'

Write-Host '==> compile Umbra (isolated)' -ForegroundColor Cyan
& (Join-Path $Root 'build.cmd') -Task compile -BuildDir $BuildDir
if ($LASTEXITCODE -ne 0) { throw "Umbra compile failed with exit code $LASTEXITCODE" }

Write-Host '==> package build-qa/umbra.jar' -ForegroundColor Cyan
$manifest = Join-Path $BuildDir 'MANIFEST.MF'
[System.IO.File]::WriteAllText($manifest,
    "Manifest-Version: 1.0`r`nMain-Class: io.umbra.cli.Main`r`nImplementation-Title: Umbra`r`nImplementation-Version: 2.0.0`r`n`r`n",
    (New-Object System.Text.UTF8Encoding($false)))
$fat = Join-Path $BuildDir 'fat'
if (Test-Path $fat) { Remove-Item $fat -Recurse -Force }
New-Item -ItemType Directory -Force -Path $fat | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($lib in Get-ChildItem (Join-Path $Root 'lib') -Filter '*.jar') {
    $temp = Join-Path $BuildDir ('unzip-' + [guid]::NewGuid().ToString('N'))
    [System.IO.Compression.ZipFile]::ExtractToDirectory($lib.FullName, $temp)
    Copy-Item (Join-Path $temp '*') $fat -Recurse -Force
    Remove-Item $temp -Recurse -Force
}
Copy-Item (Join-Path $Classes '*') $fat -Recurse -Force
if (Test-Path $UmbraJar) { Remove-Item $UmbraJar -Force }
$result = & $Jar cfm $UmbraJar $manifest -C $fat .
if ($LASTEXITCODE -ne 0) { throw "jar failed with exit code $LASTEXITCODE" }
$size = [Math]::Round((Get-Item $UmbraJar).Length / 1KB, 0)
Write-Host ("  {0} ({1} KB, {2} classes)" -f $UmbraJar, $size,
    @(Get-ChildItem $Classes -Recurse -Filter '*.class').Count) -ForegroundColor Green

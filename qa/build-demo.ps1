#requires -Version 5.1
<#
.SYNOPSIS
    Builds the Umbra demo application (demo/demo.jar).

.DESCRIPTION
    Compiles demo/src/**/*.java with the Java 8 compiler, bundles the text
    resource from demo/resources, writes an executable jar and runs the
    built-in self-checks. Plain javac/jar only, no build tool and no deps.

.EXAMPLE
    qa\build-demo.cmd
    qa\build-demo.cmd -Clean
    qa\build-demo.cmd -SkipRun
#>
param(
    [string]$Output = '',
    [switch]$Clean,
    [switch]$SkipRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path $PSScriptRoot -Parent
$DemoSrc = Join-Path $Root 'demo\src'
$DemoResources = Join-Path $Root 'demo\resources'
$Classes = Join-Path $Root 'demo\classes'
$Manifest = Join-Path $Root 'demo\MANIFEST.MF'
if (-not $Output) {
    $Output = Join-Path $Root 'demo\demo.jar'
} elseif (-not [System.IO.Path]::IsPathRooted($Output)) {
    $Output = Join-Path $Root $Output
}

function Find-JdkTool([string]$Name) {
    $candidates = @()
    if ($env:JAVA_HOME) {
        $candidates += (Join-Path $env:JAVA_HOME "bin\$Name.exe")
    }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
    $candidates += "C:\Program Files\Zulu\zulu-8\bin\$Name.exe"
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    throw "Cannot find $Name. Install JDK 8+ or set JAVA_HOME."
}

<#
    Runs a native JDK tool and returns its exit code and captured output.
    PowerShell would otherwise turn javac's stderr notes into terminating
    errors under $ErrorActionPreference = 'Stop'.
#>
function Invoke-Tool([string]$Exe, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $token = [guid]::NewGuid().ToString('N')
    $outFile = Join-Path $env:TEMP ("umbra-demo-$token.out")
    $errFile = Join-Path $env:TEMP ("umbra-demo-$token.err")
    try {
        & $Exe @Arguments 1> $outFile 2> $errFile
        $code = $LASTEXITCODE
        $stdout = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { '' }
        $stderr = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { '' }
    } finally {
        $ErrorActionPreference = $previous
        Remove-Item $outFile, $errFile -ErrorAction SilentlyContinue
    }
    if ($null -eq $stdout) { $stdout = '' }
    if ($null -eq $stderr) { $stderr = '' }
    return [pscustomobject]@{ Code = $code; StdOut = $stdout; StdErr = $stderr }
}

$Javac = Find-JdkTool 'javac'
$Java = Find-JdkTool 'java'
$Jar = Find-JdkTool 'jar'

Write-Host '==> build demo' -ForegroundColor Cyan

if ($Clean) {
    foreach ($path in @($Classes, $Output)) {
        if (Test-Path $path) { Remove-Item $path -Recurse -Force }
    }
}
if (-not (Test-Path $DemoSrc)) { throw "Missing demo sources: $DemoSrc" }

$sources = @(Get-ChildItem $DemoSrc -Recurse -Filter '*.java' | ForEach-Object { $_.FullName })
if ($sources.Count -eq 0) { throw "No Java sources under $DemoSrc" }
New-Item -ItemType Directory -Force -Path $Classes | Out-Null
$argFile = Join-Path $Classes 'sources.txt'
[System.IO.File]::WriteAllLines($argFile, $sources, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("  compiling {0} source files" -f $sources.Count)
$compile = Invoke-Tool $Javac @('-encoding', 'UTF-8', '-source', '1.8', '-target', '1.8',
    '-Xlint:-options', '-nowarn', '-d', $Classes, "@$argFile")
Remove-Item $argFile -ErrorAction SilentlyContinue
if ($compile.StdErr.Trim()) { Write-Host $compile.StdErr.TrimEnd() -ForegroundColor DarkGray }
if ($compile.Code -ne 0) { throw "javac failed with exit code $($compile.Code)" }

if (Test-Path $DemoResources) {
    Copy-Item (Join-Path $DemoResources '*') $Classes -Recurse -Force
}

$manifestLines = @(
    'Manifest-Version: 1.0',
    'Main-Class: demo.Main',
    'Implementation-Title: Umbra demo',
    'Implementation-Version: 1.0.0',
    'Created-By: qa/build-demo.ps1'
)
[System.IO.File]::WriteAllText($Manifest, ($manifestLines -join "`r`n") + "`r`n",
    (New-Object System.Text.UTF8Encoding($false)))

$outputDir = Split-Path $Output -Parent
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
if (Test-Path $Output) { Remove-Item $Output -Force }
$package = Invoke-Tool $Jar @('cfm', $Output, $Manifest, '-C', $Classes, '.')
if ($package.Code -ne 0) { throw "jar failed with exit code $($package.Code): $($package.StdErr)" }

$size = (Get-Item $Output).Length
$entries = (Invoke-Tool $Jar @('tf', $Output)).StdOut -split "`r?`n"
if (-not ($entries -contains 'demo/assets/data.txt')) {
    throw "built jar is missing demo/assets/data.txt"
}
Write-Host ("  wrote {0} ({1} bytes, {2} class files)" -f $Output, $size,
    @(Get-ChildItem $Classes -Recurse -Filter '*.class').Count)

if ($SkipRun) {
    Write-Host '  -SkipRun: self-check skipped' -ForegroundColor DarkGray
    return
}

$run = Invoke-Tool $Java @('-jar', $Output)
$text = $run.StdOut.Trim()
if ($run.Code -ne 0) {
    throw "demo self-check failed with exit code $($run.Code)`n$text`n$($run.StdErr)"
}
if ($text -ne 'OK') { throw "demo printed unexpected output: '$text'" }
Write-Host '  self-check: OK' -ForegroundColor Green

#requires -Version 5.1
<#
.SYNOPSIS
    Builds, tests and packages Umbra.

.DESCRIPTION
    Umbra deliberately avoids a build tool: a single JDK 8 and the vendored
    ASM jars are enough. This keeps the build reproducible on a locked-down
    machine and makes a clean build fast enough for CI.

    Tasks:
      compile  Compile src/main/java into build/classes (resources copied too).
      test     Compile and run the self-test harness under src/test/java.
      dist     Produce the executable fat jar dist/umbra.jar.
      gui      Start the desktop GUI from the compiled classes.
      clean    Remove build/ and dist/.
      all      compile + test + dist (default).

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Task compile
    .\build.ps1 -Task test -SkipDist
#>
param(
    [ValidateSet('all', 'compile', 'test', 'dist', 'package', 'gui', 'clean')]
    [string]$Task = 'all',
    [string]$BuildDir = '',
    [switch]$SkipTests,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = $PSScriptRoot
if ($BuildDir) {
    if ([System.IO.Path]::IsPathRooted($BuildDir)) { $Build = $BuildDir }
    else { $Build = Join-Path $Root $BuildDir }
} else {
    $Build = Join-Path $Root 'build'
}
$Classes = Join-Path $Build 'classes'
$TestClasses = Join-Path $Build 'test-classes'
$LibDir = Join-Path $Root 'lib'
# A custom -BuildDir also gets its own dist/ so parallel agents and branches did not overwrite the shared dist\umbra.jar.
if ($BuildDir) { $Dist = Join-Path $Build 'dist' } else { $Dist = Join-Path $Root 'dist' }
$MainSources = Join-Path $Root 'src\main\java'
$TestSources = Join-Path $Root 'src\test\java'
$MainResources = Join-Path $Root 'src\main\resources'

function Find-JdkTool([string]$Name) {
    $candidates = @()
    if ($env:JAVA_HOME) {
        $candidates += (Join-Path $env:JAVA_HOME "bin\$Name.exe")
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    $candidates += "C:\Program Files\Zulu\zulu-8\bin\$Name.exe"
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    throw "Cannot find $Name. Install a JDK 8+ or set JAVA_HOME."
}

$Javac = Find-JdkTool 'javac'
$Java = Find-JdkTool 'java'
$Jar = Find-JdkTool 'jar'

$LibJars = @()
if (Test-Path $LibDir) {
    $LibJars = @(Get-ChildItem $LibDir -Filter '*.jar' | ForEach-Object { $_.FullName })
}
$LibCp = ($LibJars -join ';')

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

<#
    SHA-256 through .NET rather than Get-FileHash. The cmdlet ships in a module
    that is not auto-loadable on every build host (it is missing on the CI
    runners), and these checksums are a release artifact, so the hashing must not
    depend on module autoloading.
#>
function Get-Sha256Hex([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $digest = $sha.ComputeHash($stream)
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

<#
    Runs a native tool without letting PowerShell turn its stderr output into a
    terminating NativeCommandError. javac prints deprecation notes on stderr on
    every JDK, so the exit code is the only signal we trust.
#>
function Invoke-Native([string]$Exe, [string[]]$Arguments, [string]$Label) {
    $errFile = Join-Path $Build ("stderr-" + [guid]::NewGuid().ToString('N') + ".txt")
    $outFile = Join-Path $Build ("stdout-" + [guid]::NewGuid().ToString('N') + ".txt")
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 1> $outFile 2> $errFile
        $code = $LASTEXITCODE
        $stdout = if (Test-Path $outFile) { Get-Content $outFile -Raw -ErrorAction SilentlyContinue } else { '' }
        $stderr = if (Test-Path $errFile) { Get-Content $errFile -Raw -ErrorAction SilentlyContinue } else { '' }
        if ($stdout -and $stdout.Trim()) { Write-Host $stdout.TrimEnd() }
        if ($stderr -and $stderr.Trim()) { Write-Host $stderr.TrimEnd() -ForegroundColor DarkGray }
    } finally {
        $ErrorActionPreference = $previous
        Remove-Item $errFile -ErrorAction SilentlyContinue
        Remove-Item $outFile -ErrorAction SilentlyContinue
    }
    if ($code -ne 0) { throw "$Label failed with exit code $code" }
}

function Invoke-Javac([string]$SourceRoot, [string]$Destination, [string]$ExtraClasspath = '') {
    if (-not (Test-Path $SourceRoot)) { return }
    $sources = @(Get-ChildItem $SourceRoot -Recurse -Filter '*.java' | ForEach-Object { $_.FullName })
    if ($sources.Count -eq 0) { return }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $argFile = Join-Path $Build ("sources-" + [guid]::NewGuid().ToString('N') + ".txt")
    [System.IO.File]::WriteAllLines($argFile, $sources, (New-Object System.Text.UTF8Encoding($false)))
    $cp = $LibCp
    if ($ExtraClasspath) { $cp = "$cp;$ExtraClasspath" }
    Write-Host ("  compiling {0} source files" -f $sources.Count)
    Invoke-Native $Javac @(
        '-encoding', 'UTF-8', '-source', '1.8', '-target', '1.8',
        '-Xlint:-options', '-nowarn', '-cp', $cp, '-d', $Destination, "@$argFile"
    ) 'javac'
    Remove-Item $argFile -ErrorAction SilentlyContinue
}

function Copy-Resources([string]$SourceRoot, [string]$Destination) {
    if (-not (Test-Path $SourceRoot)) { return }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item (Join-Path $SourceRoot '*') $Destination -Recurse -Force
}

function Clean-Build {
    Write-Step 'clean'
    foreach ($path in @($Build, $Dist)) {
        if (Test-Path $path) { Remove-Item $path -Recurse -Force }
    }
}

function Build-Compile {
    Write-Step 'compile'
    if (-not (Test-Path $LibDir) -or $LibJars.Count -eq 0) {
        throw "Missing vendored ASM jars in $LibDir"
    }
    New-Item -ItemType Directory -Force -Path $Build | Out-Null
    if (Test-Path $Classes) { Remove-Item $Classes -Recurse -Force }
    Invoke-Javac $MainSources $Classes
    Copy-Resources $MainResources $Classes
    $count = @(Get-ChildItem $Classes -Recurse -Filter '*.class').Count
    Write-Host ("  {0} classes in {1}" -f $count, $Classes)
}

function Build-Test {
    Write-Step 'test'
    if (-not (Test-Path $TestSources)) {
        Write-Host '  (no test sources)' -ForegroundColor DarkGray
        return
    }
    Invoke-Javac $TestSources $TestClasses $Classes
    $runners = @(Get-ChildItem $TestClasses -Recurse -Filter '*Test.class' | Where-Object { $_.Name -notmatch '\$' })
    if ($runners.Count -eq 0) { Write-Host '  (no test runners)' -ForegroundColor DarkGray; return }
    foreach ($runner in $runners) {
        $relative = $runner.FullName.Substring($TestClasses.Length + 1)
        $className = $relative.Substring(0, $relative.Length - 6).Replace('\', '.').Replace('/', '.')
        Write-Host ("  running {0}" -f $className)
        # A hung test must never hang the whole build (guards against a
        # pathological sample in a teammate's test); 240s per runner.
        $log = Join-Path $Build ("test-" + $className + ".log")
        $err = Join-Path $Build ("test-" + $className + ".err")
        # Run through cmd so the real child exit code is available in
        # $LASTEXITCODE (Start-Process's ExitCode is unreliable for console
        # children in Windows PowerShell 5.1).
        $cp = "$Classes;$TestClasses;$LibCp"
        $commandLine = '"' + $Java + '" -cp "' + $cp + '" ' + $className + ' > "' + $log + '" 2> "' + $err + '"'
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        & cmd.exe /c $commandLine
        $exitCode = $LASTEXITCODE
        $watch.Stop()
        if ($watch.Elapsed.TotalSeconds -gt 240) {
            throw "test $className timed out after 240s (see $log)"
        }
        if (Test-Path $log) { Get-Content $log | Write-Host }
        if (Test-Path $err) {
            $text = Get-Content $err -Raw -ErrorAction SilentlyContinue
            if ($text -and $text.Trim()) { Write-Host $text.TrimEnd() -ForegroundColor DarkGray }
        }
        if ($exitCode -ne 0) { throw "test $className failed with exit code $exitCode" }
    }
}

function Copy-GuiArtifacts {
    # The desktop front end lives in its own jar because it needs JavaFX, which the
    # build JDK does not have to ship. Refresh it next to the engine jar on every
    # dist/package run, otherwise dist\ keeps launching the previous console.
    $guiJar = Join-Path $Root 'gui-fx\umbra-gui-fx.jar'
    if (-not (Test-Path $guiJar)) {
        $buildFx = Join-Path $Root 'gui-fx\build-fx.cmd'
        if (Test-Path $buildFx) {
            Write-Host "  gui-fx\umbra-gui-fx.jar is missing; building it (needs a JDK 8 with JavaFX)" -ForegroundColor Yellow
            & cmd.exe /c "`"$buildFx`"" 2>&1 | ForEach-Object { Write-Host ("  " + $_) }
        }
    }
    New-Item -ItemType Directory -Force -Path $Dist | Out-Null
    if (Test-Path $guiJar) {
        Copy-Item $guiJar (Join-Path $Dist 'umbra-gui-fx.jar') -Force
        Copy-Item (Join-Path $Root 'umbra-fx.cmd') $Dist -Force
        $size = [math]::Round((Get-Item $guiJar).Length / 1KB, 1)
        Write-Host ("  {0} ({1} KB)" -f (Join-Path $Dist 'umbra-gui-fx.jar'), $size)
    } else {
        Write-Host "  WARNING: no JavaFX front end available; the package ships the classic console only" -ForegroundColor Yellow
    }
    Copy-Item (Join-Path $Root 'Umbra.cmd') $Dist -Force
    Copy-Item (Join-Path $Root 'umbra-cli.cmd') $Dist -Force
    Copy-Item (Join-Path $Root 'umbra.example.yml') $Dist -Force
}

function Build-Dist {
    Write-Step 'dist'
    if (-not (Test-Path $Classes)) { Build-Compile }
    $Fat = Join-Path $Build 'fat'
    if (Test-Path $Fat) { Remove-Item $Fat -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Fat | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($lib in $LibJars) {
        $temp = Join-Path $Build ('unzip-' + [guid]::NewGuid().ToString('N'))
        [System.IO.Compression.ZipFile]::ExtractToDirectory($lib, $temp)
        Copy-Item (Join-Path $temp '*') $Fat -Recurse -Force
        Remove-Item $temp -Recurse -Force
    }
    Copy-Item (Join-Path $Classes '*') $Fat -Recurse -Force
    $manifest = Join-Path $Build 'MANIFEST.MF'
    $lines = @(
        'Manifest-Version: 1.0',
        'Main-Class: io.umbra.cli.Main',
        'Implementation-Title: Umbra',
        'Implementation-Version: 3.2.2',
        'Created-By: Umbra build.ps1'
    )
    [System.IO.File]::WriteAllText($manifest, ($lines -join "`r`n") + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
    New-Item -ItemType Directory -Force -Path $Dist | Out-Null
    $target = Join-Path $Dist 'umbra.jar'
    if (Test-Path $target) { Remove-Item $target -Force }
    Invoke-Native $Jar @('cfm', $target, $manifest, '-C', $Fat, '.') 'jar'
    $size = [math]::Round((Get-Item $target).Length / 1MB, 2)
    Write-Host ("  {0} ({1} MB)" -f $target, $size)
    Copy-GuiArtifacts
}

function Build-Package {
    $distJar = Join-Path $Dist 'umbra.jar'
    if (-not (Test-Path $distJar)) { Build-Dist }
    Write-Step 'package'
    $version = '3.2.2'
    # Refreshes dist\umbra-gui-fx.jar, the launchers and the example config next to
    # the engine jar, and builds the GUI when it is missing.
    Copy-GuiArtifacts
    $guiJar = Join-Path $Root 'gui-fx\umbra-gui-fx.jar'
    $stage = Join-Path $Build 'package'
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Copy-Item $distJar $stage
    Copy-Item (Join-Path $Root 'README.md') $stage
    Copy-Item (Join-Path $Root 'umbra.example.yml') $stage
    Copy-Item (Join-Path $Root 'Umbra.cmd') $stage
    Copy-Item (Join-Path $Root 'umbra-cli.cmd') $stage
    Copy-Item (Join-Path $Root 'umbra-fx.cmd') $stage
    if (Test-Path $guiJar) { Copy-Item $guiJar $stage }
    Copy-Item (Join-Path $Root 'demo\demo.jar') $stage
    Copy-Item (Join-Path $Root 'docs') $stage -Recurse
    $pluginDist = Join-Path $Root 'plugins\dist'
    if (Test-Path $pluginDist) {
        $pluginStage = Join-Path $stage 'plugins'
        New-Item -ItemType Directory -Force -Path $pluginStage | Out-Null
        Copy-Item (Join-Path $pluginDist '*') $pluginStage -Recurse -Force -ErrorAction SilentlyContinue
        $pluginReadme = Join-Path $Root 'plugins\README.md'
        if (Test-Path $pluginReadme) { Copy-Item $pluginReadme $pluginStage }
    }
    $zip = Join-Path $Dist ("umbra-" + $version + ".zip")
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip)
    # Checksums cover the two user-facing artifacts.
    $sums = Join-Path $Dist 'SHA256SUMS'
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($artifact in @($distJar, $zip)) {
        $hash = Get-Sha256Hex $artifact
        $lines.Add($hash + '  ' + (Split-Path $artifact -Leaf))
    }
    [System.IO.File]::WriteAllLines($sums, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  {0} ({1} MB)" -f $zip, [math]::Round((Get-Item $zip).Length / 1MB, 2))
    Write-Host ("  {0}" -f $sums)
    Get-Content $sums | Write-Host
}

switch ($Task) {
    'clean' { Clean-Build; return }
    'compile' { Build-Compile; return }
    'test' { Build-Compile; Build-Test; return }
    'dist' { Build-Compile; Build-Dist; return }
    'package' {
        # Keep an already-built dist/umbra.jar byte-identical when packaging a
        # tested release candidate; only build it when it is missing.
        if (-not (Test-Path (Join-Path $Dist 'umbra.jar'))) {
            Build-Compile
            Build-Dist
        }
        Build-Package
        return
    }
    'gui' {
        # The console is a JavaFX jar of its own (the engine jar stays JavaFX-free),
        # so refresh it next to the engine jar and start it from there.
        if (-not (Test-Path (Join-Path $Dist 'umbra.jar'))) {
            Build-Compile
            Build-Dist
        }
        Copy-GuiArtifacts
        Invoke-Native $Java @('-cp', (Join-Path $Dist 'umbra-gui-fx.jar'),
            'io.umbra.guifx.FxGui', '--jar', (Join-Path $Dist 'umbra.jar')) 'gui'
        return
    }
    'all' {
        Build-Compile
        if (-not $SkipTests) { Build-Test }
        Build-Dist
        Write-Host ""
        Write-Host "Build OK." -ForegroundColor Green
    }
}

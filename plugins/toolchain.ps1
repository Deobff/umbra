# Shared toolchain discovery for the Umbra build-tool plugin scripts.
#
# Dot-source from a script in plugins/ or plugins/qa/:
#     . "$PSScriptRoot\..\toolchain.ps1"
#
# Everything here is Windows/pwsh + PowerShell 5.1 compatible. The only
# download performed is the pinned Apache Maven distribution, cached under
# plugins/.cache/ (git-ignored); Gradle is taken from an existing installation,
# GRADLE_HOME or the local Gradle wrapper cache.

$PluginsDir = $PSScriptRoot
$UmbraRoot = Split-Path -Parent $PluginsDir
$PluginVersion = '3.0.0'
$MavenVersion = '3.9.9'
# Pinned download used only when no local Maven is found. SHA-256 of
# apache-maven-3.9.9-bin.zip is checked after download when the file is new.
$MavenDownloadUrl = 'https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.zip'
$MavenDownloadSha256 = '4EC3F26FB1A692473AEA0235C300BD20F0F9FE741947C82C1234CEFD76AC3A3C'

function Resolve-JavaHome {
    param([string]$Requested)
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @($Requested, $env:JAVA_HOME, 'C:\Program Files\Zulu\zulu-8')) {
        if ($candidate -and -not $candidates.Contains($candidate)) {
            $candidates.Add($candidate)
        }
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $candidate 'bin\java.exe') -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'No JDK found. Set JAVA_HOME (tested: Zulu 8) or pass -JavaHome.'
}

function Resolve-GradleBat {
    param([string]$Requested)
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Requested) { $candidates.Add((Join-Path $Requested 'bin\gradle.bat')) }
    if ($env:GRADLE_HOME) { $candidates.Add((Join-Path $env:GRADLE_HOME 'bin\gradle.bat')) }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $command = Get-Command gradle.bat -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $dists = Join-Path $env:USERPROFILE '.gradle\wrapper\dists'
    if (Test-Path -LiteralPath $dists) {
        $preferred = Get-ChildItem -LiteralPath $dists -Recurse -Filter 'gradle.bat' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'gradle-8\.14' } | Select-Object -First 1
        if (-not $preferred) {
            $preferred = Get-ChildItem -LiteralPath $dists -Recurse -Filter 'gradle.bat' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\gradle-[0-9]' } | Sort-Object FullName | Select-Object -Last 1
        }
        if ($preferred) { return $preferred.FullName }
    }
    throw ('Gradle not found. Install Gradle 8.14 ' +
        '(https://services.gradle.org/distributions/gradle-8.14-bin.zip), set GRADLE_HOME, ' +
        'or let a Gradle wrapper download it first.')
}

function Resolve-MavenCmd {
    param([string]$Requested)
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Requested) { $candidates.Add((Join-Path $Requested 'bin\mvn.cmd')) }
    if ($env:MAVEN_HOME) { $candidates.Add((Join-Path $env:MAVEN_HOME 'bin\mvn.cmd')) }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $command = Get-Command mvn.cmd -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $cached = Join-Path $PluginsDir ".cache\maven\apache-maven-$MavenVersion\bin\mvn.cmd"
    if (Test-Path -LiteralPath $cached -PathType Leaf) {
        return (Resolve-Path -LiteralPath $cached).Path
    }

    Write-Host "Apache Maven $MavenVersion not found locally; downloading and caching it."
    Write-Host "  url: $MavenDownloadUrl"
    $cacheDir = Join-Path $PluginsDir '.cache'
    New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
    $zip = Join-Path $cacheDir "apache-maven-$MavenVersion-bin.zip"
    if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $MavenDownloadUrl -OutFile $zip -UseBasicParsing
        $actualSha256 = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        if ($actualSha256 -ne $MavenDownloadSha256) {
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            throw ("Checksum mismatch for $MavenDownloadUrl (expected $MavenDownloadSha256, " +
                "got $actualSha256).")
        }
    }
    Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $cacheDir 'maven') -Force
    if (Test-Path -LiteralPath $cached -PathType Leaf) {
        return (Resolve-Path -LiteralPath $cached).Path
    }
    throw "Maven download failed: $cached was not created."
}

function Resolve-UmbraJar {
    param([string]$Requested)
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Requested) { $candidates.Add($Requested) }
    if ($env:UMBRA_JAR) { $candidates.Add($env:UMBRA_JAR) }
    $candidates.Add((Join-Path $UmbraRoot 'dist\umbra.jar'))
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw ('Umbra tool jar not found. Build it first (build.cmd in the Umbra root) ' +
        'or set UMBRA_JAR.')
}

function Format-NativeArguments {
    param([string[]]$Arguments)
    $quoted = foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            '"' + ($argument -replace '"', '\"') + '"'
        } else {
            $argument
        }
    }
    return ($quoted -join ' ')
}

<#
.SYNOPSIS
Runs a native command, captures combined stdout+stderr and its exact exit code.

.DESCRIPTION
Uses cmd.exe for the redirection for two reasons: PowerShell 5.1 turns native
stderr redirected inside PowerShell into terminating NativeCommandError records
under $ErrorActionPreference = 'Stop', and cmd.exe preserves the child's exit
code unchanged. Arguments are passed as one quoted command line; no shell
expansion happens on the caller side beyond that quoting.
#>
function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$WorkDir = (Get-Location).Path
    )
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('umbra-native-' + [guid]::NewGuid().ToString('N') + '.log')
    $argumentString = Format-NativeArguments $Arguments
    Push-Location $WorkDir
    try {
        $commandLine = '"{0}" {1} > "{2}" 2>&1' -f $FilePath, $argumentString, $temp
        & cmd.exe /c $commandLine | Out-Null
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    $text = ''
    if (Test-Path -LiteralPath $temp -PathType Leaf) {
        $text = Get-Content -LiteralPath $temp -Raw -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    if ($null -eq $text) { $text = '' }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Text     = $text
    }
}

function Get-FileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

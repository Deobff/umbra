#requires -Version 5.1
<#
.SYNOPSIS
    Produces deobfuscation-resistance evidence for one protected jar.

.DESCRIPTION
    1. Downloads CFR (if needed) from Maven Central and decompiles the jar.
    2. Runs javap -p -c on the main class and on a virtualized method.
    3. Runs qa/tools/scan_strings.py to count clear-text constants and names.
    4. Writes analysis/deobfuscation.md and analysis/deobfuscation.json.

    Network is optional: when CFR cannot be downloaded the step is recorded as
    SKIP with the reason and the local evidence (javap + string scan) is still
    produced.

.EXAMPLE
    qa\deobfuscate.cmd -Jar qa\results\20240101-120000\out\maximum.jar -OutDir qa\results\20240101-120000\analysis
#>
param(
    [Parameter(Mandatory = $true)][string]$Jar,
    [string]$OutDir = '',
    [string]$ResultsDir = '',
    [switch]$SkipCfr
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path $PSScriptRoot -Parent
$Tools = Join-Path $PSScriptRoot 'tools'
$ScanScript = Join-Path $Tools 'scan_strings.py'

function Resolve-Absolute([string]$Path, [string]$Base) {
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $Base $Path)
}

function Invoke-Tool([string]$Exe, [string[]]$Arguments, [int]$TimeoutMs = 300000) {
    $ErrorActionPreference = 'Continue'
    $process = New-Object System.Diagnostics.Process
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Exe
    $quoted = @()
    foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            $quoted += ('"' + ($argument -replace '"', '\"') + '"')
        } else {
            $quoted += $argument
        }
    }
    $startInfo.Arguments = ($quoted -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process.StartInfo = $startInfo
    $null = $process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMs)) {
        try { $process.Kill() } catch { }
        return [pscustomobject]@{ Code = -1; StdOut = $stdoutTask.Result; StdErr = "timed out after $TimeoutMs ms"; TimedOut = $true }
    }
    return [pscustomobject]@{ Code = $process.ExitCode; StdOut = $stdoutTask.Result; StdErr = $stderrTask.Result; TimedOut = $false }
}

function Write-Utf8([string]$Path, [string]$Text) {
    $parent = Split-Path $Path -Parent
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

$Jar = Resolve-Absolute $Jar $Root
if (-not (Test-Path $Jar)) { throw "Jar not found: $Jar" }
if (-not $OutDir) {
    if ($ResultsDir) { $OutDir = Join-Path (Resolve-Absolute $ResultsDir $Root) 'analysis' }
    else { $OutDir = Join-Path $Root ('qa\results\' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '\analysis') }
}
$OutDir = Resolve-Absolute $OutDir $Root
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Java = $null
$javaCandidates = @('C:\Program Files\Zulu\zulu-8\bin\java.exe')
if ($env:JAVA_HOME) { $javaCandidates = @((Join-Path $env:JAVA_HOME 'bin\java.exe')) + $javaCandidates }
$javaOnPath = (Get-Command java -ErrorAction SilentlyContinue)
if ($javaOnPath) { $javaCandidates += $javaOnPath.Source }
foreach ($candidate in $javaCandidates) {
    if ($candidate -and (Test-Path $candidate)) { $Java = $candidate; break }
}
if (-not $Java) { throw 'java.exe not found' }
$Javap = Join-Path (Split-Path $Java -Parent) 'javap.exe'
if (-not (Test-Path $Javap)) { $Javap = 'javap' }

$report = [ordered]@{
    jar = $Jar
    sha256 = (Get-FileHash $Jar -Algorithm SHA256).Hash.ToLowerInvariant()
    sizeBytes = (Get-Item $Jar).Length
    generated = (Get-Date).ToString('s')
    cfr = [ordered]@{ status = 'SKIP'; path = ''; reason = ''; decompiledFiles = 0; decompiledBytes = 0; failedFiles = 0; sample = @() }
    strings = $null
    javap = [ordered]@{ mainClass = ''; mainFile = ''; virtualizedClasses = 0; virtualizedSampleFile = ''; counts = [ordered]@{} }
}

$scanJson = Join-Path $OutDir 'strings.json'
$python = $null
foreach ($toolName in @('python', 'python3')) {
    $pythonCommand = Get-Command $toolName -ErrorAction SilentlyContinue
    if ($pythonCommand -and (Test-Path $pythonCommand.Source)) { $python = $pythonCommand.Source; break }
}
if ($python -and (Test-Path $ScanScript)) {
    $scan = Invoke-Tool $python @($ScanScript, '--jar', $Jar, '--out', $scanJson, '--label', (Split-Path $Jar -Leaf)) 120000
    if ($scan.Code -eq 0) {
        $report.strings = $scanJson
        Write-Host ("  scan: " + ($scan.StdOut.Trim()))
    } else {
        Write-Host ("  scan failed: " + $scan.StdErr.Trim()) -ForegroundColor DarkYellow
    }
} else {
    Write-Host '  python not found: string scan skipped' -ForegroundColor DarkYellow
}

# --- javap: main class and virtualized methods --------------------------------
$extractDir = Join-Path $OutDir 'javap-classes'
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$extracted = $false
try {
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Jar, $extractDir)
    $extracted = $true
} catch {
    Write-Host ("  jar extraction failed: " + $_) -ForegroundColor DarkYellow
}

$javapCounts = [ordered]@{ invokedynamic = 0; tableswitch = 0; lookupswitch = 0; reflection = 0; nativeMethods = 0; vmRuntimeCalls = 0 }
if ($extracted) {
    $manifest = Join-Path $extractDir 'META-INF\MANIFEST.MF'
    $mainClass = ''
    if (Test-Path $manifest) {
        foreach ($line in Get-Content $manifest) {
            if ($line -match '^Main-Class:\s*(.+)$') { $mainClass = $Matches[1].Trim() }
        }
    }
    $report.javap.mainClass = $mainClass
    if ($mainClass -and $mainClass -ne 'io.umbra.cli.Main') {
        $mainOut = Invoke-Tool $Javap @('-p', '-c', '-constants', '-classpath', $extractDir, $mainClass) 120000
        $mainFile = Join-Path $OutDir 'javap-main.txt'
        Write-Utf8 $mainFile ($mainOut.StdOut + $mainOut.StdErr)
        $report.javap.mainFile = $mainFile
        $javapCounts.invokedynamic = ([regex]::Matches($mainOut.StdOut, 'invokedynamic')).Count
        $javapCounts.tableswitch = ([regex]::Matches($mainOut.StdOut, 'tableswitch')).Count
        $javapCounts.lookupswitch = ([regex]::Matches($mainOut.StdOut, 'lookupswitch')).Count
        $javapCounts.reflection = ([regex]::Matches($mainOut.StdOut, 'java/lang/reflect')).Count
    }

    # Classes that call into the injected VM runtime.
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $candidates = @()
    foreach ($classFile in Get-ChildItem $extractDir -Recurse -Filter '*.class') {
        $bytes = [System.IO.File]::ReadAllBytes($classFile.FullName)
        $text = $latin1.GetString($bytes)
        if ($text.Contains('umbra/runtime/')) {
            $relative = $classFile.FullName.Substring($extractDir.Length + 1)
            $className = $relative.Substring(0, $relative.Length - 6).Replace('\', '.').Replace('/', '.')
            if (-not $className.StartsWith('umbra.runtime.')) {
                $candidates += $className
            }
        }
    }
    $report.javap.virtualizedClasses = $candidates.Count
    $best = $null
    $bestCount = -1
    $index = 0
    foreach ($candidate in ($candidates | Select-Object -First 6)) {
        $index++
        $out = Invoke-Tool $Javap @('-p', '-c', '-classpath', $extractDir, $candidate) 120000
        $file = Join-Path $OutDir ("javap-virtualized-$index.txt")
        Write-Utf8 $file ($out.StdOut + $out.StdErr)
        $count = ([regex]::Matches($out.StdOut, 'umbra/runtime')).Count
        if ($count -gt $bestCount) { $best = @($out.StdOut, $file); $bestCount = $count }
        $javapCounts.invokedynamic += ([regex]::Matches($out.StdOut, 'invokedynamic')).Count
        $javapCounts.tableswitch += ([regex]::Matches($out.StdOut, 'tableswitch')).Count
        $javapCounts.lookupswitch += ([regex]::Matches($out.StdOut, 'lookupswitch')).Count
    }
    if ($best) {
        $lines = $best[0] -split "`r?`n"
        $interesting = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'umbra/runtime') { $interesting = $i; break }
        }
        if ($interesting -ge 0) {
            $from = [Math]::Max(0, $interesting - 30)
            $to = [Math]::Min($lines.Count - 1, $interesting + 25)
            $snippet = ($lines[$from..$to] -join "`r`n")
            $snippetFile = Join-Path $OutDir 'javap-virtualized-method.txt'
            Write-Utf8 $snippetFile $snippet
            $report.javap.virtualizedSampleFile = $snippetFile
        }
        $report.javap.macroFile = $best[1]
    }
    $javapCounts.vmRuntimeCalls = ([regex]::Matches($(if ($best) { $best[0] } else { '' }), 'umbra/runtime')).Count
    $report.javap.counts = $javapCounts
}

# --- CFR decompilation -------------------------------------------------------
$cfrJar = Join-Path $Tools 'cfr-0.152.jar'
if (-not $SkipCfr) {
    if (-not (Test-Path $cfrJar)) {
        New-Item -ItemType Directory -Force -Path $Tools | Out-Null
        $urls = @(
            'https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar',
            'https://repo.maven.apache.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar'
        )
        $downloaded = $false
        foreach ($url in $urls) {
            try {
                Write-Host "  downloading CFR: $url"
                Invoke-WebRequest -Uri $url -OutFile $cfrJar -UseBasicParsing -TimeoutSec 90
                $downloaded = $true
                break
            } catch {
                Write-Host ("  CFR download failed: " + $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
        if (-not $downloaded -and (Test-Path $cfrJar)) { Remove-Item $cfrJar -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path $cfrJar) {
        $cfrOut = Join-Path $OutDir 'cfr'
        if (Test-Path $cfrOut) { Remove-Item $cfrOut -Recurse -Force }
        $cfr = Invoke-Tool $Java @('-jar', $cfrJar, $Jar, '--outputdir', $cfrOut, '--silent', 'true') 300000
        Write-Utf8 (Join-Path $OutDir 'cfr-decompile.log') ($cfr.StdOut + $cfr.StdErr)
        $javaFiles = @(Get-ChildItem $cfrOut -Recurse -Filter '*.java' -ErrorAction SilentlyContinue)
        $report.cfr.status = 'OK'
        $report.cfr.path = $cfrJar
        $report.cfr.decompiledFiles = $javaFiles.Count
        $report.cfr.decompiledBytes = ($javaFiles | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $report.cfr.decompiledBytes) { $report.cfr.decompiledBytes = 0 }
        $failed = 0
        $samples = @()
        foreach ($file in $javaFiles) {
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -and ($content -match 'failed to decompile|// This method has failed')) {
                $failed++
                if ($samples.Count -lt 3) { $samples += $file.FullName.Substring($cfrOut.Length + 1) }
            }
        }
        $report.cfr.failedFiles = $failed
        $report.cfr.sample = @($javaFiles | Select-Object -First 20 | ForEach-Object { $_.FullName.Substring($cfrOut.Length + 1) })
        if ($cfr.Code -ne 0) {
            $report.cfr.reason = "CFR exit code $($cfr.Code)"
        }
        Write-Host ("  cfr: {0} java files, {1} failed" -f $javaFiles.Count, $failed)
    } else {
        $report.cfr.status = 'SKIP'
        $report.cfr.reason = 'CFR could not be downloaded (offline or blocked)'
        Write-Host '  cfr: SKIP (download failed)' -ForegroundColor DarkYellow
    }
} else {
    $report.cfr.status = 'SKIP'
    $report.cfr.reason = '-SkipCfr'
}

# --- markdown report ---------------------------------------------------------
$md = New-Object System.Text.StringBuilder
$null = $md.AppendLine('# Deobfuscation evidence')
$null = $md.AppendLine('')
$null = $md.AppendLine(("- jar: ``{0}``" -f $report.jar))
$null = $md.AppendLine(("- sha256: ``{0}``" -f $report.sha256))
$null = $md.AppendLine(("- size: {0:N0} bytes" -f $report.sizeBytes))
$null = $md.AppendLine('')
$null = $md.AppendLine('## String / name readability (`qa/tools/scan_strings.py`)')
$null = $md.AppendLine('')
if ($report.strings -and (Test-Path $report.strings)) {
    $scan = Get-Content $report.strings -Raw -Encoding UTF8 | ConvertFrom-Json
    $null = $md.AppendLine(('| metric | value |'))
    $null = $md.AppendLine(('|---|---|'))
    $null = $md.AppendLine(('| classes | {0} |' -f $scan.classes))
    $null = $md.AppendLine(('| constant-pool UTF-8 entries | {0} |' -f $scan.counts.utf8Total))
    $null = $md.AppendLine(('| human-readable text constants | {0} |' -f $scan.counts.humanText))
    $null = $md.AppendLine(('| class references | {0} |' -f $scan.counts.classRefs))
    $null = $md.AppendLine(('| method-name entries | {0} |' -f $scan.counts.methodNames))
    $null = $md.AppendLine(('| field-name entries | {0} |' -f $scan.counts.fieldNames))
    $null = $md.AppendLine('')
    $null = $md.AppendLine(('Demo string markers still present: **{0}**' -f @($scan.markerHits.strings).Count))
    foreach ($hit in @($scan.markerHits.strings)) {
        $null = $md.AppendLine(("- string ``{0}`` (in {1})" -f $hit.marker, ($hit.classes -join ', ')))
    }
    $null = $md.AppendLine(('Demo class-name markers still present: **{0}**' -f @($scan.markerHits.classes).Count))
    foreach ($hit in @($scan.markerHits.classes)) {
        $null = $md.AppendLine(("- class ``{0}``" -f $hit.marker))
    }
    $methodCount = @($scan.markerHits.methods).Count
    $fieldCount = @($scan.markerHits.fields).Count
    $null = $md.AppendLine(('Method markers: **{0}**, field markers: **{1}**' -f $methodCount, $fieldCount))
    if ($methodCount -gt 0) {
        $names = @($scan.markerHits.methods | ForEach-Object { $_.marker })
        $null = $md.AppendLine(("- methods: {0}" -f ($names -join ', ')))
    }
    if ($fieldCount -gt 0) {
        $names = @($scan.markerHits.fields | ForEach-Object { $_.marker })
        $null = $md.AppendLine(("- fields: {0}" -f ($names -join ', ')))
    }
    $textResources = @($scan.resources | Where-Object { $_.text })
    if ($textResources.Count -gt 0) {
        $null = $md.AppendLine('')
        $null = $md.AppendLine('Plaintext resources still in the archive:')
        foreach ($resource in $textResources) {
            $markers = if ($resource.markers) { ' markers: ' + ($resource.markers -join ', ') } else { '' }
            $null = $md.AppendLine(("- ``{0}`` ({1} bytes){2}" -f $resource.name, $resource.sizeBytes, $markers))
        }
    }
} else {
    $null = $md.AppendLine('_String scan not available._')
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## javap bytecode view')
$null = $md.AppendLine('')
$null = $md.AppendLine(("- Main-Class: ``{0}``" -f $report.javap.mainClass))
$null = $md.AppendLine(("- classes with clear-text calls into the injected VM runtime: **{0}**" -f $report.javap.virtualizedClasses))
if ($report.javap.counts) {
    $null = $md.AppendLine('')
    $null = $md.AppendLine('| javap marker | count |')
    $null = $md.AppendLine('|---|---|')
    foreach ($key in $report.javap.counts.Keys) {
        $null = $md.AppendLine(('| {0} | {1} |' -f $key, $report.javap.counts[$key]))
    }
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## CFR decompiler')
$null = $md.AppendLine('')
$null = $md.AppendLine(("- status: **{0}** {1}" -f $report.cfr.status, $report.cfr.reason))
if ($report.cfr.status -eq 'OK') {
    $null = $md.AppendLine(("- decompiled files: {0} ({1:N0} bytes)" -f $report.cfr.decompiledFiles, $report.cfr.decompiledBytes))
    $null = $md.AppendLine(("- files with failed method bodies: {0}" -f $report.cfr.failedFiles))
    if ($report.cfr.sample.Count -gt 0) {
        $null = $md.AppendLine('')
        $null = $md.AppendLine('First decompiled files:')
        foreach ($file in $report.cfr.sample) { $null = $md.AppendLine(("- ``{0}``" -f $file)) }
    }
    if ($report.javap.mainClass) {
        $mainSource = Join-Path (Join-Path $OutDir 'cfr') (($report.javap.mainClass -replace '\.', '\') + '.java')
        if (Test-Path $mainSource) {
            $null = $md.AppendLine('')
            $null = $md.AppendLine('### What the analyst sees (main class, CFR)')
            $null = $md.AppendLine('')
            $null = $md.AppendLine('```java')
            $sourceLines = Get-Content $mainSource -TotalCount 45 -Encoding UTF8
            foreach ($sourceLine in $sourceLines) { $null = $md.AppendLine($sourceLine) }
            $null = $md.AppendLine('```')
        }
    }
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## Files')
$null = $md.AppendLine('')
foreach ($file in @($report.javap.mainFile, $report.javap.virtualizedSampleFile, $scanJson)) {
    if ($file) { $null = $md.AppendLine(("- ``{0}``" -f $file)) }
}
$mdPath = Join-Path $OutDir 'deobfuscation.md'
Write-Utf8 $mdPath $md.ToString()
$jsonPath = Join-Path $OutDir 'deobfuscation.json'
Write-Utf8 $jsonPath (($report | ConvertTo-Json -Depth 8))
Write-Host ("  wrote {0}" -f $mdPath)
Write-Host ("  wrote {0}" -f $jsonPath)

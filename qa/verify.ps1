#requires -Version 5.1
<#
.SYNOPSIS
    Umbra end-to-end verification matrix.

.DESCRIPTION
    Obfuscates demo/demo.jar with increasingly strong configurations, runs
    `--verify` on every output, executes the protected jar and compares its
    stdout with "OK". Results land in qa/results/<timestamp>/ as summary.json,
    summary.md, per-case logs and a copy of the audit reports.

    Unimplemented features are probed first and excluded from a case, which is
    then reported as PARTIAL (development mode). With -SkipUnimplemented those
    PARTIAL results do not fail the run; without it (strict final mode) any
    SKIP/PARTIAL/FAIL fails the run.

.EXAMPLE
    qa\verify.cmd -SkipUnimplemented
    qa\verify.cmd -UmbraJar dist\umbra.jar
    qa\verify.cmd -UmbraJar dist\umbra.jar -SkipUnimplemented -SkipDecompile
#>
param(
    [string]$UmbraJar = '',
    [string]$DemoJar = '',
    [string]$ResultsDir = '',
    [string]$Seed = '23303',
    [string]$CorpusRoot = '',
    [switch]$SkipUnimplemented,
    [switch]$SkipDecompile,
    [switch]$SkipAnalysis,
    [switch]$SkipPresets,
    [switch]$SkipCompat3,
    [switch]$SkipGuiSmoke,
    [switch]$NoSecondaryJdk,
    [switch]$KeepProbeJars,
    [int]$TimeoutSeconds = 300,
    [int]$LayoutTimeoutSeconds = 240
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path $PSScriptRoot -Parent
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function Resolve-Absolute([string]$Path, [string]$Base) {
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $Base $Path)
}

function Invoke-Tool([string]$Exe, [string[]]$Arguments, [int]$TimeoutMs = ($TimeoutSeconds * 1000)) {
    $process = New-Object System.Diagnostics.Process
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Exe
    $quoted = @()
    foreach ($argument in $Arguments) {
        if ($null -eq $argument) { continue }
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

function Get-JavaVersion([string]$Java) {
    if (-not $Java -or -not (Test-Path $Java)) { return '' }
    $result = Invoke-Tool $Java @('-version') 30000
    $text = ($result.StdOut + ' ' + $result.StdErr).Trim()
    return ($text -split "`r?`n")[0].Trim()
}

function Get-Sha256([string]$Path) {
    if (Test-Path $Path) { return (Get-FileHash $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
    return ''
}

function Get-LogTail([string]$Text, [int]$Lines = 25) {
    if (-not $Text) { return '' }
    $all = @($Text -split "`r?`n")
    if ($all.Count -le $Lines) { return ($all -join "`n") }
    return (($all[($all.Count - $Lines)..($all.Count - 1)]) -join "`n")
}

function Get-Stat($Stats, [string]$Key) {
    if ($null -eq $Stats) { return 0 }
    $property = $Stats.PSObject.Properties[$Key]
    if ($null -eq $property) { return 0 }
    return $property.Value
}

function Get-BagValue($Bag, [string]$Key, $Fallback = 0) {
    if ($null -eq $Bag) { return $Fallback }
    if ($Bag -is [System.Collections.IDictionary]) {
        if ($Bag.Contains($Key)) { return $Bag[$Key] }
        return $Fallback
    }
    $property = $Bag.PSObject.Properties[$Key]
    if ($null -eq $property) { return $Fallback }
    return $property.Value
}

# --- paths -------------------------------------------------------------------
if (-not $UmbraJar) {
    if (Test-Path (Join-Path $Root 'dist\umbra.jar')) {
        $UmbraJar = Join-Path $Root 'dist\umbra.jar'
    } elseif (Test-Path (Join-Path $Root 'build-qa\umbra.jar')) {
        $UmbraJar = Join-Path $Root 'build-qa\umbra.jar'
        Write-Host 'warning: dist\umbra.jar not found, using build-qa\umbra.jar (dev build)' -ForegroundColor DarkYellow
    } else {
        throw 'No Umbra jar found. Build one with: build.cmd -Task dist'
    }
}
$UmbraJar = Resolve-Absolute $UmbraJar $Root
if (-not (Test-Path $UmbraJar)) { throw "Umbra jar not found: $UmbraJar" }
$UmbraJar = (Resolve-Path $UmbraJar).Path

if (-not $DemoJar) { $DemoJar = Join-Path $Root 'demo\demo.jar' }
if (-not $CorpusRoot) { $CorpusRoot = Join-Path $Root 'qa\compat\cache\artifacts' }
$CorpusRoot = Resolve-Absolute $CorpusRoot $Root
$CompatArtifacts = $CorpusRoot
$DemoJar = Resolve-Absolute $DemoJar $Root
if (-not (Test-Path $DemoJar)) {
    Write-Host 'demo/demo.jar missing: building it with qa/build-demo.cmd'
    $build = Invoke-Tool 'powershell' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $PSScriptRoot 'build-demo.ps1'), '-SkipRun') 240000
    if ($build.Code -ne 0) { throw "demo build failed: $($build.StdOut) $($build.StdErr)" }
}
if (-not (Test-Path $DemoJar)) { throw "demo jar not found: $DemoJar" }
$DemoJar = (Resolve-Path $DemoJar).Path

if (-not $ResultsDir) { $ResultsDir = Join-Path $Root "qa\results\$Stamp" }
$ResultsDir = Resolve-Absolute $ResultsDir $Root
$OutDir = Join-Path $ResultsDir 'out'
$LogDir = Join-Path $ResultsDir 'logs'
$ReportDir = Join-Path $ResultsDir 'reports'
$ProbeDir = Join-Path $ResultsDir 'probes'
$AnalysisDir = Join-Path $ResultsDir 'analysis'
foreach ($dir in @($OutDir, $LogDir, $ReportDir, $ProbeDir, $AnalysisDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Host "==> Umbra verification matrix: $Stamp" -ForegroundColor Cyan
Write-Host "    umbra: $UmbraJar"
Write-Host "    demo:  $DemoJar"
Write-Host "    out:   $ResultsDir"

# --- toolchain and environment ----------------------------------------------
$Java = $null
$javaCandidates = @('C:\Program Files\Zulu\zulu-8\bin\java.exe')
if ($env:JAVA_HOME) { $javaCandidates = @((Join-Path $env:JAVA_HOME 'bin\java.exe')) + $javaCandidates }
$javaOnPath = (Get-Command java -ErrorAction SilentlyContinue)
if ($javaOnPath) { $javaCandidates += $javaOnPath.Source }
foreach ($candidate in $javaCandidates) {
    if ($candidate -and (Test-Path $candidate)) { $Java = $candidate; break }
}
if (-not $Java) { throw 'java.exe not found' }

$Javac = Join-Path (Split-Path $Java -Parent) 'javac.exe'
$python = $null
foreach ($toolName in @('python', 'python3')) {
    $pythonCommand = Get-Command $toolName -ErrorAction SilentlyContinue
    if ($pythonCommand -and (Test-Path $pythonCommand.Source)) { $python = $pythonCommand.Source; break }
}
$Gcc = $null
foreach ($toolName in @('gcc', 'clang', 'cc')) {
    $compilerCommand = Get-Command $toolName -ErrorAction SilentlyContinue
    if ($compilerCommand -and (Test-Path $compilerCommand.Source)) { $Gcc = $compilerCommand.Source; break }
}
$GccVersion = ''
if ($Gcc) {
    $gccResult = Invoke-Tool $Gcc @('--version') 30000
    $GccVersion = (($gccResult.StdOut -split "`r?`n")[0]).Trim()
}

$SecondaryJava = ''
$ThirdJava = ''
if (-not $NoSecondaryJdk) {
    foreach ($candidate in @(
            'C:\Program Files\Zulu\zulu-21\bin\java.exe',
            'C:\Program Files\Java\jdk-21.0.10\bin\java.exe')) {
        if (Test-Path $candidate) { $SecondaryJava = $candidate; break }
    }
    foreach ($candidate in @(
            'C:\Program Files\Java\jdk-26.0.1\bin\java.exe',
            'C:\Program Files\Java\jdk-25.0.1\bin\java.exe',
            'C:\Program Files\Zulu\zulu-25\bin\java.exe')) {
        if (Test-Path $candidate) { $ThirdJava = $candidate; break }
    }
}

$umbraVersion = (Invoke-Tool $Java @('-jar', $UmbraJar, '--version') 60000)
$environment = [ordered]@{
    generated = (Get-Date).ToString('s')
    host = [Environment]::MachineName
    os = [Environment]::OSVersion.VersionString
    powershell = $PSVersionTable.PSVersion.ToString()
    seed = $Seed
    umbraJar = $UmbraJar
    umbraSha256 = (Get-Sha256 $UmbraJar)
    umbraBytes = (Get-Item $UmbraJar).Length
    umbraVersion = ($umbraVersion.StdOut.Trim() + ' ' + $umbraVersion.StdErr.Trim()).Trim()
    demoJar = $DemoJar
    demoSha256 = (Get-Sha256 $DemoJar)
    demoBytes = (Get-Item $DemoJar).Length
    java = $Java
    javaVersion = (Get-JavaVersion $Java)
    secondaryJava = $SecondaryJava
    secondaryJavaVersion = (Get-JavaVersion $SecondaryJava)
    tertiaryJava = $ThirdJava
    tertiaryJavaVersion = (Get-JavaVersion $ThirdJava)
    gcc = $Gcc
    gccVersion = $GccVersion
}
$environment | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $ResultsDir 'environment.json') -Encoding UTF8
Write-Host "    java:  $($environment.javaVersion)"
if ($SecondaryJava) { Write-Host "    java2: $($environment.secondaryJavaVersion) ($SecondaryJava)" }
if ($ThirdJava) { Write-Host "    java3: $($environment.tertiaryJavaVersion) ($ThirdJava)" }
Write-Host "    gcc:   $($environment.gccVersion)"

# --- feature probes ----------------------------------------------------------
$baselineFlags = @('--no-rename', '--no-string', '--no-integer', '--no-flow',
    '--no-shuffle', '--no-junk', '--no-watermark')

$featureSpecs = @(
    [pscustomobject]@{ Name = 'flatten'; Args = @('--flatten'); Tool = ''; NoFlowDisable = $true },
    [pscustomobject]@{ Name = 'virtualize'; Args = @('--virtualize'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'antiLlm'; Args = @('--anti-llm'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'reference'; Args = @('--reference-obfuscation', '--reference-virtual', '--reference-fields', '--reference-constructors'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'exception'; Args = @('--exception-obfuscation'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'mba'; Args = @('--set', 'mba.enabled=true'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'vm2'; Args = @('--virtualize', '--set', 'vm2.enabled=true', '--set', 'vm2.trys=true'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'classEncryption'; Args = @('--set', 'classEncryption.enabled=true'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'integrity'; Args = @('--set', 'integrity.enabled=true'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'antiDebug'; Args = @('--anti-debug', '--set', 'antiDebug.level=2'); Tool = ''; NoFlowDisable = $false },
    [pscustomobject]@{ Name = 'native'; Args = @('--set', 'native.enabled=true'); Tool = 'gcc'; NoFlowDisable = $false },
    # --- Umbra 3.0 passes (stats-gated: an option that is silently ignored is
    # NOT reported as supported; the engine must publish the matching stats) ---
    [pscustomobject]@{ Name = 'typeConfusion'; Args = @('--set', 'typeConfusion.enabled=true', '--set', 'typeConfusion.level=1'); Tool = ''; NoFlowDisable = $false; StatsKey = 'typeConfusion.methods'; StatsKind = 'positive' },
    [pscustomobject]@{ Name = 'stringV2'; Args = @('--set', 'string.engine=auto', '--set', 'string.engineOrder=chacha20,aes-ctr,rc4,speck', '--set', 'string.stackTraceHide=true', '--set', 'string.wipe=true'); Tool = ''; NoFlowDisable = $false; StatsKey = 'strings.engineKinds'; StatsKind = 'positive'; RemoveBase = @('--no-string') },
    [pscustomobject]@{ Name = 'vm2fusion'; Args = @('--virtualize', '--set', 'vm2.enabled=true', '--set', 'vm2.fusion=true'); Tool = ''; NoFlowDisable = $false; StatsKey = 'virtualization.vm2.fusion'; StatsKind = 'positive' },
    [pscustomobject]@{ Name = 'reflectionGate'; Args = @('--set', 'reflectionGate.enabled=true', '--set', 'reflectionGate.action=mask'); Tool = ''; NoFlowDisable = $false; StatsKey = 'reflectionGate.sealed'; StatsKind = 'positive'; Jar = 'maven-shade.jar'; Expected = 'SHADE-OK' },
    [pscustomobject]@{ Name = 'nativeAntiDump'; Args = @('--set', 'native.enabled=true', '--set', 'native.antiDump=true', '--set', 'native.antiBackfill=true'); Tool = 'gcc'; NoFlowDisable = $false; StatsKey = 'native.antiDump'; StatsKind = 'positive' },
    # --- Umbra 3.1 dynamic-protection options (stats-gated) ---
    [pscustomobject]@{ Name = 'guardAttachWatch'; Args = @('--anti-debug', '--set', 'antiDebug.level=2', '--set', 'antiDebug.attachWatch=true'); Tool = ''; NoFlowDisable = $false; StatsKey = 'antiDebug.attachWatch'; StatsKind = 'positive' },
    [pscustomobject]@{ Name = 'guardPortProbe'; Args = @('--anti-debug', '--set', 'antiDebug.level=2', '--set', 'antiDebug.portProbe=true'); Tool = ''; NoFlowDisable = $false; StatsKey = 'antiDebug.portProbe'; StatsKind = 'positive' },
    [pscustomobject]@{ Name = 'guardEnvMarkers'; Args = @('--anti-debug', '--set', 'antiDebug.level=2', '--set', 'antiDebug.env=true'); Tool = ''; NoFlowDisable = $false; StatsKey = 'antiDebug.env'; StatsKind = 'positive' },
    [pscustomobject]@{ Name = 'guardTimingDrift'; Args = @('--anti-debug', '--set', 'antiDebug.level=2', '--set', 'antiDebug.timing=true'); Tool = ''; NoFlowDisable = $false; StatsKey = 'antiDebug.timing'; StatsKind = 'positive' },
    [pscustomobject]@{ Name = 'nativeGuardV31'; Args = @('--anti-debug', '--set', 'antiDebug.level=3', '--set', 'antiDebug.nativeGuard=true'); Tool = 'gcc'; NoFlowDisable = $false; StatsKey = 'antiDebug.nativeGuard.dllBytes'; StatsKind = 'positive' }
)

$probes = [ordered]@{}
Write-Host ''
Write-Host '==> probing feature support' -ForegroundColor Cyan
foreach ($spec in $featureSpecs) {
    $probe = [ordered]@{
        name = $spec.Name
        status = 'skipped'
        reason = ''
        durationMs = 0
        log = ''
    }
    if ($spec.Tool -eq 'gcc' -and -not $Gcc) {
        $probe.status = 'no-toolchain'
        $probe.reason = 'no C compiler (gcc/clang/cc) on PATH'
        $probes[$spec.Name] = $probe
        Write-Host ("  {0,-16} {1}" -f $spec.Name, $probe.status, $probe.reason)
        continue
    }
    $probeJar = Join-Path $ProbeDir ($spec.Name + '.jar')
    $probeReport = Join-Path $ProbeDir ($spec.Name + '.report.json')
    $probeInput = $DemoJar
    $probeExpected = 'OK'
    if ($spec.PSObject.Properties['Jar'] -and $spec.Jar) {
        $candidate = Join-Path $CompatArtifacts $spec.Jar
        if (-not (Test-Path $candidate)) {
            $probe.status = 'no-corpus'
            $probe.reason = 'corpus artifact not found: ' + $candidate + ' (run qa\compat\build-corpus.cmd)'
            $probes[$spec.Name] = $probe
            Write-Host ("  {0,-16} {1,-14} {2}" -f $spec.Name, $probe.status, $probe.reason)
            continue
        }
        $probeInput = $candidate
    }
    if ($spec.PSObject.Properties['Expected'] -and $spec.Expected) { $probeExpected = $spec.Expected }
    $probeBase = $baselineFlags
    if ($spec.PSObject.Properties['RemoveBase'] -and @($spec.RemoveBase).Count -gt 0) {
        $probeBase = @($probeBase | Where-Object { @($spec.RemoveBase) -notcontains $_ })
    }
    if ($spec.NoFlowDisable) {
        $probeBase = @($baselineFlags | Where-Object { $_ -ne '--no-flow' })
        $probeBase += @('--no-shuffle', '--no-junk', '--no-watermark')
    }
    $probeArgs = @('-jar', $UmbraJar, '-i', $probeInput, '-o', $probeJar) + $probeBase + $spec.Args +
        @('--seed', $Seed, '--verify', '--report-json', $probeReport)
    if ($spec.Tool -eq 'gcc' -and $Gcc) { $probeArgs += @('--set', "native.compiler=$Gcc") }
    $started = Get-Date
    $result = Invoke-Tool $Java $probeArgs ($TimeoutSeconds * 1000)
    $probe.durationMs = [int]((Get-Date) - $started).TotalMilliseconds
    $combined = $result.StdOut + "`n" + $result.StdErr
    $probe.log = Join-Path $LogDir ("probe-" + $spec.Name + ".log")
    Write-Utf8 $probe.log $combined
    if ($result.Code -ne 0) {
        $unimplemented = $combined -match 'not implemented|implementation pending|UnsupportedOperationException'
        $probe.status = if ($unimplemented) { 'unimplemented' } else { 'broken' }
        $reasonLine = @($combined -split "`r?`n" | Where-Object { $_ -match 'not implemented|implementation pending|UnsupportedOperationException|Umbra failed' } | Select-Object -First 1)
        $probe.reason = if ($reasonLine.Count -gt 0) { $reasonLine[0].Trim() } else { "obfuscation exit code $($result.Code)" }
    } else {
        $noop = $combined -match 'implementation pending'
        $probe.status = if ($noop) { 'noop' } else { 'supported' }
        if ($noop) { $probe.reason = 'pass runs but reports "implementation pending" (no-op)' }
        if (Test-Path $probeJar) {
            $run = Invoke-Tool $Java @('-jar', $probeJar) ($TimeoutSeconds * 1000)
            $runText = ($run.StdOut + ' ' + $run.StdErr).Trim()
            if ($run.Code -ne 0 -or $runText -ne $probeExpected) {
                $probe.status = 'broken'
                $runLine = @($run.StdErr -split "`r?`n" | Where-Object { $_ -match 'Exception|FAIL' } | Select-Object -First 1)
                $probe.reason = if ($runLine.Count -gt 0) { "runtime: " + $runLine[0].Trim() } else { "runtime output: $runText" }
            }
        } else {
            $probe.status = 'broken'
            $probe.reason = 'obfuscation succeeded but produced no output jar'
        }
        # 3.0 passes are stats-gated: an option silently accepted but ignored is
        # NOT supported. Require the engine to publish the feature statistic.
        if ($spec.PSObject.Properties['StatsKey'] -and $spec.StatsKey -and $probe.status -eq 'supported') {
            $statsReport = $null
            if (Test-Path $probeReport) {
                try { $statsReport = Get-Content $probeReport -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $statsReport = $null }
            }
            $statValue = $null
            if ($statsReport -and $statsReport.PSObject.Properties['stats']) {
                $statProperty = $statsReport.stats.PSObject.Properties[$spec.StatsKey]
                if ($statProperty) { $statValue = $statProperty.Value }
            }
            $statsKind = 'positive'
            if ($spec.PSObject.Properties['StatsKind'] -and $spec.StatsKind) { $statsKind = $spec.StatsKind }
            $statsOk = $false
            if ($null -ne $statValue) {
                if ($statsKind -eq 'positive') {
                    $number = 0.0
                    if ([double]::TryParse([string]$statValue, [ref]$number)) { $statsOk = ($number -gt 0) }
                } else { $statsOk = $true }
            }
            if (-not $statsOk) {
                $probe.status = 'unimplemented'
                $probe.reason = "engine published no support for $($spec.StatsKey) (option ignored/no-op)"
            }
        }
    }
    if (-not $KeepProbeJars -and (Test-Path $probeJar)) { Remove-Item $probeJar -Force -ErrorAction SilentlyContinue }
    $probes[$spec.Name] = $probe
    Write-Host ("  {0,-16} {1,-14} {2}" -f $spec.Name, $probe.status, $probe.reason)
}

function Get-FeatureArgs([string]$Name) {
    foreach ($spec in $featureSpecs) {
        if ($spec.Name -eq $Name) { return $spec.Args }
    }
    return @()
}

# --- cases -------------------------------------------------------------------
$lightFlags = @('--no-flow', '--no-shuffle', '--no-junk', '--no-watermark')
$strongBase = @('--no-shuffle', '--no-junk', '--no-watermark')
$extraMaximum = @('--trim', '--parameter-obfuscation', '--rewrite-resources')

$caseSpecs = @(
    [pscustomobject]@{
        Name = 'baseline'
        Description = 'no transforms'
        Base = $baselineFlags
        Features = @()
        Required = @()
        Extra = @()
        Optional = $false
        StrictNotes = 'reference baseline; proves the demo harness itself is stable'
    },
    [pscustomobject]@{
        Name = 'light'
        Description = 'rename + string encryption + integer encryption'
        Base = $lightFlags
        Features = @()
        Required = @()
        Extra = @()
        Optional = $false
        StrictNotes = 'renaming + string encryption'
    },
    [pscustomobject]@{
        Name = 'balanced'
        Description = 'light + flow flattening + method virtualization + anti-LLM + reference obfuscation'
        Base = $strongBase
        Features = @('flatten', 'virtualize', 'antiLlm', 'reference')
        Required = @('flatten', 'virtualize', 'antiLlm', 'reference')
        Extra = @()
        Optional = $false
        StrictNotes = 'flattening + VM2'
    },
    [pscustomobject]@{
        Name = 'maximum'
        Description = 'balanced + MBA + VM2 + class encryption + integrity + anti-debug + exception/trim/parameter/resource transforms'
        Base = @()
        Features = @('flatten', 'virtualize', 'antiLlm', 'reference', 'exception', 'mba', 'vm2',
            'classEncryption', 'integrity', 'antiDebug')
        Required = @('mba', 'vm2', 'classEncryption', 'integrity', 'antiDebug')
        Extra = $extraMaximum
        Optional = $false
        StrictNotes = 'strings + flattening + VM2 + integrity + class encryption'
    },
    [pscustomobject]@{
        Name = 'native'
        Description = 'light + C/JNI native code generation (slow: compiles C and loads a DLL)'
        Base = $lightFlags
        Features = @('native')
        Required = @('native')
        Extra = @()
        Optional = $true
        StrictNotes = 'JNI native code'
    },
    [pscustomobject]@{
        Name = 'v3'
        Description = 'Umbra 3.0 passes: type confusion + string engine v2 + VM2 fusion (all stats-gated probes)'
        Base = $lightFlags
        Features = @('typeConfusion', 'stringV2', 'vm2fusion')
        Required = @('typeConfusion', 'stringV2', 'vm2fusion')
        Extra = @()
        Optional = $false
        StrictNotes = 'typeConfusion + string v2 engines + vm2.fusion'
    }
)

function Build-CaseFlags([object]$Case) {
    $flags = New-Object System.Collections.Generic.List[string]
    foreach ($flag in $Case.Base) { $flags.Add($flag) }
    $included = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    $broken = New-Object System.Collections.Generic.List[string]
    foreach ($name in $Case.Features) {
        if (-not $probes.Contains($name)) {
            $missing.Add($name)
            continue
        }
        $probe = $probes[$name]
        if ($probe.status -eq 'supported' -or $probe.status -eq 'noop') {
            $included.Add($name)
            foreach ($arg in (Get-FeatureArgs $name)) { $flags.Add($arg) }
        } elseif ($probe.status -eq 'broken') {
            if ($Case.Required -contains $name) {
                $broken.Add($name)
                foreach ($arg in (Get-FeatureArgs $name)) { $flags.Add($arg) }
            } else {
                $missing.Add($name)
            }
        } else {
            $missing.Add($name)
        }
        if ($name -eq 'native' -and $Gcc) { $flags.Add('--set'); $flags.Add("native.compiler=$Gcc") }
    }
    foreach ($flag in $Case.Extra) { $flags.Add($flag) }
    return [pscustomobject]@{
        Flags = $flags.ToArray()
        Included = $included.ToArray()
        Missing = $missing.ToArray()
        Broken = $broken.ToArray()
    }
}

$caseResults = @()
Write-Host ''
Write-Host '==> running cases' -ForegroundColor Cyan
foreach ($case in $caseSpecs) {
    $build = Build-CaseFlags $case
    $caseOut = Join-Path $OutDir ($case.Name + '.jar')
    $caseReport = Join-Path $ReportDir ($case.Name + '.json')
    $umbraLogPath = Join-Path $LogDir ($case.Name + '-umbra.log')
    $caseResult = [ordered]@{
        case = $case.Name
        description = $case.Description
        technique = $case.StrictNotes
        status = 'RUNNING'
        reason = ''
        includedFeatures = @($build.Included)
        missingFeatures = @($build.Missing)
        brokenFeatures = @($build.Broken)
        command = ''
        obfuscateExitCode = -1
        verifyOk = $false
        obfuscateMs = 0
        outputJar = $caseOut
        outputBytes = 0
        inputBytes = (Get-Item $DemoJar).Length
        sizeRatio = 0
        outputSha256 = ''
        runJdk8 = [ordered]@{ exitCode = -1; stdout = ''; ok = $false; log = '' }
        runJdk21 = [ordered]@{ exitCode = -1; stdout = ''; ok = $false; log = '' }
        runJdk26 = [ordered]@{ exitCode = -1; stdout = ''; ok = $false; log = '' }
        optional = [bool]$Case.Optional
        warnings = @()
        stats = @{}
        statsHighlights = [ordered]@{}
        strings = [ordered]@{ json = ''; humanText = -1; classRefs = -1; markerStrings = -1; markerClasses = -1; markerMethods = -1; markerFields = -1 }
        logTail = ''
        started = (Get-Date).ToString('s')
        durationMs = 0
    }
    $started = Get-Date
    $caseArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', $caseOut) + $build.Flags +
        @('--seed', $Seed, '--verify', '--report-json', $caseReport)
    $caseResult.command = ('java ' + ((@('-jar', $UmbraJar, '-i', $DemoJar, '-o', $caseOut) + $build.Flags +
        @('--seed', $Seed, '--verify')) -join ' '))
    $obf = Invoke-Tool $Java $caseArgs ($TimeoutSeconds * 1000)
    $caseResult.obfuscateExitCode = $obf.Code
    $umbraLog = $obf.StdOut + "`n" + $obf.StdErr
    Write-Utf8 $umbraLogPath $umbraLog
    $caseResult.logTail = Get-LogTail $umbraLog 25
    $caseResult.verifyOk = ($umbraLog -match 'Verification: OK')
    $caseResult.obfuscateMs = [int]((Get-Date) - $started).TotalMilliseconds

    if ($obf.Code -ne 0) {
        $caseResult.status = 'FAIL'
        $reasonLine = @($umbraLog -split "`r?`n" | Where-Object { $_ -match 'Umbra failed|Configuration error|not implemented' } | Select-Object -First 1)
        $caseResult.reason = if ($reasonLine.Count -gt 0) { $reasonLine[0].Trim() } else { "obfuscation exit code $($obf.Code)" }
    } elseif (-not $caseResult.verifyOk) {
        $caseResult.status = 'FAIL'
        $caseResult.reason = 'Umbra --verify did not report OK'
    } elseif (-not (Test-Path $caseOut)) {
        $caseResult.status = 'FAIL'
        $caseResult.reason = 'Umbra produced no output jar'
    } else {
        $caseResult.outputBytes = (Get-Item $caseOut).Length
        $caseResult.outputSha256 = Get-Sha256 $caseOut
        $caseResult.sizeRatio = [Math]::Round($caseResult.outputBytes / $caseResult.inputBytes, 2)
        $run1 = Invoke-Tool $Java @('-jar', $caseOut) ($TimeoutSeconds * 1000)
        $caseResult.runJdk8.exitCode = $run1.Code
        $caseResult.runJdk8.stdout = $run1.StdOut.Trim()
        $caseResult.runJdk8.ok = ($run1.Code -eq 0 -and $caseResult.runJdk8.stdout -eq 'OK')
        $caseResult.runJdk8.log = Join-Path $LogDir ($case.Name + '-run-jdk8.log')
        Write-Utf8 $caseResult.runJdk8.log ($run1.StdOut + "`n" + $run1.StdErr)
        if ($SecondaryJava) {
            $run2 = Invoke-Tool $SecondaryJava @('-jar', $caseOut) ($TimeoutSeconds * 1000)
            $caseResult.runJdk21.exitCode = $run2.Code
            $caseResult.runJdk21.stdout = $run2.StdOut.Trim()
            $caseResult.runJdk21.ok = ($run2.Code -eq 0 -and $caseResult.runJdk21.stdout -eq 'OK')
            $caseResult.runJdk21.log = Join-Path $LogDir ($case.Name + '-run-jdk21.log')
            Write-Utf8 $caseResult.runJdk21.log ($run2.StdOut + "`n" + $run2.StdErr)
        }
        if ($ThirdJava) {
            $run3 = Invoke-Tool $ThirdJava @('-jar', $caseOut) ($TimeoutSeconds * 1000)
            $caseResult.runJdk26.exitCode = $run3.Code
            $caseResult.runJdk26.stdout = $run3.StdOut.Trim()
            $caseResult.runJdk26.ok = ($run3.Code -eq 0 -and $caseResult.runJdk26.stdout -eq 'OK')
            $caseResult.runJdk26.log = Join-Path $LogDir ($case.Name + '-run-jdk26.log')
            Write-Utf8 $caseResult.runJdk26.log ($run3.StdOut + "`n" + $run3.StdErr)
        }
        if (-not $caseResult.runJdk8.ok) {
            $caseResult.status = 'FAIL'
            $runLine = @(($run1.StdErr) -split "`r?`n" | Where-Object { $_ -match 'Exception|FAIL' } | Select-Object -First 1)
            $caseResult.reason = if ($runLine.Count -gt 0) { "runtime (JDK 8): " + $runLine[0].Trim() } else { "runtime (JDK 8): exit $($run1.Code), stdout '$($caseResult.runJdk8.stdout)'" }
            $caseResult.logTail = (Get-LogTail $umbraLog 10) + "`n--- runtime (JDK 8) ---`n" + (Get-LogTail ($run1.StdOut + "`n" + $run1.StdErr) 30)
        } elseif ($SecondaryJava -and -not $caseResult.runJdk21.ok) {
            $caseResult.status = 'FAIL'
            $caseResult.reason = "runtime (JDK 21): exit $($run2.Code), stdout '$($caseResult.runJdk21.stdout)'"
            $caseResult.logTail = (Get-LogTail $umbraLog 10) + "`n--- runtime (JDK 21) ---`n" + (Get-LogTail ($run2.StdOut + "`n" + $run2.StdErr) 30)
        } elseif ($ThirdJava -and -not $caseResult.runJdk26.ok) {
            $caseResult.status = 'FAIL'
            $caseResult.reason = "runtime (JDK 26): exit $($run3.Code), stdout '$($caseResult.runJdk26.stdout)'"
            $caseResult.logTail = (Get-LogTail $umbraLog 10) + "`n--- runtime (JDK 26) ---`n" + (Get-LogTail ($run3.StdOut + "`n" + $run3.StdErr) 30)
        } elseif ($build.Missing.Count -gt 0) {
            if ($Case.Optional) {
                $caseResult.status = 'SKIP'
                $caseResult.reason = 'optional feature unavailable: ' + ($build.Missing -join ', ')
            } elseif ($SkipUnimplemented) {
                $caseResult.status = 'PARTIAL'
                $caseResult.reason = 'unimplemented/unsupported features skipped: ' + ($build.Missing -join ', ')
            } else {
                $caseResult.status = 'FAIL'
                $caseResult.reason = 'strict mode: required features unimplemented: ' + ($build.Missing -join ', ')
            }
        } elseif ($build.Broken.Count -gt 0) {
            # The isolated feature probe failed in its own configuration, but
            # the composed case itself passed on every JDK (the probe base is
            # deliberately different from the case base). Record a warning
            # instead of failing an applicable case; the probe row keeps the
            # defect visible and it is reported to the feature owner.
            $caseResult.warnings = @(('feature probe failed in its probe configuration: ' + ($build.Broken -join ', ') + ' (composed case passed on all JDKs)'))
            $caseResult.status = 'PASS'
        } else {
            $caseResult.status = 'PASS'
        }

        if (Test-Path $caseReport) {
            try {
                $report = Get-Content $caseReport -Raw -Encoding UTF8 | ConvertFrom-Json
                $stats = @{}
                foreach ($property in $report.stats.PSObject.Properties) { $stats[$property.Name] = $property.Value }
                $caseResult.stats = $stats
                $highlights = [ordered]@{
                    classes = (Get-Stat $report.stats 'output.classes')
                    methodsRenamed = (Get-Stat $report.stats 'methods.renamed')
                    fieldsRenamed = (Get-Stat $report.stats 'fields.renamed')
                    stringsEncrypted = (Get-Stat $report.stats 'strings.encrypted')
                    intsObfuscated = (Get-Stat $report.stats 'constants.obfuscated')
                    flowMethods = (Get-Stat $report.stats 'flow.methods')
                    flattenedMethods = (Get-Stat $report.stats 'flow.flattened.methods')
                    virtualizedMethods = (Get-Stat $report.stats 'virtualization.methods')
                    references = (Get-Stat $report.stats 'references.indy')
                    antiLlmDecoys = (Get-Stat $report.stats 'antiLlm.decoys')
                    mba = (Get-Stat $report.stats 'mba.expressions')
                    classEncrypted = (Get-Stat $report.stats 'classEncryption.classes')
                    classPayloadEntries = (Get-Stat $report.stats 'classEncryption.payloadEntries')
                    integrity = (Get-Stat $report.stats 'integrity.entries')
                    integrityGuard = (Get-Stat $report.stats 'integrity.guard')
                    antiDebug = (Get-Stat $report.stats 'protection.antiDebug')
                    nativeMethods = (Get-Stat $report.stats 'native.methods')
                    nativeInstructions = (Get-Stat $report.stats 'native.instructions')
                    nativeDllBytes = (Get-Stat $report.stats 'native.dll.bytes')
                    nativeClasses = (Get-Stat $report.stats 'native.classes')
                }
                $caseResult.statsHighlights = $highlights
            } catch {
                $caseResult.logTail = (Get-LogTail $umbraLog 25)
            }
        }

        if (-not $SkipAnalysis -and (Test-Path $caseOut)) {
            $scanJson = Join-Path $AnalysisDir ($case.Name + '.strings.json')
            $scan = Invoke-Tool $python @((Join-Path $PSScriptRoot 'tools\scan_strings.py'), '--jar', $caseOut,
                '--out', $scanJson, '--label', $case.Name) 120000
            if ($scan.Code -eq 0 -and (Test-Path $scanJson)) {
                $caseResult.strings.json = $scanJson
                try {
                    $scanData = Get-Content $scanJson -Raw -Encoding UTF8 | ConvertFrom-Json
                    $caseResult.strings.humanText = $scanData.counts.humanText
                    $caseResult.strings.classRefs = $scanData.counts.classRefs
                    $caseResult.strings.markerStrings = @($scanData.markerHits.strings).Count
                    $caseResult.strings.markerClasses = @($scanData.markerHits.classes).Count
                    $caseResult.strings.markerMethods = @($scanData.markerHits.methods).Count
                    $caseResult.strings.markerFields = @($scanData.markerHits.fields).Count
                } catch { }
            } else {
                $caseResult.strings.json = ''
                $caseResult.logTail += "`n[scan] " + $scan.StdErr
            }
        }
    }
    $caseResult.durationMs = [int]((Get-Date) - $started).TotalMilliseconds
    $caseResults += [pscustomobject]$caseResult
    Write-Host ("  {0,-9} {1,-8} {2}" -f $case.Name, $caseResult.status, $caseResult.reason)
}

# --- deobfuscation evidence --------------------------------------------------
$decompile = [ordered]@{ status = 'SKIP'; reason = ''; target = ''; dir = ''; json = '' }
if (-not $SkipDecompile) {
    $target = $null
    foreach ($preferred in @('maximum', 'balanced', 'light', 'baseline')) {
        $candidate = Join-Path $OutDir ($preferred + '.jar')
        if (Test-Path $candidate) { $target = $candidate; break }
    }
    if ($target) {
        Write-Host ''
        Write-Host "==> deobfuscation evidence: $target" -ForegroundColor Cyan
        $deobf = Invoke-Tool 'powershell' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $PSScriptRoot 'deobfuscate.ps1'), '-Jar', $target, '-OutDir', $AnalysisDir) 600000
        $decompile.target = $target
        $decompile.dir = $AnalysisDir
        $deobfJson = Join-Path $AnalysisDir 'deobfuscation.json'
        if (Test-Path $deobfJson) {
            $decompile.json = $deobfJson
            $decompile.status = 'OK'
        } else {
            $decompile.status = 'FAIL'
            $decompile.reason = (Get-LogTail ($deobf.StdOut + "`n" + $deobf.StdErr) 12)
        }
        Write-Host ("  decompile: {0}" -f $decompile.status)
    } else {
        $decompile.reason = 'no output jar available'
    }
}

# --- preset compatibility ----------------------------------------------------
$presetResults = @()
$presetNames = @('library', 'spring-boot', 'jackson', 'service-loader', 'micronaut', 'aggressive')
if (-not $SkipPresets) {
    Write-Host ''
    Write-Host '==> preset compatibility checks' -ForegroundColor Cyan
    foreach ($preset in $presetNames) {
        $presetJar = Join-Path $OutDir ('preset-' + $preset + '.jar')
        $presetReport = Join-Path $ReportDir ('preset-' + $preset + '.json')
        $presetLog = Join-Path $LogDir ('preset-' + $preset + '.log')
        $presetArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', $presetJar,
            '--preset', $preset, '--seed', $Seed, '--verify', '--report-json', $presetReport)
        $run = Invoke-Tool $Java $presetArgs ($TimeoutSeconds * 1000)
        $log = $run.StdOut + "`n" + $run.StdErr
        Write-Utf8 $presetLog $log
        $entry = [ordered]@{
            preset = $preset
            status = 'FAIL'
            reason = ''
            verifyOk = ($log -match 'Verification: OK')
            obfuscateExitCode = $run.Code
            outputJar = $presetJar
            outputBytes = 0
            runOk = $false
            runExitCode = -1
            command = ('java ' + ($presetArgs -join ' '))
        }
        if ($run.Code -ne 0) {
            $line = @($log -split "`r?`n" | Where-Object { $_ -match 'Umbra failed|Configuration error' } | Select-Object -First 1)
            $entry.reason = if ($line.Count -gt 0) { $line[0].Trim() } else { "obfuscation exit code $($run.Code)" }
        } elseif (-not $entry.verifyOk) {
            $entry.reason = '--verify did not report OK'
        } elseif (-not (Test-Path $presetJar)) {
            $entry.reason = 'no output jar'
        } else {
            $entry.outputBytes = (Get-Item $presetJar).Length
            $exec = Invoke-Tool $Java @('-jar', $presetJar) ($TimeoutSeconds * 1000)
            $entry.runExitCode = $exec.Code
            $entry.runOk = ($exec.Code -eq 0 -and $exec.StdOut.Trim() -eq 'OK')
            if ($entry.runOk) {
                $entry.status = 'PASS'
            } else {
                $line = @($exec.StdErr -split "`r?`n" | Where-Object { $_ -match 'Exception|FAIL' } | Select-Object -First 1)
                $entry.reason = if ($line.Count -gt 0) { 'runtime: ' + $line[0].Trim() } else { "runtime exit $($exec.Code)" }
            }
        }
        $presetResults += [pscustomobject]$entry
        Write-Host ("  preset {0,-14} {1,-6} {2}" -f $preset, $entry.status, $entry.reason)
    }
}

# --- Umbra 3.0: layout modes, CLI compatibility tools, GUI smoke -------------
$compat3Results = New-Object System.Collections.ArrayList
$cliResults = New-Object System.Collections.ArrayList
$compat3LogDir = Join-Path $ResultsDir 'compat3'
New-Item -ItemType Directory -Force -Path $compat3LogDir | Out-Null

function Get-FreeTcpPort {
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        return [int]$listener.LocalEndpoint.Port
    } finally { if ($listener) { try { $listener.Stop() } catch { } } }
}

function Test-JarEntryPresent {
    param([string]$JarPath, [string]$EntryName)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $JarPath).Path)
    try { return [bool]($zip.GetEntry($EntryName)) } finally { $zip.Dispose() }
}

function Test-NestedJarsStored {
    param([string]$JarPath, [string]$Prefix)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $JarPath).Path)
    try {
        $nested = @($zip.Entries | Where-Object { $_.FullName.StartsWith($Prefix) -and $_.FullName.EndsWith('.jar') })
        if ($nested.Count -eq 0) { return [pscustomobject]@{ ok = $false; detail = "no nested jars under $Prefix" } }
        $bad = @($nested | Where-Object { $_.CompressedLength -ne $_.Length })
        return [pscustomobject]@{ ok = ($bad.Count -eq 0); detail = $(if ($bad.Count -eq 0) { "$($nested.Count) nested jars STORED" } else { 'recompressed: ' + (($bad | ForEach-Object { $_.FullName }) -join ',') }) }
    } finally { $zip.Dispose() }
}

function Get-ReportStats {
    param([string]$ReportPath)
    if (-not (Test-Path $ReportPath)) { return $null }
    try {
        $report = Get-Content $ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($report.PSObject.Properties['stats']) { return $report.stats }
    } catch { }
    return $null
}

function Get-ReportStatValue {
    param($Stats, [string]$Key)
    if (-not $Stats) { return $null }
    $property = $Stats.PSObject.Properties[$Key]
    if (-not $property) { return $null }
    return $property.Value
}

function Invoke-ProtectedHttpRun {
    param([string]$JavaExe, [string[]]$Arguments, [string]$UrlPath, [string]$Expected, [int]$TimeoutSec)
    $port = Get-FreeTcpPort
    $resolved = @()
    foreach ($argument in $Arguments) { $resolved += ([string]$argument).Replace('{port}', [string]$port) }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $JavaExe
    $quoted = @()
    foreach ($a in $resolved) { if ($a -match '[\s"]') { $quoted += ('"' + ($a -replace '"', '\"') + '"') } else { $quoted += $a } }
    $psi.Arguments = ($quoted -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $url = 'http://127.0.0.1:' + $port + $UrlPath
    $body = ''
    $status = 0
    $lastError = ''
    $started = Get-Date
    $outTask = $null
    $errTask = $null
    try {
        $null = $process.Start()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        while ((Get-Date) -lt $deadline) {
            if ($process.HasExited) { break }
            try {
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
                $status = [int]$response.StatusCode
                $body = [string]$response.Content
                break
            } catch { $lastError = $_.Exception.Message; Start-Sleep -Milliseconds 300 }
        }
    } finally {
        if ($process -and -not $process.HasExited) { try { $process.Kill() } catch { }; try { $null = $process.WaitForExit(10000) } catch { } }
    }
    $stdout = ''
    $stderr = ''
    if ($outTask -and $outTask.Wait(5000)) { $stdout = $outTask.Result }
    if ($errTask -and $errTask.Wait(5000)) { $stderr = $errTask.Result }
    $seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 2)
    $ok = ($status -eq 200 -and $body.Contains($Expected))
    return [pscustomobject]@{
        ok = $ok; status = $status; body = $body; seconds = $seconds
        stdout = $stdout; stderr = $stderr; url = $url; lastError = $lastError
        command = ($JavaExe + ' ' + ($resolved -join ' '))
    }
}

function Add-Compat3Result {
    param($List, [string]$Id, [string]$Status, [string]$Reason, [string]$Command, [string]$Log)
    $null = $List.Add([ordered]@{ id = $Id; status = $Status; reason = $Reason; command = $Command; log = $Log })
    $color = if ($Status -eq 'PASS') { 'Gray' } elseif ($Status -eq 'SKIP') { 'DarkYellow' } else { 'Red' }
    Write-Host ("    {0,-34} {1,-8} {2}" -f $Id, $Status, $Reason) -ForegroundColor $color
}

if (-not $SkipCompat3) {
    Write-Host ''
    Write-Host '==> Umbra 3.0 layout modes (real corpus artifacts, --preset balanced)' -ForegroundColor Cyan
    $layoutCases = @(
        [pscustomobject]@{ Id = '3.0-springboot2-fat'; Jar = 'springboot2-fat.jar'; Mode = 'http'; Expected = 'UMBRA-SB2-OK'; Url = '/token'; Args = @('-jar', '{out}', '--server.port={port}'); StatsKey = 'layout.springBoot.classes'; NestedPrefix = 'BOOT-INF/lib/'; SkipStat = 'classEncryption.skipped.layout'; Jdk = 'java8' }
        [pscustomobject]@{ Id = '3.0-springboot-war'; Jar = 'springboot-war.war'; Mode = 'http'; Expected = 'UMBRA-WAR-OK'; Url = '/token'; Args = @('-jar', '{out}', '--server.port={port}'); StatsKey = 'layout.war.classes'; NestedPrefix = 'WEB-INF/lib/'; SkipStat = 'classEncryption.skipped.layout'; Jdk = 'java8' }
    )
    foreach ($layoutCase in $layoutCases) {
        $logPath = Join-Path $compat3LogDir ($layoutCase.Id + '.log')
        $lines = @()
        $sourceJar = Join-Path $CompatArtifacts $layoutCase.Jar
        if (-not (Test-Path $sourceJar)) {
            Add-Compat3Result $compat3Results $layoutCase.Id 'SKIP' ('corpus artifact missing: ' + $sourceJar) '' $logPath
            continue
        }
        $outJar = Join-Path $OutDir ($layoutCase.Id + '.jar')
        $reportPath = Join-Path $ReportDir ($layoutCase.Id + '.report.json')
        $protectArgs = @('-jar', $UmbraJar, '-i', $sourceJar, '-o', $outJar, '--preset', 'balanced',
            '--seed', $Seed, '--verify', '--report-json', $reportPath)
        $protect = Invoke-Tool $Java $protectArgs ($LayoutTimeoutSeconds * 1000)
        $lines += ('protect: ' + $protect.StdOut + $protect.StdErr)
        $status = 'PASS'
        $reason = ''
        if ($protect.Code -ne 0 -or -not ($protect.StdOut + $protect.StdErr) -match 'Verification: OK' -or -not (Test-Path $outJar)) {
            $status = 'FAIL'; $reason = 'protection/verify failed'
        } elseif (-not (Test-Path $reportPath)) {
            $status = 'FAIL'; $reason = 'no --report-json report written'
        } else {
            $stats = Get-ReportStats $reportPath
            $layoutValue = Get-ReportStatValue $stats $layoutCase.StatsKey
            if (-not $layoutValue -or [double]$layoutValue -le 0) { $status = 'FAIL'; $reason = "report stat $($layoutCase.StatsKey) missing/zero (layout not detected)" }
            else {
                $skipValue = Get-ReportStatValue $stats $layoutCase.SkipStat
                if (-not $skipValue) { $status = 'FAIL'; $reason = "expected class-encryption auto-skip stat $($layoutCase.SkipStat) on nested layout (got none)" }
                $stored = Test-NestedJarsStored $outJar $layoutCase.NestedPrefix
                if (-not $stored.ok) { $status = 'FAIL'; $reason = $stored.detail } else { $reason = ($layoutCase.StatsKey + '=' + $layoutValue + '; ' + $stored.detail) }
            }
            if ($status -eq 'PASS') {
                $runtimeArgs = @(); foreach ($argTemplate in $layoutCase.Args) { $runtimeArgs += ([string]$argTemplate).Replace('{out}', $outJar) }
                $runtime = Invoke-ProtectedHttpRun -JavaExe $Java -Arguments $runtimeArgs -UrlPath $layoutCase.Url -Expected $layoutCase.Expected -TimeoutSec $LayoutTimeoutSeconds
                $lines += ('run: ' + $runtime.command + "`nexit=$($runtime.status) body=$($runtime.body)`n" + $runtime.stdout + $runtime.stderr)
                if (-not $runtime.ok) { $status = 'FAIL'; $reason = "protected HTTP run failed: status $($runtime.status) body '$($runtime.body)'" }
                else { $reason = $reason + '; HTTP ' + $runtime.body }
            }
        }
        Write-Utf8 $logPath ($lines -join "`n")
        Add-Compat3Result $compat3Results $layoutCase.Id $status $reason ($protectArgs -join ' ') $logPath
    }

    # Multi-release: both JDK 8 (base) and JDK 21 (versioned) behaviour.
    $mrSource = Join-Path $CompatArtifacts 'multi-release.jar'
    $mrLog = Join-Path $compat3LogDir '3.0-multi-release.log'
    if (-not (Test-Path $mrSource)) {
        Add-Compat3Result $compat3Results '3.0-multi-release' 'SKIP' ('corpus artifact missing: ' + $mrSource) '' $mrLog
    } else {
        $mrOut = Join-Path $OutDir '3.0-multi-release.jar'
        $mrReport = Join-Path $ReportDir '3.0-multi-release.report.json'
        $mrArgs = @('-jar', $UmbraJar, '-i', $mrSource, '-o', $mrOut, '--preset', 'balanced', '--seed', $Seed, '--verify', '--report-json', $mrReport)
        $mrProtect = Invoke-Tool $Java $mrArgs ($LayoutTimeoutSeconds * 1000)
        $mrLogText = 'protect: ' + $mrProtect.StdOut + $mrProtect.StdErr
        $mrStatus = 'PASS'
        $mrReason = ''
        if ($mrProtect.Code -ne 0 -or -not (Test-Path $mrOut)) { $mrStatus = 'FAIL'; $mrReason = 'protection/verify failed' }
        else {
            $run8 = Invoke-Tool $Java @('-jar', $mrOut) ($TimeoutSeconds * 1000)
            $run21 = $null
            if ($SecondaryJava) { $run21 = Invoke-Tool $SecondaryJava @('-jar', $mrOut) ($TimeoutSeconds * 1000) }
            $mrLogText += "`nJDK8: " + $run8.StdOut + $run8.StdErr
            if ($run21) { $mrLogText += "`nJDK21: " + $run21.StdOut + $run21.StdErr }
            $stats = Get-ReportStats $mrReport
            $mrClasses = Get-ReportStatValue $stats 'layout.multiRelease.classes'
            $mrEntries = @(); Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue; $mrZip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $mrOut).Path); try { $mrEntries = @($mrZip.Entries | Where-Object { $_.FullName.StartsWith('META-INF/versions/17/') } | ForEach-Object { $_.FullName }) } finally { $mrZip.Dispose() }; $versionedPresent = ($mrEntries.Count -gt 0)
            if ($run8.Code -ne 0 -or $run8.StdOut.Trim() -ne 'MULTI-BASE') { $mrStatus = 'FAIL'; $mrReason = 'JDK 8 run did not print MULTI-BASE' }
            elseif (-not $SecondaryJava) { $mrStatus = 'SKIP'; $mrReason = 'JDK 21 not available for versioned-class run' }
            elseif ($run21.Code -ne 0 -or $run21.StdOut.Trim() -ne 'MULTI-V17') { $mrStatus = 'FAIL'; $mrReason = 'JDK 21 run did not print MULTI-V17' }
            elseif (-not $versionedPresent) { $mrStatus = 'FAIL'; $mrReason = 'META-INF/versions/17 class not preserved' }
            elseif (-not $mrClasses -or [double]$mrClasses -le 0) { $mrStatus = 'FAIL'; $mrReason = 'layout.multiRelease.classes missing/zero' }
            else { $mrReason = "JDK8=MULTI-BASE, JDK21=MULTI-V17, versions entry preserved, layout.multiRelease.classes=$mrClasses" }
        }
        Write-Utf8 $mrLog $mrLogText
        Add-Compat3Result $compat3Results '3.0-multi-release' $mrStatus $mrReason ($mrArgs -join ' ') $mrLog
    }

    # JPMS: module descriptor must stay valid and the module main class runnable.
    $jpmsSource = Join-Path $CompatArtifacts 'jpms-module.jar'
    $jpmsLog = Join-Path $compat3LogDir '3.0-jpms.log'
    if (-not (Test-Path $jpmsSource)) {
        Add-Compat3Result $compat3Results '3.0-jpms-module' 'SKIP' ('corpus artifact missing: ' + $jpmsSource) '' $jpmsLog
    } elseif (-not $SecondaryJava) {
        Add-Compat3Result $compat3Results '3.0-jpms-module' 'SKIP' 'JDK 21 not available for --module-path run' '' $jpmsLog
    } else {
        $jpmsOut = Join-Path $OutDir '3.0-jpms-module.jar'
        $jpmsReport = Join-Path $ReportDir '3.0-jpms.report.json'
        $jpmsArgs = @('-jar', $UmbraJar, '-i', $jpmsSource, '-o', $jpmsOut, '--preset', 'balanced', '--seed', $Seed, '--verify', '--report-json', $jpmsReport)
        $jpmsProtect = Invoke-Tool $Java $jpmsArgs ($LayoutTimeoutSeconds * 1000)
        $jpmsLogText = 'protect: ' + $jpmsProtect.StdOut + $jpmsProtect.StdErr
        $jpmsStatus = 'PASS'
        $jpmsReason = ''
        if ($jpmsProtect.Code -ne 0 -or -not (Test-Path $jpmsOut)) { $jpmsStatus = 'FAIL'; $jpmsReason = 'protection/verify failed' }
        else {
            $moduleRun = Invoke-Tool $SecondaryJava @('--module-path', $jpmsOut, '-m', 'qa.mod') ($TimeoutSeconds * 1000)
            $jpmsLogText += "`nmodule run: " + $moduleRun.StdOut + $moduleRun.StdErr
            $stats = Get-ReportStats $jpmsReport
            $moduleStat = Get-ReportStatValue $stats 'layout.moduleInfo'
            if ($moduleRun.Code -ne 0 -or $moduleRun.StdOut.Trim() -ne 'JPMS-OK') {
                $jpmsStatus = 'FAIL'
                $jpmsReason = 'java --module-path -m qa.mod failed: ' + (Get-LogTail ($moduleRun.StdOut + $moduleRun.StdErr) 3)
            } elseif (-not $moduleStat -or [double]$moduleStat -le 0) {
                $jpmsStatus = 'FAIL'; $jpmsReason = 'layout.moduleInfo stat missing/zero'
            } else { $jpmsReason = "module run OK, layout.moduleInfo=$moduleStat" }
        }
        Write-Utf8 $jpmsLog $jpmsLogText
        Add-Compat3Result $compat3Results '3.0-jpms-module' $jpmsStatus $jpmsReason ($jpmsArgs -join ' ') $jpmsLog
    }

    # CLI compatibility tools: --inspect-json, --compat-report, --mapping.
    Write-Host ''
    Write-Host '==> Umbra 3.0 CLI compatibility tools' -ForegroundColor Cyan
    foreach ($inspectTarget in @(
            @{ Id = '3.0-inspect-demo'; Jar = $DemoJar; ExpectedLayout = 'flat' },
            @{ Id = '3.0-inspect-springboot2'; Jar = (Join-Path $CompatArtifacts 'springboot2-fat.jar'); ExpectedLayout = 'spring-boot' })) {
        $logPath = Join-Path $compat3LogDir ($inspectTarget.Id + '.log')
        if (-not (Test-Path $inspectTarget.Jar)) {
            Add-Compat3Result $cliResults $inspectTarget.Id 'SKIP' ('input missing: ' + $inspectTarget.Jar) '' $logPath
            continue
        }
        $inspectJson = Join-Path $OutDir ($inspectTarget.Id + '.json')
        $inspectArgs = @('-jar', $UmbraJar, '-i', $inspectTarget.Jar, '--inspect-json', $inspectJson)
        $inspectRun = Invoke-Tool $Java $inspectArgs ($TimeoutSeconds * 1000)
        Write-Utf8 $logPath ($inspectRun.StdOut + "`n" + $inspectRun.StdErr)
        $inspectStatus = 'PASS'
        $inspectReason = ''
        if ($inspectRun.Code -ne 0 -or -not (Test-Path $inspectJson)) { $inspectStatus = 'FAIL'; $inspectReason = '--inspect-json failed or wrote no file' }
        else {
            try {
                $inspection = Get-Content $inspectJson -Raw -Encoding UTF8 | ConvertFrom-Json
                $layoutValue = $inspection.layout
                if ([string]$layoutValue -ne $inspectTarget.ExpectedLayout) { $inspectStatus = 'FAIL'; $inspectReason = "layout '$layoutValue' != '$($inspectTarget.ExpectedLayout)'" }
                else { $inspectReason = 'layout=' + $layoutValue }
            } catch { $inspectStatus = 'FAIL'; $inspectReason = 'inspection JSON is not valid JSON' }
        }
        Add-Compat3Result $cliResults $inspectTarget.Id $inspectStatus $inspectReason ($inspectArgs -join ' ') $logPath
    }

    # --compat-report after a real run.
    $compatReportLog = Join-Path $compat3LogDir '3.0-compat-report.log'
    $compatJson = Join-Path $OutDir '3.0-compat-report.json'
    $compatOut = Join-Path $OutDir '3.0-compat-report.jar'
    $compatArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', $compatOut, '--preset', 'balanced', '--seed', $Seed, '--verify', '--compat-report', $compatJson)
    $compatRun = Invoke-Tool $Java $compatArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $compatReportLog ($compatRun.StdOut + "`n" + $compatRun.StdErr)
    $compatStatus = 'PASS'
    $compatReason = ''
    if ($compatRun.Code -ne 0 -or -not (Test-Path $compatJson)) { $compatStatus = 'FAIL'; $compatReason = '--compat-report failed or wrote no file' }
    else {
        try {
            $compatData = Get-Content $compatJson -Raw -Encoding UTF8 | ConvertFrom-Json
            $hasLayout = ($null -ne $compatData.PSObject.Properties['layout']) -and $compatData.layout
            $hasStats = ($null -ne $compatData.PSObject.Properties['stats']) -and $compatData.stats
            $hasTimings = $null -ne $compatData.PSObject.Properties['passTimesMs']
            if (-not ($hasLayout -and $hasStats -and $hasTimings)) { $compatStatus = 'FAIL'; $compatReason = 'compat report lacks layout/stats/passTimesMs' }
            else { $compatReason = 'layout=' + [string]$compatData.layout + ', stats present, pass timings present' }
        } catch { $compatStatus = 'FAIL'; $compatReason = 'compat report is not valid JSON' }
    }
    Add-Compat3Result $cliResults '3.0-compat-report' $compatStatus $compatReason ($compatArgs -join ' ') $compatReportLog

    # --mapping writes a real mapping file.
    $mappingLog = Join-Path $compat3LogDir '3.0-mapping.log'
    $mappingFile = Join-Path $OutDir '3.0-mapping.txt'
    $mappingArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', (Join-Path $OutDir '3.0-mapping.jar'), '--preset', 'light', '--seed', $Seed, '--verify', '--mapping', $mappingFile)
    $mappingRun = Invoke-Tool $Java $mappingArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $mappingLog ($mappingRun.StdOut + "`n" + $mappingRun.StdErr)
    $mappingStatus = 'PASS'
    $mappingReason = ''
    if ($mappingRun.Code -ne 0 -or -not (Test-Path $mappingFile)) { $mappingStatus = 'FAIL'; $mappingReason = '--mapping failed or wrote no file' }
    elseif ((Get-Item $mappingFile).Length -lt 100) { $mappingStatus = 'FAIL'; $mappingReason = 'mapping file is suspiciously small' }
    else { $mappingReason = 'mapping file written (' + (Get-Item $mappingFile).Length + ' bytes)' }
    Add-Compat3Result $cliResults '3.0-mapping' $mappingStatus $mappingReason ($mappingArgs -join ' ') $mappingLog

    # --dry-run: analyze only, no output written.
    $dryLog = Join-Path $compat3LogDir '3.0-dry-run.log'
    $dryOut = Join-Path $OutDir '3.0-dry-run.jar'
    if (Test-Path $dryOut) { Remove-Item $dryOut -Force }
    $dryArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', $dryOut, '--preset', 'balanced', '--seed', $Seed, '--dry-run')
    $dryRun = Invoke-Tool $Java $dryArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $dryLog ($dryRun.StdOut + "`n" + $dryRun.StdErr)
    $dryStatus = 'PASS'
    $dryReason = ''
    if ($dryRun.Code -ne 0) { $dryStatus = 'FAIL'; $dryReason = '--dry-run exit ' + $dryRun.Code }
    elseif (Test-Path $dryOut) { $dryStatus = 'FAIL'; $dryReason = '--dry-run wrote an output jar' }
    else { $dryReason = 'analysis-only run, no output written' }
    Add-Compat3Result $cliResults '3.0-dry-run' $dryStatus $dryReason ($dryArgs -join ' ') $dryLog

    # determinism: same seed twice -> byte-identical output.
    $detLog = Join-Path $compat3LogDir '3.0-determinism.log'
    $detOut1 = Join-Path $OutDir '3.0-determinism-1.jar'
    $detOut2 = Join-Path $OutDir '3.0-determinism-2.jar'
    $detArgsBase = @('-jar', $UmbraJar, '-i', $DemoJar, '--preset', 'balanced', '--seed', $Seed, '--verify', '--fixed-time')
    $detRun1 = Invoke-Tool $Java ($detArgsBase + @('-o', $detOut1)) ($TimeoutSeconds * 1000)
    $detRun2 = Invoke-Tool $Java ($detArgsBase + @('-o', $detOut2)) ($TimeoutSeconds * 1000)
    Write-Utf8 $detLog ($detRun1.StdOut + $detRun1.StdErr + "`n---`n" + $detRun2.StdOut + $detRun2.StdErr)
    $detStatus = 'PASS'
    $detReason = ''
    if ($detRun1.Code -ne 0 -or $detRun2.Code -ne 0 -or -not (Test-Path $detOut1) -or -not (Test-Path $detOut2)) {
        $detStatus = 'FAIL'; $detReason = 'determinism runs failed'
    } else {
        $sha1 = Get-Sha256 $detOut1
        $sha2 = Get-Sha256 $detOut2
        if ($sha1 -ne $sha2) { $detStatus = 'FAIL'; $detReason = "same seed produced different bytes ($sha1 vs $sha2)" }
        else { $detReason = 'two runs byte-identical: ' + $sha1 }
    }
    Add-Compat3Result $cliResults '3.0-determinism' $detStatus $detReason ($detArgsBase -join ' ') $detLog

    # integrity/tamper: flip a bundled resource byte, the guard must reject it.
    $tamperLog = Join-Path $compat3LogDir '3.0-tamper.log'
    $tamperOut = Join-Path $OutDir '3.0-tamper.jar'
    $tamperArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', $tamperOut, '--preset', 'light', '--seed', $Seed, '--verify', '--set', 'integrity.enabled=true', '--set', 'integrity.level=2')
    $tamperProtect = Invoke-Tool $Java $tamperArgs ($TimeoutSeconds * 1000)
    $tamperLogText = 'protect: ' + $tamperProtect.StdOut + $tamperProtect.StdErr
    $tamperStatus = 'PASS'
    $tamperReason = ''
    if ($tamperProtect.Code -ne 0 -or -not (Test-Path $tamperOut)) {
        $tamperStatus = 'FAIL'; $tamperReason = 'integrity-protected jar was not produced'
    } else {
        # tamper: replace the bundled resource's bytes (same length)
        $tampered = Join-Path $OutDir '3.0-tamper-modified.jar'
        Copy-Item $tamperOut $tampered -Force
        $zip = [System.IO.Compression.ZipFile]::Open($tampered, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            $entry = $null
            foreach ($candidate in $zip.Entries) { if ($candidate.FullName -like 'demo/assets/*') { $entry = $candidate; break } }
            if ($entry) {
                $reader = New-Object System.IO.StreamReader($entry.Open())
                $text = $reader.ReadToEnd()
                $reader.Dispose()
                $tamperedText = if ($text.Length -gt 0) { 'X' + $text.Substring(1) } else { 'X' }
                $entry.Delete()
                $newEntry = $zip.CreateEntry($entry.FullName)
                $writer = New-Object System.IO.StreamWriter($newEntry.Open())
                $writer.Write($tamperedText)
                $writer.Dispose()
                $tamperLogText += "`ntampered entry: " + $entry.FullName
            } else { $tamperStatus = 'SKIP'; $tamperReason = 'no bundled demo resource found to tamper' }
        } finally { $zip.Dispose() }
        if ($tamperStatus -eq 'PASS') {
            $tamperRun = Invoke-Tool $Java @('-jar', $tampered) ($TimeoutSeconds * 1000)
            $tamperLogText += "`ntampered run: " + $tamperRun.StdOut + $tamperRun.StdErr
            if ($tamperRun.Code -eq 0) { $tamperStatus = 'FAIL'; $tamperReason = 'tampered jar still ran (exit 0)' }
            else { $tamperReason = 'tampered jar rejected (exit ' + $tamperRun.Code + ')' }
        }
    }
    Write-Utf8 $tamperLog $tamperLogText
    Add-Compat3Result $cliResults '3.0-tamper-integrity' $tamperStatus $tamperReason ($tamperArgs -join ' ') $tamperLog

    # --set overrides --preset (3.0 CLI contract).
    $overrideLog = Join-Path $compat3LogDir '3.0-set-overrides-preset.log'
    $overrideOut = Join-Path $OutDir '3.0-set-overrides-preset.jar'
    $overrideReport = Join-Path $ReportDir '3.0-set-overrides-preset.report.json'
    $overrideArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', $overrideOut, '--preset', 'maximum',
        '--set', 'typeConfusion.enabled=false', '--seed', $Seed, '--verify', '--report-json', $overrideReport)
    $overrideRun = Invoke-Tool $Java $overrideArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $overrideLog ($overrideRun.StdOut + "`n" + $overrideRun.StdErr)
    $overrideStatus = 'PASS'
    $overrideReason = ''
    if ($overrideRun.Code -ne 0 -or -not (Test-Path $overrideReport) -or -not (Test-Path $overrideOut)) {
        $overrideStatus = 'FAIL'; $overrideReason = 'protect run failed/no report'
    } else {
        $overrideStats = Get-ReportStats $overrideReport
        $tcValue = Get-ReportStatValue $overrideStats 'typeConfusion.methods'
        if ($null -ne $tcValue -and [double]$tcValue -gt 0) {
            $overrideStatus = 'FAIL'; $overrideReason = "typeConfusion.methods=$tcValue despite --set typeConfusion.enabled=false (preset not overridden)"
        } else {
            $overrideReason = 'typeConfusion.methods=' + $(if ($null -eq $tcValue) { 'absent' } else { $tcValue }) + ' with preset maximum (CLI override applied)'
        }
    }
    Add-Compat3Result $cliResults '3.0-set-overrides-preset' $overrideStatus $overrideReason ($overrideArgs -join ' ') $overrideLog

    # --- Umbra 3.1 bug-regression probes (Audit-3.1 fixes observable from CLI) ---
    Write-Host ''
    Write-Host '==> Umbra 3.1 CLI/config bug regressions' -ForegroundColor Cyan
    function Get-Sha256Of { param([string]$Path) if (Test-Path -LiteralPath $Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() } return '' }
    function Add-RegressionResult {
        param([string]$Id, [bool]$Ok, [string]$Reason, [string]$Command, [string]$Log)
        Add-Compat3Result $cliResults $Id $(if ($Ok) { 'PASS' } else { 'FAIL' }) $Reason $Command $Log
    }
    $regDir = Join-Path $OutDir 'regressions-3.1'
    New-Item -ItemType Directory -Force -Path $regDir | Out-Null

    # A6/--allow-in-place: output == input must be rejected unless the flag is given (input untouched).
    $inPlaceJar = Join-Path $regDir 'inplace.jar'
    Copy-Item -LiteralPath $DemoJar -Destination $inPlaceJar -Force
    $inPlaceShaBefore = Get-Sha256Of $inPlaceJar
    $regLog = Join-Path $compat3LogDir '3.1-allow-in-place-reject.log'
    $regArgs = @('-jar', $UmbraJar, '-i', $inPlaceJar, '-o', $inPlaceJar, '--preset', 'light', '--seed', $Seed)
    $regRun = Invoke-Tool $Java $regArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $regLog ($regRun.StdOut + "`n" + $regRun.StdErr)
    $samePathRejected = ($regRun.Code -ne 0) -and ((Get-Sha256Of $inPlaceJar) -eq $inPlaceShaBefore)
    Add-RegressionResult '3.1-allow-in-place-reject' $samePathRejected ("exit={0}, input unchanged={1}" -f $regRun.Code, ((Get-Sha256Of $inPlaceJar) -eq $inPlaceShaBefore)) ($regArgs -join ' ') $regLog

    $regLog = Join-Path $compat3LogDir '3.1-allow-in-place-accept.log'
    $regArgs = @('-jar', $UmbraJar, '-i', $inPlaceJar, '-o', $inPlaceJar, '--preset', 'light', '--seed', $Seed, '--allow-in-place', '--verify')
    $regRun = Invoke-Tool $Java $regArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $regLog ($regRun.StdOut + "`n" + $regRun.StdErr)
    $inPlaceShaAfter = Get-Sha256Of $inPlaceJar
    $inPlaceAccepted = ($regRun.Code -eq 0) -and ($inPlaceShaAfter -ne $inPlaceShaBefore) -and ($regRun.StdOut + $regRun.StdErr -match 'Verification: OK')
    Add-RegressionResult '3.1-allow-in-place-accept' $inPlaceAccepted ("exit={0}, rewritten={1}" -f $regRun.Code, ($inPlaceShaAfter -ne $inPlaceShaBefore)) ($regArgs -join ' ') $regLog

    # A6: license gate exit code 3 (missing license / missing feature).
    $regLog = Join-Path $compat3LogDir '3.1-license-exit3.log'
    $regArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', (Join-Path $regDir 'lic1.jar'), '--preset', 'light', '--seed', $Seed, '--require-license')
    $regRun = Invoke-Tool $Java $regArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $regLog ($regRun.StdOut + "`n" + $regRun.StdErr)
    Add-RegressionResult '3.1-require-license-exit3' ($regRun.Code -eq 3) ("exit={0} (expected 3)" -f $regRun.Code) ($regArgs -join ' ') $regLog

    $regLog = Join-Path $compat3LogDir '3.1-require-feature-exit3.log'
    $regArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', (Join-Path $regDir 'lic2.jar'), '--preset', 'light', '--seed', $Seed, '--require-feature', 'audit')
    $regRun = Invoke-Tool $Java $regArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $regLog ($regRun.StdOut + "`n" + $regRun.StdErr)
    Add-RegressionResult '3.1-require-feature-exit3' ($regRun.Code -eq 3) ("exit={0} (expected 3)" -f $regRun.Code) ($regArgs -join ' ') $regLog

    # A: malformed JAR must be a clean configuration error, not a stack trace.
    $badJar = Join-Path $Root 'qa\audit-fixtures\bad.jar'
    if (Test-Path $badJar) {
        $regLog = Join-Path $compat3LogDir '3.1-malformed-jar.log'
        $regArgs = @('-jar', $UmbraJar, '-i', $badJar, '-o', (Join-Path $regDir 'bad-out.jar'), '--preset', 'light', '--seed', $Seed)
        $regRun = Invoke-Tool $Java $regArgs ($TimeoutSeconds * 1000)
        $badOutput = $regRun.StdOut + "`n" + $regRun.StdErr
        Write-Utf8 $regLog $badOutput
        $cleanError = ($regRun.Code -ne 0) -and ($badOutput -notmatch 'Exception in thread') -and ($badOutput -match '(?i)invalid|corrupt|not a|error|unreadable|zip')
        Add-RegressionResult '3.1-malformed-jar-clean-error' $cleanError ("exit={0}, cleanError={1}" -f $regRun.Code, $cleanError) ($regArgs -join ' ') $regLog
    } else {
        Add-RegressionResult '3.1-malformed-jar-clean-error' $false 'fixture missing: qa\audit-fixtures\bad.jar' '' ''
    }

    # A9: --dry-run works without -o and writes nothing.
    $dryOnlyJar = Join-Path $regDir 'dry-only.jar'
    if (Test-Path $dryOnlyJar) { Remove-Item $dryOnlyJar -Force }
    $regLog = Join-Path $compat3LogDir '3.1-dry-run-no-output.log'
    $regArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '--preset', 'light', '--seed', $Seed, '--dry-run')
    $regRun = Invoke-Tool $Java $regArgs ($TimeoutSeconds * 1000)
    Write-Utf8 $regLog ($regRun.StdOut + "`n" + $regRun.StdErr)
    $dryOnlyOk = ($regRun.Code -eq 0) -and -not ($regRun.StdOut + $regRun.StdErr -match 'Exception')
    Add-RegressionResult '3.1-dry-run-without-output' $dryOnlyOk ("exit={0}" -f $regRun.Code) ($regArgs -join ' ') $regLog

    # A: out-of-range numeric limit rejected cleanly.
    $regLog = Join-Path $compat3LogDir '3.1-invalid-number.log'
    $regArgs = @('-jar', $UmbraJar, '-i', $DemoJar, '-o', (Join-Path $regDir 'num-out.jar'), '--virtualize-max-instructions', '-5', '--seed', $Seed)
    $regRun = Invoke-Tool $Java $regArgs ($TimeoutSeconds * 1000)
    $numOutput = $regRun.StdOut + "`n" + $regRun.StdErr
    Write-Utf8 $regLog $numOutput
    $numRejected = ($regRun.Code -ne 0) -and ($numOutput -notmatch 'Exception in thread') -and ($numOutput -match '(?i)must|invalid|range|positive|number')
    Add-RegressionResult '3.1-invalid-number-rejected' $numRejected ("exit={0}" -f $regRun.Code) ($regArgs -join ' ') $regLog

    # A7/A8: GUI headless exits 1; unknown GUI argument exits 2 (no silent success).
    $regLog = Join-Path $compat3LogDir '3.1-gui-headless-exit.log'
    $regArgs = @('-Djava.awt.headless=true', '-cp', $UmbraJar, 'io.umbra.gui.GuiMain')
    $regRun = Invoke-Tool $Java $regArgs 60000
    $guiHeadlessText = $regRun.StdOut + "`n" + $regRun.StdErr
    Write-Utf8 $regLog $guiHeadlessText
    if ($guiHeadlessText -match 'ClassNotFoundException|Could not find or load main class') {
        Add-RegressionResult '3.1-gui-headless-exit1' $false 'GUI entry class missing' ($regArgs -join ' ') $regLog
    } else {
        Add-RegressionResult '3.1-gui-headless-exit1' ($regRun.Code -eq 1) ("exit={0} (expected 1)" -f $regRun.Code) ($regArgs -join ' ') $regLog
    }

    $regLog = Join-Path $compat3LogDir '3.1-gui-unknown-arg.log'
    $regArgs = @('-Djava.awt.headless=true', '-cp', $UmbraJar, 'io.umbra.gui.GuiMain', '--qa-unknown-argument')
    $regRun = Invoke-Tool $Java $regArgs 60000
    Write-Utf8 $regLog ($regRun.StdOut + "`n" + $regRun.StdErr)
    Add-RegressionResult '3.1-gui-unknown-arg-exit2' ($regRun.Code -eq 2) ("exit={0} (expected 2)" -f $regRun.Code) ($regArgs -join ' ') $regLog

    # GUI smoke: headless screenshot via the GUI entry class.
    if (-not $SkipGuiSmoke) {
        Write-Host ''
        Write-Host '==> Umbra 3.0 GUI headless screenshot smoke' -ForegroundColor Cyan
        $guiLog = Join-Path $compat3LogDir '3.0-gui-screenshot.log'
        $guiPng = Join-Path $OutDir '3.0-gui-screenshot.png'
        $guiArgs = @('-Djava.awt.headless=true', '-cp', $UmbraJar, 'io.umbra.gui.GuiMain', '--screenshot', $guiPng)
        $guiRun = Invoke-Tool $Java $guiArgs ($TimeoutSeconds * 1000)
        Write-Utf8 $guiLog ($guiRun.StdOut + "`n" + $guiRun.StdErr)
        $guiStatus = 'PASS'
        $guiReason = ''
        if ($guiRun.Code -ne 0 -or -not (Test-Path $guiPng)) {
            $guiStatus = 'FAIL'
            $guiReason = 'GUI --screenshot did not produce a PNG (exit ' + $guiRun.Code + ')'
            if (($guiRun.StdOut + $guiRun.StdErr) -match 'ClassNotFoundException|Could not find or load main class') {
                $guiStatus = 'SKIP'; $guiReason = 'GUI entry class io.umbra.gui.GuiMain not present in this build'
            }
        } elseif ((Get-Item $guiPng).Length -lt 1000) { $guiStatus = 'FAIL'; $guiReason = 'screenshot PNG is empty/too small' }
        else { $guiReason = 'screenshot written (' + (Get-Item $guiPng).Length + ' bytes)' }
        Add-Compat3Result $cliResults '3.0-gui-screenshot' $guiStatus $guiReason ($guiArgs -join ' ') $guiLog
    }
}

# --- summary -----------------------------------------------------------------
$failures = @($caseResults | Where-Object { $_.status -eq 'FAIL' })
$presetFailures = @($presetResults | Where-Object { $_.status -eq 'FAIL' })
$compat3Failures = @($compat3Results | Where-Object { $_.status -eq 'FAIL' })
$cliFailures = @($cliResults | Where-Object { $_.status -eq 'FAIL' })
$compat3Skips = @($compat3Results | Where-Object { $_.status -eq 'SKIP' })
$cliSkips = @($cliResults | Where-Object { $_.status -eq 'SKIP' })
$allFailures = @($failures + $presetFailures + $compat3Failures + $cliFailures)
$partials = @($caseResults | Where-Object { $_.status -eq 'PARTIAL' })
$skips = @($caseResults | Where-Object { $_.status -eq 'SKIP' })
$strict = -not $SkipUnimplemented
# An optional case (native) that is not available is an acceptable SKIP even in
# strict mode: the feature is reported, not silently ignored. Missing 3.0
# evidence (corpus artifacts / GUI smoke) is NOT acceptable in strict mode.
$strictIncomplete = @($caseResults | Where-Object {
        (-not $_.optional) -and ($_.status -eq 'PARTIAL' -or $_.status -eq 'SKIP') })
$strictIncomplete3 = @($compat3Skips + $cliSkips | ForEach-Object { $_.id })

$summary = [ordered]@{
    generated = (Get-Date).ToString('s')
    mode = [ordered]@{
        skipUnimplemented = [bool]$SkipUnimplemented
        strict = $strict
        seed = $Seed
        timeoutSeconds = $TimeoutSeconds
        secondaryJdk = [bool]$SecondaryJava
        skipPresets = [bool]$SkipPresets
    }
    environment = $environment
    probes = @($probes.Values)
    cases = $caseResults
    presets = $presetResults
    compat3 = @($compat3Results)
    cli3 = @($cliResults)
    decompile = $decompile
    overall = [ordered]@{
        status = 'PASS'
        failures = @($caseResults | Where-Object { $_.status -eq 'FAIL' } | ForEach-Object { $_.case })
        presetFailures = @($presetResults | Where-Object { $_.status -eq 'FAIL' } | ForEach-Object { $_.preset })
        compat3Failures = @($compat3Failures | ForEach-Object { $_.id })
        cliFailures = @($cliFailures | ForEach-Object { $_.id })
        partials = @($partials | ForEach-Object { $_.case })
        skips = @($skips | ForEach-Object { $_.case })
        compat3Skips = @($compat3Skips | ForEach-Object { $_.id })
        cliSkips = @($cliSkips | ForEach-Object { $_.id })
        strictIncomplete = @($strictIncomplete | ForEach-Object { $_.case })
        strictIncomplete3 = @($strictIncomplete3)
    }
}
$overallStatus = 'PASS'
if ($allFailures.Count -gt 0) { $overallStatus = 'FAIL' }
elseif ($strict -and ($strictIncomplete.Count -gt 0 -or $strictIncomplete3.Count -gt 0)) { $overallStatus = 'FAIL' }
$summary.overall.status = $overallStatus
$summaryPath = Join-Path $ResultsDir 'summary.json'
Write-Utf8 $summaryPath ($summary | ConvertTo-Json -Depth 12)

$md = New-Object System.Text.StringBuilder
$null = $md.AppendLine('# Umbra verification matrix')
$null = $md.AppendLine('')
$null = $md.AppendLine(("- generated: {0}" -f $summary.generated))
$null = $md.AppendLine(("- mode: {0} (seed {1})" -f $(if ($strict) { 'STRICT final' } else { 'development (-SkipUnimplemented)' }), $Seed))
$null = $md.AppendLine(("- overall: **{0}**" -f $overallStatus))
$null = $md.AppendLine('')
$null = $md.AppendLine('## Environment')
$null = $md.AppendLine('')
$null = $md.AppendLine('| item | value |')
$null = $md.AppendLine('|---|---|')
$null = $md.AppendLine(('| Umbra jar | `{0}` |' -f $environment.umbraJar))
$null = $md.AppendLine(('| Umbra sha256 | `{0}` |' -f $environment.umbraSha256))
$null = $md.AppendLine(('| Umbra version | {0} |' -f $environment.umbraVersion))
$null = $md.AppendLine(('| demo jar | `{0}` ({1} bytes) |' -f $environment.demoJar, $environment.demoBytes))
$null = $md.AppendLine(('| demo sha256 | `{0}` |' -f $environment.demoSha256))
$null = $md.AppendLine(('| JDK (run) | {0} |' -f $environment.javaVersion))
if ($environment.secondaryJava) { $null = $md.AppendLine(('| JDK (cross-check 21) | {0} (`{1}`) |' -f $environment.secondaryJavaVersion, $environment.secondaryJava)) }
if ($environment.tertiaryJava) { $null = $md.AppendLine(('| JDK (cross-check 26) | {0} (`{1}`) |' -f $environment.tertiaryJavaVersion, $environment.tertiaryJava)) }
$null = $md.AppendLine(('| C compiler | {0} |' -f $environment.gccVersion))
$null = $md.AppendLine(('| OS | {0} |' -f $environment.os))
$null = $md.AppendLine('')
$null = $md.AppendLine('## Feature probes')
$null = $md.AppendLine('')
$null = $md.AppendLine('| feature | status | note |')
$null = $md.AppendLine('|---|---|---|')
foreach ($probe in $probes.Values) {
    $note = $probe.reason
    if ($note.Length -gt 140) { $note = $note.Substring(0, 140) + '...' }
    $null = $md.AppendLine(('| {0} | {1} | {2} |' -f $probe.name, $probe.status, $note))
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## Result matrix')
$null = $md.AppendLine('')
$null = $md.AppendLine('| case | status | verify | run JDK 8 | run JDK 21 | run JDK 26 | out bytes | ratio | classes | strings enc | virtualized | flattened | native | markers left (str/cls/meth/fld) |')
$null = $md.AppendLine('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
foreach ($result in $caseResults) {
    $run8 = if ($result.runJdk8.ok) { 'OK' } elseif ($result.runJdk8.exitCode -ge 0) { "exit $($result.runJdk8.exitCode)" } else { '-' }
    $run21 = if ($result.runJdk21.ok) { 'OK' } elseif ($result.runJdk21.exitCode -ge 0) { "exit $($result.runJdk21.exitCode)" } else { '-' }
    $run26 = if ($result.runJdk26.ok) { 'OK' } elseif ($result.runJdk26.exitCode -ge 0) { "exit $($result.runJdk26.exitCode)" } else { '-' }
    $h = $result.statsHighlights
    $null = $md.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} | {11} | {12} | {13}/{14}/{15}/{16} |' -f
        $result.case, $result.status, $(if ($result.verifyOk) { 'OK' } else { 'no' }), $run8, $run21, $run26,
        $result.outputBytes, $result.sizeRatio,
        (Get-BagValue $h 'classes' '-'), (Get-BagValue $h 'stringsEncrypted' '-'),
        (Get-BagValue $h 'virtualizedMethods' '-'), (Get-BagValue $h 'flattenedMethods' '-'),
        (Get-BagValue $h 'nativeMethods' '-'),
        $result.strings.markerStrings, $result.strings.markerClasses,
        $result.strings.markerMethods, $result.strings.markerFields))
}
$warningCases = @($caseResults | Where-Object { @($_.warnings).Count -gt 0 })
if ($warningCases.Count -gt 0) {
    $null = $md.AppendLine('')
    $null = $md.AppendLine('## Warnings')
    $null = $md.AppendLine('')
    foreach ($warningCase in $warningCases) {
        foreach ($warningText in @($warningCase.warnings)) {
            $null = $md.AppendLine(('- **{0}**: {1}' -f $warningCase.case, $warningText))
        }
    }
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## Deobfuscation evidence')
$null = $md.AppendLine('')
$null = $md.AppendLine(("- status: **{0}**" -f $decompile.status))
if ($decompile.target) { $null = $md.AppendLine(('- target jar: `{0}`' -f $decompile.target)) }
if ($decompile.reason) { $null = $md.AppendLine(("- note: {0}" -f $decompile.reason)) }
if ($decompile.json -and (Test-Path $decompile.json)) {
    try {
        $deobf = Get-Content $decompile.json -Raw -Encoding UTF8 | ConvertFrom-Json
        $null = $md.AppendLine(("- CFR: {0} ({1} files, {2} failed method bodies)" -f $deobf.cfr.status, $deobf.cfr.decompiledFiles, $deobf.cfr.failedFiles))
        $null = $md.AppendLine(("- classes calling the injected VM runtime: {0}" -f $deobf.javap.virtualizedClasses))
        if ($deobf.strings) {
            $scan = Get-Content $deobf.strings -Raw -Encoding UTF8 | ConvertFrom-Json
            $null = $md.AppendLine(("- clear-text human strings: {0}; class references: {1}" -f $scan.counts.humanText, $scan.counts.classRefs))
            $null = $md.AppendLine(("- demo markers still readable: strings {0}, classes {1}, methods {2}, fields {3}" -f
                @($scan.markerHits.strings).Count,
                @($scan.markerHits.classes).Count,
                @($scan.markerHits.methods).Count,
                @($scan.markerHits.fields).Count))
        }
    } catch { }
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## Preset compatibility')
$null = $md.AppendLine('')
if ($SkipPresets) {
    $null = $md.AppendLine('_skipped (-SkipPresets)_')
} elseif ($presetResults.Count -eq 0) {
    $null = $md.AppendLine('_no presets checked_')
} else {
    $null = $md.AppendLine('| preset | status | verify | run | out bytes | note |')
    $null = $md.AppendLine('|---|---|---|---|---|---|')
    foreach ($preset in $presetResults) {
        $null = $md.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f
            $preset.preset, $preset.status, $(if ($preset.verifyOk) { 'OK' } else { 'no' }),
            $(if ($preset.runOk) { 'OK' } else { 'exit ' + $preset.runExitCode }),
            $preset.outputBytes, $preset.reason))
    }
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## 3.0 layout modes (real corpus artifacts, --preset balanced)')
$null = $md.AppendLine('')
if ($SkipCompat3) {
    $null = $md.AppendLine('_skipped (-SkipCompat3)_')
} elseif ($compat3Results.Count -eq 0) {
    $null = $md.AppendLine('_no layout cases checked_')
} else {
    $null = $md.AppendLine('| case | status | reason | log |')
    $null = $md.AppendLine('|---|---|---|---|')
    foreach ($layoutResult in $compat3Results) {
        $null = $md.AppendLine(('| {0} | {1} | {2} | `{3}` |' -f $layoutResult.id, $layoutResult.status, ($layoutResult.reason -replace '\|', '/'), $layoutResult.log))
    }
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## 3.0 CLI + GUI compatibility tools')
$null = $md.AppendLine('')
if ($SkipCompat3) {
    $null = $md.AppendLine('_skipped (-SkipCompat3)_')
} elseif ($cliResults.Count -eq 0) {
    $null = $md.AppendLine('_no CLI cases checked_')
} else {
    $null = $md.AppendLine('| case | status | reason | log |')
    $null = $md.AppendLine('|---|---|---|---|')
    foreach ($cliResult in $cliResults) {
        $null = $md.AppendLine(('| {0} | {1} | {2} | `{3}` |' -f $cliResult.id, $cliResult.status, ($cliResult.reason -replace '\|', '/'), $cliResult.log))
    }
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## Failures')
$null = $md.AppendLine('')
if ($allFailures.Count -eq 0) {
    $null = $md.AppendLine('_none_')
} else {
    foreach ($failure in $failures) {
        $null = $md.AppendLine(('### {0}: {1}' -f $failure.case, $failure.reason))
        $null = $md.AppendLine('')
        $null = $md.AppendLine('```')
        $null = $md.AppendLine((Get-LogTail $failure.logTail 25))
        $null = $md.AppendLine('```')
        $null = $md.AppendLine('')
    }
    foreach ($preset in $presetFailures) {
        $null = $md.AppendLine(('### preset {0}: {1}' -f $preset.preset, $preset.reason))
        $null = $md.AppendLine('')
        $null = $md.AppendLine('```bat')
        $null = $md.AppendLine($preset.command)
        $null = $md.AppendLine('```')
        $null = $md.AppendLine('')
    }
    foreach ($layoutFailure in $compat3Failures) {
        $null = $md.AppendLine(('### {0}: {1}' -f $layoutFailure.id, $layoutFailure.reason))
        $null = $md.AppendLine('')
        $null = $md.AppendLine('```bat')
        $null = $md.AppendLine($layoutFailure.command)
        $null = $md.AppendLine('```')
        $null = $md.AppendLine('')
    }
    foreach ($cliFailure in $cliFailures) {
        $null = $md.AppendLine(('### {0}: {1}' -f $cliFailure.id, $cliFailure.reason))
        $null = $md.AppendLine('')
        $null = $md.AppendLine('```bat')
        $null = $md.AppendLine($cliFailure.command)
        $null = $md.AppendLine('```')
        $null = $md.AppendLine('')
    }
}
$null = $md.AppendLine('## Commands')
$null = $md.AppendLine('')
foreach ($result in $caseResults) {
    $null = $md.AppendLine(('```bat'))
    $null = $md.AppendLine($result.command)
    $null = $md.AppendLine(('```'))
}
$null = $md.AppendLine('')
$null = $md.AppendLine('## Files')
$null = $md.AppendLine('')
$null = $md.AppendLine(('- summary.json: `{0}`' -f $summaryPath))
$null = $md.AppendLine(('- logs: `{0}`' -f $LogDir))
$null = $md.AppendLine(('- audit reports: `{0}`' -f $ReportDir))
$null = $md.AppendLine(('- string scans: `{0}`' -f $AnalysisDir))
$null = $md.AppendLine(('- protected jars: `{0}`' -f $OutDir))
$mdPath = Join-Path $ResultsDir 'summary.md'
Write-Utf8 $mdPath $md.ToString()

$repro = New-Object System.Text.StringBuilder
$null = $repro.AppendLine('# Exact reproduction commands')
$null = $repro.AppendLine('')
$null = $repro.AppendLine('Build the tool and the demo:')
$null = $repro.AppendLine('')
$null = $repro.AppendLine('```bat')
$null = $repro.AppendLine('cmd /c build.cmd -Task dist')
$null = $repro.AppendLine('cmd /c qa\build-demo.cmd -Clean')
$null = $repro.AppendLine('```')
$null = $repro.AppendLine('')
$null = $repro.AppendLine('Run the matrix:')
$null = $repro.AppendLine('')
$null = $repro.AppendLine('```bat')
$null = $repro.AppendLine('cmd /c qa\verify.cmd -UmbraJar dist\umbra.jar')
$null = $repro.AppendLine('```')
$null = $repro.AppendLine('')
foreach ($result in $caseResults) {
    $null = $repro.AppendLine(('### ' + $result.case))
    $null = $repro.AppendLine('')
    $null = $repro.AppendLine('```bat')
    $null = $repro.AppendLine($result.command)
    $null = $repro.AppendLine(('java -jar ' + $result.outputJar))
    $null = $repro.AppendLine('```')
    $null = $repro.AppendLine('')
}
foreach ($preset in $presetResults) {
    $null = $repro.AppendLine(('### preset ' + $preset.preset))
    $null = $repro.AppendLine('')
    $null = $repro.AppendLine('```bat')
    $null = $repro.AppendLine($preset.command)
    $null = $repro.AppendLine(('java -jar ' + $preset.outputJar))
    $null = $repro.AppendLine('```')
    $null = $repro.AppendLine('')
}
Write-Utf8 (Join-Path $ResultsDir 'repro.txt') $repro.ToString()

Write-Host ''
Write-Host "==> summary: $mdPath"
Write-Host "    overall: $overallStatus"
if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Write-Host ("    FAIL {0}: {1}" -f $failure.case, $failure.reason) -ForegroundColor Red
        Write-Host ((Get-LogTail $failure.logTail 12)) -ForegroundColor DarkGray
    }
}
foreach ($preset in $presetFailures) {
    Write-Host ("    FAIL preset {0}: {1}" -f $preset.preset, $preset.reason) -ForegroundColor Red
}
foreach ($layoutFailure in $compat3Failures) {
    Write-Host ("    FAIL {0}: {1}" -f $layoutFailure.id, $layoutFailure.reason) -ForegroundColor Red
}
foreach ($cliFailure in $cliFailures) {
    Write-Host ("    FAIL {0}: {1}" -f $cliFailure.id, $cliFailure.reason) -ForegroundColor Red
}
if ($strictIncomplete.Count -gt 0) {
    Write-Host ("    incomplete cases: " + (($strictIncomplete | ForEach-Object { $_.case }) -join ', ')) -ForegroundColor DarkYellow
}
if ($strictIncomplete3.Count -gt 0) {
    Write-Host ("    incomplete 3.0 evidence: " + ($strictIncomplete3 -join ', ')) -ForegroundColor DarkYellow
}
if ($overallStatus -eq 'PASS') {
    Write-Host '    matrix PASS' -ForegroundColor Green
    exit 0
}
Write-Host '    matrix FAIL' -ForegroundColor Red
exit 1


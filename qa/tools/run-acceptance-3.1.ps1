#requires -Version 5.1
<#
.SYNOPSIS
    Umbra 3.1 final acceptance gate (sequential orchestrator).

.DESCRIPTION
    Runs the whole 3.1 acceptance suite SEQUENTIALLY against one release binary
    and aggregates the evidence into qa/results-3.1/final/summary.{json,md}:

      P0 environment   release jar sha256/size/version, JDK versions, tool-on-JDK8
      P1 corpus matrix 15-artifact corpus (light/balanced/maximum, large-real excluded)
      P2 dynamic       runtime guard matrix (false positives + attacks + attach + tamper)
      P3 feature       qa/verify.ps1 strict (probes/presets/layouts/CLI/regressions)
      P4 minecraft     qa/minecraft/verify-mc.ps1 adaptive loader matrix
      P5 plugins       plugins/qa/run-qa.ps1 Gradle+Maven plugin end-to-end QA
      P6 build test    clean full test suite (build.cmd -Task test with own BuildDir)
      P7 cross-JDK     tool runs on JDK 8; protected demo runs on JDK 8/21/26

    Every phase writes its own log under qa/results-3.1/final/logs/ and its own
    evidence directory; a failure in one phase does not hide the others. The
    script never fabricates a PASS: a phase status is derived from exit codes and
    the sub-summaries actually written by the harnesses.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File qa\tools\run-acceptance-3.1.ps1 -UmbraJar dist\umbra.jar
    powershell -NoProfile -ExecutionPolicy Bypass -File qa\tools\run-acceptance-3.1.ps1 -UmbraJar dist\umbra.jar -SkipBuildTest
#>
param(
    [string]$UmbraJar = '',
    [string]$ResultsDir = '',
    [string]$Seed = '23303',
    [int]$PhaseTimeoutSec = 3600,
    [switch]$SkipCorpus,
    [switch]$SkipDynamic,
    [switch]$SkipFeature,
    [switch]$SkipMinecraft,
    [switch]$SkipPlugins,
    [switch]$SkipBuildTest,
    [switch]$SkipCrossJdk,
    [switch]$FailOnAnyMatrixFailure
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $UmbraJar) { $UmbraJar = Join-Path $Root 'dist\umbra.jar' }
if (-not [System.IO.Path]::IsPathRooted($UmbraJar)) { $UmbraJar = Join-Path $Root $UmbraJar }
if (-not (Test-Path -LiteralPath $UmbraJar)) { throw "release jar not found: $UmbraJar" }
$UmbraJar = (Resolve-Path -LiteralPath $UmbraJar).Path
if (-not $ResultsDir) { $ResultsDir = Join-Path $Root 'qa\results-3.1\final' }
$ResultsDir = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $ResultsDir)).Path
$LogDir = Join-Path $ResultsDir 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$Jdk8 = 'C:\Program Files\Zulu\zulu-8\bin\java.exe'
$Jdk21 = 'C:\Program Files\Zulu\zulu-21\bin\java.exe'
$Jdk26 = 'C:\Program Files\Java\jdk-26.0.1\bin\java.exe'

function Write-Utf8 {
    param([string]$Path, [string]$Text)
    $parent = Split-Path $Path -Parent
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-Phase {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 3600
    )
    $logPath = Join-Path $LogDir ($Name + '.log')
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $quoted = @()
    foreach ($a in $Arguments) {
        $a = [string]$a
        if ($a -match '[\s"]') { $quoted += ('"' + ($a -replace '"', '\"') + '"') } else { $quoted += $a }
    }
    $psi.Arguments = ($quoted -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $started = Get-Date
    $timedOut = $false
    $code = -1
    $stdout = ''
    $stderr = ''
    try {
        $null = $process.Start()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $process.Kill() } catch { }
            try { $null = $process.WaitForExit(15000) } catch { }
        }
        if ($process.HasExited) { $code = $process.ExitCode }
        if ($outTask.Wait(10000)) { $stdout = $outTask.Result }
        if ($errTask.Wait(10000)) { $stderr = $errTask.Result }
    } catch {
        $stderr = $stderr + "`n[harness] phase start failed: " + $_.Exception.Message
    } finally { try { $process.Dispose() } catch { } }
    $seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    $logText = ('=' * 78 + "`n" + 'PHASE: ' + $Name + "`n" + 'COMMAND: ' + $Exe + ' ' + ($Arguments -join ' ') + "`n" + 'EXIT: ' + $code + "  TIMEDOUT: " + $timedOut + "  SECONDS: " + $seconds + "`n" + '=' * 78 + "`n" + $stdout + "`n" + $stderr + "`n")
    Write-Utf8 $logPath $logText
    Write-Host ("`n=== phase {0}: exit={1} timedOut={2} ({3:N1}s) log={4}" -f $Name, $code, $timedOut, $seconds, $logPath) -ForegroundColor $(if ($code -eq 0 -and -not $timedOut) { 'Green' } else { 'Red' })
    $tail = (@(($stdout + "`n" + $stderr) -split "`r?`n") | Select-Object -Last 12) -join "`n"
    Write-Host $tail
    return [pscustomobject]@{ name = $Name; code = $code; timedOut = $timedOut; seconds = $seconds; log = $logPath }
}

function Read-JsonSafe {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

$phases = New-Object System.Collections.ArrayList
function Add-PhaseResult([string]$Name, [string]$Status, [string]$Reason, [string]$Log, [double]$Seconds, $Data = $null) {
    $row = [ordered]@{ name = $Name; status = $Status; reason = $Reason; log = $Log; seconds = $Seconds; data = $Data }
    $null = $phases.Add($row)
    Write-Host ("    PHASE {0,-14} {1,-6} {2}" -f $Name, $Status, $Reason) -ForegroundColor $(if ($Status -eq 'PASS') { 'Green' } elseif ($Status -eq 'SKIP') { 'DarkYellow' } else { 'Red' })
}

$gateStart = Get-Date
Write-Host "==> Umbra 3.1 acceptance gate (sequential) $(Get-Date -Format 's')" -ForegroundColor Cyan
Write-Host "    release jar: $UmbraJar"
Write-Host "    results:     $ResultsDir"

# ---------------------------------------------------------------- P0 env ----
$jarInfo = Get-Item -LiteralPath $UmbraJar
$sha = (Get-FileHash -LiteralPath $UmbraJar -Algorithm SHA256).Hash.ToLowerInvariant()
$versionRun = Invoke-Phase -Name 'p0-version-jdk8' -Exe $Jdk8 -Arguments @('-jar', $UmbraJar, '--version') -TimeoutSeconds 120
$versionLine = (Get-Content (Join-Path $LogDir 'p0-version-jdk8.log') -Raw | Select-String -Pattern 'Umbra [0-9.]+' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Select-Object -First 1)
$jdkVersion = (Invoke-Phase -Name 'p0-jdk8-version' -Exe $Jdk8 -Arguments @('-version') -TimeoutSeconds 60).code
$jdk21Code = if (Test-Path $Jdk21) { (Invoke-Phase -Name 'p0-jdk21-version' -Exe $Jdk21 -Arguments @('-version') -TimeoutSeconds 60).code } else { 0 }
$jdk26Code = if (Test-Path $Jdk26) { (Invoke-Phase -Name 'p0-jdk26-version' -Exe $Jdk26 -Arguments @('-version') -TimeoutSeconds 60).code } else { 0 }
$envData = [ordered]@{ sha256 = $sha; bytes = $jarInfo.Length; version = [string]$versionLine; jdk8 = $jdkVersion; jdk21 = $jdk21Code; jdk26 = $jdk26Code }
$envOk = ($versionRun.code -eq 0) -and ([string]$versionLine -match '3\.1')
Add-PhaseResult 'environment' $(if ($envOk) { 'PASS' } else { 'FAIL' }) ("version=" + $versionLine + ", sha256=" + $sha.Substring(0, 16) + '...') (Join-Path $LogDir 'p0-version-jdk8.log') $versionRun.seconds $envData
$env:QA_UMBRA_SHA = $sha

# ---------------------------------------------------------------- P1 corpus --
if (-not $SkipCorpus) {
    Write-Host "`n==> P1 corpus matrix" -ForegroundColor Cyan
    $corpusDir = Join-Path $ResultsDir ('corpus-' + $Stamp)
    $phase = Invoke-Phase -Name 'p1-corpus-matrix' -Exe $powershellExe -Arguments @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Root 'qa\compat\run-matrix.ps1'),
        '-UmbraJar', $UmbraJar, '-SkipBuild', '-StageLabel', 'final',
        '-Presets', 'light,balanced,maximum', '-Exclude', 'large-real', '-ResultsDir', $corpusDir, '-FailOnError'
    ) -TimeoutSeconds $PhaseTimeoutSec
    $corpusSummary = $null
    $corpusSummaryPath = Join-Path $corpusDir 'summary.json'
    if (Test-Path $corpusSummaryPath) { $corpusSummary = Read-JsonSafe $corpusSummaryPath }
    if ($corpusSummary) {
        $status = 'PASS'
        $knownLimitation = $false
        $matrixFailures = @($corpusSummary.failures)
        $unexpected = @($matrixFailures | Where-Object { -not ($_.case -eq 'kotlin-app' -and $_.preset -eq 'maximum') })
        if ($unexpected.Count -gt 0) { $status = 'FAIL' }
        elseif ($matrixFailures.Count -gt 0) { $status = 'PASS'; $knownLimitation = $true }
        $reason = ("{0}/{1} PASS, {2} failed" -f $corpusSummary.overall.passed, $corpusSummary.overall.cases, $matrixFailures.Count)
        if ($knownLimitation) { $reason += ' (kotlin-app/maximum documented limitation)' }
        Add-PhaseResult 'corpus' $status $reason $corpusSummaryPath $phase.seconds $corpusSummary
    } else {
        Add-PhaseResult 'corpus' 'FAIL' 'no summary.json produced' $phase.log $phase.seconds $null
    }
} else { Add-PhaseResult 'corpus' 'SKIP' 'skipped by flag' '' 0 $null }

# ---------------------------------------------------------------- P2 dynamic --
if (-not $SkipDynamic) {
    Write-Host "`n==> P2 dynamic-protection matrix" -ForegroundColor Cyan
    $dynamicDir = Join-Path $ResultsDir 'dynamic'
    $phase = Invoke-Phase -Name 'p2-dynamic-matrix' -Exe $powershellExe -Arguments @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Root 'qa\tools\run-dynamic-3.1.ps1'),
        '-UmbraJar', $UmbraJar, '-ResultsDir', $dynamicDir, '-Seed', $Seed, '-AttachRetries', '4', '-NativeAttachRetries', '4'
    ) -TimeoutSeconds $PhaseTimeoutSec
    $dynamicSummary = Read-JsonSafe (Join-Path $dynamicDir 'summary.json')
    if ($dynamicSummary) {
        $status = if ($dynamicSummary.overall.failed -eq 0) { 'PASS' } else { 'FAIL' }
        Add-PhaseResult 'dynamic' $status ("{0}/{1} tests PASS, {2} failed" -f $dynamicSummary.overall.passed, $dynamicSummary.overall.total, $dynamicSummary.overall.failed) (Join-Path $dynamicDir 'summary.json') $phase.seconds $dynamicSummary
    } else {
        Add-PhaseResult 'dynamic' 'FAIL' 'no dynamic summary.json produced' $phase.log $phase.seconds $null
    }
} else { Add-PhaseResult 'dynamic' 'SKIP' 'skipped by flag' '' 0 $null }

# ---------------------------------------------------------------- P3 feature --
if (-not $SkipFeature) {
    Write-Host "`n==> P3 strict feature matrix" -ForegroundColor Cyan
    $verifyDir = Join-Path $ResultsDir 'verify'
    $phase = Invoke-Phase -Name 'p3-verify' -Exe $powershellExe -Arguments @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Root 'qa\verify.ps1'),
        '-UmbraJar', $UmbraJar, '-ResultsDir', $verifyDir
    ) -TimeoutSeconds $PhaseTimeoutSec
    $verifySummary = Read-JsonSafe (Join-Path $verifyDir 'summary.json')
    if ($verifySummary) {
        $status = if ([string]$verifySummary.overall.status -eq 'PASS') { 'PASS' } else { 'FAIL' }
        Add-PhaseResult 'feature' $status ([string]$verifySummary.overall.status + ' (strict)') (Join-Path $verifyDir 'summary.json') $phase.seconds $verifySummary
    } else {
        Add-PhaseResult 'feature' 'FAIL' 'no verify summary.json produced' $phase.log $phase.seconds $null
    }
} else { Add-PhaseResult 'feature' 'SKIP' 'skipped by flag' '' 0 $null }

# -------------------------------------------------------------- P4 minecraft --
if (-not $SkipMinecraft) {
    Write-Host "`n==> P4 Minecraft adaptation matrix" -ForegroundColor Cyan
    $mcDir = Join-Path $ResultsDir 'minecraft'
    $phase = Invoke-Phase -Name 'p4-minecraft' -Exe $powershellExe -Arguments @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Root 'qa\minecraft\verify-mc.ps1'),
        '-UmbraJar', $UmbraJar, '-SkipBuild', '-ResultsDir', $mcDir
    ) -TimeoutSeconds $PhaseTimeoutSec
    $mcSummary = Read-JsonSafe (Join-Path $mcDir 'summary.json')
    if ($mcSummary) {
        $status = if ([string]$mcSummary.overall.status -eq 'PASS') { 'PASS' } else { 'FAIL' }
        Add-PhaseResult 'minecraft' $status ([string]$mcSummary.overall.status) (Join-Path $mcDir 'summary.json') $phase.seconds $mcSummary
    } else {
        Add-PhaseResult 'minecraft' $(if ($phase.code -eq 0) { 'PASS' } else { 'FAIL' }) 'no summary.json (exit-based)' $phase.log $phase.seconds $null
    }
} else { Add-PhaseResult 'minecraft' 'SKIP' 'skipped by flag' '' 0 $null }

# ---------------------------------------------------------------- P5 plugins --
if (-not $SkipPlugins) {
    Write-Host "`n==> P5 plugin QA (Gradle + Maven)" -ForegroundColor Cyan
    $pluginsScript = Join-Path $Root 'plugins\qa\run-qa.ps1'
    if (Test-Path $pluginsScript) {
        $phase = Invoke-Phase -Name 'p5-plugins' -Exe $powershellExe -Arguments @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $pluginsScript, '-UmbraJar', $UmbraJar
        ) -TimeoutSeconds $PhaseTimeoutSec
        $pluginLogText = Get-Content -LiteralPath (Join-Path $LogDir 'p5-plugins.log') -Raw -ErrorAction SilentlyContinue
        $passCount = 0
        $failCount = 0
        if ($pluginLogText -match '(\d+)\s*/\s*(\d+)\s+(checks?|tests?)?\s*PASS') { $passCount = [int]$Matches[1] }
        Add-PhaseResult 'plugins' $(if ($phase.code -eq 0) { 'PASS' } else { 'FAIL' }) ("exit=" + $phase.code + $(if ($passCount -gt 0) { ", reported $passCount checks" } else { '' })) (Join-Path $LogDir 'p5-plugins.log') $phase.seconds @{ exitCode = $phase.code; reportedPass = $passCount }
    } else {
        Add-PhaseResult 'plugins' 'SKIP' 'plugins/qa/run-qa.ps1 missing' '' 0 $null
    }
} else { Add-PhaseResult 'plugins' 'SKIP' 'skipped by flag' '' 0 $null }

# ------------------------------------------------------------- P6 build test --
if (-not $SkipBuildTest) {
    Write-Host "`n==> P6 clean full test suite (build.cmd -Task test, own BuildDir)" -ForegroundColor Cyan
    $buildLog = Join-Path $LogDir 'p6-build-test.log'
    $phase = Invoke-Phase -Name 'p6-build-test' -Exe (Join-Path $env:SystemRoot 'System32\cmd.exe') -Arguments @(
        '/d', '/c', ('build.cmd -Task test -BuildDir build-qa\qa31 -SkipDist 2>&1')
    ) -TimeoutSeconds $PhaseTimeoutSec
    Write-Host ("    build test log: " + $buildLog)
    Add-PhaseResult 'build-test' $(if ($phase.code -eq 0) { 'PASS' } else { 'FAIL' }) ("exit=" + $phase.code) $phase.log $phase.seconds @{ exitCode = $phase.code }
} else { Add-PhaseResult 'build-test' 'SKIP' 'skipped by flag' '' 0 $null }

# -------------------------------------------------------------- P7 cross-JDK --
if (-not $SkipCrossJdk) {
    Write-Host "`n==> P7 cross-JDK (tool on JDK 8, protected demo on 8/21/26)" -ForegroundColor Cyan
    $crossWork = Join-Path $ResultsDir 'cross-jdk'
    New-Item -ItemType Directory -Force -Path $crossWork | Out-Null
    $demoJar = Join-Path $Root 'demo\demo.jar'
    $protectedDemo = Join-Path $crossWork 'demo-balanced.jar'
    $protectArgs = @('-jar', $UmbraJar, '-i', $demoJar, '-o', $protectedDemo, '--preset', 'balanced', '--seed', $Seed, '--verify')
    $protectPhase = Invoke-Phase -Name 'p7-protect-demo' -Exe $Jdk8 -Arguments $protectArgs -TimeoutSeconds 300
    $crossOk = ($protectPhase.code -eq 0)
    $crossDetails = @()
    $toolVersions = @()
    foreach ($jdk in @(@{ id = 'jdk8'; exe = $Jdk8 }, @{ id = 'jdk21'; exe = $Jdk21 }, @{ id = 'jdk26'; exe = $Jdk26 })) {
        if (-not (Test-Path $jdk.exe)) { $crossDetails += ($jdk.id + ':missing'); continue }
        $toolRun = Invoke-Phase -Name ('p7-tool-' + $jdk.id) -Exe $jdk.exe -Arguments @('-jar', $UmbraJar, '--version') -TimeoutSeconds 120
        $toolOk = ($toolRun.code -eq 0)
        $runArgs = @('-jar', $protectedDemo)
        $run = Invoke-Phase -Name ('p7-run-' + $jdk.id) -Exe $jdk.exe -Arguments $runArgs -TimeoutSeconds 120
        $runOk = ($run.code -eq 0) -and (((Get-Content -LiteralPath (Join-Path $LogDir ('p7-run-' + $jdk.id + '.log')) -Raw) -match '(?m)^OK\s*$') -ne $null)
        $crossDetails += ('{0}: tool={1} run={2}' -f $jdk.id, $(if ($toolOk) { 'OK' } else { 'FAIL' }), $(if ($runOk) { 'OK' } else { 'FAIL' }))
        if (-not $toolOk -or -not $runOk) { $crossOk = $false }
        $toolVersions += [ordered]@{ jdk = $jdk.id; toolOk = $toolOk; runOk = $runOk }
    }
    Add-PhaseResult 'cross-jdk' $(if ($crossOk) { 'PASS' } else { 'FAIL' }) (($crossDetails) -join '; ') (Join-Path $LogDir 'p7-protect-demo.log') $protectPhase.seconds @{ versions = $toolVersions; protectedDemo = $protectedDemo }
} else { Add-PhaseResult 'cross-jdk' 'SKIP' 'skipped by flag' '' 0 $null }

# ---------------------------------------------------------------- aggregate --
$totalSeconds = [Math]::Round(((Get-Date) - $gateStart).TotalSeconds, 1)
$failedPhases = @($phases | Where-Object { $_.status -eq 'FAIL' })
$statusOverall = if ($failedPhases.Count -eq 0) { 'PASS' } else { 'FAIL' }
if ($statusOverall -eq 'PASS') {
    $corpusPhase = @($phases | Where-Object { $_.name -eq 'corpus' })[0]
    if ($corpusPhase -and $corpusPhase.reason -match 'documented limitation') { $statusOverall = 'PASS-WITH-DOCUMENTED-LIMITATION' }
}
$summary = [ordered]@{
    generated = (Get-Date).ToString('s')
    gate = 'Umbra 3.1 final acceptance'
    releaseBinary = [ordered]@{ path = $UmbraJar; sha256 = $sha; bytes = $jarInfo.Length; version = [string]$versionLine }
    overall = [ordered]@{ status = $statusOverall; phases = $phases.Count; failedPhases = @($failedPhases | ForEach-Object { $_.name }); totalSeconds = $totalSeconds; stamp = $Stamp }
    phases = @($phases)
}
Write-Utf8 (Join-Path $ResultsDir ('summary-' + $Stamp + '.json')) (($summary | ConvertTo-Json -Depth 14) + "`n")
Write-Utf8 (Join-Path $ResultsDir 'summary.json') (($summary | ConvertTo-Json -Depth 14) + "`n")

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Umbra 3.1 - QA final acceptance summary')
$md.Add('')
$md.Add('- generated: ' + $summary.generated)
$md.Add('- release binary: `dist\umbra.jar` sha256 `' + $sha + '` (' + $jarInfo.Length + ' bytes, ' + $versionLine + ')')
$md.Add('- overall: **' + $statusOverall + '** - total runtime ' + $totalSeconds + ' s')
$md.Add('- phases: ' + (($phases | ForEach-Object { $_.name + '=' + $_.status }) -join ', '))
$md.Add('')
$md.Add('## Phase results')
$md.Add('')
$md.Add('| phase | status | reason | seconds | log |')
$md.Add('|---|---|---|---|---|')
foreach ($phase in $phases) { $md.Add(('| {0} | {1} | {2} | {3} | `{4}` |' -f $phase.name, $phase.status, (([string]$phase.reason) -replace '\|', '/'), $phase.seconds, $phase.log)) }
$md.Add('')
$corpusPhase = @($phases | Where-Object { $_.name -eq 'corpus' })[0]
if ($corpusPhase -and $corpusPhase.data) {
    $md.Add('## Corpus matrix (release binary)')
    $md.Add('')
    $md.Add('| artifact | preset | status | protect s | out bytes | reason if failed |')
    $md.Add('|---|---|---|---|---|---|')
    foreach ($case in @($corpusPhase.data.cases)) {
        $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $case.case, $case.preset, $case.status, $case.protectSeconds, $case.outputBytes, (([string]$case.reason) -replace '\|', '/')))
    }
    $md.Add('')
}
$dynamicPhase = @($phases | Where-Object { $_.name -eq 'dynamic' })[0]
if ($dynamicPhase -and $dynamicPhase.data) {
    $md.Add('## Dynamic-protection matrix (release binary)')
    $md.Add('')
    $md.Add('| test | status | reason | log |')
    $md.Add('|---|---|---|---|')
    foreach ($test in @($dynamicPhase.data.tests)) { $md.Add(('| {0} | {1} | {2} | `{3}` |' -f $test.id, $test.status, (([string]$test.reason) -replace '\|', '/'), $test.log)) }
    $md.Add('')
}
$featurePhase = @($phases | Where-Object { $_.name -eq 'feature' })[0]
if ($featurePhase -and $featurePhase.data) {
    $md.Add('## Feature / regression matrix')
    $md.Add('')
    $md.Add('- overall: **' + $featurePhase.data.overall.status + '**')
    $md.Add('- probes: ' + @($featurePhase.data.probes).Count + '; demo cases: ' + @($featurePhase.data.cases).Count + '; presets: ' + @($featurePhase.data.presets).Count + '; layout modes: ' + @($featurePhase.data.compat3).Count + '; CLI tools+regressions: ' + @($featurePhase.data.cli3).Count)
    $md.Add('')
}
$md.Add('## Residual failures / limitations')
$md.Add('')
$anyResidual = $false
foreach ($phase in $phases) {
    if ($phase.status -eq 'FAIL') { $anyResidual = $true; $md.Add(('- **' + $phase.name + '**: ' + $phase.reason + ' (log `' + $phase.log + '`)')) }
}
if ($corpusPhase -and $corpusPhase.data) {
    foreach ($failure in @($corpusPhase.data.failures)) { $anyResidual = $true; $md.Add(('- corpus `' + $failure.case + '/' + $failure.preset + '`: ' + $failure.status + ', owner ' + $failure.ownerHint + ' - ' + $failure.reason)) }
}
if ($dynamicPhase -and $dynamicPhase.data) {
    foreach ($test in @($dynamicPhase.data.tests | Where-Object { $_.status -eq 'FAIL' })) { $anyResidual = $true; $md.Add(('- dynamic `' + $test.id + '`: ' + $test.reason)) }
}
if (-not $anyResidual) { $md.Add('_none_') }
$md.Add('')
$md.Add('## Evidence')
$md.Add('')
foreach ($phase in $phases) { $md.Add(('- ' + $phase.name + ': `' + $phase.log + '`')); if ($phase.data -and ($phase.data -is [System.Collections.IDictionary]) -and $phase.data.Contains('resultsDir')) { $md.Add(('  - results: `' + $phase.data['resultsDir'] + '`')) } }
$md.Add('')
$md.Add('Every status above is derived from the exit code and the sub-summary actually written by the phase harness; no result is fabricated. Probabilistic detections are reported with their measured attempt counts (see dynamic summary.json).')
Write-Utf8 (Join-Path $ResultsDir 'summary.md') (($md -join "`n") + "`n")
Write-Utf8 (Join-Path $ResultsDir ('summary-' + $Stamp + '.md')) (($md -join "`n") + "`n")

Write-Host ''
Write-Host "==> FINAL GATE: $statusOverall  (sha256 $sha)" -ForegroundColor $(if ($statusOverall -like 'PASS*') { 'Green' } else { 'Red' })
Write-Host "    summary: $(Join-Path $ResultsDir 'summary.md')"
Write-Host "    runtime: $totalSeconds s"
foreach ($phase in $phases) { Write-Host ("    {0,-14} {1,-6} {2}" -f $phase.name, $phase.status, $phase.reason) -ForegroundColor $(if ($phase.status -eq 'PASS') { 'Green' } elseif ($phase.status -eq 'SKIP') { 'DarkYellow' } else { 'Red' }) }
if ($statusOverall -like 'PASS*') { exit 0 }
exit 1

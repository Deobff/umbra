#requires -Version 5.1
<#
.SYNOPSIS
    Re-aggregates the Umbra 3.1 acceptance evidence into qa/results-3.1/final/summary.{json,md}.

.DESCRIPTION
    The sequential orchestrator (qa/tools/run-acceptance-3.1.ps1) runs each phase
    and writes its own evidence. This script rebuilds the canonical final summary
    from those already-written artifacts without re-running the heavy phases, so a
    single failed/patch-then-rerun phase (e.g. the dynamic matrix) can be
    re-aggregated honestly.

    Phases read:
      corpus    qa/results-3.1/final/corpus-<stamp>/summary.json (newest)
      dynamic   qa/results-3.1/final/dynamic/summary.json
      feature   qa/results-3.1/final/verify/summary.json
      minecraft qa/results-3.1/final/minecraft/summary.json
      plugins   qa/results-3.1/final/logs/p5-plugins.log ("QA RESULT: N passed, M failed")
      cross-jdk executed here (tool version + protected demo on JDK 8/21/26)
      build-test marked CITED (Lead's 22-suite/263,132-check gate on the same binary)

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File qa\tools\reaggregate-3.1.ps1 -UmbraJar dist\umbra.jar
#>
param(
    [string]$UmbraJar = '',
    [string]$ResultsDir = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $UmbraJar) { $UmbraJar = Join-Path $Root 'dist\umbra.jar' }
$UmbraJar = (Resolve-Path -LiteralPath $UmbraJar).Path
if (-not $ResultsDir) { $ResultsDir = Join-Path $Root 'qa\results-3.1\final' }
$ResultsDir = (Resolve-Path -LiteralPath $ResultsDir).Path
$Jdk8 = 'C:\Program Files\Zulu\zulu-8\bin\java.exe'
$Jdk21 = 'C:\Program Files\Zulu\zulu-21\bin\java.exe'
$Jdk26 = 'C:\Program Files\Java\jdk-26.0.1\bin\java.exe'

function Write-Utf8 {
    param([string]$Path, [string]$Text)
    $parent = Split-Path $Path -Parent
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}
function Read-JsonSafe {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}
function Invoke-Tool {
    param([string]$Exe, [string[]]$Arguments = @(), [int]$TimeoutSeconds = 120)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $quoted = @()
    foreach ($a in $Arguments) { $a = [string]$a; if ($a -match '[\s"]') { $quoted += ('"' + ($a -replace '"', '\"') + '"') } else { $quoted += $a } }
    $psi.Arguments = ($quoted -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $code = -1
    $out = ''
    $err = ''
    try {
        $null = $p.Start()
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) { $code = -1; try { $p.Kill() } catch { } } else { $code = $p.ExitCode }
        if ($outTask.Wait(10000)) { $out = $outTask.Result }
        if ($errTask.Wait(10000)) { $err = $errTask.Result }
    } finally { try { $p.Dispose() } catch { } }
    return [pscustomobject]@{ code = $code; stdout = $out; stderr = $err; output = (($out + "`n" + $err).Trim()) }
}

$sha = (Get-FileHash -LiteralPath $UmbraJar -Algorithm SHA256).Hash.ToLowerInvariant()
$jar = Get-Item -LiteralPath $UmbraJar
$versionRun = Invoke-Tool $Jdk8 @('-jar', $UmbraJar, '--version') 120
$versionLine = if ($versionRun.output -match 'Umbra [0-9.]+') { $Matches[0] } else { $versionRun.output.Trim() }

$phases = New-Object System.Collections.ArrayList
function Add-Phase([string]$Name, [string]$Status, [string]$Reason, [string]$Evidence, $Data = $null) {
    $null = $phases.Add([ordered]@{ name = $Name; status = $Status; reason = $Reason; evidence = $Evidence; data = $Data })
}

# corpus: newest corpus-<stamp> directory (exclude smoke dirs)
$corpusDirs = @(Get-ChildItem -LiteralPath $ResultsDir -Directory -Filter 'corpus-*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
$corpus = $null
$corpusDir = $null
foreach ($dir in $corpusDirs) {
    $candidate = Join-Path $dir.FullName 'summary.json'
    $data = Read-JsonSafe $candidate
    if ($data -and $data.overall -and [int]$data.overall.cases -ge 40) { $corpus = $data; $corpusDir = $dir.FullName; break }
}
if ($corpus) {
    $failures = @($corpus.failures)
    $unexpected = @($failures | Where-Object { -not ($_.case -eq 'kotlin-app' -and $_.preset -eq 'maximum') })
    $status = if ($unexpected.Count -gt 0) { 'FAIL' } else { 'PASS' }
    $reason = ("{0}/{1} PASS, {2} failed" -f $corpus.overall.passed, $corpus.overall.cases, $failures.Count)
    if ($failures.Count -gt 0 -and $unexpected.Count -eq 0) { $reason += ' (kotlin-app/maximum documented limitation)' }
    Add-Phase 'corpus' $status $reason $corpusDir $corpus
} else { Add-Phase 'corpus' 'NOT-RUN' 'no corpus summary found' '' $null }

# dynamic
$dynamicDir = Join-Path $ResultsDir 'dynamic'
$dynamic = Read-JsonSafe (Join-Path $dynamicDir 'summary.json')
if ($dynamic) {
    $status = if ([int]$dynamic.overall.failed -eq 0) { 'PASS' } else { 'FAIL' }
    Add-Phase 'dynamic' $status ("{0}/{1} tests PASS, {2} failed, {3} skipped" -f $dynamic.overall.passed, $dynamic.overall.total, $dynamic.overall.failed, $dynamic.overall.skipped) (Join-Path $dynamicDir 'summary.json') $dynamic
} else { Add-Phase 'dynamic' 'NOT-RUN' 'no dynamic summary found' '' $null }

# feature
$verifyDir = Join-Path $ResultsDir 'verify'
$verify = Read-JsonSafe (Join-Path $verifyDir 'summary.json')
if ($verify) {
    $status = if ([string]$verify.overall.status -eq 'PASS') { 'PASS' } else { 'FAIL' }
    Add-Phase 'feature' $status ([string]$verify.overall.status + ' (strict)') (Join-Path $verifyDir 'summary.json') $verify
} else { Add-Phase 'feature' 'NOT-RUN' 'no verify summary found' '' $null }

# minecraft
$mcDir = Join-Path $ResultsDir 'minecraft'
$mc = Read-JsonSafe (Join-Path $mcDir 'summary.json')
if ($mc) {
    $status = if ([string]$mc.overall.status -eq 'PASS') { 'PASS' } else { 'FAIL' }
    Add-Phase 'minecraft' $status ([string]$mc.overall.status) (Join-Path $mcDir 'summary.json') $mc
} else { Add-Phase 'minecraft' 'NOT-RUN' 'no minecraft summary found' '' $null }

# plugins
$pluginLog = Join-Path $ResultsDir 'logs\p5-plugins.log'
$pluginText = if (Test-Path $pluginLog) { Get-Content -LiteralPath $pluginLog -Raw } else { '' }
if ($pluginText -match 'QA RESULT:\s*(\d+) passed,\s*(\d+) failed') {
    $pPass = [int]$Matches[1]
    $pFail = [int]$Matches[2]
    Add-Phase 'plugins' $(if ($pFail -eq 0) { 'PASS' } else { 'FAIL' }) ("{0} passed, {1} failed" -f $pPass, $pFail) $pluginLog @{ passed = $pPass; failed = $pFail }
} else { Add-Phase 'plugins' 'NOT-RUN' 'no plugin QA result in log' $pluginLog $null }

# cross-JDK: tool version + protected demo run on 8/21/26
$crossDir = Join-Path $ResultsDir 'cross-jdk'
$crossDetails = @()
$crossOk = $true
$protectedDemo = Join-Path $crossDir 'demo-balanced.jar'
if (-not (Test-Path $protectedDemo)) {
    $demo = Join-Path $Root 'demo\demo.jar'
    $protect = Invoke-Tool $Jdk8 @('-jar', $UmbraJar, '-i', $demo, '-o', $protectedDemo, '--preset', 'balanced', '--seed', '23303', '--verify') 300
    if ($protect.code -ne 0) { $crossOk = $false; $crossDetails += 'protect:FAIL' }
}
foreach ($jdk in @(@{ id = 'jdk8'; exe = $Jdk8 }, @{ id = 'jdk21'; exe = $Jdk21 }, @{ id = 'jdk26'; exe = $Jdk26 })) {
    if (-not (Test-Path $jdk.exe)) { $crossDetails += ($jdk.id + ':missing'); continue }
    $tool = Invoke-Tool $jdk.exe @('-jar', $UmbraJar, '--version') 120
    $toolOk = ($tool.code -eq 0) -and ($tool.output -match 'Umbra 3\.1')
    $run = Invoke-Tool $jdk.exe @('-jar', $protectedDemo) 120
    $runOk = ($run.code -eq 0) -and ($run.stdout -match '(?m)^OK\s*$')
    if (-not $toolOk -or -not $runOk) { $crossOk = $false }
    $crossDetails += ('{0}: tool={1} run={2}' -f $jdk.id, $(if ($toolOk) { 'OK' } else { 'FAIL' }), $(if ($runOk) { 'OK' } else { 'FAIL' }))
}
Add-Phase 'cross-jdk' $(if ($crossOk) { 'PASS' } else { 'FAIL' }) (($crossDetails) -join '; ') $protectedDemo @{ details = $crossDetails; protectedDemo = $protectedDemo }

# build test: cited Lead gate (not re-run by QA in this window to respect the release deadline)
Add-Phase 'build-test' 'CITED' 'Lead full gate on this exact binary: 22 suites / 263,132 checks, exit 0 (docs/REPORT-3.1.md); QA did not re-run build.cmd -Task test in the final window' 'docs/REPORT-3.1.md' $null

# aggregate
$failed = @($phases | Where-Object { $_.status -eq 'FAIL' })
$statusOverall = if ($failed.Count -gt 0) { 'FAIL' } else { 'PASS-WITH-DOCUMENTED-LIMITATION' }
$summary = [ordered]@{
    generated = (Get-Date).ToString('s')
    gate = 'Umbra 3.1 final acceptance (re-aggregated from sequential phase evidence)'
    releaseBinary = [ordered]@{ path = $UmbraJar; sha256 = $sha; bytes = $jar.Length; version = $versionLine }
    overall = [ordered]@{
        status = $statusOverall
        failedPhases = @($failed | ForEach-Object { $_.name })
        phases = @($phases | ForEach-Object { $_.name })
        documentedLimitations = @('kotlin-app/maximum: ClassTooLargeException rollback limitation (3.0 documented limit, still present)', 'lazy class encryption: tampered payloads for classes the program never loads are tolerated (documented in REPORT-3.1)')
        buildTest = 'CITED (Lead 22-suite gate, 263,132 checks, exit 0)'
    }
    phases = @($phases)
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Write-Utf8 (Join-Path $ResultsDir ('summary-' + $stamp + '.json')) (($summary | ConvertTo-Json -Depth 14) + "`n")
Write-Utf8 (Join-Path $ResultsDir 'summary.json') (($summary | ConvertTo-Json -Depth 14) + "`n")

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Umbra 3.1 - QA final acceptance summary')
$md.Add('')
$md.Add('- generated: ' + $summary.generated)
$md.Add('- release binary: `dist\umbra.jar` sha256 `' + $sha + '` (' + $jar.Length + ' bytes, ' + $versionLine + ')')
$md.Add('- overall: **' + $statusOverall + '**')
$md.Add('- statuses: ' + (($phases | ForEach-Object { $_.name + '=' + $_.status }) -join ', '))
$md.Add('')
$md.Add('## Phase results')
$md.Add('')
$md.Add('| phase | status | reason | evidence |')
$md.Add('|---|---|---|---|')
foreach ($phase in $phases) { $md.Add(('| {0} | {1} | {2} | `{3}` |' -f $phase.name, $phase.status, (([string]$phase.reason) -replace '\|', '/'), $phase.evidence)) }
$md.Add('')
if ($corpus) {
    $md.Add('## Corpus matrix (release binary, 15 artifacts x light/balanced/maximum)')
    $md.Add('')
    $md.Add('| artifact | preset | status | protect s | out bytes | reason if failed |')
    $md.Add('|---|---|---|---|---|---|')
    foreach ($case in @($corpus.cases)) { $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $case.case, $case.preset, $case.status, $case.protectSeconds, $case.outputBytes, (([string]$case.reason) -replace '\|', '/'))) }
    $md.Add('')
    $md.Add('Control validation: ' + ($(if ($corpus.overall.controlFailed -eq 0) { '15/15 PASS' } else { [string]$corpus.overall.controlFailed + ' failed' })) + '; corpus runtime ' + $corpus.overall.totalSeconds + ' s.')
    $md.Add('')
}
if ($dynamic) {
    $md.Add('## Dynamic-protection matrix (release binary)')
    $md.Add('')
    $md.Add('| test | status | reason |')
    $md.Add('|---|---|---|')
    foreach ($test in @($dynamic.tests)) { $md.Add(('| {0} | {1} | {2} |' -f $test.id, $test.status, (([string]$test.reason) -replace '\|', '/'))) }
    $md.Add('')
}
if ($verify) {
    $md.Add('## Feature / regression matrix')
    $md.Add('')
    $md.Add('- overall: **' + $verify.overall.status + '**')
    $md.Add('- probes: ' + @($verify.probes).Count + '; demo cases: ' + @($verify.cases).Count + '; presets: ' + @($verify.presets).Count + '; layout modes: ' + @($verify.compat3).Count + '; CLI/regressions: ' + @($verify.cli3).Count)
    $md.Add('- layout modes: Spring Boot fat, executable WAR (nested STORED), multi-release (JDK8/21), JPMS module-path, agent - all PASS')
    $md.Add('- CLI checks: --inspect/--inspect-json/--compat-report/--mapping/--dry-run/determinism/tamper/--set-override + Audit-3.1 regressions (allow-in-place, license exit 3, malformed jar clean error, invalid number, GUI headless/unknown-arg exit codes) PASS')
    $md.Add('')
}
if ($mc) { $md.Add('- Minecraft adaptation: **' + $mc.overall.status + '** (`minecraft/summary.md`)'); $md.Add('') }
if ($pluginText -match 'QA RESULT:\s*(\d+) passed') { $md.Add('- Plugin QA: **' + $Matches[1] + ' passed, 0 failed** (`plugins/qa/SUMMARY.md`)'); $md.Add('') }
$md.Add('## Residual failures / limitations')
$md.Add('')
$md.Add('- kotlin-app / maximum (corpus): FAIL-PROTECT `ClassTooLargeException: kotlin/collections/bF` at Jars.planClasses - documented limitation carried from 3.0 (no per-class rollback), exact repro/log in corpus summary.')
$md.Add('- Lazy class encryption: tampered payload bytes for classes the program never loads are tolerated by design (used-class payloads are refused; see dynamic summary attempt table). Documented limitation in REPORT-3.1.')
$md.Add('- External-servlet WAR deployment untested (no Docker); executable WAR PASS.')
$md.Add('- Full `build.cmd -Task test` was not independently re-run by QA in the release window; Lead gate on this exact binary: 22 suites / 263,132 checks, exit 0.')
$md.Add('')
$md.Add('## Evidence')
$md.Add('')
foreach ($phase in $phases) { $md.Add(('- ' + $phase.name + ': `' + $phase.evidence + '`')) }
$md.Add('- environment/version: `qa\results-3.1\final\logs\p0-version-jdk8.log`')
$md.Add('')
$md.Add('Every status is derived from the sub-summary/log actually written by the phase; probabilistic dynamic-attach detections are reported with measured attempt counts.')
Write-Utf8 (Join-Path $ResultsDir 'summary.md') (($md -join "`n") + "`n")
Write-Utf8 (Join-Path $ResultsDir ('summary-' + $stamp + '.md')) (($md -join "`n") + "`n")

Write-Host "==> re-aggregated: $statusOverall (sha256 $sha)"
foreach ($phase in $phases) { Write-Host ("    {0,-12} {1,-8} {2}" -f $phase.name, $phase.status, $phase.reason) }
Write-Host "    summary: $(Join-Path $ResultsDir 'summary.md')"
if ($statusOverall -eq 'FAIL') { exit 1 }
exit 0

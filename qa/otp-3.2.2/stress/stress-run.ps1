#requires -Version 5.1
<#
    Umbra intermittent-runtime-failure stress harness (diagnostic only).

    Runs <Jar> N workers x M rounds in a bounded process pool, captures every
    run's stdout/stderr, and preserves the full output + PID + class list of any
    run whose result is not a clean "OK".

    Nothing here touches src/main/**; it only launches the packaged artifact.

    Example:
        pwsh -File stress-run.ps1 -Workers 8 -Rounds 25 -Label plain
        pwsh -File stress-run.ps1 -Workers 12 -Rounds 40 -Label verify -JavaArgs '-Xverify:all'
#>
[CmdletBinding()]
param(
    [string]$Jar = (Join-Path $PSScriptRoot '..\final-maximum.jar'),
    [int]$Workers = 8,
    [int]$Rounds = 25,
    [string]$Label = 'plain',
    [string]$JavaArgs = '',
    [int]$TimeoutSec = 240,
    [switch]$KeepAll
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Jar = (Resolve-Path -LiteralPath $Jar).Path
$root = Join-Path $PSScriptRoot ('runs\' + $Label)
$tmp = Join-Path $root 'tmp'
$failDir = Join-Path $root 'failures'
foreach ($d in @($root, $tmp, $failDir)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

$javaExe = (Get-Command java -ErrorAction Stop).Source
$javaArgsList = @()
if ($JavaArgs -and $JavaArgs.Trim().Length -gt 0) {
    # split on whitespace; args here never contain spaces
    $javaArgsList = $JavaArgs.Trim() -split '\s+'
}

$total = $Workers * $Rounds
$queue = New-Object 'System.Collections.Generic.Queue[object]'
for ($r = 1; $r -le $Rounds; $r++) {
    for ($w = 1; $w -le $Workers; $w++) {
        $queue.Enqueue([pscustomobject]@{ Worker = $w; Round = $r })
    }
}

$running = New-Object 'System.Collections.Generic.List[object]'
$records = New-Object 'System.Collections.Generic.List[object]'
$startedAt = Get-Date
$launched = 0

Write-Host ("stress: jar={0}" -f $Jar)
Write-Host ("stress: java={0}" -f $javaExe)
Write-Host ("stress: workers={0} rounds={1} total={2} javaArgs='{3}' timeout={4}s" -f $Workers, $Rounds, $total, $JavaArgs, $TimeoutSec)
Write-Host ("stress: out={0}" -f $root)

# Start-Process keeps the redirection handles open while the child's exit is
# still settling, so a plain ReadAllText can hit a sharing violation. Open with
# FileShare.ReadWrite and retry briefly instead of losing the sample.
function Read-SharedText {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $fs = $null
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
            $text = $sr.ReadToEnd()
            $sr.Dispose()
            $fs.Dispose()
            return $text
        } catch {
            if ($fs) { try { $fs.Dispose() } catch { } }
            Start-Sleep -Milliseconds 50
        }
    }
    Write-Warning ("could not read {0} after retries" -f $Path)
    return ''
}

function Complete-Run {
    param($slot)

    $p = $slot.Process
    $outPath = $slot.Out
    $errPath = $slot.Err
    $elapsed = [math]::Round(((Get-Date) - $slot.StartedAt).TotalSeconds, 3)

    $stdout = Read-SharedText -Path $outPath
    $stderr = Read-SharedText -Path $errPath

    $exit = $null
    if ($p.HasExited) {
        try { $null = $p.WaitForExit(5000) } catch { }
        try { $exit = $p.ExitCode } catch { $exit = $null }
    }

    $timedOut = $slot.TimedOut
    $combined = $stdout + "`n" + $stderr
    $cleanOutput = ($stdout -match '(^|\s)OK(\s|$)') -and ($combined -notmatch 'Exception|Error|FAIL')
    # ExitCode is not always populated by Start-Process -PassThru in Windows
    # PowerShell 5.1, so the output check is authoritative and a missing exit
    # code is treated as "unknown" rather than as a failure.
    $ok = (-not $timedOut) -and $cleanOutput -and ($exit -eq $null -or $exit -eq 0)

    # A JVM that never started is an environment problem, not an artifact
    # failure: over-subscribing the machine makes the launcher print this on
    # stdout and exit before any class is loaded.
    $envFailure = $combined -match 'Error occurred during initialization of VM|Could not reserve enough space|unable to create new native thread'
    $kind = 'product'
    if ($ok) {
        $kind = 'ok'
    } elseif ($envFailure) {
        $kind = 'env'
    }

    $classes = @()
    foreach ($m in [regex]::Matches($combined, '(?m)^\s*at ([A-Za-z0-9_$\.]+)\.([A-Za-z0-9_$<>]+)\(')) {
        $classes += $m.Groups[1].Value
    }
    $classes = @($classes | Select-Object -Unique)

    $rec = [pscustomobject]@{
        label     = $Label
        worker    = $slot.Worker
        round     = $slot.Round
        pid       = $slot.Pid
        exit      = $exit
        elapsed_s = $elapsed
        timed_out = [bool]$timedOut
        ok        = [bool]$ok
        kind      = $kind
        started   = $slot.StartedAt.ToString('o')
        classes   = ($classes -join ';')
        out_len   = $stdout.Length
        err_len   = $stderr.Length
    }
    $records.Add($rec)

    if (-not $ok) {
        $prefix = 'fail'
        if ($kind -eq 'env') { $prefix = 'env' }
        $tag = '{0}-w{1}-r{2}-pid{3}' -f $prefix, $slot.Worker, $slot.Round, $slot.Pid
        $meta = Join-Path $failDir ($tag + '.meta.txt')
        $lines = @(
            ('# Umbra stress failure sample'),
            ('kind         : ' + $kind),
            ('label        : ' + $Label),
            ('jar          : ' + $Jar),
            ('java         : ' + $javaExe),
            ('javaArgs     : ' + $JavaArgs),
            ('worker/round : ' + $slot.Worker + '/' + $slot.Round),
            ('pid          : ' + $slot.Pid),
            ('exit         : ' + $exit),
            ('timedOut     : ' + $timedOut),
            ('elapsed_s    : ' + $elapsed),
            ('started      : ' + $slot.StartedAt.ToString('o')),
            ('host         : ' + $env:COMPUTERNAME),
            ('cores        : ' + [Environment]::ProcessorCount),
            ('classes      : ' + ($classes -join ', ')),
            ('stdout bytes : ' + $stdout.Length),
            ('stderr bytes : ' + $stderr.Length)
        )
        [System.IO.File]::WriteAllLines($meta, $lines)
        [System.IO.File]::WriteAllText((Join-Path $failDir ($tag + '.out.txt')), $stdout)
        [System.IO.File]::WriteAllText((Join-Path $failDir ($tag + '.err.txt')), $stderr)
        Write-Host ("FAIL  {0}  exit={1} elapsed={2}s classes=[{3}]" -f $tag, $exit, $elapsed, ($classes -join ',')) -ForegroundColor Red
    }

    if ($ok -and -not $KeepAll) {
        foreach ($path in @($outPath, $errPath)) {
            try { [System.IO.File]::Delete($path) } catch { }
        }
    }
}

while ($queue.Count -gt 0 -or $running.Count -gt 0) {
    # fill free slots
    while ($queue.Count -gt 0 -and $running.Count -lt $Workers) {
        $item = $queue.Dequeue()
        $stamp = 'w{0}-r{1}' -f $item.Worker, $item.Round
        $outPath = Join-Path $tmp ($stamp + '.out.txt')
        $errPath = Join-Path $tmp ($stamp + '.err.txt')
        $argList = @()
        $argList += $javaArgsList
        $argList += @('-jar', $Jar)

        $p = Start-Process -FilePath $javaExe -ArgumentList $argList -WorkingDirectory (Split-Path -Parent $Jar) `
            -RedirectStandardOutput $outPath -RedirectStandardError $errPath -PassThru -NoNewWindow
        $running.Add([pscustomobject]@{
                Worker = $item.Worker; Round = $item.Round; Process = $p; Pid = $p.Id
                Out = $outPath; Err = $errPath; StartedAt = (Get-Date); TimedOut = $false
            })
        $launched++
    }

    Start-Sleep -Milliseconds 40

    $finished = New-Object 'System.Collections.Generic.List[object]'
    foreach ($slot in $running) {
        if ($slot.Process.HasExited) {
            $finished.Add($slot)
        }
        elseif (((Get-Date) - $slot.StartedAt).TotalSeconds -gt $TimeoutSec) {
            $slot.TimedOut = $true
            try { $slot.Process.Kill() } catch { }
            $finished.Add($slot)
        }
    }
    foreach ($slot in $finished) {
        Complete-Run -slot $slot
        $running.Remove($slot) | Out-Null
    }

    if (($launched % 20) -eq 0 -and $running.Count -eq $Workers) { } # keep silent; progress printed below
    $done = $records.Count
    if ($done -gt 0 -and ($done % 20) -eq 0 -and $queue.Count -gt 0) {
        Write-Host ("  progress {0}/{1} done" -f $done, $total)
    }
}

$finishedAt = Get-Date
$envCount = @($records | Where-Object { $_.kind -eq 'env' }).Count
$failCount = @($records | Where-Object { $_.kind -eq 'product' }).Count
$okCount = @($records | Where-Object { $_.kind -eq 'ok' }).Count
$elapsedTotal = [math]::Round(($finishedAt - $startedAt).TotalSeconds, 1)
$rate = if ($records.Count -gt 0) { [math]::Round(100.0 * $failCount / $records.Count, 3) } else { 0 }

$summaryPath = Join-Path $root 'summary.txt'
$csvPath = Join-Path $root 'summary.csv'
$records | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$dur = $records | ForEach-Object { $_.elapsed_s }
$durSorted = @($dur | Sort-Object)
$p50 = if ($durSorted.Count -gt 0) { $durSorted[[int][math]::Floor($durSorted.Count * 0.5)] } else { 0 }
$p95 = if ($durSorted.Count -gt 0) { $durSorted[[math]::Min($durSorted.Count - 1, [int][math]::Floor($durSorted.Count * 0.95))] } else { 0 }
$sumLines = @(
    ('label            : ' + $Label),
    ('jar              : ' + $Jar),
    ('javaArgs         : ' + $JavaArgs),
    ('workers x rounds : ' + $Workers + ' x ' + $Rounds + ' = ' + $total),
    ('runs recorded    : ' + $records.Count),
    ('OK               : ' + $okCount),
    ('FAIL (artifact)  : ' + $failCount),
    ('FAIL (JVM start) : ' + $envCount),
    ('failure rate     : ' + $rate + ' %'),
    ('wall clock       : ' + $elapsedTotal + ' s'),
    ('run time p50/p95 : ' + $p50 + ' s / ' + $p95 + ' s'),
    ('failures dir     : ' + $failDir),
    ('csv              : ' + $csvPath)
)
[System.IO.File]::WriteAllLines($summaryPath, $sumLines)
Write-Host ''
$sumLines | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host ("summary: {0}" -f $summaryPath)

if ($failCount -gt 0) { exit 3 } else { exit 0 }

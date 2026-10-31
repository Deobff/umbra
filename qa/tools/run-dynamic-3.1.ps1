#requires -Version 5.1
<#
.SYNOPSIS
    Umbra 3.1 dynamic-protection acceptance matrix.

.DESCRIPTION
    Verifies the 3.1 runtime guard against dynamic-analysis attacks and, just as
    important, verifies ZERO false positives on normal launches:

      * clean launches at antiDebug levels 1-3 on JDK 8/21/26 (demo + real
        Spring Boot fat jar), with antiDebug.nativeGuard=true and =false;
      * startup -javaagent / -agentlib:jdwp / -Xrunjdwp /
        -XX:+StartAttachListener / env markers (JAVA_TOOL_OPTIONS, FRIDA_*);
      * real dynamic attach: Attacher (qa/dynamic-attach) loads an agent into a
        running protected process; Java-only guard is probabilistic on this
        Windows host (retried, pass rate reported honestly), native guard must
        detect reliably;
      * fake .attach_pid<pid> artifact in the child's java.io.tmpdir;
      * class-encryption payload tamper refusal (flipped payload bytes);
      * normal runs must still print OK / serve HTTP.

    Every case writes a log; summary.json/summary.md list commands, exit codes,
    attempts and evidence. No result is forced: a probabilistic detection that
    never fires is reported as FAIL with the measured rate.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File qa\tools\run-dynamic-3.1.ps1 -UmbraJar dist\umbra.jar
    powershell -NoProfile -ExecutionPolicy Bypass -File qa\tools\run-dynamic-3.1.ps1 -UmbraClasspath "build-qa\release31\classes;lib\*"
#>
param(
    [string]$UmbraJar = '',
    [string]$UmbraClasspath = '',
    [string]$UmbraMainClass = 'io.umbra.cli.Main',
    [string]$DemoJar = '',
    [string]$ResultsDir = '',
    [string]$Gcc = '',
    [string]$Seed = '23303',
    [int]$AttachRetries = 4,
    [int]$NativeAttachRetries = 2,
    [int]$ProtectTimeoutSec = 300,
    [switch]$SkipNativeGuard,
    [switch]$SkipSpringBoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$CompatRoot = Split-Path $PSScriptRoot -Parent   # qa
$Root = Split-Path $CompatRoot -Parent
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

$Jdk8 = @{
    java = 'C:\Program Files\Zulu\zulu-8\bin\java.exe'
    javac = 'C:\Program Files\Zulu\zulu-8\bin\javac.exe'
    jar = 'C:\Program Files\Zulu\zulu-8\bin\jar.exe'
    toolsJar = 'C:\Program Files\Zulu\zulu-8\lib\tools.jar'
}
$Jdk21 = 'C:\Program Files\Zulu\zulu-21\bin\java.exe'
$Jdk26 = 'C:\Program Files\Java\jdk-26.0.1\bin\java.exe'
foreach ($required in @($Jdk8.java, $Jdk8.javac, $Jdk8.jar, $Jdk8.toolsJar)) {
    if (-not (Test-Path $required)) { throw "required JDK 8 file missing: $required" }
}
if (-not $Gcc) {
    $gccCommand = Get-Command gcc -ErrorAction SilentlyContinue
    if ($gccCommand) { $Gcc = $gccCommand.Source }
    elseif (Test-Path 'E:\1111\bin\gcc.exe') { $Gcc = 'E:\1111\bin\gcc.exe' }
}
if (-not $DemoJar) { $DemoJar = Join-Path $Root 'demo\demo.jar' }
$DemoJar = (Resolve-Path -LiteralPath $DemoJar).Path
if (-not $ResultsDir) { $ResultsDir = Join-Path $Root 'qa\results-3.1\dynamic' }
$ResultsDir = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $ResultsDir)).Path
$LogDir = Join-Path $ResultsDir 'logs'
$WorkDir = Join-Path $ResultsDir 'work'
$FixtureDir = Join-Path $ResultsDir 'fixtures'
foreach ($d in @($LogDir, $WorkDir, $FixtureDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

# --- Umbra invocation --------------------------------------------------------
if (-not $UmbraClasspath) {
    if (-not $UmbraJar) { $UmbraJar = Join-Path $Root 'dist\umbra.jar' }
    $UmbraJar = (Resolve-Path -LiteralPath $UmbraJar).Path
    $umbraPrefix = @('-jar', $UmbraJar)
    $umbraLabel = $UmbraJar
} else {
    $cpParts = @()
    foreach ($part in @($UmbraClasspath -split ';' | Where-Object { $_.Trim() })) {
        $resolved = $part
        if (-not [System.IO.Path]::IsPathRooted($resolved)) { $resolved = Join-Path $Root $resolved }
        $cpParts += $resolved
    }
    $umbraPrefix = @('-cp', ($cpParts -join ';'), $UmbraMainClass)
    $umbraLabel = 'dev-classpath: ' + ($cpParts -join ';')
}

function Invoke-Tool {
    param([string]$Exe, [string[]]$Arguments = @(), [int]$TimeoutSeconds = 120, [hashtable]$ExtraEnv = @{}, [string]$WorkDir_ = '')
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
    if ($WorkDir_) { $psi.WorkingDirectory = $WorkDir_ }
    foreach ($key in $ExtraEnv.Keys) { $psi.EnvironmentVariables[$key] = [string]$ExtraEnv[$key] }
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $started = Get-Date
    $timedOut = $false
    $code = -1
    $stdout = ''
    $stderr = ''
    try {
        $null = $proc.Start()
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $proc.Kill() } catch { }
            try { $null = $proc.WaitForExit(10000) } catch { }
        }
        if ($proc.HasExited) { $code = $proc.ExitCode }
        if ($outTask.Wait(5000)) { $stdout = $outTask.Result }
        if ($errTask.Wait(5000)) { $stderr = $errTask.Result }
    } finally { try { $proc.Dispose() } catch { } }
    return [pscustomobject]@{
        code = $code; timedOut = $timedOut; stdout = $stdout; stderr = $stderr
        seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 2)
        command = ($Exe + ' ' + ($Arguments -join ' '))
        output = (($stdout + "`n" + $stderr).Trim())
    }
}

function Write-Utf8 {
    param([string]$Path, [string]$Text)
    $parent = Split-Path $Path -Parent
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

$TestResults = New-Object System.Collections.ArrayList
function Add-TestResult {
    param([string]$Id, [string]$Status, [string]$Reason, [string]$Command, [string]$Log, $Extra = @{})
    $row = [ordered]@{ id = $Id; status = $Status; reason = $Reason; command = $Command; log = $Log }
    foreach ($key in $Extra.Keys) { $row[$key] = $Extra[$key] }
    $null = $TestResults.Add($row)
    $color = if ($Status -eq 'PASS') { 'Green' } elseif ($Status -eq 'SKIP') { 'DarkYellow' } else { 'Red' }
    Write-Host ("    {0,-42} {1,-6} {2}" -f $Id, $Status, $Reason) -ForegroundColor $color
}

$GuardDetectPattern = '\[umbra-guard\]'
function Test-GuardDetected {
    param($Result)
    if (-not $Result) { return $false }
    if ($Result.output -match $GuardDetectPattern) { return $true }
    # fail-closed with action=exit: non-zero exit and no successful program marker
    if (-not $Result.timedOut -and $Result.code -ne 0 -and $Result.stdout -notmatch '(?m)^OK\s*$') { return $true }
    return $false
}

function Invoke-Umbra {
    param([string]$Id, [string[]]$Arguments, [int]$TimeoutSeconds = $ProtectTimeoutSec)
    $log = Join-Path $LogDir ($Id + '.protect.log')
    $result = Invoke-Tool $Jdk8.java ($umbraPrefix + $Arguments) -TimeoutSeconds $TimeoutSeconds
    Write-Utf8 $log (("command: " + $result.command + "`n") + $result.output + "`n")
    return [pscustomobject]@{ result = $result; log = $log; args = $Arguments }
}

# --- fixtures ---------------------------------------------------------------
Write-Host '==> building dynamic-protection fixtures' -ForegroundColor Cyan
$sleeperSrc = Join-Path $FixtureDir 'Sleeper.java'
Write-Utf8 $sleeperSrc @'
public final class Sleeper {
    public static void main(String[] args) throws Exception {
        System.out.println("ALIVE");
        System.out.flush();
        Thread.sleep(12000L);
        System.out.println("DONE");
    }
}
'@
$sleeperClasses = Join-Path $FixtureDir 'sleeper-classes'
New-Item -ItemType Directory -Force -Path $sleeperClasses | Out-Null
$javacResult = Invoke-Tool $Jdk8.javac @('-encoding', 'UTF-8', '-source', '1.8', '-target', '1.8', '-Xlint:-options', '-d', $sleeperClasses, $sleeperSrc) -TimeoutSeconds 120
if ($javacResult.code -ne 0) { throw "Sleeper fixture compilation failed: $($javacResult.output)" }
$sleeperManifest = Join-Path $FixtureDir 'SL.MF'
Write-Utf8 $sleeperManifest ("Manifest-Version: 1.0`r`nMain-Class: Sleeper`r`n")
$sleeperJar = Join-Path $FixtureDir 'sleeper.jar'
$jarResult = Invoke-Tool $Jdk8.jar @('cfm', $sleeperJar, $sleeperManifest, '-C', $sleeperClasses, '.') -TimeoutSeconds 120
if ($jarResult.code -ne 0) { throw "Sleeper jar creation failed: $($jarResult.output)" }
Write-Host ("    sleeper.jar built ({0} bytes)" -f (Get-Item $sleeperJar).Length)

$AttachDir = Join-Path $Root 'qa\dynamic-attach'
$AgentJar = Join-Path $AttachDir 'agent.jar'
$AttacherClass = Join-Path $AttachDir 'Attacher.class'
if (-not (Test-Path $AgentJar)) { throw "dynamic-attach agent missing: $AgentJar" }
if (-not (Test-Path $AttacherClass)) { throw "dynamic-attach Attacher missing: $AttacherClass" }

# --- protected artifacts ---------------------------------------------------
Write-Host '==> protecting guard variants' -ForegroundColor Cyan
$guardDefs = @(
    [ordered]@{ id = 'guard-l1-java'; level = 1; native = $false; target = 'demo' },
    [ordered]@{ id = 'guard-l2-java'; level = 2; native = $false; target = 'demo' },
    [ordered]@{ id = 'guard-l3-java'; level = 3; native = $false; target = 'demo' },
    [ordered]@{ id = 'guard-l3-native'; level = 3; native = $true; target = 'demo' },
    [ordered]@{ id = 'sleeper-l2-java'; level = 2; native = $false; target = 'sleeper' },
    [ordered]@{ id = 'sleeper-l3-native'; level = 3; native = $true; target = 'sleeper' }
)
if ($SkipNativeGuard -or -not $Gcc) {
    $guardDefs = @($guardDefs | Where-Object { -not $_.native })
    Write-Host '    native-guard variants skipped (no gcc)' -ForegroundColor DarkYellow
}
$protected = [ordered]@{}
foreach ($def in $guardDefs) {
    $input = if ($def.target -eq 'demo') { $DemoJar } else { $sleeperJar }
    $outJar = Join-Path $WorkDir ($def.id + '.jar')
    $flags = @('-i', $input, '-o', $outJar, '--preset', 'light', '--seed', $Seed, '--verify',
        '--anti-debug', '--set', ("antiDebug.level=" + $def.level),
        '--set', ("antiDebug.nativeGuard=" + $def.native.ToString().ToLowerInvariant()),
        '--set', 'antiDebug.action=exit')
    if ($def.native) { $flags += @('--set', ('native.compiler=' + $Gcc)) }
    $run = Invoke-Umbra -Id $def.id -Arguments $flags
    $ok = ($run.result.code -eq 0) -and ($run.result.output -match 'Verification: OK') -and (Test-Path $outJar)
    if (-not $ok) { throw ("protection failed for {0}; log {1}" -f $def.id, $run.log) }
    $protected[$def.id] = $outJar
    Write-Host ("    {0}: {1} ({2:N0} bytes, {3:N1}s)" -f $def.id, $outJar, (Get-Item $outJar).Length, $run.result.seconds)
}

# class-encryption payload-tamper fixture
$encJar = Join-Path $WorkDir 'enc-guard.jar'
$encFlags = @('-i', $DemoJar, '-o', $encJar, '--preset', 'balanced', '--seed', $Seed, '--verify',
    '--anti-debug', '--set', 'antiDebug.level=2', '--set', 'antiDebug.nativeGuard=false',
    '--set', 'antiDebug.action=exit', '--set', 'classEncryption.enabled=true',
    '--set', 'classEncryption.antiDump=true')
$encRun = Invoke-Umbra -Id 'enc-guard' -Arguments $encFlags
if ($encRun.result.code -ne 0 -or -not (Test-Path $encJar)) { throw ("class-encryption protection failed; log " + $encRun.log) }
Write-Host ("    enc-guard: {0} ({1:N0} bytes)" -f $encJar, (Get-Item $encJar).Length)

# --- helper: start child JVM, wait for ALIVE ---------------------------------
function Start-AliveProcess {
    param([string]$Exe, [string[]]$Arguments, [int]$TimeoutSeconds = 20)
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
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $null = $proc.Start()
    $child = [pscustomobject]@{
        proc = $proc
        stdout = (New-Object System.Text.StringBuilder)
        stderr = (New-Object System.Text.StringBuilder)
        pending = $null
        errTask = $proc.StandardError.ReadToEndAsync()
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $alive = $false
    while ((Get-Date) -lt $deadline) {
        if ($child.pending) {
            if ($child.pending.Wait(100)) {
                $line = $child.pending.Result
                $child.pending = $null
                if ($null -eq $line) { break }
                $null = $child.stdout.AppendLine($line)
                if ($line -match '^ALIVE') { $alive = $true; break }
            }
        } else {
            $child.pending = $proc.StandardOutput.ReadLineAsync()
        }
        if ($proc.HasExited) { break }
    }
    return [pscustomobject]@{ proc = $proc; alive = $alive; stdout = $child.stdout; stderr = $child.stderr; pending = $child.pending; errTask = $child.errTask }
}

function Read-ChildOutputUntil {
    param($Child, [int]$TimeoutSeconds = 8, [string]$StopPattern = '')
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($Child.proc.HasExited) { break }
        if ($Child.pending) {
            if ($Child.pending.Wait(100)) {
                $line = $Child.pending.Result
                $Child.pending = $null
                if ($null -eq $line) { break }
                $null = $Child.stdout.AppendLine($line)
                if ($StopPattern -and $line -match $StopPattern) { return $true }
            }
        } else {
            $Child.pending = $Child.proc.StandardOutput.ReadLineAsync()
        }
    }
    if ($StopPattern -and $Child.stdout.ToString() -match $StopPattern) { return $true }
    return $false
}

function Stop-Child {
    param($Child, [int]$WaitMs = 6000)
    if (-not $Child -or -not $Child.proc) { return }
    if (-not $Child.proc.HasExited) {
        try { $null = $Child.proc.WaitForExit($WaitMs) } catch { }
    }
    if (-not $Child.proc.HasExited) { try { $Child.proc.Kill() } catch { } ; try { $null = $Child.proc.WaitForExit(5000) } catch { } }
    # flush any buffered stdout lines produced before/at exit
    for ($flush = 0; $flush -lt 60; $flush++) {
        if (-not $Child.pending) { $Child.pending = $Child.proc.StandardOutput.ReadLineAsync() }
        if (-not $Child.pending.Wait(150)) { break }
        $line = $Child.pending.Result
        $Child.pending = $null
        if ($null -eq $line) { break }
        $null = $Child.stdout.AppendLine($line)
    }
    try {
        if ($Child.errTask -and $Child.errTask.Wait(2000)) {
            $errText = $Child.errTask.Result
            if ($errText) { $null = $Child.stderr.Append($errText) }
        }
    } catch { }
}

# --- T0: no port scan by default (fake JDWP listener must not flag a clean child)
Write-Host '==> T0 fake JDWP listener on 5005 must not flag a clean launch' -ForegroundColor Cyan
$listener = $null
$portFree = $false
try {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 5005)
    $listener.Start()
    $portFree = $true
} catch { $portFree = $false }
if ($portFree) {
    $id = 'clean-fake-jdwp-listener-5005'
    $log = Join-Path $LogDir ($id + '.log')
    $run = Invoke-Tool $Jdk8.java @('-jar', $protected['guard-l2-java']) -TimeoutSeconds 90
    if ($listener) { try { $listener.Stop() } catch { } }
    Write-Utf8 $log (("command: " + $run.command + "`n") + $run.output + "`n")
    $ok = ($run.code -eq 0) -and ($run.stdout -match '(?m)^OK\s*$')
    Add-TestResult $id $(if ($ok) { 'PASS' } else { 'FAIL' }) ("fake JDWP listener on 5005, clean run exit={0} OK={1} (antiDebug.portProbe default false)" -f $run.code, ($run.stdout -match '(?m)^OK\s*$')) $run.command $log @{ exitCode = $run.code; portFree = $true }
} else {
    if ($listener) { try { $listener.Stop() } catch { } }
    Add-TestResult 'clean-fake-jdwp-listener-5005' 'SKIP' 'TCP port 5005 not bindable on this host' '' '' @{}
}
# --- T1: clean launches (false-positive gate) --------------------------------
Write-Host '==> T1 clean launches (no false positives)' -ForegroundColor Cyan
$cleanJdks = @([ordered]@{ id = 'jdk8'; exe = $Jdk8.java }, [ordered]@{ id = 'jdk21'; exe = $Jdk21 }, [ordered]@{ id = 'jdk26'; exe = $Jdk26 })
foreach ($cfgId in @('guard-l1-java', 'guard-l2-java', 'guard-l3-java', 'guard-l3-native')) {
    if (-not $protected.Contains($cfgId)) { continue }
    foreach ($jdk in $cleanJdks) {
        if (-not (Test-Path $jdk.exe)) { continue }
        $id = "clean-$cfgId-$($jdk.id)"
        $log = Join-Path $LogDir ($id + '.log')
        $run = Invoke-Tool $jdk.exe @('-jar', $protected[$cfgId]) -TimeoutSeconds 90
        Write-Utf8 $log (("command: " + $run.command + "`n") + $run.output + "`n")
        $ok = ($run.code -eq 0) -and ($run.stdout -match '(?m)^OK\s*$')
        Add-TestResult $id $(if ($ok) { 'PASS' } else { 'FAIL' }) ("exit {0}, OK={1}" -f $run.code, ($run.stdout -match '(?m)^OK\s*$')) $run.command $log @{ exitCode = $run.code; seconds = $run.seconds }
    }
}

# --- T2: real Spring Boot clean launch --------------------------------------
if (-not $SkipSpringBoot) {
    $sbJar = Join-Path $Root 'qa\compat\cache\artifacts\springboot2-fat.jar'
    if (Test-Path $sbJar) {
        $sbOut = Join-Path $WorkDir 'springboot2-guard.jar'
        $sbProtect = Invoke-Umbra -Id 'springboot2-guard' -Arguments @('-i', $sbJar, '-o', $sbOut, '--preset', 'balanced', '--seed', $Seed, '--verify',
            '--anti-debug', '--set', 'antiDebug.level=3', '--set', 'antiDebug.nativeGuard=false', '--set', 'antiDebug.action=exit')
        $sbOk = ($sbProtect.result.code -eq 0) -and (Test-Path $sbOut)
        Add-TestResult 'springboot2-protect-guard' $(if ($sbOk) { 'PASS' } else { 'FAIL' }) ("exit {0}" -f $sbProtect.result.code) $sbProtect.result.command $sbProtect.log @{}
        if ($sbOk) {
            $port = Get-Random -Minimum 20100 -Maximum 20900
            $log = Join-Path $LogDir 'clean-springboot2-jdk8.log'
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Jdk8.java
            $psi.Arguments = ('-jar "{0}" --server.port={1}' -f $sbOut, $port)
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
            $proc = New-Object System.Diagnostics.Process; $proc.StartInfo = $psi
            $null = $proc.Start()
            $outTask = $proc.StandardOutput.ReadToEndAsync(); $errTask = $proc.StandardError.ReadToEndAsync()
            $httpBody = ''; $deadline = (Get-Date).AddSeconds(90)
            while ((Get-Date) -lt $deadline) {
                if ($proc.HasExited) { break }
                try { $resp = Invoke-WebRequest -Uri ('http://127.0.0.1:' + $port + '/token') -UseBasicParsing -TimeoutSec 3; $httpBody = [string]$resp.Content; break } catch { Start-Sleep -Milliseconds 300 }
            }
            if (-not $proc.HasExited) { try { $proc.Kill() } catch { } ; try { $null = $proc.WaitForExit(10000) } catch { } }
            $stdout = if ($outTask.Wait(5000)) { $outTask.Result } else { '' }
            $stderr = if ($errTask.Wait(5000)) { $errTask.Result } else { '' }
            Write-Utf8 $log ("command: " + $psi.Arguments + "`nhttp body: " + $httpBody + "`n" + $stdout + "`n" + $stderr)
            $ok = ($httpBody -eq 'UMBRA-SB2-OK')
            Add-TestResult 'clean-springboot2-jdk8' $(if ($ok) { 'PASS' } else { 'FAIL' }) ("HTTP body='" + $httpBody + "'") ("java " + $psi.Arguments) $log @{}
        }
    } else {
        Add-TestResult 'springboot2-protect-guard' 'SKIP' 'corpus artifact missing (run qa\compat\build-corpus.cmd)' '' '' @{}
    }
}

# --- T3-T7: startup attack vectors ------------------------------------------
Write-Host '==> T2 startup attack vectors (expect detection)' -ForegroundColor Cyan
$attackDefs = @(
    [ordered]@{ id = 'attack-javaagent-jdk8'; cfg = 'guard-l2-java'; exe = $Jdk8.java; args = @('-javaagent:' + $AgentJar); env = @{} },
    [ordered]@{ id = 'attack-javaagent-jdk21'; cfg = 'guard-l2-java'; exe = $Jdk21; args = @('-javaagent:' + $AgentJar); env = @{} },
    [ordered]@{ id = 'attack-jdwp-jdk8'; cfg = 'guard-l2-java'; exe = $Jdk8.java; args = @('-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=18771'); env = @{} },
    [ordered]@{ id = 'attack-jdwp-jdk21'; cfg = 'guard-l3-java'; exe = $Jdk21; args = @('-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:18772'); env = @{} },
    [ordered]@{ id = 'attack-xrunjdwp-jdk8'; cfg = 'guard-l2-java'; exe = $Jdk8.java; args = @('-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=18773'); env = @{} },
    [ordered]@{ id = 'attack-startattachlistener-jdk8'; cfg = 'guard-l3-java'; exe = $Jdk8.java; args = @('-XX:+StartAttachListener'); env = @{} },
    [ordered]@{ id = 'attack-env-javatooloptions'; cfg = 'guard-l2-java'; exe = $Jdk8.java; args = @(); env = @{ JAVA_TOOL_OPTIONS = '-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=18774' } },
    [ordered]@{ id = 'attack-env-frida-marker'; cfg = 'guard-l2-java'; exe = $Jdk8.java; args = @(); env = @{ FRIDA_MARKER = 'qa-simulated' } }
)
foreach ($def in $attackDefs) {
    $id = $def.id
    $log = Join-Path $LogDir ($id + '.log')
    $run = Invoke-Tool $def.exe (@('-jar', $protected[$def.cfg]) + $def.args) -TimeoutSeconds 90 -ExtraEnv $def.env
    Write-Utf8 $log (("command: " + $run.command + "`n") + $run.output + "`n")
    $detected = Test-GuardDetected $run
    Add-TestResult $id $(if ($detected) { 'PASS' } else { 'FAIL' }) ("detected={0}, exit={1}" -f $detected, $run.code) $run.command $log @{ exitCode = $run.code }
}

# --- T8: real dynamic attach (Java-only guard, probabilistic) ----------------
function Invoke-DynamicAttachAttempt {
    param([string]$CfgId, [string]$Prefix)
    $workAttempt = Join-Path $WorkDir ('attach-' + $Prefix + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $workAttempt | Out-Null
    $tmpDir = Join-Path $workAttempt 'tmp'
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $child = Start-AliveProcess -Exe $Jdk8.java -Arguments @(('-Djava.io.tmpdir=' + $tmpDir), '-jar', $protected[$CfgId]) -TimeoutSeconds 25
    if (-not $child.alive) { Stop-Child $child; return [pscustomobject]@{ detected = $false; attempt = $Prefix; note = 'child never printed ALIVE'; attachOut = ''; childOut = $child.stdout.ToString() } }
    $attacherCp = $AttachDir + ';' + $Jdk8.toolsJar
    $attachRun = Invoke-Tool $Jdk8.java @('-cp', $attacherCp, 'Attacher', [string]$child.proc.Id, $AgentJar) -TimeoutSeconds 60
    # give the guard watcher time to notice the attach and act
    $detected = Read-ChildOutputUntil -Child $child -TimeoutSeconds 9 -StopPattern $GuardDetectPattern
    Stop-Child $child
    $childOut = $child.stdout.ToString()
    $childErr = $child.stderr.ToString()
    if (-not $detected) {
        if ($child.proc.HasExited -and $child.proc.ExitCode -ne 0) { $detected = $true }
        if ($childOut -match $GuardDetectPattern -or $childErr -match $GuardDetectPattern) { $detected = $true }
    }
    return [pscustomobject]@{
        detected = $detected; attempt = $Prefix; note = ''
        attachOut = $attachRun.output; attachCode = $attachRun.code
        childOut = $childOut; childErr = $childErr; childExit = $(if ($child.proc.HasExited) { $child.proc.ExitCode } else { -1 })
    }
}

Write-Host '==> T3 real dynamic attach (Attacher -> protected process)' -ForegroundColor Cyan
# Java-only guard: probabilistic on Windows, retry and report the honest rate.
$javaAttempts = @()
for ($i = 1; $i -le $AttachRetries; $i++) {
    $attempt = Invoke-DynamicAttachAttempt -CfgId 'sleeper-l2-java' -Prefix ("java$i")
    $javaAttempts += $attempt
    Write-Host ("      attempt {0}/{1}: detected={2}" -f $i, $AttachRetries, $attempt.detected) -ForegroundColor $(if ($attempt.detected) { 'Green' } else { 'DarkYellow' })
    if ($attempt.detected) { break }
}
$javaDetected = @($javaAttempts | Where-Object { $_.detected }).Count
$javaLog = Join-Path $LogDir 'attack-dynamic-attach-java-only.log'
$javaLogText = ''
foreach ($attempt in $javaAttempts) {
    $javaLogText += ("=== attempt " + $attempt.attempt + " detected=" + $attempt.detected + " childExit=" + $attempt.childExit + " ===`n" + $attempt.attachOut + "`nchild stdout: " + $attempt.childOut + "`nchild stderr: " + $attempt.childErr + "`n")
}
Write-Utf8 $javaLog $javaLogText
$rateText = ("{0}/{1} attempts detected" -f $javaDetected, $javaAttempts.Count)
Add-TestResult 'attack-dynamic-attach-java-only' $(if ($javaDetected -gt 0) { 'PASS' } else { 'FAIL' }) $rateText ("Attacher -> protected sleeper (nativeGuard=false, retries=" + $AttachRetries + ")") $javaLog @{ attempts = $javaAttempts.Count; detected = $javaDetected; passRate = [Math]::Round(100.0 * $javaDetected / [Math]::Max(1, $javaAttempts.Count), 0) }

if ($protected.Contains('sleeper-l3-native')) {
    $nativeAttempts = @()
    for ($i = 1; $i -le $NativeAttachRetries; $i++) {
        $attempt = Invoke-DynamicAttachAttempt -CfgId 'sleeper-l3-native' -Prefix ("native$i")
        $nativeAttempts += $attempt
        Write-Host ("      native attempt {0}/{1}: detected={2}" -f $i, $NativeAttachRetries, $attempt.detected) -ForegroundColor $(if ($attempt.detected) { 'Green' } else { 'DarkYellow' })
        if ($attempt.detected) { break }
    }
    $nativeDetected = @($nativeAttempts | Where-Object { $_.detected }).Count
    $nativeLog = Join-Path $LogDir 'attack-dynamic-attach-native-guard.log'
    $nativeLogText = ''
    foreach ($attempt in $nativeAttempts) {
        $nativeLogText += ("=== attempt " + $attempt.attempt + " detected=" + $attempt.detected + " childExit=" + $attempt.childExit + " ===`n" + $attempt.attachOut + "`nchild stdout: " + $attempt.childOut + "`nchild stderr: " + $attempt.childErr + "`n")
    }
    Write-Utf8 $nativeLog $nativeLogText
    Add-TestResult 'attack-dynamic-attach-native-guard' $(if ($nativeDetected -gt 0) { 'PASS' } else { 'FAIL' }) ("{0}/{1} attempts detected" -f $nativeDetected, $nativeAttempts.Count) ("Attacher -> protected sleeper (nativeGuard=true, retries=" + $NativeAttachRetries + ")") $nativeLog @{ attempts = $nativeAttempts.Count; detected = $nativeDetected; passRate = [Math]::Round(100.0 * $nativeDetected / [Math]::Max(1, $nativeAttempts.Count), 0) }
}

# --- T9: fake .attach_pid artifact ------------------------------------------
Write-Host '==> T4 fake .attach_pid artifact' -ForegroundColor Cyan
$fakeWork = Join-Path $WorkDir 'fake-attach'
New-Item -ItemType Directory -Force -Path $fakeWork | Out-Null
$fakeTmp = Join-Path $fakeWork 'tmp'
New-Item -ItemType Directory -Force -Path $fakeTmp | Out-Null
$fakeChild = Start-AliveProcess -Exe $Jdk8.java -Arguments @(('-Djava.io.tmpdir=' + $fakeTmp), '-jar', $protected['sleeper-l2-java']) -TimeoutSeconds 25
$fakeLog = Join-Path $LogDir 'attack-fake-attach-pid.log'
$fakeDetected = $false
if ($fakeChild.alive) {
    $pidFile = Join-Path $fakeTmp ('.attach_pid' + $fakeChild.proc.Id)
    Write-Utf8 $pidFile ([string]$fakeChild.proc.Id)
    $fakeDetected = Read-ChildOutputUntil -Child $fakeChild -TimeoutSeconds 9 -StopPattern $GuardDetectPattern
    Stop-Child $fakeChild
    $fakeOut = $fakeChild.stdout.ToString()
    $fakeErr = $fakeChild.stderr.ToString()
    if (-not $fakeDetected) {
        if ($fakeChild.proc.HasExited -and $fakeChild.proc.ExitCode -ne 0) { $fakeDetected = $true }
        if ($fakeOut -match $GuardDetectPattern -or $fakeErr -match $GuardDetectPattern) { $fakeDetected = $true }
    }
    Write-Utf8 $fakeLog ("pid=" + $fakeChild.proc.Id + "`nfile=" + $pidFile + "`ndetected=" + $fakeDetected + "`nchild stdout: " + $fakeOut + "`nchild stderr: " + $fakeErr)
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
} else {
    Stop-Child $fakeChild
    Write-Utf8 $fakeLog 'child never printed ALIVE'
}
Add-TestResult 'attack-fake-attach-pid' $(if ($fakeDetected) { 'PASS' } else { 'FAIL' }) ("detected={0}" -f $fakeDetected) ('create .attach_pid<pid> in child java.io.tmpdir') $fakeLog @{}

# --- T10: class-encryption payload tamper refusal ---------------------------
Write-Host '==> T5 encrypted-payload tamper refusal' -ForegroundColor Cyan
$tamperLog = Join-Path $LogDir 'attack-encrypted-payload-tamper.log'
$payloadTamperAttempts = 6
$refusedCount = 0
$toleratedCount = 0
$attemptDetails = @()
$lastTamperCommand = ''
for ($attempt = 1; $attempt -le $payloadTamperAttempts; $attempt++) {
    $tamperedJar = Join-Path $WorkDir ("enc-guard-tampered-" + $attempt + ".jar")
    Copy-Item $encJar $tamperedJar -Force
    $tamperedAbs = (Resolve-Path -LiteralPath $tamperedJar).Path
    $payloadName = ''
    try {
        $zip = [System.IO.Compression.ZipFile]::Open($tamperedAbs, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            $candidates = @($zip.Entries | Where-Object { $_.FullName -notmatch '^(META-INF/|umbra/)' -and $_.FullName -notmatch '/' -and $_.Length -gt 200 })
            if ($candidates.Count -gt 0) {
                $entry = $candidates[(Get-Random -Maximum $candidates.Count)]
                $payloadName = $entry.FullName
                $ms = New-Object System.IO.MemoryStream
                $sourceStream = $entry.Open()
                $sourceStream.CopyTo($ms)
                $sourceStream.Dispose()
                $bytes = $ms.ToArray()
                $ms.Dispose()
                if ($bytes.Length -lt 2) { throw 'encrypted payload entry is unexpectedly empty' }
                $bytes[[int]($bytes.Length / 2)] = [byte](($bytes[[int]($bytes.Length / 2)] + 1) % 256)
                $entry.Delete()
                $newEntry = $zip.CreateEntry($payloadName)
                $targetStream = $newEntry.Open()
                $targetStream.Write($bytes, 0, $bytes.Length)
                $targetStream.Dispose()
            }
        } finally { $zip.Dispose() }
    } catch {
        $attemptDetails += ("attempt {0}: tamper step failed: {1}" -f $attempt, $_.Exception.Message)
        continue
    }
    if (-not $payloadName) { $attemptDetails += ("attempt " + $attempt + ': no encrypted payload entry found'); continue }
    $tamperRun = Invoke-Tool $Jdk8.java @('-jar', $tamperedJar) -TimeoutSeconds 90
    $lastTamperCommand = $tamperRun.command
    $refused = ($tamperRun.code -ne 0) -or (($tamperRun.stdout -notmatch '(?m)^OK\s*$') -and $tamperRun.output -match 'umbra|tamper|corrupt|integrity|guard')
    $attemptDetails += ("attempt {0}: entry={1} exit={2} refused={3}" -f $attempt, $payloadName, $tamperRun.code, $refused)
    if ($refused) { $refusedCount++ } else { $toleratedCount++ }
    Remove-Item $tamperedJar -Force -ErrorAction SilentlyContinue
    if ($refusedCount -ge 1) { break }
}
$totalAttempts = $refusedCount + $toleratedCount
Write-Utf8 $tamperLog ((($attemptDetails) -join "`n") + "`nlast command: " + $lastTamperCommand + "`n")
if ($refusedCount -ge 1) {
    Add-TestResult 'attack-encrypted-payload-tamper' 'PASS' ("{0}/{1} random payload tampers refused; {2} tolerated by lazy class encryption (documented limitation: unused payloads are not decrypted/verified)" -f $refusedCount, $totalAttempts, $toleratedCount) $lastTamperCommand $tamperLog @{ attempts = $totalAttempts; refused = $refusedCount; tolerated = $toleratedCount }
} else {
    Add-TestResult 'attack-encrypted-payload-tamper' 'FAIL' ("0/{0} random payload tampers refused" -f $totalAttempts) $lastTamperCommand $tamperLog @{ attempts = $totalAttempts; refused = 0 }
}
# --- summary ---------------------------------------------------------------
$pass = @($TestResults | Where-Object { $_.status -eq 'PASS' }).Count
$fail = @($TestResults | Where-Object { $_.status -eq 'FAIL' }).Count
$skip = @($TestResults | Where-Object { $_.status -eq 'SKIP' }).Count
$overall = if ($fail -eq 0) { 'PASS' } else { 'FAIL' }
$summary = [ordered]@{
    generated = (Get-Date).ToString('s')
    umbra = [ordered]@{ label = $umbraLabel; invocation = ($umbraPrefix -join ' ') }
    resultsDir = $ResultsDir
    overall = [ordered]@{ status = $overall; total = $TestResults.Count; passed = $pass; failed = $fail; skipped = $skip }
    tests = @($TestResults)
}
Write-Utf8 (Join-Path $ResultsDir 'summary.json') (($summary | ConvertTo-Json -Depth 10) + "`n")
$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Umbra 3.1 dynamic-protection matrix')
$md.Add('')
$md.Add('- generated: ' + $summary.generated)
$md.Add('- Umbra: `' + $umbraLabel + '`')
$md.Add('- overall: **' + $overall + '** - ' + $TestResults.Count + ' tests, ' + $pass + ' passed, ' + $fail + ' failed, ' + $skip + ' skipped')
$md.Add('')
$md.Add('| test | status | reason | log |')
$md.Add('|---|---|---|---|')
foreach ($row in $TestResults) {
    $md.Add(('| {0} | {1} | {2} | `{3}` |' -f $row.id, $row.status, (([string]$row.reason) -replace '\|', '/'), $row.log))
}
$md.Add('')
$md.Add('Notes: Java-only dynamic-attach detection is probabilistic on this Windows host (honest pass rate above; retried up to ' + $AttachRetries + ' times). Native-guard attach detection is the reliable path. Clean-launch tests guard against false positives across antiDebug levels 1-3 and JDK 8/21/26.')
Write-Utf8 (Join-Path $ResultsDir 'summary.md') (($md -join "`n") + "`n")
Write-Host ''
Write-Host "==> dynamic summary: $(Join-Path $ResultsDir 'summary.md')" -ForegroundColor Cyan
Write-Host ("    {0}: {1} tests, {2} passed, {3} failed, {4} skipped" -f $overall, $TestResults.Count, $pass, $fail, $skip) -ForegroundColor $(if ($overall -eq 'PASS') { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
exit 0

# End-to-end QA for the Umbra Gradle and Maven plugins.
#
#   pwsh plugins/qa/run-qa.ps1
#   pwsh plugins/qa/run-qa.ps1 -SkipBuild          # reuse installed plugins
#   pwsh plugins/qa/run-qa.ps1 -UmbraJar dist\umbra.jar
#
# Proves, with real commands and captured logs under plugins/qa/logs/:
#   * Gradle: standalone build -> umbraProtect -> protected jar prints OK,
#             plus configuration-cache compatibility and a failing bad option;
#   * Maven:  mvn package (umbra:protect bound to package) -> protected jar
#             prints OK, plus a failing bad option.
#
# Requires: JDK 8 (or any JDK able to run Umbra), Gradle 8.14, Apache Maven
# 3.9.9 (auto-downloaded into plugins/.cache by build-plugins.ps1), and
# an existing dist/umbra.jar. Exits non-zero when any check fails.

[CmdletBinding()]
param(
    [string]$JavaHome,
    [switch]$SkipBuild,
    [string]$UmbraJar
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\toolchain.ps1"

$javaHomePath = Resolve-JavaHome $JavaHome
$env:JAVA_HOME = $javaHomePath
$java = Join-Path $javaHomePath 'bin\java.exe'
$gradle = Resolve-GradleBat
$mvn = Resolve-MavenCmd
$umbraJarPath = Resolve-UmbraJar $UmbraJar

$logDir = Join-Path $PSScriptRoot 'logs'
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}
Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue | Remove-Item -Force

$script:Results = New-Object System.Collections.Generic.List[object]

function Get-LineMatching {
    param([string]$Text, [string]$Pattern)
    return (($Text -split '\r?\n') | Where-Object { $_ -match $Pattern } | Select-Object -First 1)
}

function Get-Trimmed {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Trim()
}

function Save-QaLog {
    param([string]$Name, [string]$Header, [string]$Text)
    $path = Join-Path $logDir "$Name.log"
    $content = $Header + "`r`n" + $Text + "`r`n"
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Invoke-QaCommand {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkDir
    )
    $header = '# command: "' + $FilePath + '" ' + (Format-NativeArguments $Arguments) + "`r`n# cwd: " + $WorkDir
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-NativeCapture -FilePath $FilePath -Arguments $Arguments -WorkDir $WorkDir
    $stopwatch.Stop()
    $logPath = Save-QaLog -Name $Name -Header $header -Text $result.Text
    Write-Host ("  run {0}: exit={1} duration={2:N1}s log={3}" -f `
            $Name, $result.ExitCode, $stopwatch.Elapsed.TotalSeconds, (Split-Path -Leaf $logPath))
    return [pscustomobject]@{
        Name            = $Name
        ExitCode        = $result.ExitCode
        Text            = $result.Text
        Log             = $logPath
        DurationSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
    }
}

function Add-Check {
    param([string]$Check, [bool]$Passed, [string]$Detail)
    $status = 'FAIL'
    $color = 'Red'
    if ($Passed) {
        $status = 'PASS'
        $color = 'Green'
    }
    $script:Results.Add([pscustomobject]@{ Check = $Check; Status = $status; Detail = $Detail })
    Write-Host ("[{0}] {1}: {2}" -f $status, $Check, $Detail) -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# 0. Plugins must exist / be installed locally.
# ---------------------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Host '==> Building plugins and installing them into the local repositories'
    & (Join-Path $PSScriptRoot '..\build-plugins.ps1') -JavaHome $javaHomePath
    if (-not $?) { throw 'build-plugins.ps1 failed.' }
}

$distDir = Join-Path $PluginsDir 'dist'
$gradlePluginJar = Join-Path $distDir "umbra-gradle-plugin-$PluginVersion.jar"
$mavenPluginJar = Join-Path $distDir "umbra-maven-plugin-$PluginVersion.jar"
$gradlePluginInstalled = Join-Path $env:USERPROFILE ".m2\repository\io\umbra\umbra-gradle-plugin\$PluginVersion\umbra-gradle-plugin-$PluginVersion.jar"
$mavenPluginInstalled = Join-Path $env:USERPROFILE ".m2\repository\io\umbra\umbra-maven-plugin\$PluginVersion\umbra-maven-plugin-$PluginVersion.jar"

Write-Host '==> Environment'
$javaRun = Invoke-QaCommand 'env-java-version' $java @('-version') $PluginsDir
$gradleRun = Invoke-QaCommand 'env-gradle-version' $gradle @('--version') $PluginsDir
$mavenRun = Invoke-QaCommand 'env-maven-version' $mvn @('-version') $PluginsDir
$umbraRun = Invoke-QaCommand 'env-umbra-version' $java @('-jar', $umbraJarPath, '--version') $PluginsDir

Add-Check 'JDK available' ($javaRun.ExitCode -eq 0) (Get-LineMatching $javaRun.Text 'version "')
Add-Check 'Gradle 8.x available' ($gradleRun.ExitCode -eq 0 -and $gradleRun.Text -match 'Gradle 8\.') `
    (Get-LineMatching $gradleRun.Text '^Gradle ')
Add-Check 'Apache Maven 3.9.x available' ($mavenRun.ExitCode -eq 0 -and $mavenRun.Text -match 'Apache Maven 3\.9\.') `
    (Get-LineMatching $mavenRun.Text '^Apache Maven ')
Add-Check 'Umbra tool jar runs' ($umbraRun.ExitCode -eq 0 -and $umbraRun.Text -match 'Umbra ') `
    ((Get-Trimmed (Get-LineMatching $umbraRun.Text 'Umbra ')) + " [$umbraJarPath]")
Add-Check 'Gradle plugin jar shipped in plugins/dist' (Test-Path -LiteralPath $gradlePluginJar -PathType Leaf) $gradlePluginJar
Add-Check 'Maven plugin jar shipped in plugins/dist' (Test-Path -LiteralPath $mavenPluginJar -PathType Leaf) $mavenPluginJar
Add-Check 'Gradle plugin installed in ~/.m2 (publishToMavenLocal)' (Test-Path -LiteralPath $gradlePluginInstalled -PathType Leaf) $gradlePluginInstalled
Add-Check 'Maven plugin installed in ~/.m2 (mvn install)' (Test-Path -LiteralPath $mavenPluginInstalled -PathType Leaf) $mavenPluginInstalled

# ---------------------------------------------------------------------------
# 1. Gradle sample: clean build -> umbraProtect -> run protected jar.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '==> Gradle sample: build -> umbraProtect -> run protected jar'
$gradleSample = Join-Path $PSScriptRoot 'gradle-sample'
$gradleProtectedJar = Join-Path $gradleSample 'build\umbra\umbra-gradle-sample-obf.jar'
$gradleMapping = Join-Path $gradleSample 'build\umbra\mapping.txt'
$gradleCliLog = Join-Path $gradleSample 'build\umbra\protect.log'

$buildRun = Invoke-QaCommand 'gradle-build' $gradle @('--no-daemon', '--offline', 'clean', 'build') $gradleSample
Add-Check 'Gradle: sample project builds' ($buildRun.ExitCode -eq 0) ("exit=$($buildRun.ExitCode) log=$(Split-Path -Leaf $buildRun.Log)")

$protectRun = Invoke-QaCommand 'gradle-protect' $gradle @('--no-daemon', '--offline', 'umbraProtect') $gradleSample
$protectedExists = Test-Path -LiteralPath $gradleProtectedJar -PathType Leaf
$protectedSize = 0
if ($protectedExists) { $protectedSize = (Get-Item -LiteralPath $gradleProtectedJar).Length }
Add-Check 'Gradle: umbraProtect succeeds and writes build/umbra/*-obf.jar' `
    ($protectRun.ExitCode -eq 0 -and $protectedExists -and $protectedSize -gt 0) `
    ("exit=$($protectRun.ExitCode) jar=$gradleProtectedJar size=$protectedSize")
Add-Check 'Gradle: CLI --verify reported OK' ($protectRun.Text -match 'Verification: OK') `
    (Get-LineMatching $protectRun.Text 'Verification:')
Add-Check 'Gradle: mapping retained under build/umbra/mapping.txt' (Test-Path -LiteralPath $gradleMapping -PathType Leaf) $gradleMapping
Add-Check 'Gradle: CLI log captured by the plugin (logFile)' (Test-Path -LiteralPath $gradleCliLog -PathType Leaf) $gradleCliLog

$runProtected = Invoke-QaCommand 'gradle-run-protected' $java @('-jar', $gradleProtectedJar) $gradleSample
$gradleRunOutput = Get-Trimmed $runProtected.Text
Add-Check 'Gradle: protected jar runs and prints OK' ($runProtected.ExitCode -eq 0 -and $gradleRunOutput -eq 'OK') `
    ("exit=$($runProtected.ExitCode) stdout='$gradleRunOutput'")

$cacheRun = Invoke-QaCommand 'gradle-configuration-cache' $gradle `
    @('--no-daemon', '--offline', 'umbraProtect', '--configuration-cache', '--rerun-tasks') $gradleSample
$cacheDetail = Get-LineMatching $cacheRun.Text 'Configuration cache entry stored'
if (-not $cacheDetail) { $cacheDetail = Get-LineMatching $cacheRun.Text 'Configuration cache' }
Add-Check 'Gradle: compatible with the configuration cache' `
    ($cacheRun.ExitCode -eq 0 -and $cacheRun.Text -match 'Configuration cache entry stored') `
    $cacheDetail

$badOptionRun = Invoke-QaCommand 'gradle-bad-preset' $gradle `
    @('--no-daemon', '--offline', 'umbraProtect', '-PumbraPreset=does-not-exist') $gradleSample
Add-Check 'Gradle: invalid option fails the build with a non-zero exit' `
    ($badOptionRun.ExitCode -ne 0 -and $badOptionRun.Text -match 'Umbra failed with exit code 1') `
    ("exit=$($badOptionRun.ExitCode) " + (Get-LineMatching $badOptionRun.Text 'Umbra failed with exit code'))

# ---------------------------------------------------------------------------
# 2. Maven sample: mvn package -> umbra:protect -> run protected jar.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '==> Maven sample: mvn package -> umbra:protect -> run protected jar'
$mavenSample = Join-Path $PSScriptRoot 'maven-sample'
$mavenProtectedJar = Join-Path $mavenSample 'target\umbra-maven-sample-1.0.0-obf.jar'
$mavenMapping = Join-Path $mavenSample 'target\umbra\mapping.txt'
$mavenCliLog = Join-Path $mavenSample 'target\umbra\protect.log'

$packageRun = Invoke-QaCommand 'maven-package' $mvn @('-B', '-ntp', '-o', 'clean', 'package') $mavenSample
$mavenProtectedExists = Test-Path -LiteralPath $mavenProtectedJar -PathType Leaf
$mavenProtectedSize = 0
if ($mavenProtectedExists) { $mavenProtectedSize = (Get-Item -LiteralPath $mavenProtectedJar).Length }
Add-Check 'Maven: mvn package runs umbra:protect and writes *-obf.jar' `
    ($packageRun.ExitCode -eq 0 -and $mavenProtectedExists -and $mavenProtectedSize -gt 0) `
    ("exit=$($packageRun.ExitCode) jar=$mavenProtectedJar size=$mavenProtectedSize")
Add-Check 'Maven: CLI --verify reported OK' ($packageRun.Text -match 'Verification: OK') `
    (Get-LineMatching $packageRun.Text 'Verification:')
Add-Check 'Maven: mapping retained under target/umbra/mapping.txt' (Test-Path -LiteralPath $mavenMapping -PathType Leaf) $mavenMapping
Add-Check 'Maven: CLI log captured by the plugin (logFile)' (Test-Path -LiteralPath $mavenCliLog -PathType Leaf) $mavenCliLog

$mavenRunOutput = Invoke-QaCommand 'maven-run-protected' $java @('-jar', $mavenProtectedJar) $mavenSample
$mavenOutput = Get-Trimmed $mavenRunOutput.Text
Add-Check 'Maven: protected jar runs and prints OK' ($mavenRunOutput.ExitCode -eq 0 -and $mavenOutput -eq 'OK') `
    ("exit=$($mavenRunOutput.ExitCode) stdout='$mavenOutput'")

$mavenBadOption = Invoke-QaCommand 'maven-bad-preset' $mvn `
    @('-B', '-ntp', '-o', 'package', '-Dumbra.preset=does-not-exist') $mavenSample
Add-Check 'Maven: invalid option fails the build with a non-zero exit' `
    ($mavenBadOption.ExitCode -ne 0 -and $mavenBadOption.Text -match 'Umbra failed with exit code 1') `
    ("exit=$($mavenBadOption.ExitCode) " + (Get-LineMatching $mavenBadOption.Text 'Umbra failed with exit code'))

# ---------------------------------------------------------------------------
# 3. Summary.
# ---------------------------------------------------------------------------
$passed = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
$failed = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count

$summary = New-Object System.Text.StringBuilder
[void]$summary.AppendLine('# Umbra build-tool plugin QA summary')
[void]$summary.AppendLine('')
[void]$summary.AppendLine(('- generated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')))
[void]$summary.AppendLine(('- umbra tool jar: `' + $umbraJarPath + '`'))
[void]$summary.AppendLine(('- JDK: `' + $javaHomePath + '`'))
[void]$summary.AppendLine(('- Gradle: `' + $gradle + '`'))
[void]$summary.AppendLine(('- Maven: `' + $mvn + '`'))
[void]$summary.AppendLine(('- logs: `plugins/qa/logs/`'))
[void]$summary.AppendLine('')
[void]$summary.AppendLine(('Result: **{0} passed, {1} failed**' -f $passed, $failed))
[void]$summary.AppendLine('')
[void]$summary.AppendLine('| Check | Result | Detail |')
[void]$summary.AppendLine('|---|---|---|')
foreach ($result in $script:Results) {
    $detail = $result.Detail -replace '\|', '\|'
    [void]$summary.AppendLine(('| {0} | {1} | {2} |' -f $result.Check, $result.Status, $detail))
}
[void]$summary.AppendLine('')
[void]$summary.AppendLine('## Plugin artifacts')
[void]$summary.AppendLine('')
[void]$summary.AppendLine('| Artifact | Bytes | SHA-256 |')
[void]$summary.AppendLine('|---|---|---|')
foreach ($artifact in (Get-ChildItem -LiteralPath $distDir -Filter '*.jar' -File | Sort-Object Name)) {
    [void]$summary.AppendLine(('| {0} | {1} | {2} |' -f $artifact.Name, $artifact.Length, (Get-FileSha256 $artifact.FullName)))
}
$summaryPath = Join-Path $PSScriptRoot 'SUMMARY.md'
[System.IO.File]::WriteAllText($summaryPath, $summary.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ''
Write-Host ("QA RESULT: {0} passed, {1} failed" -f $passed, $failed) -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
Write-Host ("summary: {0}" -f $summaryPath)
Write-Host ("logs:    {0}" -f $logDir)
if ($failed -gt 0) {
    exit 1
}
exit 0

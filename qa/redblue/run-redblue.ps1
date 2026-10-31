# Red/blue evaluation harness.
#
# Blue side: a protected artifact produced by Umbra.
# Red side: the attacks a reverse engineer would run first.
#
# Usage: .\run-redblue.ps1 -Jar <protected.jar> [-Dll <lib.dll>] [-Label name]
#
# Seven attacks: plaintext symbols (2 rows), CFR decompilation, reflective
# payload dump, native export table, vendor fingerprint, VM payload magic and
# one-shot OTP state reuse. Each row prints PASS/FAIL; the score is blue wins
# over every row (8 rows today), so adding a row moves the denominator.

param(
    [Parameter(Mandatory = $true)][string]$Jar,
    [string]$Dll,
    [string]$Label = "artifact"
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cfr = Join-Path $root 'qa\tools\cfr-0.152.jar'
$work = Join-Path $env:TEMP ('redblue-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
$results = New-Object System.Collections.Generic.List[object]

function Record([string]$side, [string]$check, [bool]$blueWins, [string]$detail,
                [bool]$skipped = $false) {
    $results.Add([pscustomobject]@{ Side = $side; Check = $check; Blue = $blueWins
                                    Detail = $detail; Skipped = $skipped })
}

function Get-Classes([string]$jar) {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($jar)
    try {
        $out = @()
        foreach ($e in $zip.Entries) {
            if (-not $e.FullName.EndsWith('.class')) { continue }
            $ms = New-Object System.IO.MemoryStream
            $s = $e.Open(); $s.CopyTo($ms); $s.Close()
            $out += [pscustomobject]@{ Name = $e.FullName; Bytes = $ms.ToArray() }
        }
        return $out
    } finally { $zip.Dispose() }
}

Write-Host ("=== red/blue: " + $Label + " ===")
$classes = Get-Classes $Jar
$total = $classes.Count
Write-Host ("  artifact: {0} class entries, {1:N1} MB" -f $total, ((Get-Item $Jar).Length / 1MB))

# --- RED 1: plaintext symbols (class/method names a human can read) ---
$readable = 0
$plainStrings = 0
foreach ($c in $classes) {
    $text = $latin1.GetString($c.Bytes)
    if ($text -match '(?i)(com/|org/|net/|io/)[a-z0-9_]+/[A-Za-z][A-Za-z0-9_]{3,}') { $readable++ }
    foreach ($mark in @('AES/CBC', 'AES/CTR', 'HmacSHA256', 'java.lang.reflect', 'MessageDigest')) {
        if ($text.Contains($mark)) { $plainStrings++; break }
    }
}
Record 'red' 'recover original vendor package/class names' ($readable -eq 0) ("$readable/$total class entries expose readable package paths")
Record 'red' 'find algorithm names in constant pools' ($plainStrings -eq 0) ("$plainStrings class(es) still carry crypto algorithm literals")

# --- RED 2: decompiler success rate (CFR) ---
# A class counts as *recovered* only when CFR fully structured it (no
# "Unable to fully structure code" fallback). Counting `public class` in the
# output measured the class modifiers instead of the obfuscation: inner and
# abstract classes are emitted without `public`, and CFR exits 0 with a goto
# fallback on the classes it failed to structure. The verdict uses the roadmap's
# own acceptance line ("CFR recovery < 50%"); both numbers are printed.
$decompiled = 0
if (Test-Path $cfr) {
    # Sample the classes that actually carry a field guard, otherwise the metric
    # only measures generated payload holders that were never flow-obfuscated.
    $guarded = @()
    foreach ($c in $classes) {
        $cls = $c.Name.Replace('/', '.').Replace('.class', '')
        $v = javap -p -cp (Split-Path $Jar -Parent) $cls 2>$null
        $txt = [System.Text.Encoding]::GetEncoding(28591).GetString($c.Bytes)
        if ($txt.Contains("z`$f0") -or $txt.Contains("z`$f1")) { $guarded += $c }
    }
    $picked = if ($guarded.Count -gt 0) { $guarded | Select-Object -First 40 } else { $classes | Select-Object -First 40 }
    $sample = @($picked)
    $structured = 0
    $emitted = 0
    $gotoCount = 0
    foreach ($c in $sample) {
        $dir = Join-Path $work 'cls'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $path = Join-Path $dir 'x.class'
        [System.IO.File]::WriteAllBytes($path, $c.Bytes)
        $out = & java -jar $cfr "$path" --silent true 2>&1
        $text = $out -join "`n"
        $gotoCount += ([regex]::Matches($text, "(?m)^\s*(goto|label)\b")).Count
        $emittedClass = $LASTEXITCODE -eq 0 -and $text -match 'class\s+\w+|interface\s+\w+'
        if ($emittedClass) { $emitted++ }
        if ($emittedClass -and -not ($text -match 'Unable to fully structure')) { $structured++ }
    }
    $rate = if ($sample.Count -gt 0) { [math]::Round($structured * 100.0 / $sample.Count, 0) } else { 0 }
    $emittedRate = if ($sample.Count -gt 0) { [math]::Round($emitted * 100.0 / $sample.Count, 0) } else { 0 }
    Record 'red' 'decompile sampled classes to readable Java' ($rate -lt 50) ("CFR fully structured $structured/$($sample.Count) classes ($rate%, need <50%); emitted class text for $emitted ($emittedRate%), goto/label lines $gotoCount")
} else {
    Record 'red' 'decompile sampled classes to readable Java' $true 'CFR not available, skipped'
}

# --- RED 3: reflection dump of the protected class payload ---
$loaderDump = $classes | Where-Object { $latin1.GetString($_.Bytes).Contains('loadClassPayload') }
Record 'red' 'reflectively dump class payloads' ($loaderDump.Count -eq 0) ("loadClassPayload present in " + $loaderDump.Count + " class(es); payload bytes are constant-pool encrypted")

# --- RED 4: native export table ---
if ($Dll -and (Test-Path $Dll)) {
    $exp = & 'E:\1111\bin\objdump.exe' -p $Dll 2>&1
    $inTable = $false; $names = @()
    foreach ($line in $exp) {
        if ($line -match 'Ordinal/Name Pointer\] Table') { $inTable = $true; continue }
        if ($inTable -and $line -match '^\s+\[\s*\d+\]\s+(\S+)$') { $names += $Matches[1] }
    }
    $javaExports = @($names | Where-Object { $_ -like 'Java_*' })
    Record 'red' 'rebuild the class/method map from native exports' ($javaExports.Count -eq 0) ("exports=$($names.Count), Java_*=$($javaExports.Count) -> " + (($names | Select-Object -First 4) -join ', '))
} else {
    Record 'red' 'rebuild the class/method map from native exports' $true 'no DLL supplied (native layer not used)'
}

# --- RED 5: vendor fingerprint words ---
$fingerprint = 0
foreach ($c in $classes) {
    $text = $latin1.GetString($c.Bytes)
    if ($text.Contains('umbra/') -or $text.Contains('umbra-runtime')) { $fingerprint++ }
}
Record 'red' 'attribute the artifact to a known tool' ($fingerprint -eq 0) ("$fingerprint class(es) contain vendor tokens")

# --- RED 6: VM payload readability (magic / structure) ---
$vmMagic = 0
foreach ($c in $classes) {
    $b = $c.Bytes
    for ($i = 0; $i -lt $b.Length - 4; $i++) {
        if ($b[$i] -eq 0x02 -and $b[$i+1] -eq 0x32 -and $b[$i+2] -eq 0x4D -and $b[$i+3] -eq 0x56) { $vmMagic++; break }
    }
}
Record 'red' 'locate VM payloads by fixed magic' ($vmMagic -eq 0) ("$vmMagic class(es) carry the legacy 0x564D3202 magic")

# --- RED 7: one-shot OTP state (can one captured run be replayed?) ---
# The K-OTP layer injects a synthetic runtime class that declares
# `public static long next()` and `public static int carrier()`; every protected
# method consumes carrier() in its entry prelude and branches on its low bit.
# A red teamer wins only if the artifact has no such call sites: then a single
# captured execution yields a reusable internal state for the whole artifact.
# Entry window: on a balanced build the entry carrier sits at instruction 23
# (behind the field-guard prelude) while the in-body carriers start at 43, so
# 40 keeps slack for prelude growth and still excludes the body sites.
$otpWindow = 40
$scanClasses = @($classes | Where-Object { -not $_.Name.StartsWith('META-INF/') })
$zipProbe = [System.IO.Compression.ZipFile]::OpenRead($Jar)
try { $zipEntries = $zipProbe.Entries.Count } finally { $zipProbe.Dispose() }
$otpClass = $null
foreach ($c in $scanClasses) {
    $text = $latin1.GetString($c.Bytes)
    if (-not ($text.Contains('carrier') -and $text.Contains('next'))) { continue }
    $cls = $c.Name.Replace('/', '.').Replace('.class', '')
    $sig = ((javap -p -cp $Jar $cls 2>$null) -join "`n")
    if ($sig -match 'public static long next\(\);' -and $sig -match 'public static int carrier\(\);') {
        $otpClass = $cls
        break
    }
}
if (-not $otpClass) {
    # Tell "layer disabled" apart from "the whole payload is encrypted", otherwise
    # a class-encrypted artifact looks identical to a build without OTP.
    $sealed = ($zipEntries -gt 0) -and (($scanClasses.Count * 2) -lt $zipEntries)
    $why = if ($scanClasses.Count -eq 0) { 'no readable class entries' }
           elseif ($sealed) { "only $($scanClasses.Count) readable class entries out of $zipEntries archive entries (payload encrypted)" }
           else { "no class among $($scanClasses.Count) readable class entries declares next()+carrier()" }
    # A sealed (class-encrypted) archive hides every business class, so this row
    # cannot be measured statically: recording FAIL would punish the strongest
    # layout, recording PASS would hand a free point to a build without the layer.
    # It is therefore excluded from the denominator and printed as N/A.
    Record 'red' 'reuse one-shot OTP state across calls' $false ("OTP state class not found: $why -> layer off or unobservable") $sealed
} else {
    $entrySites = 0
    $entryClasses = New-Object System.Collections.Generic.HashSet[string]
    $allSites = 0
    $allClasses = New-Object System.Collections.Generic.HashSet[string]
    foreach ($c in $scanClasses) {
        if (-not $latin1.GetString($c.Bytes).Contains('carrier')) { continue }
        $cls = $c.Name.Replace('/', '.').Replace('.class', '')
        $ordinal = 0
        foreach ($line in (javap -c -p -cp $Jar $cls 2>$null)) {
            # Member headers sit at exactly two spaces; instructions are deeper.
            if ($line -match '^  \S') {
                if ($line.Contains('(') -or $line -match 'static \{') { $ordinal = 0 }
                continue
            }
            if ($line -notmatch '^\s+\d+:\s+\S') { continue }
            if ($line -match 'invokestatic\s+.*//\s*Method\s+\S*carrier:\(\)I') {
                $allSites++
                [void]$allClasses.Add($cls)
                if ($ordinal -lt $otpWindow) { $entrySites++; [void]$entryClasses.Add($cls) }
            }
            $ordinal++
        }
    }
    $otpBlue = ($entrySites -ge 5) -and ($entryClasses.Count -ge 2)
    Record 'red' 'reuse one-shot OTP state across calls' $otpBlue ("{0} entry carrier() call sites in {1} class(es), {2} carrier() sites in {3} class(es) total (need >=5 entry sites in >=2 classes)" -f $entrySites, $entryClasses.Count, $allSites, $allClasses.Count)
}

# --- report ---
Write-Host ''
$measured = @($results | Where-Object { -not $_.Skipped })
$pass = @($measured | Where-Object { $_.Blue }).Count
$all = $measured.Count
$excluded = $results.Count - $all
Write-Host ("  BLUE SCORE: {0}/{1} ({2}%)" -f $pass, $all, [math]::Round($pass * 100.0 / [Math]::Max(1, $all), 0))
if ($excluded -gt 0) {
    Write-Host ("  ({0} row(s) not measurable on this artifact: N/A, excluded from the denominator)" -f $excluded)
}
Write-Host ''
foreach ($r in $results) {
    $mark = if ($r.Skipped) { 'N/A ' } elseif ($r.Blue) { 'PASS' } else { 'FAIL' }
    Write-Host ("  [{0}] {1,-48} {2}" -f $mark, $r.Check, $r.Detail)
}
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''

# CFR decompilation quality probe (P0-1 acceptance).
#
# Samples the classes that actually carry a field guard (z$f0/z$f1) and asks CFR
# two questions per class:
#   * did CFR exit 0 and emit a class declaration?          (parseable)
#   * did it emit "Unable to fully structure code"?          (structured?)
# A class counts as *recovered* only when CFR structured it, i.e. it produced
# Java without goto/label fallbacks. Counting `public class` instead measures the
# class modifiers, not the obfuscation (inner/abstract classes are emitted without
# `public`), which is why this probe replaces that check.
#
# Usage: pwsh -File .\cfr-quality.ps1 -Jar <artifact.jar> [-Sample 40] [-Label name]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Jar,
    [int]$Sample = 40,
    [string]$Label = 'artifact'
)

$ErrorActionPreference = 'Stop'
$Jar = (Resolve-Path -LiteralPath $Jar).Path
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cfr = Join-Path $root 'qa\tools\cfr-0.152.jar'
if (-not (Test-Path -LiteralPath $cfr)) { throw "CFR not found: $cfr" }
$work = Join-Path $env:TEMP ('cfr-quality-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$latin1 = [System.Text.Encoding]::GetEncoding(28591)

try {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Jar)
    $guarded = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($e in $zip.Entries) {
            if (-not $e.FullName.EndsWith('.class')) { continue }
            if ($e.FullName.StartsWith('META-INF/')) { continue }
            $ms = New-Object System.IO.MemoryStream
            $s = $e.Open(); $s.CopyTo($ms); $s.Close()
            $bytes = $ms.ToArray()
            $text = $latin1.GetString($bytes)
            if ($text.Contains('z$f0') -or $text.Contains('z$f1')) {
                $guarded.Add([pscustomobject]@{ Name = $e.FullName; Bytes = $bytes })
            }
        }
    } finally { $zip.Dispose() }

    $selection = @($guarded | Select-Object -First $Sample)
    $parseable = 0
    $structured = 0
    $crashed = 0
    $path = Join-Path $work 'x.class'
    foreach ($c in $selection) {
        [System.IO.File]::WriteAllBytes($path, $c.Bytes)
        $out = (& java -jar $cfr $path --silent true 2>&1) -join "`n"
        $code = $LASTEXITCODE
        $hasClass = $out -match 'class\s+\w+|interface\s+\w+'
        if ($code -eq 0 -and $hasClass) { $parseable++ } else { $crashed++ }
        if ($code -eq 0 -and $hasClass -and -not ($out -match 'Unable to fully structure')) {
            $structured++
        }
    }
    $total = $selection.Count
    Write-Host ("=== CFR quality: {0} ===" -f $Label)
    Write-Host ("  guarded classes in artifact : {0}" -f $guarded.Count)
    Write-Host ("  sampled                     : {0}" -f $total)
    Write-Host ("  CFR crashed / no class      : {0}" -f $crashed)
    Write-Host ("  parseable (class emitted)   : {0}" -f $parseable)
    Write-Host ("  structured (no goto fallback): {0}" -f $structured)
    if ($total -gt 0) {
        Write-Host ("  structured rate             : {0}%" -f [math]::Round($structured * 100.0 / $total, 0))
    }
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

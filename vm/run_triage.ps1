<#
  Static triage runner -- runs INSIDE the analysis VM.
  Auto-detects the IDA headless binary (ida 9.x: idat.exe / 8.x: idat64.exe).

  .\run_triage.ps1 -Sample C:\samples\x.bin [-Out C:\triage\out] [-MaxDecompile 60]

  The sample is NEVER executed. IDA only parses it.
#>
param(
  [Parameter(Mandatory = $true)][string]$Sample,
  [string]$Out = "C:\triage\out",
  [int]$MaxDecompile = 60,
  [string]$IdaDir = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Sample)) { throw "sample not found: $Sample" }

# ---- locate IDA
$candidates = @()
if ($IdaDir) { $candidates += $IdaDir }
$candidates += @(
  "C:\Program Files\IDA Professional 9.2", "C:\Program Files\IDA Professional 9.1",
  "C:\Program Files\IDA Professional 9.0", "C:\Program Files\IDA Pro 9.0",
  "C:\Program Files\IDA Pro 8.4", "C:\Program Files\IDA Pro 8.3",
  "C:\Program Files\IDA Pro 8.2", "C:\Program Files\IDA 9.2", "C:\Program Files\IDA 9.1"
)
$candidates += (Get-ChildItem "C:\Program Files","C:\Program Files (x86)" -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^IDA' } | ForEach-Object { $_.FullName })

$ida = $null
foreach ($d in ($candidates | Select-Object -Unique)) {
  foreach ($exe in @("idat.exe", "idat64.exe")) {
    $p = Join-Path $d $exe
    if (Test-Path $p) { $ida = $p; break }
  }
  if ($ida) { break }
}
if (-not $ida) { throw "could not find idat.exe / idat64.exe -- pass -IdaDir explicitly" }
Write-Host "[runner] IDA     : $ida"

$script = Join-Path $PSScriptRoot "dump_static.py"
if (-not (Test-Path $script)) { throw "dump_static.py not found next to this runner" }

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$log = Join-Path $Out "ida.log"
$env:TRIAGE_MAX_DECOMPILE = "$MaxDecompile"

# work on a copy so the original sample and its .i64 stay untouched
$work = Join-Path $Out "work"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$copy = Join-Path $work ([System.IO.Path]::GetFileName($Sample))
Copy-Item $Sample $copy -Force

Write-Host "[runner] sample  : $copy"
Write-Host "[runner] out     : $Out"
Write-Host "[runner] running headless analysis (this can take a while on large binaries)..."

$sw = [Diagnostics.Stopwatch]::StartNew()
& $ida -A -S"`"$script`" `"$Out`"" -L"$log" $copy
$code = $LASTEXITCODE
$sw.Stop()

Write-Host "[runner] exit=$code elapsed=$([int]$sw.Elapsed.TotalSeconds)s"
if (Test-Path $log) {
  Write-Host "[runner] --- IDA log tail ---"
  Get-Content $log -Tail 25
}

foreach ($f in @("meta.json", "functions.json", "strings.json", "api_map.json", "callgraph.json")) {
  $p = Join-Path $Out $f
  if (Test-Path $p) {
    Write-Host ("[runner] OK  {0,-18} {1,10:N0} bytes" -f $f, (Get-Item $p).Length)
  } else {
    Write-Host "[runner] MISSING $f"
  }
}
$pc = Join-Path $Out "pseudocode"
if (Test-Path $pc) {
  Write-Host "[runner] OK  pseudocode/      $((Get-ChildItem $pc -File).Count) functions"
}

# ---- optional: capa (structured capability list, great for the agent)
$capa = (Get-Command capa.exe -ErrorAction SilentlyContinue).Source
if ($capa) {
  Write-Host "[runner] running capa..."
  & $capa -j $copy | Out-File -FilePath (Join-Path $Out "capa.json") -Encoding utf8
  Write-Host "[runner] OK  capa.json"
} else {
  Write-Host "[runner] capa.exe not on PATH -- skipping (optional)"
}

# ---- optional: FLOSS (deobfuscated / stack strings)
$floss = (Get-Command floss.exe -ErrorAction SilentlyContinue).Source
if ($floss) {
  Write-Host "[runner] running floss..."
  & $floss -j $copy | Out-File -FilePath (Join-Path $Out "floss.json") -Encoding utf8
  Write-Host "[runner] OK  floss.json"
} else {
  Write-Host "[runner] floss.exe not on PATH -- skipping (optional)"
}

Write-Host ""
Write-Host "[runner] DONE. Copy ONLY these text/JSON artifacts to the host:"
Write-Host "         $Out\*.json  and  $Out\pseudocode\"
Write-Host "[runner] DO NOT copy $work (it holds the sample) back to the host."

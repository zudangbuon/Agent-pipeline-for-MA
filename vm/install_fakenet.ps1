<#
install_fakenet.ps1 -- unpack the FakeNet-NG bundle inside the guest.

Pushed and invoked by `host/mal.py setup-guest`. That call happens AFTER detonate's
pre-run revert, so whatever this script installs survives the revert and the
known-good baseline snapshot (clean-nodefender) never has to be retaken to add
tooling -- there is only one copy of it.

Contract with detonate.ps1: on success, and ONLY on success, write the full path of
fakenet.exe to <Dest>\fakenet_path.txt. detonate.ps1 reads that marker; if it is
absent the run records fakenet=False and says so, rather than reporting a fake
internet that is not actually running. An unnoticed FakeNet failure turns "zero DNS,
zero TCP" from a statement about the sample into a statement about the
instrumentation -- which is the mistake this marker exists to prevent.

This script unpacks an archive. It does not run anything out of it.
#>
param(
  [Parameter(Mandatory = $true)][string]$Zip,
  [Parameter(Mandatory = $true)][string]$Dest
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$marker = Join-Path $Dest "fakenet_path.txt"

try {
  if (Test-Path -LiteralPath $marker) {
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  }
  if (-not (Test-Path -LiteralPath $Zip)) { throw "zip not found: $Zip" }
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null

  if (-not (Get-Command Expand-Archive -ErrorAction SilentlyContinue)) {
    # Expand-Archive needs PowerShell 5+. An XP/PS2 guest reaches this line, and
    # failing loudly here is better than a silent fakenet=False three steps later.
    throw "Expand-Archive is unavailable (PowerShell $($PSVersionTable.PSVersion)) -- " +
          "unpack the bundle into $Dest by hand and re-run setup-guest"
  }
  Expand-Archive -LiteralPath $Zip -DestinationPath $Dest -Force

  $exe = Get-ChildItem -Path $Dest -Filter fakenet.exe -Recurse -File -ErrorAction Stop |
         Select-Object -First 1
  if (-not $exe) { throw "no fakenet.exe under $Dest after extraction" }

  $cfg = Join-Path $exe.DirectoryName "configs\default.ini"
  if (-not (Test-Path -LiteralPath $cfg)) {
    Write-Output "WARNING: $cfg missing -- FakeNet will fall back to built-in defaults"
  }

  Set-Content -LiteralPath $marker -Value $exe.FullName -Encoding ascii
  Write-Output "fakenet.exe: $($exe.FullName)"
  Write-Output "marker     : $marker"
  exit 0
} catch {
  Write-Output "fakenet install FAILED: $($_.Exception.Message)"
  if (Test-Path -LiteralPath $marker) {
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  }
  exit 1
}

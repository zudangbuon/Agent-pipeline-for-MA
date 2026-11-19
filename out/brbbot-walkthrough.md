# brbbot.exe — static (host) → dynamic (VM), with evidence capture flow

Sample: `samples-host/for610/day1/brbbot.exe` (FOR610 day1)
Static tag: `out/static/brbbot-static` (re-verified as `brbbot-verify`, identical counts + sha)
Dynamic run cited: `out/dynamic/brbbot.exe-20261106-112802` (mode full, timeout 90s)

Every claim below cites an address, an artifact line, or a hash. Where something is
inferred rather than observed it says so.

---

# PART A — Static results (ran on the host, Ghidra parses, never executes)

## A.1 BACKGROUND + STATIC/File Hash

| Template row | Value |
|---|---|
| File Name | `brbbot.exe` |
| File Location | `samples-host/for610/day1/brbbot.exe` |
| File Size | **75,776** bytes |
| File Timestamps | created `2016-09-20 17:10:09 UTC`, modified `2015-02-25 06:12:18 UTC` |
| MD5 | `1c7243c8f3586b799a5f9a2e4200aa92` |
| SHA1 | `4db5a8e237937b6d7b435a8506b8584121a7e9e3` |
| SHA256 | `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e` |
| Imp Hash | `475b069fec5e5868caeb7d4d89236c89` (source: pefile) |
| Compile Time | `2015-02-25 06:12:18 UTC` (raw `1424844738`, `0x54ed67c2`) |
| Icon Graphic | **none** — no icon resource, shows the generic Windows default |
| Signed? | **no** — no Authenticode certificate |
| File Properties | VERSIONINFO **empty**, no manifest, subsystem GUI, linker 10.0, machine x86-64, characteristics `0x0022` (`EXECUTABLE_IMAGE`, `LARGE_ADDRESS_AWARE`), imagebase `0x140000000`, entry `0x140003f94` |

**Compile time is plausible, not faked.** It equals the file's own mtime to the second
(`2015-02-25 06:12:18`), and sits with the rest of the 2015-era FOR610 material. Compare
against siblings in the collection, not against absolute plausibility — `Lab01-04.exe`
in the PMA set claims 2019 and is faked even though 2019 is in the past.

**This sample is 64-bit.** `machine = x86-64`, imagebase `0x140000000`. That matters for
the dynamic side: it runs natively on the Win10 x64 guest, unlike the PMA labs.

## A.2 STATIC/Packed + Entropy — not packed

| Section | Raw size | Entropy | x | w |
|---|---|---|---|---|
| `.text` | 50,176 | 6.349 | yes | no |
| `.rdata` | 14,848 | 4.760 | no | no |
| `.data` | 5,120 | 1.973 | no | yes |
| `.pdata` | 3,072 | 4.505 | no | no |
| `.rsrc` | 512 | 1.868 | no | no |
| `.reloc` | 1,024 | 2.555 | no | no |

File entropy 5.918. Entropy source is **`pe_meta` (raw file bytes)** — confirm the
`q.py summary` header says this. Ghidra's own numbers are measured over the zero-padded
virtual block and read far too low on a packed section (`UPX1` reads 3.378 virtual vs
**7.067** raw).

`q.py pack_signals()` is silent: 115 imports, 225 recovered functions, max entropy 6.349,
`.data` smaller and sparser than `.text`. No packing on any of the structural grounds.

## A.3 STATIC/Imported Functions

`ADVAPI32.DLL` 14 · `KERNEL32.DLL` 86 · `USER32.DLL` 1 · `WININET.DLL` 9 · `WS2_32.DLL` 5
— 115 symbols total, 5 of them imported by ordinal. No exports.

Capability-bearing imports:

- **persist** — `RegOpenKeyExA`, `RegSetValueExA`
- **crypto** — `CryptAcquireContextW`, `CryptCreateHash`, `CryptHashData`, `CryptDeriveKey`, `CryptEncrypt`, `CryptDecrypt`
- **network** — `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `WSAStartup`, `gethostname`, `gethostbyname`, `inet_ntoa`
- **exec** — `CreateProcessA`
- **dynresolve** — `GetModuleHandleA/W`, `GetProcAddress`, `LoadLibraryW`
- **antianalysis** — `IsDebuggerPresent`, `GetTickCount`, `QueryPerformanceCounter`, `Sleep`

## A.4 STATIC/Strings — and a tagging trap to avoid

Real, citable strings:

| Address | String |
|---|---|
| `0x14000fdf8` | `CONFIG` |
| `0x14000fe00` | `brbconfig.tmp` |
| `0x14000fe10` | `YnJiYm90` |
| `0x14000fe48` | `encode` |
| `0x14000fe78` | `APPDATA` |
| `0x14000fe80` | `Software\Microsoft\Windows\CurrentVersion\Run` |
| `0x14000feb0` | `brbbot` |
| `0x14000fec0` | `Microsoft Enhanced Cryptographic Provider v1.0` |
| `0x14000ff30` | `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)` |
| `0x14000ff70` | `HTTP/1.1` |
| `0x14000ff80` | `Connection: close\r\n` |
| `0x14000ff98` | `ZwQuerySystemInformation` |
| `0x14000ffb8` | `ntdll.dll` |
| `0x14000ffc8` | `Idle` |

**Do not cite these tags as findings.** `q.py` tagged `'CryptDecrypt'` (`0x140011116`)
as `ransom` and `'ZwQuerySystemInformation'`, `'GetSystemDirectoryA'`,
`'GetSystemWow64DirectoryA'`, `'GetSystemTimeAsFileTime'` as `regkey`. Everything from
`0x140011052` upward is the **import name table**, not data the malware uses as a key path
or a ransom note. The tag is a hint; confirm the use site before citing it. The only
genuine `regkey` string is `0x14000fe80`.

## A.5 CODE ANALYSIS — persistence, fully citable

`FUN_140002230` (score 17, 785 bytes, 4 xrefs, called by `FUN_1400027c0`):

| Address | Call | Meaning |
|---|---|---|
| `0x14000230a` | `GetEnvironmentVariableA("APPDATA", …)` | resolve `%APPDATA%` |
| `0x1400023e2` | `CopyFileA(own path → %APPDATA%\brbbot.exe, 0)` | self-copy |
| `0x140002432` | `RegOpenKeyExA(0x80000002, "Software\Microsoft\Windows\CurrentVersion\Run", 0, 0x20006)` | **HKLM** Run key, `KEY_WRITE\|KEY_READ` |
| `0x14000247a` | `RegSetValueExA(hKey, "brbbot", 0, 1, lpData, …)` | value name `brbbot`, type `1` = `REG_SZ` |
| — | `MoveFileExA(own path, NULL, 4)` | `MOVEFILE_DELAY_UNTIL_REBOOT` → self-delete on reboot |
| — | `MoveFileExA("brbconfig.tmp", NULL, 4)` | config also deleted on reboot |

`0x80000002` is `HKEY_LOCAL_MACHINE` (sign-extended in the decompiler output as
`0xffffffff80000002`). The two `MoveFileExA(…, NULL, 4)` calls are what land in
`PendingFileRenameOperations`.

## A.6 CODE ANALYSIS — the config is RC4, and the key is in the binary

Two functions share one key derivation:

- `FUN_140002940` — writes: `CreateFileA("brbconfig.tmp", 2 /*WRITE*/, …)` … `CryptEncrypt`
- `FUN_140002c50` — reads: `CreateFileA("brbconfig.tmp", 1 /*READ*/, …)` … `CryptDecrypt`

```
CryptAcquireContextW(…, L"Microsoft Enhanced Cryptographic Provider v1.0", 1, …)
CryptCreateHash(hProv, 0x8003, 0, 0, &hHash)      // 0x8003 = CALG_MD5
CryptHashData(hHash, "YnJiYm90", 8, 0)            // passphrase, 8 bytes, hardcoded
CryptDeriveKey(hProv, 0x6801, hHash, 0x800000, …) // 0x6801 = CALG_RC4, 128-bit
```

128-bit RC4 derived from an MD5 hash takes the whole 16-byte digest, so the key is
exactly `MD5("YnJiYm90")` = `e2834a5bba1c28b7f536bd3ec5f1d8e0`.
(`YnJiYm90` is base64 for `brbbot` — inference, not needed for the decrypt.)

**The initial config ships as a PE resource.** `pe_meta` reports one resource:
type `CONFIG`, id `101`, rva `0x17070`, size **73**. `FUN_140001150` writes it out
(`GetModuleHandleA` → `FindResourceA` → `SizeofResource` → `LoadResource` → `LockResource`
→ `CreateFileA` → `WriteFile`).

Decrypting that resource on the host with the recovered key:

```
cipher    b89cc3aadf98671166abfe2379076e17f3b7447cdd2afa3079564c75a276717d
          72913a1ada028e81e3273cc2367cc048a017eddc01442d952c1d123c88bfce2d
          6bc0611646b50c1692
plaintext uri=ads.php;exec=cexe;file=elif;conf=fnoc;exit=tixe;encode=5b;sleep=30000
```

| Field | Value | Reading |
|---|---|---|
| `uri` | `ads.php` | C2 request path |
| `exec` | `cexe` | command keyword — run a payload |
| `file` | `elif` | command keyword — file transfer |
| `conf` | `fnoc` | command keyword — update config |
| `exit` | `tixe` | command keyword — terminate |
| `encode` | `5b` | encoding marker, `0x5b` |
| `sleep` | `30000` | beacon interval, 30 s |

The four command keywords are their own names reversed (`exec`→`cexe`, `file`→`elif`,
`conf`→`fnoc`, `exit`→`tixe`) — that is the C2 command vocabulary, recovered without
running anything.

## A.7 CODE ANALYSIS — network, and the one thing static cannot give

- `FUN_140002f50` — `InternetOpenA(UA, 1, …)` with the MSIE 8.0 user-agent at
  `0x14000ff30`, then `InternetSetOptionA`, then
  `InternetConnectA(hInternet, param_1, port, 0, 0, 3, 0, 0)`.
  Service type `3` = `INTERNET_SERVICE_HTTP`.
- `FUN_140003030` — `HttpOpenRequestA` / `HttpSendRequestA` / `HttpQueryInfoA`; this is
  where `uri=ads.php` is used.
- `FUN_140001840` — `InternetQueryDataAvailable` / `InternetReadFile`; reads the reply.
- `FUN_140001770` — `gethostname` → `gethostbyname` → `inet_ntoa`: collects the **victim's
  own** hostname and IP, not the C2's.

**No C2 hostname exists in the binary or in the config.** There is no domain-shaped string
anywhere in the 209 strings, and the decrypted config carries only the URI path. The host
reaches `InternetConnectA` as `param_1`, and `FUN_140002f50` has **0 callers** in the
callgraph, so the call path is unresolved statically (indirect call, or Ghidra did not
recover it). Recovering the host needs either a responding C2 or a network simulator.

## A.8 Other capabilities

- `FUN_140003100` — `GetTempPathA` → `GetTempFileNameA` → `CreateFileA` → `WriteFile` →
  `CreateProcessA` → `MoveFileExA`: writes a payload to `%TEMP%` and executes it. This is
  the `exec=cexe` command path. *(inferred link between the two, from the keyword)*
- `FUN_140003300` — `GetModuleHandleA("ntdll.dll")` + `GetProcAddress("ZwQuerySystemInformation")`:
  resolves a process-enumeration syscall at runtime rather than importing it. The `Idle`
  string at `0x14000ffc8` is consistent with walking a process list.
- Anti-analysis imports are present (`IsDebuggerPresent`, `GetTickCount`,
  `QueryPerformanceCounter`) but 7 of the functions tagged `antianalysis` are MSVCRT —
  `__security_init_cookie` at `0x140008994` is the CRT, not malware logic. Check the caller
  chain before walking a function whose only calls are `GetSystemTimeAsFileTime` /
  `GetCurrentProcessId` / `GetTickCount` / `QueryPerformanceCounter`.

---

# PART B — Screenshot checklist, static

Reproduce the analysis on the host, then capture these. Run first:

```bash
set JAVA_HOME=D:\tools\jdk\jdk-25.0.5+8
```

```bash
set GHIDRA_INSTALL_DIR=D:\tools\ghidra\ghidra_12.2_PUBLIC
```

```bash
python host/ghidra_dump.py "..\samples-host\for610\day1\brbbot.exe" out\static\brbbot-static
```

```bash
python host/pe_meta.py "..\samples-host\for610\day1\brbbot.exe" --json out\static\brbbot-static\pe_meta.json
```

Then open the same binary in the Ghidra GUI and capture:

| # | Where in Ghidra | Capture | Template row |
|---|---|---|---|
| 1 | — | terminal showing `ghidra_dump.py` + `pe_meta.py` completing | method/tooling |
| 2 | `Window → Memory Map` | the 6 sections with sizes and R/W/X flags | Packed + Entropy |
| 3 | `Symbol Tree → Imports`, expand all 5 DLLs | the import tree | Imported Functions |
| 4 | `Window → Defined Strings`, filter `brb` | `brbconfig.tmp`, `brbbot`, `YnJiYm90`, `CONFIG` | Strings |
| 5 | `Window → Defined Strings`, filter `Software\` | the Run key string | Strings |
| 6 | `G` → `140002230`, Decompile window | `GetEnvironmentVariableA`/`CopyFileA`/`RegOpenKeyExA`/`RegSetValueExA` visible | Persistence |
| 7 | `G` → `140002c50`, Decompile window | `CryptHashData(…,"YnJiYm90",8,0)` + `CryptDeriveKey(…,0x6801,…)` | Code Analysis |
| 8 | `G` → `140002f50`, Decompile window | `InternetOpenA` with the user-agent, `InternetConnectA` | Network Artifacts |
| 9 | `G` → `140003030`, Decompile window | `HttpOpenRequestA` / `HttpSendRequestA` | Network Artifacts |
| 10 | `G` → `140001150`, Decompile window | the `FindResourceA`→`WriteFile` resource drop | Code Analysis |
| 11 | terminal | the config decrypt output (cipher → plaintext) | Network Artifacts |

In the Listing window press `G` and type the address **without** `0x`.

Shot 11 has no GUI equivalent — run the decrypt and screenshot the terminal. The script is
at `out/decrypt_brbconfig.py` (see Part D.4).

`q.py plan` regenerates this walkthrough from the artifacts at any time:

```bash
set TRIAGE_OUT=out\static\brbbot-static
```

```bash
python host/q.py plan
```

---

# PART C — Dynamic results (VMware), and how they corroborate static

**Two runs, and they disagree.** Same sample, same snapshot, same `--mode full`. The
only difference is privilege, and it changes the headline finding, so both are reported.

| | Run A | Run B |
|---|---|---|
| tag | `brbbot.exe-20261106-112802` | `brbbot.exe-20261107-131857` |
| timeout | 90 s | 120 s |
| **elevated** | **True** | **False** |
| launched pid | 784 | 4528 |
| still alive at timeout | no (`killed: []`) | **yes** (`killed: [4528]`) |
| `dropped_new` | 2 | 1 |
| `reg_new` | **1** | **0** |
| `new_processes` | 4 | 9 |
| procmon rows | 384,834 → 92,553 | 1,297,780 → 169,408 |
| persistence | **HKLM Run key written** | **none in the diff** |
| tcp / dns | 0 / 0 | 0 / 0 |

`detonate.log` records the privilege on its launch line — read it, do not assume:

```
Run A: launch target: …\brbbot.exe (PE=True, elevated=True)
Run B: launch target: …\brbbot.exe (PE=True, elevated=False)
```

Run A was launched with `--elevated`. Run B was not. Section C.3 is why that matters.

## C.1 Counts (Run A, the elevated one)

```
dropped_new 2   dropped_modified 1   deleted 0
reg_new 1       reg_changed 0
new_processes 4 new_services 0       new_tasks 0
tcp_endpoints 0 dns_names 0
procmon: 384,834 rows -> 92,553 kept
```

## C.2 File System Artifacts (Run A)

| State | Size | Path | SHA256 |
|---|---|---|---|
| new | 75,776 | `C:\Users\REM\AppData\Roaming\brbbot.exe` | `F47060D0…34A21E` |
| new | 73 | `C:\Users\REM\Desktop\Malware\Day1\brbconfig.tmp` | `EE20EC1F…131E08` |
| modified | 720,896 | `…\Microsoft\Windows\UsrClass.dat.LOG1` | — (OS noise) |

The self-copy's SHA256 **equals the original sample's** — a plain `CopyFileA`, no
re-packing, exactly what `0x1400023e2` does.

Run B dropped only `brbconfig.tmp`, with the **same** sha256 `EE20EC1F…131E08`. The
config drop is privilege-independent and reproduced across both runs; the self-copy
did not survive (C.3). Run B's other three entries — `UpdateSessionOrchestration.001.etl`,
`UsrClass.dat.LOG1`, `pagefile.sys` — are OS noise.

## C.3 Registry / Persistence — privilege-dependent, and it rolls itself back

**Run A (elevated):**

```
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::brbbot
    = C:\Users\REM\AppData\Roaming\brbbot.exe
```

Hive, key path, value name and value type all match the static read at
`0x140002432`–`0x14000247a`.

**Run B (not elevated):** `dyn.py persist` reports *no persistence indicators*, and
`dyn.py dropped` shows only `brbconfig.tmp`. Taken at face value that reads as "the
sample did not persist, and did not copy itself". Both halves are wrong.

Procmon has the real sequence, four events inside 5 ms:

```
1:19:17.9726  CreateFile                    SUCCESS         C:\Users\REM\AppData\Roaming\brbbot.exe
1:19:17.9764  WriteFile                     SUCCESS         C:\Users\REM\AppData\Roaming\brbbot.exe
1:19:17.9768  RegOpenKey                    ACCESS DENIED   HKLM\Software\Microsoft\Windows\CurrentVersion\Run
1:19:17.9769  SetDispositionInformationFile SUCCESS         C:\Users\REM\AppData\Roaming\brbbot.exe
```

So, in order: it **did** copy itself to `%APPDATA%` (`CopyFileA`, `0x1400023e2`); the
HKLM open was **denied** because `0x20006` = `KEY_WRITE|KEY_READ` on `HKEY_LOCAL_MACHINE`
needs administrator (`0x140002432`); and **1 ms later it deleted its own copy**
(`SetDispositionInformationFile` is the `DeleteFileA(lpData)` on the cleanup path at the
end of `FUN_140002230`).

Two things follow, and both belong in the report:

1. **Persistence is gated on administrator rights.** Without them brbbot leaves no
   file and no registry trace — it cleans up after itself. Fill
   *Environment-specific Impact* with this, not with "it persists".
2. **The snapshot diff is blind to a file created and deleted inside the run window.**
   `dropped.json` is a baseline-vs-after comparison, so a file whose whole lifetime
   fits between the two snapshots never appears. Procmon saw it; the diff could not.
   `dyn.py dropped` saying "nothing new" is not the same as "nothing was written".

The rollback is itself a usable indicator: a `CreateFile` → `WriteFile` →
`SetDispositionInformationFile` burst on one path in `%APPDATA%`, bracketing an
`ACCESS DENIED` on a Run key, is the signature of a failed install.

## C.4 The loop that closes

The dropped `brbconfig.tmp` is **byte-identical to the embedded resource**:

```
resource CONFIG/101  73 bytes  sha256 EE20EC1F9A574280270C0045CAA6EDA5B35B35D131E7A45DB7D0AFDAEF131E08
brbconfig.tmp        73 bytes  sha256 EE20EC1F9A574280270C0045CAA6EDA5B35B35D131E7A45DB7D0AFDAEF131E08
```

So the config recovered and decrypted on the host in A.6 is the same config the sample
actually wrote in the VM. Static gave the key, dynamic gave the artifact, and the hash
ties them together.

## C.5 Network Artifacts — what is missing and why

Zero TCP endpoints and zero DNS names in **both** runs — 90 s elevated and 120 s
unelevated, `conns=0` at every 10 s poll. Four beacon intervals' worth at
`sleep=30000` and still nothing, so this is not a timeout artefact.

**This is an instrumentation result, not a property of the sample.** The guest NIC is
host-only and no network simulator is installed, so DNS goes to `192.168.134.1:53`
unanswered and the first connect fails immediately. Procmon logs UDP endpoints but not
payloads. The sample's network code is present and reachable (A.7), so absence here is
weak evidence.

The C2 **host** is the one template field this chain cannot fill. What *is* recovered:
protocol (HTTP, `INTERNET_SERVICE_HTTP`), URI path (`ads.php`), user-agent
(`Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)`), beacon interval
(30 s), and the command vocabulary — all from static.

`Malware/day3/session.zip` does **not** help here: `session.pcap` contains no `ads.php`,
no `Trident/4.0` and no `MSIE 8.0` — zero matches. It is a different exercise
(`www.hiltongardeninnoakville.com`, `195.154.122.33`, `POST /setting/get_setting.php`).
Do not cite it as brbbot's traffic.

To fill the C2 host, install FakeNet-NG in the guest, re-snapshot, and re-run `--mode full`.

## C.6 Memory Analysis — not for brbbot, but the capability now exists

**brbbot has no paired memory image**, so this row stays empty *for this sample*. Do
not borrow another image's findings to fill it.

The capability is in place and proven on two images. Volatility 3 2.28.2 plus the
840 MB symbol pack, driven through `host/mem.py`:

```bash
set MEM_IMAGE=..\samples-host\for610\day4\great.vmem
```

```bash
python host/mem.py plan
```

| Image | OS | Captured | Notes |
|---|---|---|---|
| `samples-host/for610/day4/great.vmem` | Win10 x86 build 10240 | 2017-01-05 16:53:21 | 2 GB |
| `Malware/day6/memory/themida.img` | Win XP SP2 build 2600 | 2008-12-02 01:20:40 | 268 MB, **not zipped** |
| `Malware/day5/known-memory.zip` | — | — | not extracted yet |

For a report that needs the Memory Analysis row filled, pick a sample that has an
image: `themida.img` is the cheapest (no extraction, and it contains a clear
masquerading process, `lsass.exe.exe` in `system32`, with its Themida-unpacked payload
sitting in RWX memory).

One warning carried over from that work: `malfind`'s `MZ header` note is largely noise
on Windows 10 — a zero-filled VAD mapped into ordinary processes, which fired on
`notepad++.exe`, `Taskmgr.exe` and `cmd.exe` on `great.vmem`. `mem.py inject` separates
those out. Do not cite an `MZ header` region as injection without checking there is a
`PE\0\0` behind it.

---

# PART D — Flow to reproduce dynamic and capture evidence

## D.1 Check the rails first — every time

```bash
python host/mal.py check
```

Confirmed at the time of writing: `ethernet0 = hostonly`, **HGFS disabled**,
`clean-nodefender` present, `detonate allowed: YES`. Still open as warnings: clipboard
copy/paste and drag-and-drop are not disabled, and `numvcpus = 1` is a sandbox tell that
can keep a sample dormant.

Do not trust a containment claim in any notes that this command does not confirm at run
time. CLAUDE.md previously asserted HGFS was disabled when it was not, and detonations
ran on that false assumption.

Screenshot this output — it is the Workstation/containment evidence for the report.

## D.2 Detonate

```bash
python host/mal.py detonate --guest-sample "C:\Users\REM\Desktop\Malware\Day1\brbbot.exe" --timeout 120 --mode full --elevated
```

**`--elevated` is not optional for this sample.** Leave it off and the HKLM write is
denied, the malware rolls back its own self-copy, and the run reports no persistence at
all (C.3). Omitting it does not give you "the same result, unprivileged" — it gives you
a different answer to the template's Persistence row. Run it both ways if you want the
privilege dependency as a finding; run it elevated if you want the behaviour.

The VM is reverted to `clean-nodefender` **before** the run, and again in a `finally`
block after it. `setup-guest` runs after the revert, so anything it pushes survives.
If the command ever prints `REVERT FAILED`, stop and treat the VM as infected.

A host-side copy works too — `detonate "..\samples-host\for610\day1\brbbot.exe"` — but
in-guest keeps the sample's companion files beside it and puts no sample byte on the host.

## D.3 Query, do not dump

```bash
python host/dyn.py --dir out/dynamic/<tag> summary
```

```bash
python host/dyn.py --dir out/dynamic/<tag> persist
```

```bash
python host/dyn.py --dir out/dynamic/<tag> dropped
```

```bash
python host/dyn.py --dir out/dynamic/<tag> proc
```

```bash
python host/dyn.py --dir out/dynamic/<tag> net
```

Do not `cat` `procmon.csv` and do not field-split it with `cut -d,` — its Detail column
contains commas inside quoted fields, and splitting on commas silently returns the wrong
columns. Use `dyn.py procmon <regex>`, which parses it with a real CSV reader.

The JSON artifacts carry a **UTF-8 BOM**; `dyn.py` handles it, an ad-hoc
`json.load(open(...))` does not and will look like an empty file.

## D.4 Decrypt the config on the host

`out/decrypt_brbconfig.py` is already in the tree. Against the PE resource:

```bash
python -I out/decrypt_brbconfig.py "..\samples-host\for610\day1\brbbot.exe"
```

You do **not** need to pull `brbconfig.tmp` out of the VM for this run: its SHA256
matches the embedded resource exactly (C.4), so decrypting the resource decrypts the
dropped file. `.tmp` is not on the pull allowlist, and renaming it in the guest to get
it past that is the one workaround Rule 3 names explicitly — don't.

A config that has *changed* in the guest (after a `conf=fnoc` command from a live C2)
is a different matter: decrypt it **inside** the VM. Push the script in and run it
there; only its text output comes back.

```bash
python -I out/decrypt_brbconfig.py --raw <config file>
```

Verified output:

```
source    : CONFIG/101 rva=0x17070 size=73
sha256    : EE20EC1F9A574280270C0045CAA6EDA5B35B35D131E7A45DB7D0AFDAEF131E08
passphrase: b'YnJiYm90'
rc4 key   : e2834a5bba1c28b7f536bd3ec5f1d8e0   (= MD5 of the passphrase)
plaintext : uri=ads.php;exec=cexe;file=elif;conf=fnoc;exit=tixe;encode=5b;sleep=30000
```

The key never changes — it is compiled in, so the same script works on any brbbot
config, from the resource or from disk.

## D.5 Screenshot checklist, dynamic

| # | Source | Capture | Template row |
|---|---|---|---|
| 1 | `mal.py check` | the rails output, `detonate allowed: YES` | Workstation / containment |
| 2 | VMware window | `clean-nodefender` snapshot selected, NIC = Host-only | Workstation |
| 3 | `mal.py detonate` terminal | revert → push → detonate → revert, end to end | method |
| 4 | `dyn.py summary` | the counts block + persistence indicator | Behavioral overview |
| 5 | `dyn.py dropped` | both new files with sizes and SHA256 | File System Artifacts |
| 6 | `dyn.py persist` | the HKLM Run value | Persistence |
| 7 | `dyn.py proc` | process list with the sample's descendants | Behavioral |
| 8 | `dyn.py net` | the empty result **plus** its explanatory note | Network Artifacts |
| 9 | `out/dynamic/<tag>/screen.png` | the guest desktop at end of run | Behavioral |
| 10 | Procmon GUI in guest, filter `Operation is RegSetValue` | the Run key write as Procmon saw it | Persistence |
| 11 | terminal | resource SHA256 == `brbconfig.tmp` SHA256 | corroboration |
| 12 | `detonate.log`, the `launch target:` line | `elevated=True` / `elevated=False` | method |
| 13 | `dyn.py procmon "Roaming.brbbot"` on the **unelevated** run | the create → write → **delete** burst | Environment-specific Impact |
| 14 | `dyn.py procmon "CurrentVersion.Run"` on the **unelevated** run | the ACCESS DENIED on HKLM | Environment-specific Impact |

Shots 12–14 are what make the privilege dependency a finding rather than an
inconsistency between two runs. Capture 13 and 14 together — the denial and the
rollback are 1 ms apart and only mean something side by side.

Shot 8 matters as much as the others: capture the note, not just the zero. A screenshot of
"0 endpoints" with no explanation reads as "the sample has no network capability", which
the static analysis contradicts.

## D.6 Before writing "the sample did nothing"

Four separate causes have produced identical-looking empty output in this project:
Defender truncating the sample to 0 bytes, a `.bin` extension that made the file
unexecutable, a real `0xC0000005` crash, and a Procmon noise filter hiding the one
process that mattered. Check the exit status first:

```bash
python host/dyn.py --dir out/dynamic/<tag> pevents brbbot.exe
```

- `Exit Status: 0` → it ran and chose to do nothing
- `Exit Status: -1073741819` + a `WerFault.exe` child → it crashed
- no `Process Start` at all → it never launched; read `detonate.log`

Check `Process Create` as well as `Process Start` — a process created suspended and
memory-replaced may never emit its own `Process Start`.

---

# PART E — ANALYSIS SUMMARY rows

**Key host IOCs**
- `%APPDATA%\brbbot.exe`, 75,776 bytes, sha256 `f47060d0…34a21e` (identical to the original) — *admin runs only; deleted again if persistence fails*
- `brbconfig.tmp`, 73 bytes, sha256 `ee20ec1f…131e08`, written beside the running sample — *both privilege levels, the most reliable host IOC here*
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value `brbbot` (`REG_SZ`) — *admin runs only*
- imphash `475b069fec5e5868caeb7d4d89236c89`
- `PendingFileRenameOperations` entries for the sample and its config
- failed-install signature: `CreateFile`→`WriteFile`→`SetDispositionInformationFile` on one `%APPDATA%` path around an `ACCESS DENIED` on an HKLM Run key

**Key network IOCs**
- user-agent `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)`
- HTTP request path `ads.php`
- beacon interval 30 s
- C2 command keywords `cexe`, `elif`, `fnoc`, `tixe`
- **C2 host: not recovered.** Needs FakeNet-NG or a live C2.

**Key functionality** (each line has an address in Part A)
- self-copy to `%APPDATA%` and HKLM Run persistence — `FUN_140002230`
- RC4-encrypted config in a PE resource, dropped and re-read — `FUN_140001150`, `FUN_140002940`, `FUN_140002c50`
- HTTP C2 over WININET with a fixed user-agent — `FUN_140002f50`, `FUN_140003030`, `FUN_140001840`
- payload drop to `%TEMP%` and execute — `FUN_140003100`
- victim host/IP collection — `FUN_140001770`
- runtime resolution of `ZwQuerySystemInformation` — `FUN_140003300`
- self-delete on reboot via `MoveFileExA(…, NULL, 4)`

**Purpose** — an HTTP backdoor/bot. It installs itself for all users, beacons to a
configurable host every 30 s, and supports four operator commands including arbitrary
payload execution. *Inference*, from the capability set and the command vocabulary; the
command handlers themselves were not walked.

**Persistence** — `HKLM\…\Run` value `brbbot` → `%APPDATA%\brbbot.exe`, `REG_SZ`.
Observed statically (`0x140002432`–`0x14000247a`) and dynamically **in the elevated run
only**. Machine-wide, not per-user: it survives a reboot for every account on the host.

**Environment-specific impact** — persistence is **gated on administrator rights**.
Measured both ways on the same snapshot: elevated, the Run key is written; unelevated,
`RegOpenKey` on `HKLM\…\Run` returns ACCESS DENIED and the malware **deletes the copy it
had just written to `%APPDATA%`**, leaving only `brbconfig.tmp` behind. So on a
standard-user host this sample installs nothing and cleans up its own evidence — but it
still drops and reads its config, and its network code is untouched by the failure.
A host where users run as administrator is the one that gets a persistent bot.

**Root cause** — not determined; no delivery vector is present in this artifact set
(`Notification Vector` in BACKGROUND is unfilled).

**Attribution** — none attempted. No PDB path, no VERSIONINFO, no certificate.

No malicious/benign verdict is issued here. The evidence above plus its confidence levels
is the deliverable; the verdict is the analyst's.

---

# PART F — Corrections to CLAUDE.md found during this run

1. **`session.pcap` is not brbbot's traffic.** CLAUDE.md states the day3 capture supplies
   "C2 host, protocol, user-agent" and that "FakeNet-NG is no longer on the critical path".
   The pcap has zero matches for `ads.php`, `MSIE 8.0` or `Trident/4.0`. For a brbbot
   report FakeNet-NG **is** still the only way to the C2 host.

2. **brbbot's config is recoverable statically**, against the note that "C2 domains are not
   recoverable without FakeNet". The URI, beacon interval, command vocabulary and encoding
   marker all come out of the PE resource with a key read off the disassembly. Only the
   *host* needs the network.

3. **HGFS is now genuinely disabled** — `mal.py check` confirms it. The CLAUDE.md section
   warning that a writable shared folder points at the coursework tree is stale.

4. **The dynamic JSON artifacts carry a UTF-8 BOM.** `dyn.py` handles it; a plain
   `json.load(open(...))` fails and the file reads as empty — a fifth way to manufacture
   a false "the sample did nothing".

5. **The snapshot diff cannot see a file created and deleted inside the run window.**
   Found by running brbbot unelevated: it wrote `%APPDATA%\brbbot.exe` and deleted it
   1 ms after the HKLM write was denied, and `dropped.json` showed neither. A sixth
   false-negative mode, and the only one so far that checking the exit status would not
   have caught — the process ran fine, it just undid its own work. Corroborate
   "nothing new" against Procmon before writing it down.

6. **`--elevated` changes the finding, not the performance.** Nothing in the pipeline's
   stdout flags which privilege a run used; only `detonate.log`'s `launch target:` line
   records it. Two runs that differ only in that flag gave opposite answers to the
   Persistence row.

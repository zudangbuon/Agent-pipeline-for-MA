#!/usr/bin/env python3
"""Fill the course report template with the brbbot.exe analysis.

Keeps the template's own table, styles and row order; only writes into the
empty value cells. Section hashes are read from pe_meta.json, not retyped.
"""
import json, os, sys

# `python -I` implies -P, which drops the script's own directory from sys.path,
# so a sibling module is not importable without this. The project runs these
# tools with -I on purpose (no user site-packages, no env influence), so fix the
# path here rather than dropping the flag.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_writer

HERE = os.path.dirname(os.path.abspath(__file__))     # .../agent-pipeline/host
PIPE = os.path.dirname(HERE)                          # .../agent-pipeline
ROOT = os.path.dirname(PIPE)                          # the coursework tree
TPL = os.path.join(ROOT, "References", "Malware_Analysis_Report_Template.docx")
if not os.path.isfile(TPL):
    sys.exit("template not found: %s" % TPL)

pm = json.load(open(os.path.join(PIPE, "out", "static", "brbbot-static",
                                 "pe_meta.json"), encoding="utf-8"))

# ---------------------------------------------------------------- section rows
sec_lines = ["%-8s %10s  H=%-6s %-4s  md5 %s" %
             ("name", "raw size", "entr", "perm", "sha256")]
for s in pm["sections"]:
    sec_lines.append("%-8s %10d  H=%-6s %-4s  %s" %
                     (s["name"], s["rawsize"], s["entropy"], s["perm"], s["md5"]))
    sec_lines.append("%-8s %10s  %s" % ("", "", s["sha256"]))

ent_lines = ["Whole file: H = %s  (75,776 bytes)" % pm["file_entropy"], ""]
for s in pm["sections"]:
    ent_lines.append("  %-8s H = %-6s  raw %d bytes  %s"
                     % (s["name"], s["entropy"], s["rawsize"], s["perm"]))
ent_lines += [
    "",
    "Entropy source: pe_meta.py, over RAW FILE BYTES. Ghidra's own figure is",
    "measured over the zero-padded virtual block and reads far too low on a",
    "packed section, so it was not used.",
    "",
    "No section exceeds 6.349. Nothing here indicates packing.",
]

NOT_DONE = "NOT PERFORMED in this analysis."

DATA = {
    # ---- BACKGROUND (label cell + value cell on the same row)
    1: ["2026-11-07 (analysis); report compiled 2026-11-08"],
    2: ["Host (static): Windows 11 x64, Ghidra 12.2 + JDK 25, Python 3.12, "
        "Volatility 3 2.28.2, cdb 10.0.26100.4188.",
        "Analysis VM (dynamic): malware.vmx - 64-bit Windows 10, user REM, Procmon "
        "installed, baseline snapshot 'clean-nodefender'. (The guest is documented "
        "as build 16299; no artifact of these two runs records the OS build, so the "
        "exact build is taken from environment notes, not observed. That it is "
        "64-bit Windows IS observed - the x64 sample ran, and Procmon logged "
        "C:\\Windows\\SysWOW64 paths.)",
        "Verified at run time by the pre-flight check, both runs: ethernet0 = "
        "host-only (isolated), shared folders (HGFS) disabled, clean snapshot "
        "present. The VM was confirmed reverted after each detonation.",
        "NOT verified at run time: Windows Defender state inside the guest. The "
        "snapshot is documented as having Defender disabled, but no check "
        "(sc query WinDefend) was run during either detonation, so that is a "
        "configuration assumption rather than an observation. It matters because a "
        "live Defender can truncate a sample as it is written, which would make the "
        "pipeline analyse a stub.",
        "No FakeNet-NG or other network simulator installed - see Network Artifacts."],
    3: ["brbbot.exe"],
    4: ["Host: samples-host\\for610\\day1\\brbbot.exe",
        "Origin archive: Malware\\day1\\brbbot.zip (password: malware)",
        "In guest: C:\\Users\\REM\\Desktop\\Malware\\Day1\\brbbot.exe"],
    5: ["Created:  2016-09-20 17:10:09 UTC",
        "Modified: 2015-02-25 06:12:18 UTC"],
    6: ["Course material (SANS FOR610, day 1). No real-world delivery vector is "
        "present in this artifact set - there is no carrier document, e-mail or "
        "dropper alongside the sample, so the infection vector is not determinable "
        "from what was analysed."],

    # ---- STATIC ANALYSIS (label cell + value cell)
    8: ["75,776"],
    9: ["None. The PE carries no icon resource, so Explorer shows the generic "
        "Windows default. There is no attempt to disguise the file as a document."],
    10: ["No. No Authenticode certificate is present (signature.signed = false)."],
    11: ["MD5    : 1c7243c8f3586b799a5f9a2e4200aa92",
         "SHA1   : 4db5a8e237937b6d7b435a8506b8584121a7e9e3",
         "SHA256 : f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e"],
    12: ["475b069fec5e5868caeb7d4d89236c89   (computed via pefile)"],

    # ---- STATIC ANALYSIS (content goes in the row AFTER the label)
    14: sec_lines,
    16: ["2015-02-25 06:12:18 UTC   (TimeDateStamp 1424844738 / 0x54ed67c2)",
         "",
         "Assessed as PROBABLY GENUINE, with the basis stated:",
         "  - it matches the file's own filesystem modified timestamp to the second "
         "(2015-02-25 06:12:18 UTC), which a faked header value would not normally do",
         "  - it is not in the future, and not absurd for the collection",
         "",
         "Measured against the other FOR610 samples in this analysis set, which is "
         "NOT a consistency argument in brbbot's favour - it is the honest picture:",
         "  brbbot.exe  2015-02-25      bill.exe  2016-08-19      known.exe  2016-10-05",
         "brbbot is the only 2015 build among them, so there is no sibling at the "
         "same date to corroborate it. The claim rests on the mtime agreement alone.",
         "",
         "Note on method: absolute plausibility is not enough to call a timestamp "
         "genuine. In the same collection Lab01-04.exe claims 2019-08-30 while its "
         "chapter siblings are Dec 2010 / Jan 2011 - clearly faked, yet it passes any "
         "'is it in the future' test because 2019 is now in the past."],
    18: ["Machine        : x86-64 (64-bit). NOTE: this sample is x64, not x86.",
         "Subsystem      : GUI",
         "Linker version : 10.0",
         "Image base     : 0x140000000",
         "Entry point    : 0x140003f94",
         "Characteristics: 0x0022 - EXECUTABLE_IMAGE, LARGE_ADDRESS_AWARE",
         "Is DLL/driver  : no / no.  Exports: none.  Ordinal imports: 5",
         "VERSIONINFO    : EMPTY - no description, version, company or product name",
         "Manifest       : none",
         "Resources      : exactly one - type CONFIG, id 101, RVA 0x17070, 73 bytes",
         "",
         "The empty VERSIONINFO plus the missing icon and signature means the file "
         "offers no provenance of any kind. The single CONFIG resource is the "
         "sample's encrypted configuration (see Code Analysis)."],
    20: ["Address        String",
         "0x14000fdf8    CONFIG",
         "0x14000fe00    brbconfig.tmp",
         "0x14000fe10    YnJiYm90",
         "0x14000fe48    encode",
         "0x14000fe78    APPDATA",
         "0x14000fe80    Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "0x14000feb0    brbbot",
         "0x14000fec0    Microsoft Enhanced Cryptographic Provider v1.0",
         "0x14000ff30    Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
         "0x14000ff70    HTTP/1.1",
         "0x14000ff80    Connection: close",
         "0x14000ff98    ZwQuerySystemInformation",
         "0x14000ffb8    ntdll.dll",
         "0x14000ffc8    Idle",
         "",
         "209 strings recovered in total. No domain name or IP address appears "
         "anywhere among them.",
         "",
         "CAUTION on automated tagging: the triage tool tagged 'CryptDecrypt' "
         "(0x140011116) as a ransom-note string and 'ZwQuerySystemInformation', "
         "'GetSystemDirectoryA', 'GetSystemWow64DirectoryA' and "
         "'GetSystemTimeAsFileTime' as registry keys. Everything from 0x140011052 "
         "upward is the IMPORT NAME TABLE, not data the malware uses as a key path "
         "or a note. Those tags are artifacts and are not cited as findings. The "
         "only genuine registry-key string is 0x14000fe80."],
    22: ["NOT PACKED.",
         "",
         "Judged on structure, not on an entropy threshold alone:",
         "  - 115 imported symbols across 5 DLLs (a packer stub typically has 1-10)",
         "  - 225 functions recovered by the disassembler",
         "  - highest section entropy 6.349, whole-file 5.918",
         "  - .data is both smaller on disk (5,120 B vs 50,176 B) and sparser "
         "(H=1.973 vs 6.349) than .text, i.e. the normal shape",
         "  - all six sections are normally named; none has a raw size of 0",
         "",
         "One section DOES have a virtual size larger than its raw size, and it is "
         "reported here rather than glossed over:",
         "  .data   raw 5,120 B   virtual 15,616 B   ratio 3.05x",
         "This is NOT a packing indicator. Uninitialised data (BSS) is counted in a "
         "section's virtual size but occupies no bytes in the file, so a .data "
         "section several times larger in memory than on disk is normal for any "
         "compiler. The pattern that WOULD matter is an EXECUTABLE section with that "
         "shape, or any section with raw size 0 and a large virtual size - the UPX0 "
         "signature. Neither is present: every executable section here is 0.99x.",
         "",
         "The structural check matters: a sample can be packed with a maximum "
         "section entropy of only 6.4, so entropy > 7.0 on its own is not a "
         "reliable test. Here every signal agrees that the file is not packed."],
    24: ent_lines,
    26: ["IMPORTS - 115 symbols, 5 DLLs:",
         "  KERNEL32.DLL   86      ADVAPI32.DLL   14      WININET.DLL     9",
         "  WS2_32.DLL      5      USER32.DLL      1",
         "",
         "EXPORTS: none (this is an EXE, not a DLL).",
         "",
         "Capability-bearing imports, grouped:",
         "  Persistence   RegOpenKeyExA, RegSetValueExA, RegFlushKey, RegCloseKey,",
         "                RegDeleteValueA",
         "  Cryptography  CryptAcquireContextW, CryptCreateHash, CryptHashData,",
         "                CryptDeriveKey, CryptEncrypt, CryptDecrypt,",
         "                CryptDestroyHash, CryptDestroyKey, CryptReleaseContext",
         "  Network       InternetOpenA, InternetConnectA, InternetSetOptionA,",
         "                HttpOpenRequestA, HttpSendRequestA, HttpQueryInfoA,",
         "                InternetReadFile, InternetQueryDataAvailable,",
         "                InternetCloseHandle, WSAStartup, gethostname,",
         "                gethostbyname, inet_ntoa",
         "  Filesystem    CreateFileA/W, WriteFile, CopyFileA, DeleteFileA,",
         "                MoveFileExA, GetTempPathA, GetTempFileNameA,",
         "                GetModuleFileNameA/W, GetFileSize",
         "  Execution     CreateProcessA",
         "  Dynamic res.  GetModuleHandleA/W, GetProcAddress, LoadLibraryW",
         "  Resources     FindResourceA, SizeofResource, LoadResource, LockResource",
         "  Anti-analysis IsDebuggerPresent, GetTickCount, QueryPerformanceCounter,",
         "                Sleep",
         "",
         "The import table alone establishes the sample's whole capability set: "
         "it persists, encrypts, speaks HTTP, drops and launches files."],
    28: [NOT_DONE,
         "",
         "No VirusTotal lookup, search-engine query or malware-repository search was "
         "carried out, so no third-party detection name, first-seen date or family "
         "attribution is offered anywhere in this report.",
         "",
         "If this row is completed later, the sample must NOT be uploaded. A hash "
         "lookup on the SHA256 above is safe; uploading the file publishes it, "
         "which can expose victim data and tip off the operator.",
         "",
         "Hash for lookup: "
         "f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e"],

    # ---- BEHAVIORAL ANALYSIS
    31: ["Tooling: Process Monitor plus a full baseline/after snapshot diff inside "
         "the VM, which is reverted to a clean snapshot before and after every run. "
         "TWO runs were performed; they differ only in privilege and they DISAGREE, "
         "so both are reported.",
         "",
         "The two runs were made on different days and are kept as separate "
         "artifact sets: Run A out/dynamic/brbbot.exe-20261106-112802 (2026-11-06), "
         "Run B out/dynamic/brbbot.exe-20261107-131857 (2026-11-07). Each has its "
         "own detonate.log recording the privilege it ran with.",
         "",
         "RUN A - launched ELEVATED, 90 s timeout, sample PID 784",
         "  NEW   75,776 B  C:\\Users\\REM\\AppData\\Roaming\\brbbot.exe",
         "                  SHA256 f47060d0...34a21e - IDENTICAL to the original, so a",
         "                  plain file copy with no re-packing",
         "  NEW        73 B  C:\\Users\\REM\\Desktop\\Malware\\Day1\\brbconfig.tmp",
         "                  SHA256 ee20ec1f...131e08",
         "  REG   HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "          value 'brbbot' (REG_SZ) = C:\\Users\\REM\\AppData\\Roaming\\brbbot.exe",
         "  Counts: 2 new files, 1 modified, 1 new registry value, 4 new processes",
         "  The sample exited on its own inside the 90 s window.",
         "",
         "RUN B - launched UNELEVATED, 120 s timeout, sample PID 4528",
         "  NEW        73 B  brbconfig.tmp  (same SHA256 as Run A)",
         "  No self-copy and NO persistence appear in the snapshot diff.",
         "  The sample was still running at timeout and had to be killed.",
         "",
         "Run B's diff is MISLEADING and must not be reported at face value. "
         "Procmon recorded four events 5 ms apart:",
         "    1:19:17.9726  CreateFile                     SUCCESS        %APPDATA%\\brbbot.exe",
         "    1:19:17.9764  WriteFile                      SUCCESS        %APPDATA%\\brbbot.exe",
         "    1:19:17.9768  RegOpenKey                     ACCESS DENIED  HKLM\\...\\Run",
         "    1:19:17.9769  SetDispositionInformationFile  SUCCESS        %APPDATA%\\brbbot.exe",
         "",
         "So the sample DID copy itself, was denied write access to the HKLM Run key "
         "because that needs administrator rights, and then DELETED its own copy 1 ms "
         "later. A baseline/after snapshot diff cannot see a file whose entire "
         "lifetime falls between the two snapshots; Procmon, being a first-hand "
         "record, can. 'Nothing new in the diff' is not the same as 'nothing was "
         "written'.",
         "",
         "TRIGGERS: none of the usual ones. No browser, mail client, web page, clock "
         "or reboot trigger was observed, and the sample acts immediately on launch. "
         "The one real gate is PRIVILEGE - see Environment-specific Impact. (A time "
         "trigger far in the future cannot be ruled out from a 120 s run.)",
         "",
         "DEPENDENCIES: WININET and WS2_32 for HTTP and name resolution; DNS to "
         "reach its configured host; ADVAPI32 for the registry and for CryptoAPI "
         "(it requests 'Microsoft Enhanced Cryptographic Provider v1.0'). "
         "Administrator rights for persistence. No IRC or ARP dependency. "
         "The sample is x64, so it will not run on a 32-bit Windows at all."],
    33: ["OBSERVED: nothing. Zero TCP endpoints and zero DNS queries in BOTH runs - "
         "90 s elevated and 120 s unelevated, polled every 10 s.",
         "",
         "This is a property of the INSTRUMENTATION, not of the sample. The guest "
         "NIC is host-only and no network simulator (FakeNet-NG / INetSim / fakedns) "
         "is installed, so DNS goes to 192.168.134.1:53 unanswered and the first "
         "connect fails immediately. Procmon logs UDP endpoints but not payloads. "
         "The sample's network code is present and reachable, so this absence is "
         "weak evidence - 120 s is four beacon intervals at its configured 30 s, so "
         "a short timeout is not the explanation either.",
         "",
         "RECOVERED STATICALLY instead (see Code Analysis for how):",
         "  Protocol      HTTP (InternetConnectA service type 3 = "
         "INTERNET_SERVICE_HTTP)",
         "  URI path      ads.php",
         "  User-Agent    Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; "
         "Trident/4.0)",
         "  HTTP version  HTTP/1.1, with 'Connection: close'",
         "  Beacon        every 30,000 ms (30 s)",
         "  C2 commands   cexe (execute), elif (file), fnoc (config), tixe (exit)",
         "",
         "C2 HOST: NOT RECOVERED. No domain- or IP-shaped string exists in the 209 "
         "strings, the decrypted configuration carries only the URI path, and the "
         "function that calls InternetConnectA receives the host as a parameter on a "
         "call path the disassembler could not resolve (0 callers in the call graph). "
         "Recovering it requires a responding C2 or a network simulator.",
         "",
         "NOTE: Malware\\day3\\session.pcap was checked and is NOT this sample's "
         "traffic - it contains zero matches for 'ads.php', 'MSIE 8.0' or "
         "'Trident/4.0'. It belongs to a different exercise and must not be cited "
         "as brbbot's network evidence."],
    35: ["NOT APPLICABLE to this sample.",
         "",
         "brbbot has no paired memory image in the course material, and no memory "
         "capture was taken of either detonation. No finding in this report rests on "
         "memory forensics, and findings from other images are deliberately not "
         "borrowed to fill this row.",
         "",
         "The capability does exist in the analysis environment (Volatility 3 2.28.2 "
         "with the Windows symbol pack, verified working on two unrelated images), so "
         "this row is empty by choice of sample, not for want of tooling. To complete "
         "it for brbbot, capture a .vmem during detonation and analyse that.",
         "",
         "This gap matters more than it looks: process replacement, code injection "
         "and in-RAM decryption leave no file, registry, service or network trace, "
         "and Procmon does not log WriteProcessMemory or CreateRemoteThread. For that "
         "class of behaviour the dynamic findings above would be silent. Nothing in "
         "brbbot's import table suggests injection, but it has not been excluded."],
    37: [NOT_DONE,
         "",
         "No centralops, robtex, urlvoid, ipvoid or TrustedSource lookup was done - "
         "and with the C2 host unrecovered there is no domain or IP to look up. The "
         "only network indicator that could be researched is the URI path 'ads.php', "
         "which is far too generic to be worth a reputation query."],

    # ---- CODE ANALYSIS
    40: ["Tool used: GHIDRA 12.2 driven by PyGhidra on the host, not IDA Pro. The "
         "IDA Freeware build available here has no IDAPython and cannot be scripted. "
         "Ghidra PARSES the sample; it never executes it. 225 functions, 29 "
         "decompiled.",
         "",
         "PERSISTENCE - FUN_140002230 (785 bytes, 4 xrefs, called by FUN_1400027c0)",
         "  0x14000230a  GetEnvironmentVariableA(\"APPDATA\")   resolve %APPDATA%",
         "  0x1400023e2  CopyFileA(own path -> %APPDATA%\\brbbot.exe)",
         "  0x140002432  RegOpenKeyExA(0x80000002, \"Software\\Microsoft\\Windows\\"
         "CurrentVersion\\Run\", 0, 0x20006)",
         "               0x80000002 = HKEY_LOCAL_MACHINE; 0x20006 = KEY_WRITE|KEY_READ",
         "  0x14000247a  RegSetValueExA(hKey, \"brbbot\", 0, 1, lpData)   type 1 = REG_SZ",
         "               MoveFileExA(own path, NULL, 4)    4 = MOVEFILE_DELAY_UNTIL_REBOOT",
         "               MoveFileExA(\"brbconfig.tmp\", NULL, 4)",
         "               DeleteFileA(lpData)   rollback path - removes the %APPDATA% copy",
         "",
         "Variable identities, since the distinction decides what the mechanism means:",
         "  local_138 = GetModuleFileNameA result = the path the sample was LAUNCHED FROM",
         "  lpData    = %APPDATA% + '\\' + its own filename = the INSTALLED COPY",
         "  pcVar7    = strstr(local_138, %APPDATA%) - non-NULL when the running file "
         "IS already the installed copy, i.e. an 'am I installed?' check",
         "",
         "So CopyFileA goes launched-path -> %APPDATA%, the Run value is set to the "
         "%APPDATA% path, and MoveFileExA(local_138, NULL, 4) queues the LAUNCHED "
         "file for deletion - guarded by 'if (pcVar7 == NULL)' so it never deletes "
         "its own installed copy. The two MoveFileExA calls are what land in "
         "PendingFileRenameOperations.",
         "",
         "DeleteFileA(lpData) sits outside those branches, under "
         "'if (DVar5 < 0 && bVar3)' - any failure after the copy succeeded. That is "
         "exactly the path Run B took: RegOpenKeyExA was denied, DVar5 became an "
         "HRESULT-wrapped error, and the %APPDATA% copy was deleted 1 ms later.",
         "",
         "CONFIGURATION CRYPTO - FUN_140002940 (write) and FUN_140002c50 (read)",
         "Both derive the same key:",
         "  CryptAcquireContextW(..., L\"Microsoft Enhanced Cryptographic Provider "
         "v1.0\", 1, ...)",
         "  CryptCreateHash(hProv, 0x8003, 0, 0, &hHash)          0x8003 = CALG_MD5",
         "  CryptHashData(hHash, \"YnJiYm90\", 8, 0)                 hardcoded passphrase",
         "  CryptDeriveKey(hProv, 0x6801, hHash, 0x800000, &hKey)  0x6801 = CALG_RC4,",
         "                                                         0x800000 = 128-bit",
         "",
         "A 128-bit RC4 key derived from an MD5 hash is the whole 16-byte digest, so "
         "the key is exactly MD5(\"YnJiYm90\") = e2834a5bba1c28b7f536bd3ec5f1d8e0. "
         "The key is compiled in and never changes, so the configuration can be "
         "decrypted offline, on the host, without running the sample.",
         "",
         "FUN_140002940 writes brbconfig.tmp with CryptEncrypt; FUN_140002c50 reads "
         "it back with CryptDecrypt. FUN_140001150 drops the initial copy out of the "
         "PE resource (GetModuleHandleA -> FindResourceA -> SizeofResource -> "
         "LoadResource -> LockResource -> CreateFileA -> WriteFile).",
         "",
         "DECRYPTED CONFIGURATION (resource CONFIG/101, 73 bytes):",
         "  uri=ads.php;exec=cexe;file=elif;conf=fnoc;exit=tixe;encode=5b;sleep=30000",
         "",
         "    uri     ads.php   C2 request path",
         "    exec    cexe      command keyword - run a payload",
         "    file    elif      command keyword - file transfer",
         "    conf    fnoc      command keyword - update configuration",
         "    exit    tixe      command keyword - terminate",
         "    encode  5b        encoding marker (0x5b)",
         "    sleep   30000     beacon interval, milliseconds",
         "",
         "The four command keywords are their own names spelled backwards. This is "
         "the C2 command vocabulary, recovered without running the sample.",
         "",
         "CROSS-CONFIRMATION: resource CONFIG/101 and the brbconfig.tmp that the "
         "sample actually wrote in the VM are BYTE-IDENTICAL - SHA256 "
         "ee20ec1f9a574280270c0045caa6eda5b35b35d131e7a45db7d0afdaef131e08 for both. "
         "Static analysis supplied the key, dynamic analysis supplied the artifact, "
         "and the hash ties them together.",
         "",
         "NETWORK - FUN_140002f50 / FUN_140003030 / FUN_140001840",
         "  0x140002f76  InternetOpenA(user-agent at 0x14000ff30, 1, ...)",
         "  0x140002fbe  InternetSetOptionA",
         "  0x140002ff5  InternetConnectA(h, param_1 = host, port, 0, 0, 3, 0, 0)",
         "               service type 3 = INTERNET_SERVICE_HTTP",
         "  FUN_140003030  HttpOpenRequestA / HttpSendRequestA / HttpQueryInfoA - "
         "builds the request that uses uri=ads.php",
         "  FUN_140001840  InternetQueryDataAvailable / InternetReadFile - reads the "
         "reply",
         "  FUN_140001770  gethostname -> gethostbyname -> inet_ntoa - collects the "
         "VICTIM's own hostname and IP, not the C2's",
         "",
         "PAYLOAD DROP AND EXECUTE - FUN_140003100",
         "  GetTempPathA -> GetTempFileNameA -> CreateFileA -> WriteFile -> "
         "CreateProcessA -> MoveFileExA",
         "  Writes a file to %TEMP% and launches it. This is the path the 'cexe' "
         "command keyword corresponds to (inferred from the keyword, not proven by "
         "tracing the dispatcher).",
         "",
         "ANTI-ANALYSIS / DYNAMIC RESOLUTION - FUN_140003300",
         "  GetModuleHandleA(\"ntdll.dll\") + GetProcAddress"
         "(\"ZwQuerySystemInformation\")",
         "  Resolves a process-enumeration syscall at run time rather than importing "
         "it, which keeps it out of the import table. The 'Idle' string at "
         "0x14000ffc8 is consistent with walking a process list.",
         "  IsDebuggerPresent, GetTickCount and QueryPerformanceCounter are imported, "
         "but 7 of the functions flagged as anti-analysis are MSVCRT - "
         "__security_init_cookie at 0x140008994 is CRT start-up, not malware logic. "
         "Of 225 functions only a handful are the malware; the rest are the C runtime.",
         "",
         "LOOPS AND FLOW not walked exhaustively: the command dispatcher that maps "
         "'cexe'/'elif'/'fnoc'/'tixe' onto the handler functions was NOT traced, so "
         "the mapping between each keyword and its implementation is inferred from "
         "the keyword names and the capability set, not demonstrated."],
    42: ["NOT PERFORMED on this sample.",
         "",
         "No interactive debugging session was run against brbbot - no function "
         "breakpoints, no stack monitoring, no OllyDbg run. The sample is not packed, "
         "so there is no packer stub to step through and no OEP to find: the "
         "disassembly is fully readable and the configuration was recovered "
         "statically, which is what a debugger would normally have been needed for.",
         "",
         "A console-debugger harness (cdb 10.0.26100.4188, Debugging Tools for "
         "Windows) was built and validated against a benign control on the analysis "
         "host - API-call tracing with logging breakpoints, module list, memory map "
         "and RWX-region reporting, 111 calls captured on the control. It has NOT "
         "been run against this or any sample: the in-VM half of that harness is not "
         "finished, and the sample must not be executed on the host.",
         "",
         "What a debugging session would still add for brbbot: proof of which "
         "handler each C2 command keyword reaches, and the C2 host itself, by "
         "breaking on InternetConnectA and reading its second argument. Both are "
         "open items."],

    # ---- ANALYSIS SUMMARY
    45: ["HOST",
         "  File   %APPDATA%\\brbbot.exe, 75,776 bytes,",
         "         SHA256 f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e",
         "         (identical to the dropped original) - ADMINISTRATOR RUNS ONLY;",
         "         deleted again if persistence fails",
         "  File   brbconfig.tmp, 73 bytes, written beside the running sample,",
         "         SHA256 ee20ec1f9a574280270c0045caa6eda5b35b35d131e7a45db7d0afdaef131e08",
         "         - appears at BOTH privilege levels, so it is the most reliable",
         "         host indicator for this sample",
         "  Reg    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "         value 'brbbot' (REG_SZ) - administrator runs only",
         "  Reg    PendingFileRenameOperations entries for the path the sample was",
         "         LAUNCHED FROM and for brbconfig.tmp beside it - NOT for the",
         "         %APPDATA% copy, which is left in place deliberately",
         "  Hash   imphash 475b069fec5e5868caeb7d4d89236c89",
         "  Behav  failed-install signature: CreateFile -> WriteFile ->",
         "         SetDispositionInformationFile on one %APPDATA% path, bracketing an",
         "         ACCESS DENIED on an HKLM Run key",
         "",
         "NETWORK",
         "  User-Agent  Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; "
         "Trident/4.0)",
         "  URI path    ads.php",
         "  Protocol    HTTP/1.1, 'Connection: close'",
         "  Beacon      30 s",
         "  Keywords    cexe, elif, fnoc, tixe",
         "  C2 host     NOT RECOVERED - requires FakeNet-NG or a live C2",
         "",
         "Every host indicator above was observed in at least one run or computed "
         "from the file. Every network indicator was recovered statically; none was "
         "observed on the wire."],
    47: ["Each line cites an address given in Code Analysis.",
         "",
         "  1. Copies itself to %APPDATA%\\brbbot.exe and registers that copy under "
         "the HKLM Run key - FUN_140002230. Machine-wide, so it needs administrator "
         "rights.",
         "  2. Carries an RC4-encrypted configuration as PE resource CONFIG/101, "
         "drops it as brbconfig.tmp and reads it back - FUN_140001150, FUN_140002940, "
         "FUN_140002c50. The key is hardcoded.",
         "  3. Beacons over HTTP with a fixed Internet Explorer 8 user-agent to the "
         "path ads.php every 30 s - FUN_140002f50, FUN_140003030, FUN_140001840.",
         "  4. Supports four operator commands, including arbitrary payload "
         "execution: writes a file to %TEMP% and launches it - FUN_140003100.",
         "  5. Collects the victim's own hostname and IP address - FUN_140001770.",
         "  6. Resolves ZwQuerySystemInformation at run time to enumerate processes "
         "without importing it - FUN_140003300.",
         "  7. Cleans up its own dropper: queues the path it was LAUNCHED FROM and "
         "the config beside it for deletion at the next reboot via "
         "MoveFileExA(..., NULL, MOVEFILE_DELAY_UNTIL_REBOOT), guarded so it never "
         "queues the installed %APPDATA% copy - FUN_140002230.",
         "  8. Rolls back on failure: if it cannot write the Run key it deletes the "
         "%APPDATA% copy it had just made, leaving almost no disk trace - "
         "FUN_140002230, and demonstrated in the unelevated run.",
         "",
         "NOT observed and NOT excluded: code injection, keylogging, screen capture, "
         "credential theft, lateral movement, anti-VM checks acting on their result."],
    49: ["An HTTP backdoor / bot. It installs itself for all users, beacons to a "
         "configurable host on a 30-second interval, and accepts four operator "
         "commands of which one runs an arbitrary downloaded payload. The victim's "
         "hostname and IP are collected for reporting to the operator.",
         "",
         "This is an INFERENCE, with the confidence stated: HIGH that the sample is "
         "a remote-access bot, because the capability set, the beacon interval, the "
         "command vocabulary and the configuration format all agree. MODERATE on the "
         "specific mapping of each command keyword to its handler, because the "
         "dispatcher was not traced. No opinion is offered on the family or the "
         "operator.",
         "",
         "No malicious/benign verdict is issued here. The evidence above, with its "
         "confidence levels, is the deliverable; the determination is the analyst's."],
    51: ["MECHANISM: registry Run key, machine-wide.",
         "  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "    value name 'brbbot', type REG_SZ",
         "    data       C:\\Users\\REM\\AppData\\Roaming\\brbbot.exe",
         "",
         "Observed statically at 0x140002432-0x14000247a and dynamically in the "
         "ELEVATED run. Because the hive is HKLM and not HKCU, the entry survives a "
         "reboot for every account on the host, not just the one that was infected.",
         "",
         "THE INSTALLED COPY SURVIVES; THE DROPPER DOES NOT. Read from the decompiled "
         "control flow of FUN_140002230:",
         "  pcVar7 = strstr(own_path, %APPDATA%)        'am I already installed?'",
         "  CopyFileA(own_path -> %APPDATA%\\brbbot.exe)",
         "  RegSetValueExA('brbbot' = the %APPDATA% path)",
         "  if (pcVar7 == NULL) MoveFileExA(own_path, NULL, 4)   <-- CONDITIONAL",
         "  MoveFileExA('brbconfig.tmp', NULL, 4)",
         "",
         "MOVEFILE_DELAY_UNTIL_REBOOT is applied to the path the sample was LAUNCHED "
         "FROM, not to the %APPDATA% copy - and only when those two are different. "
         "So the malware removes its own dropper at the next reboot while the "
         "installed copy and the Run value that points at it both persist. It never "
         "queues its installed self for deletion.",
         "",
         "That makes the install durable, and it also means the file the victim "
         "actually ran disappears on reboot: the obvious artifact (a suspicious "
         "download in Downloads or %TEMP%) is gone, while the real persistence sits "
         "in %APPDATA% under a plausible name.",
         "",
         "The configuration beside the dropper is queued for deletion too, so after a "
         "reboot brbconfig.tmp is absent until the installed copy writes a fresh one "
         "from its CONFIG resource.",
         "",
         "OTHER PERSISTENCE MECHANISMS - what was and was not checked:",
         "  Ruled out by the monitors (0 new in both runs): new SERVICES, new "
         "SCHEDULED TASKS, new autorun entries, and any new file in the startup "
         "folders (the file snapshot would have caught one).",
         "  NOT MONITORED, therefore NOT ruled out: WMI event subscriptions "
         "(__EventFilter / CommandLineEventConsumer), COM hijacking, DLL "
         "search-order hijacking, IFEO and AppInit_DLLs. The detonation harness "
         "snapshots files, registry, processes, services and scheduled tasks only. "
         "Absence of these from the report is a gap in coverage, not a finding.",
         "",
         "Nothing in the import table suggests those techniques, but that is an "
         "inference from imports, not an observation."],
    53: ["PERSISTENCE IS GATED ON ADMINISTRATOR RIGHTS. This was measured both ways "
         "on the same clean snapshot, with the privilege as the only difference.",
         "",
         "  Run as administrator  -> HKLM Run key written, self-copy left in place",
         "  Run as standard user  -> RegOpenKey on HKLM\\...\\Run returns ACCESS "
         "DENIED, and the malware DELETES the copy it had just written to %APPDATA%",
         "",
         "Consequences for a real environment:",
         "  - On a host where users run as standard users, this sample installs "
         "nothing and cleans up its own evidence. Only brbconfig.tmp is left behind, "
         "beside wherever the file was executed from. Disk-based detection that looks "
         "only for the %APPDATA% copy or the Run key will MISS it entirely.",
         "  - The network and configuration code is untouched by that failure, so an "
         "unprivileged infection can still beacon and still run a payload - it just "
         "does not survive a reboot.",
         "  - A host where users are local administrators is the one that gets a "
         "persistent, machine-wide bot.",
         "  - The sample is x86-64. A 32-bit Windows cannot run it at all.",
         "  - Persistence writes to HKLM, so on a managed estate an application-"
         "allowlisting or HKLM-write policy would break the install while leaving "
         "the beacon behavior intact.",
         "",
         "Blast radius in THIS environment (an isolated analysis VM, host-only "
         "networking, reverted after every run): nil. No containment failure was "
         "observed and the VM was confirmed reverted after both detonations."],
    55: ["NOT DETERMINED.",
         "",
         "No delivery vector is present in the analysed artifact set - there is no "
         "carrier document, e-mail, exploit, dropper or installer accompanying the "
         "sample, and no telemetry from a real infection. The Notification Vector "
         "row is correspondingly unfilled.",
         "",
         "What the sample itself requires for a successful install is administrator "
         "rights, so in a real incident the proximate cause would be execution of "
         "the file in an administrative context. That is a precondition of the "
         "observed behaviour, not evidence of how the file arrived."],
    57: ["NONE ATTEMPTED.",
         "",
         "The sample offers no attribution material: no PDB path, no VERSIONINFO, no "
         "Authenticode certificate, no language resources, no build artifacts. The "
         "C2 host - normally the strongest lead - was not recovered. No third-party "
         "research was performed (both Open Source Research rows are empty), so no "
         "family name or detection label is carried over.",
         "",
         "The only internal clues are weak and offered as observations, not "
         "attribution: the configuration passphrase 'YnJiYm90' is Base64 for "
         "'brbbot', the same string used as the Run value name and present at "
         "0x14000feb0; and the C2 command keywords are simple reversals of their own "
         "names, which suggests a hand-rolled protocol rather than a commodity "
         "framework.",
         "",
         "Compile timestamp 2015-02-25 06:12:18 UTC appears genuine and places the "
         "build, not the author."],
}


def main():
    # This is brbbot in the 58-row institutional layout -- an ALTERNATIVE format,
    # kept as a worked example. brbbot's canonical report is the five-section one
    # from fill_report_brbbot_freeform.py, so this writes to out/ rather than to
    # report/: exactly one report per sample lives there, and a second format
    # would quietly recreate the duplicate this directory was just cleaned of.
    #
    # The template .docx is READ for its row labels and their order; nothing is
    # ever written back to it.
    out = os.path.join(PIPE, "out", "brbbot-58row-format.txt")
    report_writer.render_table_txt(
        TPL, DATA, "Malware Analysis Report - brbbot.exe", out)


if __name__ == "__main__":
    main()

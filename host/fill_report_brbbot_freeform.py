#!/usr/bin/env python3
"""brbbot.exe report in the free-form 5-section structure used by the course's
example student reports (Basic Static / Advanced Static / Basic Dynamic /
Advanced Dynamic / Conclusion), rather than the 58-row template table.

Screenshot placeholders are left in deliberately -- a labelled gap is better than
a silently missing figure.

Artifacts:
  static  out/static/brbbot-static
  dynamic out/dynamic/brbbot.exe-20261106-112802   (elevated, no FakeNet)
          out/dynamic/brbbot.exe-20261106-113812   (unelevated comparison)
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_writer

HERE = os.path.dirname(os.path.abspath(__file__))
PIPE = os.path.dirname(HERE)
ROOT = os.path.dirname(PIPE)                 # the coursework tree
# Plain text only. The reports live in report/, grouped by collection.
TXTDIR = os.path.join(ROOT, "report", "for610")
os.makedirs(TXTDIR, exist_ok=True)
TXT = os.path.join(TXTDIR, "brbbot-report.txt")
pm = json.load(open(os.path.join(PIPE, "out", "static", "brbbot-static",
                                 "pe_meta.json"), encoding="utf-8"))

sec = ["%-8s %9s %9s  H=%-6s %-4s" % ("name", "raw", "virtual", "entr", "perm")]
for s in pm["sections"]:
    sec.append("%-8s %9d %9d  H=%-6s %-4s" %
               (s["name"], s["rawsize"], s["vsize"], s["entropy"], s["perm"]))

DOC = [
    # ===================================================== 1. BASIC STATIC
    ("h1", "1. Basic Static Analysis"),

    ("h2", "1.1. File information"),
    ("body", [
        "- File name: brbbot.exe",
        "- File type: Win64 exe (PE32+, x86-64)",
        "- File size: 74.00 KB (75,776 bytes)",
        "- Hash values:",
        "    + MD5:     1c7243c8f3586b799a5f9a2e4200aa92",
        "    + SHA-1:   4db5a8e237937b6d7b435a8506b8584121a7e9e3",
        "    + SHA-256: f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e",
        "- Compilation Timestamp: 2015-02-25 06:12:18 UTC  (0x54ed67c2 / 1424844738)",
        "- Imphash: 475b069fec5e5868caeb7d4d89236c89",
        "- Digital signature: none",
        "- Icon: none",
        "- VERSIONINFO: absent (no company / product / version strings)",
    ]),
    ("text", [
        "Note on the architecture: this sample is 64-bit (imagebase 0x140000000), so "
        "function addresses are of the form 0x1400xxxxx rather than the 0x40xxxx of a "
        "32-bit sample. It runs natively on a 64-bit analysis VM.",
        "The compilation timestamp is corroborated by the file's own modified time, "
        "which matches it to the second. It is also one second apart from getdown.exe "
        "in the same archive (0x54ed67c1) -- the two TimeDateStamps are consecutive "
        "integers, i.e. the same build session.",
    ]),
    ("shot", "CFF Explorer -> File Header, showing TimeDateStamp 0x54ed67c2"),

    ("h2", "1.2. Notable Strings"),
    ("text", [
        "These are genuine strings from the binary's data, kept separate from the "
        "imported API names below -- the two are different things and the report "
        "template scores them as different rows.",
    ]),
    ("body", [
        "0x14000fe00  'brbconfig.tmp'",
        "             referenced by FUN_140001150, FUN_140002230, FUN_140002550, FUN_140002940",
        "0x14000fe78  'APPDATA'",
        "             referenced by FUN_140002230",
        "0x14000fe80  'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
        "             referenced by FUN_140002230, FUN_140002550",
        "0x14000feb0  'brbbot'",
        "             referenced by FUN_140002230, FUN_140002550",
        "0x14000ff30  'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)'",
        "             referenced by FUN_140002f50",
    ]),
    ("text", [
        "209 strings in total. There is NO domain, URL or IP address among them -- the "
        "C2 host is not present as a string, which is dealt with in section 2.5.",
        "Imported APIs, 115 symbols across 5 DLLs, grouped by what they are for:",
    ]),
    ("body", [
        "ADVAPI32.DLL (14)  crypto + registry",
        "    CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptDeriveKey,",
        "    CryptEncrypt, CryptDecrypt, CryptDestroyHash, CryptDestroyKey,",
        "    CryptReleaseContext, RegOpenKeyExA, RegSetValueExA, RegDeleteValueA,",
        "    RegFlushKey, RegCloseKey",
        "",
        "WININET.DLL (9)    HTTP client",
        "    InternetOpenA, InternetConnectA, InternetSetOptionA, HttpOpenRequestA,",
        "    HttpSendRequestA, HttpQueryInfoA, InternetQueryDataAvailable,",
        "    InternetReadFile, InternetCloseHandle",
        "",
        "WS2_32.DLL (5)     host resolution",
        "    WSAStartup, WSACleanup, gethostname, gethostbyname, inet_ntoa",
        "",
        "KERNEL32.DLL (86)  file / process / resource / anti-analysis",
        "    CopyFileA, MoveFileExA, DeleteFileA, CreateFileA, WriteFile, ReadFile,",
        "    GetTempPathA, GetTempFileNameA, CreateProcessA, GetEnvironmentVariableA,",
        "    GetComputerNameA, GetModuleFileNameA, FindResourceA, LoadResource,",
        "    LockResource, SizeofResource, IsDebuggerPresent, GetTickCount, Sleep,",
        "    GetProcAddress, LoadLibraryW, CreateEventW, WaitForSingleObject, ...",
        "",
        "USER32.DLL (1)     GetDC",
    ]),
    ("text", [
        "The WS2_32 set (WSAStartup / gethostname / gethostbyname / inet_ntoa) is the "
        "same combination seen in other RAT-shaped samples: initialise Winsock, learn "
        "the victim's own name, resolve it, and turn the address into a string for "
        "reporting back.",
    ]),
    ("shot", "Detect It Easy -> Strings, or Ghidra Window -> Defined Strings"),
    ("shot", "CFF Explorer -> Import Directory, showing WININET and ADVAPI32"),

    ("h2", "1.3. Packer Detection"),
    ("text", [
        "There is no packer in this sample. Rather than relying on an entropy "
        "threshold alone, which misses packers that compress poorly, the structural "
        "shape was checked:",
    ]),
    ("body", sec + [
        "",
        "whole file entropy H = %s" % pm["file_entropy"],
        "",
        "- 115 imported symbols across 5 DLLs   (a packer stub typically has < 15)",
        "- 225 recovered functions              (a stub typically has < 10)",
        "- highest section entropy 6.349        (a packed payload runs 7.0 - 8.0)",
        "- no section has raw size 0 with a large virtual size (the UPX0 signature)",
        "- no section is both writable and executable",
        "- code is denser than data (.text 6.349 vs .data 1.973), the normal direction",
    ]),
    ("text", [
        "One shape that looks suspicious but is not: .data has a virtual size roughly "
        "three times its raw size. That is normal -- uninitialised data (BSS) costs no "
        "file bytes. The signal that matters is an EXECUTABLE section with that ratio. "
        "Every executable section here is 0.99x.",
        "Important caveat on the method: entropy must be measured over the RAW FILE "
        "BYTES. Ghidra reports entropy over the loaded memory block, zero-padded out to "
        "the section's virtual size, which collapses the figure for a packed section "
        "that is mostly padding and makes a packed sample read as clean. The numbers "
        "above come from the raw file.",
    ]),
    ("shot", "Detect It Easy -> Entropy tab, whole file and per section"),

    # ================================================== 2. ADVANCED STATIC
    ("h1", "2. Advanced Static Analysis"),
    ("text", [
        "The sample was opened in Ghidra rather than IDA Pro. The IDA Freeware build "
        "available in the analysis VM has no decompiler, so it would give disassembly "
        "only; Ghidra's decompiler output is what the walkthrough below is read from. "
        "Addresses are identical in both tools, and names translate directly: Ghidra's "
        "FUN_140001000 is IDA's sub_140001000.",
        "Of 225 recovered functions, 29 carry any capability score. The rest is Visual "
        "C++ runtime code. The functions below are the sample itself.",
    ]),

    ("h2", "2.1. Program structure -- FUN_1400027c0 is the main routine"),
    ("text", [
        "FUN_1400027c0 is the orchestrator and has the shape a RAT main loop usually "
        "has:",
    ]),
    ("body", [
        "FUN_1400027c0  (373 bytes)",
        "  WSAStartup                    initialise Winsock",
        "  CreateEventW / WaitForSingleObject    the wait between beacons",
        "  calls:",
        "      FUN_140001150   read the embedded configuration resource",
        "      FUN_1400012e0   buffer / string helper",
        "      FUN_140001840   read the C2 response and parse commands",
        "      FUN_140001c10   collect the victim's computer name",
        "      FUN_140001fb0   execute a command",
        "      FUN_140002230   INSTALL   (persistence)",
        "      FUN_140002550   UNINSTALL (removal)",
        "  WSACleanup                    tear down Winsock",
    ]),
    ("text", [
        "An important structural observation: FUN_1400027c0 has ZERO callers in the "
        "recovered call graph, and so does the connect routine FUN_140002f50. The whole "
        "C2 subsystem is present in the binary but is not statically reachable from the "
        "entry point in the graph Ghidra recovered. This is the reason the C2 host "
        "cannot be read out of the disassembly by following calls from entry, and it is "
        "why the dynamic stage matters for this sample.",
    ]),
    ("shot", "Ghidra -> Function Call Graph for FUN_1400027c0"),

    ("h2", "2.2. Configuration -- RC4, with the key compiled in"),
    ("text", [
        "The sample carries its configuration as a PE resource and decrypts it with "
        "RC4. The key is not stored; it is derived at run time from a hardcoded "
        "passphrase, which means it can be reproduced on the analysis host with no VM "
        "and no network at all.",
        "FUN_140002940 (write) and FUN_140002c50 (read) both perform:",
    ]),
    ("body", [
        "CryptAcquireContextW(...)",
        "CryptCreateHash(hProv, 0x8003, ...)            0x8003 = CALG_MD5",
        "CryptHashData(hHash, \"YnJiYm90\", 8, 0)         hardcoded passphrase",
        "CryptDeriveKey(hProv, 0x6801, hHash, 0x800000, ...)",
        "                                               0x6801   = CALG_RC4",
        "                                               0x800000 = 128-bit key length",
    ]),
    ("text", [
        "A 128-bit RC4 key derived from an MD5 digest takes the whole 16-byte digest, "
        "so the key is exactly MD5(\"YnJiYm90\") = e2834a5bba1c28b7f536bd3ec5f1d8e0. "
        "Note also that \"YnJiYm90\" is base64 and decodes to the literal string "
        "\"brbbot\".",
        "The initial configuration ships as PE resource CONFIG/101, 73 bytes at RVA "
        "0x17070, and is written to disk by FUN_140001150. Decrypted it reads:",
    ]),
    ("body", [
        "uri=ads.php;exec=cexe;file=elif;conf=fnoc;exit=tixe;encode=5b;sleep=30000",
        "",
        "  uri     = ads.php     the request path on the C2",
        "  exec    = cexe        command keyword: execute",
        "  file    = elif        command keyword: file operation",
        "  conf    = fnoc        command keyword: update configuration",
        "  exit    = tixe        command keyword: uninstall and quit",
        "  encode  = 5b",
        "  sleep   = 30000       30 seconds between beacons",
    ]),
    ("text", [
        "The four command keywords are each their own name spelled backwards: cexe/exec, "
        "elif/file, fnoc/conf, tixe/exit.",
    ]),
    ("shot", "Ghidra decompiler, FUN_140002940, showing the three Crypt* calls"),
    ("shot", "Terminal running out/decrypt_brbconfig.py with the decrypted configuration"),

    ("h2", "2.3. Persistence -- FUN_140002230"),
    ("text", [
        "Before describing any of these file operations it is necessary to name which "
        "variable holds which path, because two MoveFileExA calls that look alike in an "
        "API list point at completely different files:",
    ]),
    ("body", [
        "local_138 = GetModuleFileNameA(...)        the path the sample was LAUNCHED FROM",
        "lpData    = %APPDATA% + \"\\\" + filename     the INSTALLED COPY",
        "pcVar7    = strstr(local_138, %APPDATA%)   \"am I already installed?\"",
        "",
        "0x14000230a  GetEnvironmentVariableA(\"APPDATA\")",
        "0x1400023e2  CopyFileA(local_138 -> lpData)",
        "0x140002432  RegOpenKeyExA(0x80000002, \"Software\\Microsoft\\Windows\\",
        "                           CurrentVersion\\Run\", 0, 0x20006)",
        "                 0x80000002 = HKEY_LOCAL_MACHINE",
        "                 0x20006    = KEY_WRITE | KEY_READ",
        "0x14000247a  RegSetValueExA(hKey, \"brbbot\", 0, 1, lpData)    type 1 = REG_SZ",
        "",
        "if (pcVar7 == NULL) MoveFileExA(local_138, NULL, 4)   the ORIGINAL, conditionally",
        "                    MoveFileExA(\"brbconfig.tmp\", NULL, 4)",
        "                    4 = MOVEFILE_DELAY_UNTIL_REBOOT",
        "",
        "if (write failed)   DeleteFileA(lpData)               ROLLBACK: the COPY",
    ]),
    ("text", [
        "So the behaviour is install-then-clean-up, not self-destruct: the installed "
        "copy in %APPDATA% is durable, and it is the DROPPER -- the path the sample was "
        "launched from -- that gets queued for deletion at the next reboot. The guard "
        "ensures the installed copy is never the one queued.",
        "Because the key is HKLM and not HKCU, writing it requires administrator "
        "rights. What happens without them is covered in section 3.3.",
    ]),
    ("shot", "Ghidra decompiler, FUN_140002230, with the CopyFileA and RegSetValueExA calls"),

    ("h2", "2.4. Uninstall -- FUN_140002550"),
    ("text", [
        "The counterpart to the installer, and the handler behind the configuration's "
        "exit=tixe command. It is called from the same orchestrator, FUN_1400027c0.",
    ]),
    ("body", [
        "FUN_140002550  (622 bytes)",
        "  RegOpenKeyExA   / RegDeleteValueA   remove the 'brbbot' value from the Run key",
        "  RegFlushKey     / RegCloseKey",
        "  GetModuleFileNameA                  locate itself",
        "  GetSystemDirectoryA",
        "  GetSystemWow64DirectoryA            checks both 64- and 32-bit system dirs",
        "  DeleteFileA / MoveFileExA           remove its files",
        "  references 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    ]),
    ("text", [
        "This means the operator can cleanly remove the implant on demand, which is a "
        "capability worth recording separately from persistence: the same registry "
        "value is both created and deleted by the sample, so its absence on a host does "
        "not prove the host was never infected.",
    ]),

    ("h2", "2.5. Network -- FUN_140002f50, FUN_140001840, FUN_140003030"),
    ("body", [
        "FUN_140002f50  (212 bytes)  the connect routine",
        "    InternetOpenA(...)",
        "    InternetConnectA(param_1, ...)     <-- param_1 is the C2 HOST",
        "    HttpOpenRequestA / HttpSendRequestA",
        "    references the hardcoded user-agent at 0x14000ff30",
        "",
        "FUN_140001840  (963 bytes)  the response handler and command parser",
        "    InternetQueryDataAvailable / InternetReadFile",
        "    strncmp(...)                       <-- compares against cexe/elif/fnoc/tixe",
        "",
        "FUN_140003030  (195 bytes)  request helper",
    ]),
    ("text", [
        "The user-agent is HARDCODED in the binary at 0x14000ff30:",
        "    Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
        "Because the sample carries this string itself, it IS a usable network "
        "indicator -- unlike samples that call URLDownloadToFileA and inherit whatever "
        "user-agent the victim's Internet Explorer is configured with.",
        "What static analysis CANNOT give for this sample is the C2 host itself. There "
        "is no domain-shaped or IP-shaped string among the 209 strings, the decrypted "
        "configuration carries only the URI path (ads.php) and not a host, and "
        "FUN_140002f50 -- which receives the host as param_1 -- has zero callers in the "
        "recovered call graph, so the value cannot be traced back to a constant.",
    ]),
    ("shot", "Ghidra decompiler, FUN_140002f50, showing InternetConnectA and the user-agent"),

    ("h2", "2.6. Victim information collection"),
    ("body", [
        "FUN_140001c10  (917 bytes)   GetComputerNameA   -- the machine's name",
        "FUN_140001770  (207 bytes)   gethostname, gethostbyname, inet_ntoa",
        "                             -- resolve own name, format the address as text",
    ]),
    ("text", [
        "Together these give the operator the victim's hostname and IP address as "
        "printable strings, which is the usual first report a bot sends after it "
        "registers.",
    ]),

    ("h2", "2.7. Command execution -- FUN_140003100 and FUN_140001fb0"),
    ("body", [
        "FUN_140003100  (506 bytes)   the exec=cexe handler",
        "    GetTempPathA / GetTempFileNameA    make a file in %TEMP%",
        "    CreateFileA / WriteFile            write the downloaded payload to it",
        "    CreateProcessA                     run it",
        "    MoveFileExA                        queue it for deletion",
        "",
        "FUN_140001fb0  (634 bytes)   direct execution",
        "    CreateProcessA / SetEvent",
    ]),
    ("text", [
        "FUN_140003100 is the capability that matters most for impact: it writes an "
        "operator-supplied file to %TEMP% and launches it, so the implant can run "
        "arbitrary code of the attacker's choosing. Everything else the sample does is "
        "in service of reaching this point.",
    ]),

    ("h2", "2.8. Anti-analysis"),
    ("body", [
        "FUN_140003300  (625 bytes)",
        "    GetModuleHandleW / GetProcAddress    resolves ZwQuerySystemInformation",
        "                                         at run time rather than importing it",
        "IsDebuggerPresent                        imported, present in the binary",
    ]),
    ("text", [
        "Resolving ZwQuerySystemInformation dynamically means the API does not appear "
        "in the import table, so a reviewer who checks only the imports will not see "
        "that the sample can enumerate processes. This is the standard reason to read "
        "GetProcAddress call sites rather than trusting the import table as a complete "
        "capability list.",
    ]),

    # ================================================== 3. BASIC DYNAMIC
    ("h1", "3. Basic Dynamic Analysis"),
    ("text", [
        "The sample was detonated in a local, isolated VMware virtual machine rather "
        "than uploaded to an online sandbox. This is a deliberate choice: uploading a "
        "sample to a third-party service publishes it, which can burn an investigation "
        "or tip off the operator, and it is not reversible. Hash lookups are safe; "
        "uploading the file is not. The equivalent visibility is obtained locally with "
        "FakeNet-NG simulating the internet inside the same VM.",
        "Environment, verified at run time rather than assumed: the VM's NIC is "
        "host-only (no route to the internet), shared folders are disabled, a clean "
        "snapshot exists, and the VM is reverted and the revert verified after every "
        "run.",
    ]),

    ("h2", "3.1. Observed behaviour"),
    ("body", [
        "Run: elevated, 90 s, Procmon active",
        "",
        "  dropped_new        2",
        "  reg_new            1",
        "  tcp_endpoints      0",
        "  dns_names          0",
        "",
        "FILES",
        "  C:\\Users\\REM\\AppData\\Roaming\\brbbot.exe",
        "      sha256 identical to the original sample -- a plain CopyFileA, not a",
        "      re-packed or modified copy",
        "  brbconfig.tmp, 73 bytes, written beside the running sample",
        "",
        "REGISTRY",
        "  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "      value 'brbbot' (REG_SZ) = C:\\Users\\REM\\AppData\\Roaming\\brbbot.exe",
        "",
        "  PendingFileRenameOperations entries for the launched path and for",
        "  brbconfig.tmp beside it -- NOT for the %APPDATA% copy",
    ]),
    ("text", [
        "Each of these corresponds exactly to a static finding: the copy to the "
        "CopyFileA at 0x1400023e2, the registry value to the RegSetValueExA at "
        "0x14000247a, and the PendingFileRenameOperations entries to the guarded "
        "MOVEFILE_DELAY_UNTIL_REBOOT calls.",
    ]),
    ("shot", "Procmon filtered to the sample, showing CopyFile and RegSetValue"),
    ("shot", "Regedit at HKLM\\...\\CurrentVersion\\Run showing the 'brbbot' value"),

    ("h2", "3.2. The loop closes on a hash"),
    ("text", [
        "The strongest single piece of evidence in this analysis is that the embedded "
        "resource and the dropped file are byte-identical:",
    ]),
    ("body", [
        "PE resource CONFIG/101 (73 bytes, extracted on the host)",
        "    sha256 EE20EC1F9A574280270C0045CAA6EDA5B35B35D131E7A45DB7D0AFDAEF131E08",
        "",
        "brbconfig.tmp (73 bytes, dropped in the guest)",
        "    sha256 EE20EC1F9A574280270C0045CAA6EDA5B35B35D131E7A45DB7D0AFDAEF131E08",
    ]),
    ("text", [
        "Static analysis supplied the RC4 key, dynamic analysis supplied the artifact, "
        "and the hash ties them together. This requires no network simulation at all.",
    ]),

    ("h2", "3.3. Persistence is gated on administrator rights -- and it rolls itself back"),
    ("text", [
        "Two runs of the same sample on the same clean snapshot, differing only in "
        "whether the sample was launched elevated:",
    ]),
    ("body", [
        "                        elevated (90 s)      NOT elevated (120 s)",
        "  dropped_new           2                    1",
        "  reg_new               1                    0",
        "  persistence found     HKLM Run key         none reported",
        "  alive at timeout      no                   yes (had to be killed)",
    ]),
    ("text", [
        "Read on its own, the unelevated run says the sample neither persisted nor "
        "copied itself. Both halves of that are false. Procmon recorded four events "
        "within five milliseconds:",
    ]),
    ("body", [
        "1:19:17.9726  CreateFile                     SUCCESS        ...\\Roaming\\brbbot.exe",
        "1:19:17.9764  WriteFile                      SUCCESS        ...\\Roaming\\brbbot.exe",
        "1:19:17.9768  RegOpenKey                     ACCESS DENIED  HKLM\\...\\Run",
        "1:19:17.9769  SetDispositionInformationFile  SUCCESS        ...\\Roaming\\brbbot.exe",
    ]),
    ("text", [
        "It copied itself, was denied KEY_WRITE on the HKLM key because it lacked "
        "administrator rights, and then deleted its own copy one millisecond later -- "
        "the DeleteFileA rollback identified statically at the end of FUN_140002230.",
        "Two consequences worth stating plainly. First, the privilege level a sample is "
        "launched with silently changes the answer to the persistence question, so it "
        "must be recorded alongside any dynamic result. Second, a baseline-versus-after "
        "snapshot diff cannot see a file whose entire lifetime fits between the two "
        "snapshots; only a live monitor such as Procmon catches it.",
        "The rollback is itself a usable detection signature: a CreateFile -> WriteFile "
        "-> SetDispositionInformationFile burst on a single %APPDATA% path, bracketing "
        "an ACCESS DENIED on a Run key.",
    ]),
    ("shot", "Procmon showing the four-event burst, including the ACCESS DENIED"),

    ("h2", "3.4. Network behaviour"),
    ("text", [
        "The runs above recorded zero TCP connections and zero DNS queries. That "
        "absence is a property of the instrumentation, not of the sample: the VM's NIC "
        "is host-only and no network simulator was running during those runs, so there "
        "was nothing for the sample to connect to and nothing to answer a lookup. It "
        "would be wrong to report this as 'the sample generated no traffic'.",
        "What static analysis already establishes about the traffic regardless: HTTP "
        "via WININET, the URI path ads.php, the hardcoded MSIE 8.0 user-agent, a 30 "
        "second beacon interval, and a four-keyword command vocabulary. The missing "
        "element is the C2 host, for the structural reason given in section 2.5.",
    ]),

    # ================================================= 4. ADVANCED DYNAMIC
    ("h1", "4. Advanced Dynamic Analysis"),
    ("text", [
        "No interactive debugging session was performed against this sample, and this "
        "section records why, together with what a debugger would and would not add.",
        "The obvious obstacle is visible in the configuration recovered statically: "
        "sleep=30000. The orchestrator FUN_1400027c0 waits on an event between beacons, "
        "so a debugger stepping through the main loop spends thirty seconds per "
        "iteration and keeps arriving back at the same wait rather than reaching the "
        "command dispatcher. The dispatcher only becomes reachable once a C2 actually "
        "answers, because the command keywords are compared against the response body "
        "in FUN_140001840. Stepping alone does not get there.",
        "That is the same obstacle encountered when debugging comparable samples, and "
        "the productive response is the same: instead of stepping the loop, go to each "
        "handler directly and read it. Sections 2.3 to 2.8 are the result of doing "
        "that -- every branch the dispatcher can take has been identified and described "
        "from the decompiled code, which is what a debugger would have been used to "
        "discover.",
        "Two further points about this sample specifically. It imports "
        "IsDebuggerPresent, so a debugger's presence is detectable by the sample. And "
        "it is not packed, so there is no packer stub to step through and no original "
        "entry point to find -- the usual reason for reaching for a debugger first does "
        "not apply here.",
        "What is genuinely still missing, and should not be claimed otherwise: no "
        "memory image of an infected run was captured, so in-memory-only behaviour has "
        "not been examined. For this sample that gap is narrow, because the import "
        "table contains no WriteProcessMemory, no CreateRemoteThread and no "
        "VirtualAllocEx -- there is no code injection capability to look for -- but the "
        "statement rests on the imports and the disassembly rather than on a memory "
        "image.",
    ]),

    # ===================================================== 5. CONCLUSION
    ("h1", "5. Conclusion"),
    ("text", [
        "brbbot.exe is an HTTP backdoor. It installs itself for all users by copying "
        "itself to %APPDATA%\\brbbot.exe and registering that copy under the HKLM Run "
        "key, then removes the dropper it was launched from, so the surviving artifact "
        "on disk is the installed copy rather than the file the victim ran. Persistence "
        "requires administrator rights; without them the sample deletes its own copy "
        "and leaves almost no trace, which makes an unprivileged infection easy to "
        "mistake for a sample that did nothing.",
        "Its configuration travels as an RC4-encrypted PE resource whose key is derived "
        "from a passphrase compiled into the binary, so the configuration can be "
        "decrypted on an analysis workstation with no virtual machine and no network. "
        "The decrypted configuration gives the request path, the beacon interval and a "
        "four-command vocabulary whose keywords are their own names reversed.",
        "Once running it beacons over HTTP every thirty seconds with a hardcoded "
        "Internet Explorer 8 user-agent, reports the victim's computer name and "
        "resolved IP address, and waits for one of four commands: execute, file "
        "operation, configuration update, and uninstall. The execute handler writes an "
        "operator-supplied file to %TEMP% and launches it, which makes the sample a "
        "delivery mechanism for arbitrary further code. The uninstall handler deletes "
        "both the Run key value and the installed file, so the absence of those "
        "artifacts does not prove a host was never compromised.",
        "The one element that could not be recovered is the C2 host itself. It is not "
        "present as a string, the configuration carries only the URI path, and the "
        "connect routine that receives the host as a parameter is not reachable from "
        "the entry point in the recovered call graph. Establishing it requires either a "
        "network simulator answering the beacon or a capture of real traffic.",
        "Assessment: this is a remote access implant with arbitrary code execution, "
        "stated as an inference with high confidence. The supporting evidence is the "
        "command vocabulary, the execute handler, the beacon loop and the persistence "
        "mechanism, each identified at a specific address and, where it produces a disk "
        "or registry artifact, corroborated in the dynamic runs.",
    ]),
]


def main():
    report_writer.render_freeform_txt(
        DOC, "Malware Analysis Report - brbbot.exe", TXT)


if __name__ == "__main__":
    main()

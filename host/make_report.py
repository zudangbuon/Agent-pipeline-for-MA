#!/usr/bin/env python3
"""Build a report skeleton for ANY sample, from the artifacts, in three sections.

    python host/make_report.py --static out/static/<tag> \
                               [--dynamic out/dynamic/<tag>] \
                               [--out report/for610/<name>.txt]

The report criteria are:

    1. Basic static analysis      file info, strings, packing
    2. Advanced static analysis   function-by-function reverse engineering
    3. Basic dynamic analysis     files, registry, processes, network

This replaces the earlier per-sample `fill_report_*.py` scripts, which held their
findings as hardcoded prose and so had to be rewritten for every new sample. Here the
measurable facts are read out of the artifacts and the analyst writes only the parts
that are genuinely judgement: what a function does, what the sample is for, and what
the evidence supports.

Two things it does that a human writing from scratch reliably forgets:

  * it carries the COVERAGE CAVEATS automatically. Section 3 always states which
    persistence classes were checked and which were not monitored at all, because
    "no persistence found" and "no persistence exists" are different claims and only
    the first one is supportable.
  * it separates the INSTRUMENT from the sample. A FakeNet run installs a WinDivert
    service and redirects traffic to 192.0.2.123; both show up in the artifacts and
    neither is sample behaviour. The generated report says so where they appear.

Anything the analyst must supply is marked `[TODO: ...]`, and the footer counts them,
so an unfinished report is obvious rather than quietly incomplete.
"""
import argparse
import csv
import io
import json
import os
import re
import sys

TODO = "[TODO: %s]"


def shot(what, tool=""):
    """A screenshot marker, in the same shape the hand-written reports use.

    Left visible on purpose: a labelled gap is better than a figure that is
    silently missing. The tool name is included because the report is marked on
    evidence, and 'which window this came from' is part of the evidence.
    """
    return "[SCREENSHOT: %s%s]" % (what, ("  --  %s" % tool) if tool else "")


# ----------------------------------------------------------------- artifact IO
def jload(path, default=None):
    """Artifacts from the guest carry a UTF-8 BOM; utf-8-sig handles both cases.

    A plain json.load() raises on the BOM and every file reads as empty, which is
    indistinguishable from a run that captured nothing.
    """
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return default
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return default


def tload(path):
    if not path or not os.path.exists(path):
        return ""
    with io.open(path, encoding="utf-8-sig", errors="replace") as fh:
        return fh.read()


def fmt(n):
    return "{:,}".format(n) if isinstance(n, int) else str(n)


# --------------------------------------------------------------- 1. BASIC STATIC
def sec1(pm, meta, strings):
    L = ["1. BASIC STATIC ANALYSIS", "=" * 24, "",
         "1.1. File information", "-" * 21, ""]

    if not pm:
        L += ["  " + TODO % "run host/pe_meta.py --json <tag>/pe_meta.json",
              "  Without it, entropy comes from Ghidra's zero-padded virtual blocks",
              "  and a packed sample can read as clean.", ""]
    else:
        hdr = pm.get("header", {}) or {}
        ct = pm.get("compile_time", {}) or {}
        fs = pm.get("fs_timestamps", {}) or {}
        sig = pm.get("signature", {}) or {}
        ico = pm.get("icon", {}) or {}
        size = pm.get("file_size")
        L += ["- File name: %s" % pm.get("file_name", "?"),
              "- File type: %s" % (meta or {}).get("filetype", "?"),
              "- File size: %s bytes" % fmt(size)]
        L += ["- Hash values:",
              "    + MD5    : %s" % pm.get("md5", "?"),
              "    + SHA-1  : %s" % pm.get("sha1", "?"),
              "    + SHA-256: %s" % pm.get("sha256", "?"),
              "- Imphash: %s%s" % (pm.get("imphash", "?"),
                                   "   (source: %s)" % pm["imphash_source"]
                                   if pm.get("imphash_source") else "")]
        if ct:
            L.append("- Compilation timestamp: %s   (%s / %s)"
                     % (ct.get("utc", "?"), ct.get("hex", "?"), ct.get("raw", "?")))
        if fs:
            L.append("- Filesystem modified  : %s" % fs.get("modified", "?"))
            if ct.get("utc") and fs.get("modified"):
                same = ct["utc"][:19] == fs["modified"][:19]
                L.append("  %s" % ("matches the header to the second -- independent "
                                   "corroboration of the build date" if same else
                                   "does NOT match the header; the two do not "
                                   "corroborate each other"))
        L += ["- Signed: %s" % ("no (no Authenticode certificate)"
                                if not sig.get("signed") else
                                "certificate present -- NOT verified; presence is not validity"),
              "- Icon: %s" % ("none -- generic Windows default"
                              if not ico.get("has_icon") else
                              "%s icon resource(s)" % ico.get("count", "?")),
              "- VERSIONINFO: %s" % ("absent -- no company / product / version strings"
                                     if not pm.get("version_info") else "present")]
        if hdr:
            L += ["- Header: %s %s-bit, subsystem=%s, linker %s%s"
                  % (hdr.get("machine", "?"), hdr.get("bits", "?"),
                     hdr.get("subsystem", "?"), hdr.get("linker", "?"),
                     ", DLL" if hdr.get("is_dll") else
                     ", driver" if hdr.get("is_driver") else ""),
                  "          image base %s, entry point %s"
                  % (hdr.get("image_base", "?"), hdr.get("entry_point", "?")),
                  "          characteristics %s = %s"
                  % (hdr.get("characteristics", "?"),
                     " | ".join(hdr.get("characteristics_flags") or []) or "-")]
        L += ["",
              "  " + TODO % "compare the compile timestamp against its siblings in the "
                            "same collection -- absolute plausibility is not enough, a "
                            "faked timestamp can still be in the past",
              "",
              shot("file hashes and size", "CFF Explorer, or the pe_meta.py terminal"),
              shot("TimeDateStamp %s" % (ct.get("hex") or "in the file header"),
                   "CFF Explorer -> File Header")]

    # ---- strings
    L += ["", "1.2. Notable strings", "-" * 20, ""]
    tagged = [s for s in (strings or []) if s.get("tags")]
    L.append("%d strings recovered, %d carrying a tag." % (len(strings or []), len(tagged)))
    L.append("")
    if tagged:
        for s in tagged[:25]:
            L.append("  %-12s %-10s %r" % (s.get("ea", ""), ",".join(s["tags"])[:10],
                                           (s.get("text") or "")[:70]))
            refs = s.get("refs") or []
            if refs:
                L.append("  %-12s %-10s referenced by %s"
                         % ("", "", ", ".join(str(r) for r in refs[:4])))
        L += ["",
              "  NOTE: a tag is a HINT, not a finding. An import name can be tagged",
              "  'regkey'; confirm the string is really used as a key path before",
              "  citing it."]
    else:
        L.append("  No tagged strings.")

    net_like = [s for s in (strings or [])
                if re.search(r"https?://|\b\d{1,3}(\.\d{1,3}){3}\b|\.(com|net|org|php)\b",
                             s.get("text") or "", re.I)]
    L += ["",
          "Network-shaped strings: %d" % len(net_like)]
    if not net_like:
        L += ["  NONE. If this sample talks to a network, its target is not stored as",
              "  plaintext -- look for it built or decoded at run time. Absence here is",
              "  a finding, not an absence of capability."]
    else:
        for s in net_like[:10]:
            L.append("  %-12s %r" % (s.get("ea", ""), (s.get("text") or "")[:70]))

    # ---- imports
    ibd = (pm or {}).get("imports_by_dll") or (meta or {}).get("imports_by_dll") or {}
    if ibd:
        total = sum(len(v) for v in ibd.values())
        L += ["", "Imported APIs: %d symbols across %d DLLs" % (total, len(ibd)), ""]
        for dll, syms in sorted(ibd.items(), key=lambda kv: -len(kv[1])):
            L.append("  %-18s %3d" % (dll, len(syms)))
            line = "      "
            for s in sorted(syms):
                # keep the separator on the wrapped line, so the list stays
                # readable as one comma-separated sequence
                if len(line) + len(s) + 2 > 76:
                    L.append(line.rstrip())
                    line = "      "
                line += s + ", "
            if line.strip():
                L.append(line.rstrip().rstrip(","))
        L += ["",
              "  Source: pe_meta.json imports_by_dll -- NOT api_map.json, which is a",
              "  cross-reference map and has been found missing a genuinely imported",
              "  symbol.",
              "",
              "  " + TODO % "say which of these carry capability, and which are CRT noise",
              "",
              shot("the import table", "CFF Explorer -> Import Directory"),
              shot("the strings list", "Detect It Easy -> Strings, or Ghidra -> "
                                       "Window -> Defined Strings")]

    # ---- packing
    L += ["", "1.3. Packer detection", "-" * 21, ""]
    secs = (pm or {}).get("sections") or []
    if not secs:
        L.append("  " + TODO % "no pe_meta.json -- packing verdict not trustworthy")
    else:
        L.append("whole-file entropy H = %s" % (pm.get("file_entropy", "?")))
        L.append("")
        L.append("  %-10s %9s %9s  %-7s %s" % ("name", "raw", "virtual", "entropy", "perm"))
        for s in secs:
            L.append("  %-10s %9s %9s  %-7s %s"
                     % (s.get("name"), fmt(s.get("rawsize", 0)), fmt(s.get("vsize", 0)),
                        s.get("entropy"), s.get("perm", "")))
        hi = max((s.get("entropy") or 0) for s in secs)
        nimp = sum(len(v) for v in ibd.values()) if ibd else 0
        nfun = (meta or {}).get("counts", {}).get("functions", 0)
        L += ["",
              "Structural signals (entropy alone is NOT enough -- a PEncrypt-packed",
              "sample in this collection peaks at H=6.4 and would pass any threshold):",
              "",
              "  highest section entropy : %s%s" % (hi, "   (packed payloads run 7.0-8.0)"),
              "  imported symbols        : %d%s" % (nimp, "   (a packer stub has < 15)"),
              "  recovered functions     : %d%s" % (nfun, "   (a stub has < 10)")]
        zero_raw = [s for s in secs if not s.get("rawsize") and (s.get("vsize") or 0) > 0]
        wx = [s for s in secs if "w" in (s.get("perm") or "") and "x" in (s.get("perm") or "")]
        L += ["  sections with raw 0 + large virtual : %s"
              % (", ".join(s["name"] for s in zero_raw) if zero_raw else "none (the UPX0 signature is absent)"),
              "  writable AND executable sections    : %s"
              % (", ".join(s["name"] for s in wx) if wx else "none")]
        L += ["",
              "  NOTE on a data section whose virtual size exceeds its raw size: that",
              "  is NORMAL -- uninitialised data costs no file bytes. The signal that",
              "  matters is an EXECUTABLE section with that shape.",
              "",
              "  Entropy above is measured over RAW FILE BYTES (pe_meta.py). Ghidra",
              "  measures the loaded block, zero-padded to the virtual size, which",
              "  makes a mostly-padding packed section read as clean.",
              "",
              "  " + TODO % "state the verdict: packed or not, and on which grounds",
              "",
              shot("entropy, whole file and per section", "Detect It Easy -> Entropy"),
              shot("the section table", "CFF Explorer -> Section Headers")]
    return L


# ------------------------------------------------------------ 2. ADVANCED STATIC
def sec2(meta, funcs):
    L = ["", "2. ADVANCED STATIC ANALYSIS", "=" * 27, ""]
    engine = (meta or {}).get("engine") or (meta or {}).get("ida_version") or "?"
    counts = (meta or {}).get("counts", {})
    L += ["Tool: %s, decompiler=%s. %s functions recovered, %s decompiled."
          % (engine, (meta or {}).get("hexrays"),
             counts.get("functions", "?"), counts.get("decompiled", "?")),
          "",
          "Ghidra's FUN_<addr> is IDA's sub_<addr> at the same address, so the",
          "walkthrough below transfers between the two tools unchanged.",
          ""]

    scored = sorted([f for f in (funcs or []) if (f.get("score") or 0) > 0],
                    key=lambda f: -(f.get("score") or 0))
    L.append("%d of %s functions carry a capability score. The rest is C runtime."
             % (len(scored), counts.get("functions", "?")))
    L += ["",
          "  CRT WARNING: functions that only call Heap*/GetProcAddress/LoadLibrary",
          "  are almost always MSVCRT, not the sample resolving APIs to hide them.",
          "  Check the caller chain before walking one.",
          ""]

    cats = {}
    for f in scored:
        for c in (f.get("cats") or []):
            cats.setdefault(c, []).append(f)
    if cats:
        L.append("Capability categories:")
        for c, fs in sorted(cats.items(), key=lambda kv: -len(kv[1])):
            L.append("  %-14s %2d   %s" % (c, len(fs),
                                           ", ".join(f.get("name", "") for f in fs[:5])))
        L.append("")

    L += ["", "2.1. Functions worth reading", "-" * 28, ""]
    for f in scored[:12]:
        L += ["%s  %s   score=%s  size=%s  xrefs=%s"
              % (f.get("ea"), f.get("name"), f.get("score"), f.get("size"),
                 f.get("nxrefs")),
              "    categories : %s" % ", ".join(f.get("cats") or []) or "-"]
        apis = f.get("apis") or []
        if apis:
            L.append("    APIs       : %s" % ", ".join(apis[:10]))
            if len(apis) > 10:
                L.append("                 (+%d more)" % (len(apis) - 10))
        strs = f.get("strings") or []
        if strs:
            L.append("    strings    : %s" % ", ".join(repr(s)[:40] for s in strs[:4]))
        L += ["    " + TODO % "what it does, and the addresses that show it",
              "    read it with:  q.py func %s" % f.get("ea"),
              "    " + shot("decompiled %s" % f.get("name"),
                            "Ghidra -> G -> %s -> Decompile window"
                            % str(f.get("ea", "")).replace("0x", "")),
              ""]

    L += ["", "2.2. Program structure", "-" * 22, "",
          "  " + TODO % "identify the orchestrator / main loop and what it dispatches to",
          "  " + TODO % "name which variable holds which path before describing any file "
                        "operation -- two calls that look alike in an API list can point "
                        "at completely different files",
          "",
          "  Useful: q.py callers <ea> and q.py callees <ea>. A function with ZERO",
          "  callers is worth noting: it is present in the binary but not reachable",
          "  from the entry point in the recovered call graph, which is a reason a",
          "  value it receives as a parameter cannot be traced back to a constant.",
          ""]
    return L


# ------------------------------------------------------------- 3. BASIC DYNAMIC
def sec3(dyn_dir):
    L = ["", "3. BASIC DYNAMIC ANALYSIS", "=" * 25, ""]
    if not dyn_dir:
        L += ["NOT PERFORMED. No detonation artifacts were supplied.",
              "",
              "  python host/mal.py detonate <sample> --mode full --timeout 60 [--elevated]",
              "",
              "  Note that --elevated is not a performance knob: it silently changes",
              "  the answer to the persistence question for any sample whose",
              "  persistence writes to HKLM.",
              ""]
        return L

    summ = jload(os.path.join(dyn_dir, "summary.json"), {}) or {}
    log = tload(os.path.join(dyn_dir, "detonate.log"))
    m = re.search(r"elevated=(\w+)", log)
    elevated = m.group(1) if m else "NOT RECORDED"
    tgt = re.search(r"launch target:\s*(\S+)", log)
    fakenet = bool(summ.get("fakenet"))
    fn_up = "FakeNet-NG up" in log

    L += ["3.1. Run context", "-" * 16, "",
          "  run directory : %s" % dyn_dir,
          "  sample sha256 : %s" % summ.get("sample_sha256", "?"),
          "  mode          : %s   timeout=%ss" % (summ.get("mode"),
                                                  summ.get("timeout_sec", "?")),
          "  finished      : %s" % summ.get("finished", "?"),
          "  elevated      : %s" % elevated,
          "  launched pid  : %s   killed: %s" % (summ.get("launched_pid"),
                                                 summ.get("killed_pids")),
          "  launch target : %s" % (tgt.group(1) if tgt else "?"),
          "  procmon       : %s" % summ.get("procmon"),
          "  fakenet       : summary=%s, log says it came up=%s" % (fakenet, fn_up),
          ""]
    if tgt and tgt.group(1).lower().endswith("sample.exe"):
        L += ["  NOTE: in --copy mode the process is named sample.exe, NOT the host",
              "  filename. Query Procmon by that name or you will get zero events and",
              "  conclude the sample did nothing.", ""]
    if not fakenet:
        L += ["  NO FAKE INTERNET. Any absence of network activity below is a property",
              "  of the instrumentation, not of the sample: there was nothing to",
              "  connect to and nothing to answer a lookup.", ""]

    counts = summ.get("counts") or {}
    if counts:
        L.append("  counts: " + "  ".join("%s=%s" % (k, v) for k, v in sorted(counts.items())))
        L.append("")

    # ---- files
    dropped = jload(os.path.join(dyn_dir, "dropped.json"), []) or []
    new = [d for d in dropped if d.get("state") == "new"]
    L += ["", "3.2. File system artifacts", "-" * 26, "",
          "%d new, %d total recorded." % (len(new), len(dropped)), ""]
    for d in new[:25]:
        L.append("  %s" % d.get("path"))
        L.append("      %s bytes  sha256 %s  magic %s"
                 % (fmt(d.get("size", 0)), (d.get("sha256") or "")[:40], d.get("magic")))
    if len(new) > 25:
        L.append("  (+%d more)" % (len(new) - 25))
    L += ["",
          "  " + TODO % "which of these are the sample's, and which are OS or "
                        "instrumentation noise",
          "",
          "  A snapshot diff CANNOT see a file created and deleted inside the run",
          "  window. 'dropped.json shows nothing new' is not 'nothing was written' --",
          "  check Procmon:   dyn.py --dir <d> procmon <regex>",
          "",
          shot("the sample's file operations", "Procmon, filtered to the sample"),
          shot("the dropped file on disk", "Explorer in the target directory"),
          ""]

    # ---- registry
    reg = jload(os.path.join(dyn_dir, "registry.json"), {}) or {}
    rnew, rchg = reg.get("new") or [], reg.get("changed") or []
    L += ["", "3.3. Registry", "-" * 13, "",
          "%d new value(s), %d changed." % (len(rnew), len(rchg)), ""]
    for r in rnew[:20]:
        key = str(r.get("key", ""))
        L.append("  %s = %s" % (key, str(r.get("value"))[:60]))
        if "WinDivert" in key:
            L.append("      ^ INSTRUMENT, not the sample: FakeNet-NG's packet driver.")
    for r in rchg[:10]:
        L.append("  [changed] %s : %s -> %s"
                 % (r.get("key"), str(r.get("before"))[:30], str(r.get("after"))[:30]))
    L += ["",
          shot("the registry value the sample wrote",
               "Regedit at the key above, or Procmon's RegSetValue"),
          ""]

    # ---- processes
    procs = jload(os.path.join(dyn_dir, "processes.json"), []) or []
    L += ["", "3.4. Processes", "-" * 14, "",
          "%d new process(es) in the snapshot diff." % len(procs), ""]
    for p in procs[:20]:
        L.append("  %-6s ppid=%-6s %-22s %s"
                 % (p.get("pid"), p.get("ppid"), (p.get("name") or "")[:22],
                    (p.get("cmdline") or "")[:40]))
    L += ["",
          "  Ancestry from a snapshot diff is WEAK: once the sample has exited an",
          "  unrelated process can carry its dead pid. Corroborate a parent-child",
          "  claim against Procmon's own 'Process Create' before making it.",
          "  dyn.py --dir <d> proc   does this and labels the three cases differently.",
          ""]

    # ---- network
    net = jload(os.path.join(dyn_dir, "network.json"), {}) or {}
    eps, dns = net.get("endpoints") or [], net.get("dns") or []
    fnlog = tload(os.path.join(dyn_dir, "fakenet.log"))
    L += ["", "3.5. Network artifacts", "-" * 22, "",
          "%d TCP endpoint(s), %d DNS name(s) in the snapshot/poll data." % (len(eps), len(dns)), ""]
    if fakenet and fnlog:
        div = re.findall(r"\[\s*Diverter\]\s+(.+)", fnlog)
        gets = re.findall(r"(GET|POST|HEAD)\s+(\S+)\s+HTTP", fnlog)
        hosts = re.findall(r"Host:\s*(\S+)", fnlog)
        L += ["FakeNet-NG attributes each flow to a pid, which Procmon does not --",
              "these lines are the best network evidence in the run:", ""]
        for d in div[:15]:
            L.append("  [Diverter] %s" % d.strip()[:90])
        if gets:
            L.append("")
            for verb, path in gets[:12]:
                L.append("  %s %s" % (verb, path[:80]))
        if hosts:
            L.append("")
            L.append("  Host headers seen: %s" % ", ".join(sorted(set(hosts))[:12]))
        L += ["",
              "  SEPARATE THE INSTRUMENT FROM THE SAMPLE. FakeNet redirects ALL",
              "  traffic to 192.0.2.123 (RFC 5737 TEST-NET-1), so endpoint tables are",
              "  dominated by the guest's own background traffic, and DNS appears even",
              "  for a sample that makes none. Only a [Diverter] line naming the",
              "  sample's pid attributes a flow to the sample.",
              "",
              "  " + TODO % "pick out the sample's own flows by pid"]
    else:
        for e in eps[:12]:
            L.append("  %s" % e)
        for d in dns[:12]:
            L.append("  DNS %s" % d)
        L += ["",
              "  Without FakeNet an absence here means nothing. Do not write 'the",
              "  sample generated no traffic'."]
    L += ["",
          "  " + TODO % "if a user-agent appears, check whether it is IN the binary's "
                        "strings. A UA supplied by URLMON/WinINet describes the "
                        "ANALYSIS MACHINE and is NOT an indicator",
          "",
          shot("the sample's request", "FakeNet-NG console"),
          shot("the Diverter line naming the sample's pid", "FakeNet-NG console")]

    # ---- persistence coverage, stated honestly every time
    auto = jload(os.path.join(dyn_dir, "autoruns.json"), {}) or {}
    L += ["", "3.6. Persistence", "-" * 16, "",
          "new services : %d" % len(auto.get("new_services") or []),
          "new tasks    : %d" % len(auto.get("new_tasks") or []), ""]
    for s in (auto.get("new_services") or [])[:10]:
        nm = str(s.get("Name", ""))
        L.append("  service %s -> %s" % (nm, s.get("PathName")))
        if "WinDivert" in nm:
            L.append("      ^ INSTRUMENT, not the sample: FakeNet-NG's packet driver.")
    for t in (auto.get("new_tasks") or [])[:10]:
        L.append("  task %s -> %s" % (t.get("Name"), t.get("Action")))

    L += ["",
          "CLASSES THAT WERE CHECKED:",
          "  files      TEMP, APPDATA, LOCALAPPDATA, ProgramData, Startup, Downloads,",
          "             Documents, Desktop, windir\\Temp, System32\\Tasks, System32,",
          "             SysWOW64, windir, C:\\, Program Files (both), and the sample's",
          "             own directory",
          "  registry   Run and RunOnce (HKCU + HKLM), Winlogon, Image File Execution",
          "             Options, User Shell Folders, CurrentControlSet\\Services",
          "  services   full Win32_Service diff",
          "  tasks      full Get-ScheduledTask diff",
          "",
          "CLASSES NOT MONITORED AT ALL -- silence about these means nothing:",
          "  WMI event subscriptions, COM hijacking, DLL search-order hijacking,",
          "  AppInit_DLLs, AppCertDlls.",
          "",
          "  Also invisible: a value nested BELOW a watched key. The snapshot records",
          "  each key's own values plus only the NAMES of its immediate subkeys, so an",
          "  IFEO Debugger value inside a per-executable subkey, or a ServiceDll inside",
          "  a service's Parameters subkey, is not seen.",
          "",
          "  Write which classes were checked. Do not write 'no persistence'.",
          ""]
    return L


# ------------------------------------------------------------------ 4. CONCLUSION
def sec4():
    return ["", "4. CONCLUSION", "=" * 13, "",
            "  " + TODO % "what the sample is, as an INFERENCE with a stated confidence",
            "  " + TODO % "key functionality, each line citing an address or artifact line",
            "  " + TODO % "host and network IOCs",
            "  " + TODO % "persistence mechanism, or that none exists and on what grounds",
            "",
            "  Rules for this section:",
            "   - separate OBSERVED from INFERRED; never merge them",
            "   - every behavioural claim cites an address or an artifact line",
            "   - do not give a final malicious/benign verdict: evidence plus a",
            "     confidence level, and a human decides",
            "   - 'not determined' with a reason beats a guess written as a fact",
            ""]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--static", required=True, help="out/static/<tag>")
    ap.add_argument("--dynamic", help="out/dynamic/<tag> (optional)")
    ap.add_argument("--out", help="output .txt (default: print to stdout)")
    ap.add_argument("--title")
    a = ap.parse_args()

    if not os.path.isdir(a.static):
        sys.exit("no such static directory: %s" % a.static)
    if a.dynamic and not os.path.isdir(a.dynamic):
        sys.exit("no such dynamic directory: %s" % a.dynamic)

    meta = jload(os.path.join(a.static, "meta.json"), {}) or {}
    pm = jload(os.path.join(a.static, "pe_meta.json"))
    funcs = jload(os.path.join(a.static, "functions.json"), []) or []
    strings = jload(os.path.join(a.static, "strings.json"), []) or []

    name = (pm or {}).get("file_name") or os.path.basename(meta.get("input", "") or "") \
        or os.path.basename(a.static.rstrip("/\\"))
    title = a.title or "Malware Analysis Report - %s" % name

    L = [title, "=" * len(title), "",
         "Generated by host/make_report.py from the analysis artifacts.",
         "static : %s" % a.static,
         "dynamic: %s" % (a.dynamic or "(none supplied)"),
         ""]
    L += sec1(pm, meta, strings)
    L += sec2(meta, funcs)
    L += sec3(a.dynamic)
    L += sec4()

    txt = "\n".join(L).rstrip() + "\n"
    todos = txt.count("[TODO:")

    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
        with io.open(a.out, "w", encoding="utf-8", newline="\r\n") as fh:
            fh.write(txt)
        print("wrote %s (%s bytes)" % (a.out, fmt(os.path.getsize(a.out))))
        print("%d section(s), %d TODO left for the analyst" % (4, todos))
        if not pm:
            print("WARNING: no pe_meta.json -- the packing verdict is not trustworthy")
        if not a.dynamic:
            print("NOTE: no dynamic artifacts -- section 3 is a stub")
    else:
        sys.stdout.write(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())

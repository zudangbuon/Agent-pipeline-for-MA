#!/usr/bin/env python3
"""
Ghidra static-triage dumper, driven through PyGhidra.

Runs as an ordinary Python program -- pyghidra.open_program() starts the JVM,
imports the binary and runs auto-analysis, so there is no analyzeHeadless
invocation and no Ghidra -postScript provider to fight with.

  python ghidra_dump.py <sample> <out_dir> [--max-decompile N] [--timeout SEC]

Emits exactly the JSON schema host/q.py already reads, plus, for every target
function, BOTH the decompiled pseudocode and the raw disassembly listing -- the
pseudocode is what the analysis reasons over, the disassembly is what the
Listing window shows at the same address.

Requires:
  pip install --no-index --find-links <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra
  GHIDRA_INSTALL_DIR and JAVA_HOME set.
"""
import json
import math
import os
import re
import sys
import time

# ----------------------------------------------------------- shared taxonomy
API_CATS = {
    "inject": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
               "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection", "RtlCreateUserThread",
               "NtWriteVirtualMemory", "VirtualProtectEx", "OpenProcess", "NtCreateThreadEx"],
    "persist": ["RegSetValue", "RegCreateKey", "CreateService", "StartServiceCtrlDispatcher",
                "SHSetValue", "RegOpenKey", "OpenSCManager", "ChangeServiceConfig"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey", "CryptDeriveKey",
               "CryptHashData", "BCryptEncrypt", "BCryptGenerateSymmetricKey", "CryptImportKey",
               "CryptStringToBinary", "SystemFunction032"],
    "network": ["WinHttpOpen", "WinHttpSendRequest", "InternetOpen", "InternetConnect", "HttpSendRequest",
                "HttpOpenRequest", "URLDownloadToFile", "socket", "connect", "WSAStartup", "WSASocket",
                "send", "recv", "gethostbyname", "DnsQuery", "InternetReadFile", "WinHttpReadData"],
    "antianalysis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                     "OutputDebugString", "QueryPerformanceCounter", "GetTickCount", "NtSetInformationThread",
                     "CreateToolhelp32Snapshot", "Process32First", "NtQuerySystemInformation", "GetSystemInfo",
                     "IsProcessorFeaturePresent", "Sleep", "NtDelayExecution"],
    "dynresolve": ["LoadLibrary", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
                   "GetModuleHandle", "RtlGetProcAddress"],
    "filesystem": ["CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile", "CopyFile",
                   "FindFirstFile", "FindNextFile", "SHFileOperation", "SetFileAttributes",
                   "GetTempPath", "SHGetFolderPath", "GetModuleFileName"],
    "exec": ["CreateProcess", "ShellExecute", "WinExec", "system", "NtCreateUserProcess",
             "CreateProcessAsUser", "CreateProcessWithToken"],
    "cred": ["CredEnumerate", "CredRead", "LsaOpenPolicy", "SamIConnect", "LogonUser",
             "ImpersonateLoggedOnUser", "NetUserEnum"],
    "spy": ["GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx", "BitBlt", "GetClipboardData",
            "GetForegroundWindow", "GetWindowText", "RegisterRawInputDevices", "waveInOpen"],
    "memory": ["VirtualAlloc", "VirtualProtect", "HeapCreate", "NtAllocateVirtualMemory", "RtlMoveMemory"],
    "privesc": ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue", "DuplicateTokenEx",
                "SetTokenInformation"],
}
CAT_WEIGHT = {"inject": 10, "cred": 9, "crypto": 7, "spy": 7, "privesc": 7, "exec": 6,
              "network": 6, "persist": 6, "dynresolve": 5, "antianalysis": 4,
              "filesystem": 2, "memory": 2}

STR_PATTERNS = [
    ("url", re.compile(r"https?://[^\s\"'<>]{4,}", re.I)),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("unc", re.compile(r"\\\\[A-Za-z0-9_.$-]+\\")),
    ("regkey", re.compile(r"(SOFTWARE|SYSTEM|HKEY_|CurrentVersion\\Run|Winlogon)", re.I)),
    ("path", re.compile(r"[A-Za-z]:\\\\?[\w .\\$-]{3,}")),
    ("cmd", re.compile(r"(cmd\.exe|powershell|/c\s|-enc\s|rundll32|regsvr32|schtasks|wscript|mshta|certutil|bitsadmin|vssadmin|wmic|bcdedit)", re.I)),
    ("useragent", re.compile(r"(Mozilla/|User-Agent)", re.I)),
    ("b64blob", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")),
    ("ransom", re.compile(r"(bitcoin|monero|\.onion|decrypt|your files|ransom|tox id)", re.I)),
    ("mutex", re.compile(r"(Global\\|Local\\|Session\\)", re.I)),
    ("sql", re.compile(r"(SELECT\s|INSERT\s|logins|cookies|credit_card)", re.I)),
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")),
]
STR_WEIGHT = {"url": 8, "ip": 7, "cmd": 7, "ransom": 8, "regkey": 4, "unc": 4,
              "sql": 5, "useragent": 4, "mutex": 3, "b64blob": 3, "path": 2, "email": 3}


def log(m):
    print("[ghidra-triage] %s" % m, flush=True)


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b & 0xFF] += 1
    n = float(len(data))
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log(p, 2)
    return round(e, 3)


def categorize(api_label):
    name = api_label.split("!", 1)[-1]
    hits = []
    for cat, needles in API_CATS.items():
        for nd in needles:
            if name.startswith(nd) or name == nd:
                hits.append(cat)
                break
    return hits


def run(sample, outdir, max_decompile=60, decomp_timeout=60):
    import pyghidra
    log("starting JVM (first run builds caches, this is the slow part)")
    pyghidra.start()

    # These must be imported after the JVM is up.
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor

    pc_dir = os.path.join(outdir, "pseudocode")
    asm_dir = os.path.join(outdir, "disasm")
    for d in (outdir, pc_dir, asm_dir):
        os.makedirs(d, exist_ok=True)

    log("importing and analysing %s" % sample)
    t0 = time.time()
    with pyghidra.open_program(sample) as flat:
        prog = flat.getCurrentProgram()
        log("analysis done in %ds" % int(time.time() - t0))

        mon = ConsoleTaskMonitor()
        listing = prog.getListing()
        fm = prog.getFunctionManager()
        refman = prog.getReferenceManager()
        st = prog.getSymbolTable()
        af = prog.getAddressFactory()

        def hx(addr):
            return "0x%x" % addr.getOffset()

        def func_key_at(addr):
            f = fm.getFunctionContaining(addr)
            return hx(f.getEntryPoint()) if f is not None else None

        # ------------------------------------------------------------ sections
        sections = []
        for blk in prog.getMemory().getBlocks():
            size = int(blk.getSize())
            data = None
            try:
                # Must read through the flat API: passing a Python bytearray into
                # blk.getBytes() fills a Java array that JPype never copies back,
                # which silently yields entropy 0.0 for every section -- making a
                # packed binary look unpacked.
                n = min(size, 512 * 1024)
                if n > 0 and blk.isInitialized():
                    raw = flat.getBytes(blk.getStart(), n)
                    data = bytes((int(x) & 0xFF) for x in raw)
            except Exception as e:
                log("entropy read failed for %s: %s" % (blk.getName(), e))
                data = None
            sections.append({
                "name": str(blk.getName()), "start": hx(blk.getStart()), "end": hx(blk.getEnd()),
                "size": size, "perm_x": bool(blk.isExecute()), "perm_w": bool(blk.isWrite()),
                "entropy": entropy(data) if data else 0.0,
            })

        # -------------------------------------------------------- entry points
        entries = []
        for ea in st.getExternalEntryPointIterator():
            sym = st.getPrimarySymbol(ea)
            entries.append({"ea": hx(ea), "name": str(sym.getName()) if sym else ""})

        # ------------------------------------------------------------- imports
        imports_by_dll, import_syms = {}, {}
        for sym in st.getExternalSymbols():
            ns = sym.getParentNamespace()
            lib = str(ns.getName()) if ns else "?"
            nm = str(sym.getName())
            label = "%s!%s" % (lib, nm)
            imports_by_dll.setdefault(lib, [])
            if nm not in imports_by_dll[lib]:
                imports_by_dll[lib].append(nm)
            import_syms.setdefault(label, []).append(sym)
        for k in imports_by_dll:
            imports_by_dll[k] = sorted(imports_by_dll[k])
        log("imports: %d symbols / %d libs" % (len(import_syms), len(imports_by_dll)))

        # ----------------------------------------------------------- functions
        funcs = {}
        fiter = fm.getFunctions(True)
        while fiter.hasNext():
            f = fiter.next()
            ep = f.getEntryPoint()
            key = hx(ep)
            nrefs = sum(1 for _ in refman.getReferencesTo(ep))
            gname = str(f.getName())
            funcs[key] = {
                "ea": key, "name": gname,
                # IDA calls an unnamed function sub_401000 where Ghidra says
                # FUN_00401000; emitting both lets a finding be located in either.
                "ida_name": ("sub_%X" % ep.getOffset()) if gname.startswith("FUN_") else gname,
                "size": int(f.getBody().getNumAddresses()),
                "thunk": bool(f.isThunk()), "lib": bool(f.isExternal()),
                "nxrefs": nrefs,
                "apis": [], "api_sites": [], "cats": [], "strings": [], "score": 0,
            }
        log("functions: %d" % len(funcs))

        # ------------------------------------------- imports -> call sites
        api_map = {}
        for label, syms in import_syms.items():
            callers = {}
            for sym in syms:
                for ref in refman.getReferencesTo(sym.getAddress()):
                    site = ref.getFromAddress()
                    k = func_key_at(site)
                    if k is None:
                        continue
                    fobj = fm.getFunctionAt(af.getAddress(k[2:]))
                    if fobj is not None and fobj.isThunk():
                        for r2 in refman.getReferencesTo(fobj.getEntryPoint()):
                            k2 = func_key_at(r2.getFromAddress())
                            if k2:
                                callers.setdefault(k2, set()).add(hx(r2.getFromAddress()))
                        continue
                    callers.setdefault(k, set()).add(hx(site))
            if callers:
                api_map[label] = sorted(callers.keys())
            cats = categorize(label)
            for k, sites in callers.items():
                if k in funcs:
                    funcs[k]["apis"].append(label)
                    funcs[k]["cats"].extend(cats)
                    for s in sorted(sites):
                        funcs[k]["api_sites"].append({"ea": s, "api": label, "cats": cats})

        # ------------------------------------------------------------- strings
        strings = []
        di = listing.getDefinedData(True)
        while di.hasNext():
            d = di.next()
            try:
                if not d.hasStringValue():
                    continue
                text = str(d.getValue())
            except Exception:
                continue
            if not text or len(text) < 4:
                continue
            tags = [t for t, rx in STR_PATTERNS if rx.search(text)]
            refs = set()
            for ref in refman.getReferencesTo(d.getAddress()):
                k = func_key_at(ref.getFromAddress())
                if k:
                    refs.add(k)
            refs = sorted(refs)
            strings.append({"ea": hx(d.getAddress()), "len": int(d.getLength()),
                            "tags": tags, "refs": refs, "text": text[:400]})
            for k in refs:
                if k in funcs and tags:
                    funcs[k]["strings"].append(text[:120])
        log("strings: %d" % len(strings))

        # --------------------------------------------------------------- score
        tag_by_func = {}
        for rec in strings:
            for k in rec["refs"]:
                tag_by_func.setdefault(k, set()).update(rec["tags"])
        entry_eas = set(e["ea"] for e in entries)
        for k, fd in funcs.items():
            cats = set(fd["cats"])
            fd["cats"] = sorted(cats)
            score = sum(CAT_WEIGHT.get(c, 1) for c in cats)
            score += sum(STR_WEIGHT.get(t, 1) for t in tag_by_func.get(k, ()))
            if fd["thunk"] or fd["lib"]:
                score = 0
            if k in entry_eas:
                score += 15
            fd["score"] = score
            fd["apis"] = sorted(set(fd["apis"]))
            fd["strings"] = sorted(set(fd["strings"]))[:12]
            fd["api_sites"] = sorted(fd["api_sites"], key=lambda s: s["ea"])[:40]

        # ------------------------------------------ decompile + disassemble
        decomp = DecompInterface()
        try:
            decomp.setOptions(DecompileOptions())
        except Exception:
            pass
        have_decomp = bool(decomp.openProgram(prog))
        log("decompiler: %s" % have_decomp)

        ranked = sorted(funcs.values(), key=lambda d: -d["score"])
        targets = [d for d in ranked if d["score"] > 0][:max_decompile]
        done = 0
        for fd in targets:
            f = fm.getFunctionAt(af.getAddress(fd["ea"][2:]))
            if f is None:
                continue
            header = ("// %s   ghidra:%s   ida:%s   score=%d\n// cats: %s\n// apis: %s\n\n"
                      % (fd["ea"], fd["name"], fd["ida_name"], fd["score"],
                         ",".join(fd["cats"]), ", ".join(fd["apis"][:25])))
            body = None
            if have_decomp:
                try:
                    res = decomp.decompileFunction(f, decomp_timeout, mon)
                    if res is not None and res.decompileCompleted():
                        body = str(res.getDecompiledFunction().getC())
                except Exception as e:
                    log("decompile %s failed: %s" % (fd["ea"], e))
            with open(os.path.join(pc_dir, "%s.c" % fd["ea"]), "w", encoding="utf-8",
                      errors="replace") as fh:
                fh.write(header + (body if body else "// decompilation unavailable\n"))
            lines = []
            ii = listing.getInstructions(f.getBody(), True)
            while ii.hasNext():
                ins = ii.next()
                lines.append("%08x  %s" % (ins.getAddress().getOffset(), str(ins)))
            with open(os.path.join(asm_dir, "%s.asm" % fd["ea"]), "w", encoding="utf-8",
                      errors="replace") as fh:
                fh.write(header + "\n".join(lines) + "\n")
            fd["decompiled"] = bool(body)
            done += 1
        log("wrote %d function bodies" % done)

        # ----------------------------------------------------------- callgraph
        edges = set()
        for fd in targets:
            f = fm.getFunctionAt(af.getAddress(fd["ea"][2:]))
            if f is None:
                continue
            for callee in f.getCalledFunctions(mon):
                k = hx(callee.getEntryPoint())
                if k in funcs and k != fd["ea"]:
                    edges.add((fd["ea"], k))
        edges = [list(e) for e in sorted(edges)]

        # ---------------------------------------------------------------- meta
        lang = prog.getLanguage()
        meta = {
            "input": str(prog.getExecutablePath()),
            "md5": str(prog.getExecutableMD5()),
            "sha256": str(prog.getExecutableSHA256()),
            "bits": int(lang.getLanguageDescription().getSize()),
            "proc": str(lang.getProcessor()),
            "filetype": str(prog.getExecutableFormat()),
            "entries": entries, "sections": sections, "imports_by_dll": imports_by_dll,
            "counts": {"functions": len(funcs), "strings": len(strings),
                       "imports": len(import_syms), "decompiled": done},
            "hexrays": have_decomp,          # key kept so q.py needs no change
            "ida_version": "ghidra",
            "engine": "ghidra",
            "compiler": str(prog.getCompiler()),
            "image_base": hx(prog.getImageBase()),
        }

        def dump(name, obj):
            p = os.path.join(outdir, name)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, indent=1, ensure_ascii=False)
            log("wrote %s (%d bytes)" % (name, os.path.getsize(p)))

        dump("meta.json", meta)
        dump("functions.json", sorted(funcs.values(), key=lambda d: -d["score"]))
        dump("strings.json", strings)
        dump("api_map.json", api_map)
        dump("callgraph.json", edges)
        log("DONE")


if __name__ == "__main__":
    argv = sys.argv[1:]
    maxd, tmo, pos = 60, 60, []
    i = 0
    while i < len(argv):
        if argv[i] == "--max-decompile":
            maxd = int(argv[i + 1]); i += 2
        elif argv[i] == "--timeout":
            tmo = int(argv[i + 1]); i += 2
        else:
            pos.append(argv[i]); i += 1
    if len(pos) < 2:
        print(__doc__)
        sys.exit(2)
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        sys.exit("GHIDRA_INSTALL_DIR is not set")
    run(os.path.abspath(pos[0]), os.path.abspath(pos[1]), maxd, tmo)

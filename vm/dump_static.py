"""
IDAPython static-triage dumper. Runs headless, writes a JSON index + pseudocode.
Compatible IDA 7.4 - 9.x (version breaks are wrapped in try/except).

Usage (in guest):
  idat.exe -A -S"C:\\triage\\dump_static.py C:\\triage\\out" -L C:\\triage\\ida.log sample.bin
  (IDA 8.x: idat64.exe)
"""
import os, sys, json, math, re

import idaapi, idautils, idc
import ida_funcs, ida_bytes, ida_nalt, ida_entry, ida_segment
import ida_auto, ida_pro, ida_xref

# ---------------------------------------------------------------- API watchlist
API_CATS = {
    "inject": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
               "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection", "RtlCreateUserThread",
               "NtWriteVirtualMemory", "VirtualProtectEx", "OpenProcess", "NtCreateThreadEx"],
    "persist": ["RegSetValue", "RegCreateKey", "CreateService", "StartServiceCtrlDispatcher",
                "SHSetValue", "RegOpenKey", "OpenSCManager", "ChangeServiceConfig"],
    "crypto":  ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey", "CryptDeriveKey",
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
    "exec":    ["CreateProcess", "ShellExecute", "WinExec", "system", "NtCreateUserProcess",
                "CreateProcessAsUser", "CreateProcessWithToken"],
    "cred":    ["CredEnumerate", "CredRead", "LsaOpenPolicy", "SamIConnect", "LogonUser",
                "ImpersonateLoggedOnUser", "NetUserEnum"],
    "spy":     ["GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx", "BitBlt", "GetClipboardData",
                "GetForegroundWindow", "GetWindowText", "RegisterRawInputDevices", "waveInOpen"],
    "memory":  ["VirtualAlloc", "VirtualProtect", "HeapCreate", "NtAllocateVirtualMemory", "RtlMoveMemory"],
    "privesc": ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue", "DuplicateTokenEx",
                "SetTokenInformation"],
}
CAT_WEIGHT = {"inject": 10, "cred": 9, "crypto": 7, "spy": 7, "privesc": 7, "exec": 6,
              "network": 6, "persist": 6, "dynresolve": 5, "antianalysis": 4,
              "filesystem": 2, "memory": 2}

STR_PATTERNS = [
    ("url",      re.compile(r"https?://[^\s\"'<>]{4,}", re.I)),
    ("ip",       re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("unc",      re.compile(r"\\\\[A-Za-z0-9_.$-]+\\")),
    ("regkey",   re.compile(r"(SOFTWARE|SYSTEM|HKEY_|CurrentVersion\\Run|Winlogon)", re.I)),
    ("path",     re.compile(r"[A-Za-z]:\\\\?[\w .\\$-]{3,}")),
    ("cmd",      re.compile(r"(cmd\.exe|powershell|/c\s|-enc\s|rundll32|regsvr32|schtasks|wscript|mshta|certutil|bitsadmin|vssadmin|wmic|bcdedit)", re.I)),
    ("useragent",re.compile(r"(Mozilla/|User-Agent)", re.I)),
    ("b64blob",  re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")),
    ("ransom",   re.compile(r"(bitcoin|monero|\.onion|decrypt|your files|ransom|tox id)", re.I)),
    ("mutex",    re.compile(r"(Global\\|Local\\|Session\\)", re.I)),
    ("sql",      re.compile(r"(SELECT\s|INSERT\s|logins|cookies|credit_card)", re.I)),
    ("email",    re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")),
]
STR_WEIGHT = {"url": 8, "ip": 7, "cmd": 7, "ransom": 8, "regkey": 4, "unc": 4,
              "sql": 5, "useragent": 4, "mutex": 3, "b64blob": 3, "path": 2, "email": 3}

MAX_DECOMPILE = int(os.environ.get("TRIAGE_MAX_DECOMPILE", "60"))


def log(m):
    print("[triage] %s" % m)


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b if isinstance(b, int) else ord(b)] += 1
    n = float(len(data))
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log(p, 2)
    return round(e, 3)


def arch_info():
    """get_inf_structure() was removed in IDA 9.0 -> try new API first."""
    bits, proc = None, None
    try:
        import ida_ida
        bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
        proc = ida_ida.inf_get_procname()
    except Exception:
        try:
            inf = idaapi.get_inf_structure()
            bits = 64 if inf.is_64bit() else (32 if inf.is_32bit() else 16)
            proc = inf.procname
        except Exception:
            pass
    return bits, proc


def func_of(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None


def is_thunk(ea):
    f = ida_funcs.get_func(ea)
    return bool(f and (f.flags & ida_funcs.FUNC_THUNK))


def collect_imports():
    """-> {ea: 'Dll!Name'}, {'Dll': [names]}"""
    by_ea, by_dll = {}, {}
    try:
        qty = ida_nalt.get_import_module_qty()
    except Exception:
        return by_ea, by_dll
    for i in range(qty):
        dll = ida_nalt.get_import_module_name(i) or "?"
        names = []

        def cb(ea, name, ordinal, _dll=dll, _names=names):
            label = name or ("ord_%d" % ordinal)
            by_ea[ea] = "%s!%s" % (_dll, label)
            _names.append(label)
            return True

        try:
            ida_nalt.enum_import_names(i, cb)
        except Exception:
            pass
        by_dll[dll] = sorted(set(names))
    return by_ea, by_dll


def categorize(api_label):
    name = api_label.split("!", 1)[-1]
    hits = []
    for cat, needles in API_CATS.items():
        for nd in needles:
            if name.startswith(nd) or name == nd:
                hits.append(cat)
                break
    return hits


def xref_callers(target_ea, depth=1):
    """functions referencing target_ea; follow one level of thunk."""
    out = set()
    for xr in idautils.XrefsTo(target_ea, 0):
        fs = func_of(xr.frm)
        if fs is None:
            continue
        if depth > 0 and is_thunk(fs) and fs != target_ea:
            inner = xref_callers(fs, depth - 1)
            if inner:
                out |= inner
                continue
        out.add(fs)
    return out


def main(outdir):
    log("waiting for auto-analysis")
    ida_auto.auto_wait()
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(os.path.join(outdir, "pseudocode"), exist_ok=True)

    bits, proc = arch_info()
    try:
        md5 = ida_nalt.retrieve_input_file_md5()
        sha = ida_nalt.retrieve_input_file_sha256()
        md5 = md5.hex() if isinstance(md5, bytes) else str(md5)
        sha = sha.hex() if isinstance(sha, bytes) else str(sha)
    except Exception:
        md5 = sha = None

    # ---- sections
    sections = []
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if not seg:
            continue
        size = seg.end_ea - seg.start_ea
        data = ida_bytes.get_bytes(seg.start_ea, min(size, 512 * 1024)) or b""
        sections.append({
            "name": ida_segment.get_segm_name(seg),
            "start": "0x%x" % seg.start_ea,
            "end": "0x%x" % seg.end_ea,
            "size": size,
            "perm_x": bool(seg.perm & ida_segment.SEGPERM_EXEC),
            "perm_w": bool(seg.perm & ida_segment.SEGPERM_WRITE),
            "entropy": entropy(data),
        })

    # ---- entry points
    entries = []
    try:
        for i in range(ida_entry.get_entry_qty()):
            o = ida_entry.get_entry_ordinal(i)
            entries.append({"ea": "0x%x" % ida_entry.get_entry(o),
                            "name": ida_entry.get_entry_name(o) or ""})
    except Exception:
        pass

    imports_by_ea, imports_by_dll = collect_imports()
    log("imports: %d symbols / %d dlls" % (len(imports_by_ea), len(imports_by_dll)))

    # ---- function skeleton
    funcs = {}
    for fea in idautils.Functions():
        f = ida_funcs.get_func(fea)
        if not f:
            continue
        funcs[fea] = {
            "ea": "0x%x" % fea,
            "name": idc.get_func_name(fea) or "",
            "size": f.end_ea - f.start_ea,
            "thunk": bool(f.flags & ida_funcs.FUNC_THUNK),
            "lib": bool(f.flags & ida_funcs.FUNC_LIB),
            "nxrefs": len(list(idautils.XrefsTo(fea, 0))),
            "apis": [], "cats": [], "strings": [], "score": 0,
        }
    log("functions: %d" % len(funcs))

    # ---- map imports -> calling functions
    api_to_funcs = {}
    for iea, label in imports_by_ea.items():
        callers = xref_callers(iea)
        if callers:
            api_to_funcs[label] = ["0x%x" % c for c in sorted(callers)]
        cats = categorize(label)
        for c in callers:
            if c in funcs:
                funcs[c]["apis"].append(label)
                funcs[c]["cats"].extend(cats)

    # ---- strings + their referencing functions
    strings = []
    try:
        sc = idautils.Strings()
        sc.setup()
        for s in sc:
            try:
                text = str(s)
            except Exception:
                continue
            if not text or len(text) < 4:
                continue
            tags = [t for t, rx in STR_PATTERNS if rx.search(text)]
            refs = sorted(xref_callers(s.ea))
            rec = {"ea": "0x%x" % s.ea, "len": s.length, "tags": tags,
                   "refs": ["0x%x" % r for r in refs],
                   "text": text[:400]}
            strings.append(rec)
            for r in refs:
                if r in funcs and tags:
                    funcs[r]["strings"].append(text[:120])
    except Exception as e:
        log("string pass failed: %s" % e)
    log("strings: %d" % len(strings))

    # ---- score
    str_tag_by_func = {}
    for rec in strings:
        for r in rec["refs"]:
            str_tag_by_func.setdefault(r, set()).update(rec["tags"])
    for fea, fd in funcs.items():
        cats = set(fd["cats"])
        fd["cats"] = sorted(cats)
        score = sum(CAT_WEIGHT.get(c, 1) for c in cats)
        score += sum(STR_WEIGHT.get(t, 1) for t in str_tag_by_func.get(fd["ea"], ()))
        if fd["thunk"] or fd["lib"]:
            score = 0
        if any(fd["ea"] == e["ea"] for e in entries):
            score += 15
        fd["score"] = score
        fd["apis"] = sorted(set(fd["apis"]))
        fd["strings"] = sorted(set(fd["strings"]))[:12]

    # ---- decompile top-N
    have_hr = False
    try:
        import ida_hexrays
        have_hr = ida_hexrays.init_hexrays_plugin()
    except Exception:
        have_hr = False
    log("hexrays: %s" % have_hr)

    ranked = sorted(funcs.values(), key=lambda d: -d["score"])
    targets = [d for d in ranked if d["score"] > 0][:MAX_DECOMPILE]
    done = []
    for fd in targets:
        fea = int(fd["ea"], 16)
        body = None
        if have_hr:
            try:
                body = str(ida_hexrays.decompile(fea))
            except Exception:
                body = None
        if body is None:  # fall back to disassembly
            lines, ea = [], fea
            end = ida_funcs.get_func(fea).end_ea
            while ea < end and ea != idc.BADADDR:
                lines.append("%08x  %s" % (ea, idc.generate_disasm_line(ea, 0) or ""))
                ea = idc.next_head(ea, end)
            body = "\n".join(lines)
        path = os.path.join(outdir, "pseudocode", "%s.c" % fd["ea"])
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("// %s  %s  score=%d\n// cats: %s\n// apis: %s\n\n%s\n"
                     % (fd["ea"], fd["name"], fd["score"], ",".join(fd["cats"]),
                        ", ".join(fd["apis"][:25]), body))
        fd["decompiled"] = True
        done.append(fd["ea"])
    log("decompiled %d functions" % len(done))

    # ---- call graph
    edges = set()
    for fd in targets:
        fea = int(fd["ea"], 16)
        f = ida_funcs.get_func(fea)
        ea = fea
        while f and ea < f.end_ea and ea != idc.BADADDR:
            for xr in idautils.XrefsFrom(ea, 0):
                if xr.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    c = func_of(xr.to)
                    if c is not None and c != fea and c in funcs:
                        edges.add((fd["ea"], "0x%x" % c))
            ea = idc.next_head(ea, f.end_ea)
    edges = [list(e) for e in sorted(edges)]

    meta = {
        "input": idc.get_input_file_path(),
        "md5": md5, "sha256": sha,
        "bits": bits, "proc": proc,
        "filetype": ida_nalt.get_file_type_name(),
        "entries": entries,
        "sections": sections,
        "imports_by_dll": imports_by_dll,
        "counts": {"functions": len(funcs), "strings": len(strings),
                   "imports": len(imports_by_ea), "decompiled": len(done)},
        "hexrays": have_hr,
        "ida_version": idaapi.get_kernel_version(),
    }

    def dump(name, obj):
        p = os.path.join(outdir, name)
        with open(p, "w", encoding="utf-8", errors="replace") as fh:
            json.dump(obj, fh, indent=1, ensure_ascii=False)
        log("wrote %s (%d bytes)" % (name, os.path.getsize(p)))

    dump("meta.json", meta)
    dump("functions.json", sorted(funcs.values(), key=lambda d: -d["score"]))
    dump("strings.json", strings)
    dump("api_map.json", api_to_funcs)
    dump("callgraph.json", edges)
    log("DONE")


if __name__ == "__main__":
    args = idc.ARGV[1:] if hasattr(idc, "ARGV") else []
    out = args[0] if args else r"C:\triage\out"
    try:
        main(out)
    except Exception:
        import traceback
        traceback.print_exc()
    ida_pro.qexit(0)

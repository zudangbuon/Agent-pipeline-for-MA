#!/usr/bin/env python3
r"""dbg.py -- the DEBUGGING row of the report template, via cdb (Debugging Tools
for Windows). Function breakpoints, stack, memory map, OEP hunting.

    python host/dbg.py where                 # locate cdb.exe, print its version
    python host/dbg.py control               # run the known-behaviour control ON THE HOST
    python host/dbg.py script apitrace       # print the cdb command script (no execution)
    python host/dbg.py parse <cdb.log>       # parse a log into JSON + terse summary
    python host/dbg.py apis   --dir <d>      # query a parsed run
    python host/dbg.py memmap --dir <d>
    python host/dbg.py modules --dir <d>

RULE 1 LIVES HERE TOO. This module will not run a sample on the host. `control`
accepts only a binary under %WINDIR% (notepad, ping, whoami) -- a known-benign
Windows file whose behaviour we can predict. To debug a SAMPLE, the cdb session
runs INSIDE the VM through vm/debug.ps1, and only cdb's text output comes back,
which is exactly what the pull rail allows.

Why cdb and not a GUI debugger: cdb is a console debugger. Everything it produces
is text, so it passes the "nothing binary comes back" rail unchanged, and it is
driveable from a single `-c` command string -- no IDAPython-style scripting gap.
"""
import sys, os, re, json, glob, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "out")

CDB_HINTS = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x86\cdb.exe",
]

# One logging breakpoint per API: print the arguments we care about, then CONTINUE.
# `gc` resumes exactly the way the breakpoint was reached, which keeps a trace from
# turning into a single-step crawl.
#
# ARGUMENTS ARE NOT IN THE SAME PLACE ON x86 AND x64. On x86 (stdcall/cdecl) they
# are on the stack, so arg N is poi(@$csp + 4*N). On x64 the first four go in
# rcx, rdx, r8, r9 and only the fifth onward touch the stack. Hardcoding
# poi(@$csp+4) -- which the first version of this file did -- gives a 64-bit
# target a confident, completely wrong first argument. brbbot.exe is x64, so that
# would have been the default case, not an edge case.
#
# Each entry is (name, modules-to-try, [(argno, fmt), ...]). fmt: %ma = ASCII at
# pointer, %mu = UTF-16 at pointer, %p = raw value. CreateFileA takes ANSI and
# CreateFileW wide; printing a wide string with %ma yields just the first character.
#
# THE MODULE IS NOT ALWAYS kernel32. Measured on Windows 11:
#     x kernel32!CreateProcessA    -> nothing
#     x *!CreateProcessA           -> KERNELBASE!CreateProcessA
# and a `bu` on a symbol whose module IS loaded but which does not exist there
# fails with "Couldn't resolve ... Extra character error" AND ABORTS THE REST OF
# THE SCRIPT -- the `g` never runs, so the log shows modules and a memory map and
# zero API hits. `.catch { }` does NOT protect against it (tested). A `bu` on a
# module that is not loaded yet is fine: it becomes a deferred `eu` breakpoint.
#
# So the module list is tried in order by probe_symbols() before anything is set.
# Old guests differ the other way: on XP these all live in kernel32, not
# kernelbase, which is why both are listed rather than hardcoding one.
APITRACE = [
    ("CreateFileA",             ("kernel32", "kernelbase"), [(1, "%ma")]),
    ("CreateFileW",             ("kernel32", "kernelbase"), [(1, "%mu")]),
    ("WriteFile",               ("kernel32", "kernelbase"), [(1, "%p")]),
    ("DeleteFileA",             ("kernel32", "kernelbase"), [(1, "%ma")]),
    ("MoveFileExA",             ("kernel32", "kernelbase"), [(1, "%ma"), (3, "%p")]),
    ("CopyFileA",               ("kernel32", "kernelbase"), [(1, "%ma"), (2, "%ma")]),
    ("CreateProcessA",          ("kernel32", "kernelbase"), [(1, "%ma"), (2, "%ma")]),
    ("CreateProcessW",          ("kernel32", "kernelbase"), [(1, "%mu"), (2, "%mu")]),
    ("WinExec",                 ("kernel32", "kernelbase"), [(1, "%ma")]),
    ("LoadLibraryA",            ("kernel32", "kernelbase"), [(1, "%ma")]),
    ("LoadLibraryW",            ("kernel32", "kernelbase"), [(1, "%mu")]),
    ("GetProcAddress",          ("kernel32", "kernelbase"), [(2, "%ma")]),
    ("VirtualAlloc",            ("kernel32", "kernelbase"), [(2, "%p"), (4, "%p")]),
    ("VirtualProtect",          ("kernel32", "kernelbase"), [(1, "%p"), (2, "%p"), (3, "%p")]),
    ("GetEnvironmentVariableA", ("kernel32", "kernelbase"), [(1, "%ma")]),
    ("RegOpenKeyExA",           ("advapi32", "kernelbase"), [(1, "%p"), (2, "%ma")]),
    ("RegSetValueExA",          ("advapi32", "kernelbase"), [(2, "%ma")]),
    ("CryptHashData",           ("advapi32",),              [(2, "%p"), (3, "%p")]),
    ("CryptDeriveKey",          ("advapi32",),              [(2, "%p")]),
    ("InternetOpenA",           ("wininet",),               [(1, "%ma")]),
    ("InternetConnectA",        ("wininet",),               [(2, "%ma"), (3, "%p")]),
    ("HttpOpenRequestA",        ("wininet",),               [(2, "%ma"), (3, "%ma")]),
    ("gethostbyname",           ("ws2_32",),                [(1, "%ma")]),
]

# For a packed sample: do not trace APIs, watch for the unpacking stub handing
# control to the real entry point. VirtualProtect making a region executable, or
# VirtualAlloc of an RWX block, is where to look.
OEPHUNT = [
    ("VirtualProtect", ("kernel32", "kernelbase"), [(1, "%p"), (2, "%p"), (3, "%p")]),
    ("VirtualAlloc",   ("kernel32", "kernelbase"), [(2, "%p"), (4, "%p")]),
]


def arg_expr(argno, arch):
    """cdb expression for the Nth (1-based) integer/pointer argument."""
    if arch == "x64":
        reg = {1: "@rcx", 2: "@rdx", 3: "@r8", 4: "@r9"}.get(argno)
        if reg:
            return reg
        # 5th onward: shadow space is 0x20, return address 8 -> csp + 0x28, 0x30...
        return "poi(@$csp+%x)" % (0x28 + 8 * (argno - 5))
    return "poi(@$csp+%x)" % (4 * argno)


def die(msg, code=2):
    print("ERROR: %s" % msg, file=sys.stderr)
    sys.exit(code)


def find_cdb():
    for p in CDB_HINTS:
        if os.path.isfile(p):
            return p
    w = shutil.which("cdb")
    if w:
        return w
    for pat in (r"C:\Program Files*\Windows Kits\*\Debuggers\*\cdb.exe",):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def cdb_for(arch):
    """The cdb of a given bitness. A 32-bit target needs the x86 cdb."""
    want = os.sep + arch + os.sep
    for p in CDB_HINTS + sorted(glob.glob(
            r"C:\Program Files*\Windows Kits\*\Debuggers\*\cdb.exe")):
        if os.path.isfile(p) and want in p:
            return p
    return None


def pe_arch(path):
    """x86 or x64 from the PE COFF machine field. Parses; never loads or runs."""
    try:
        with open(path, "rb") as fh:
            d = fh.read(0x400)
        if d[:2] != b"MZ":
            return None
        off = int.from_bytes(d[0x3c:0x40], "little")
        if d[off:off + 4] != b"PE\0\0":
            return None
        machine = int.from_bytes(d[off + 4:off + 6], "little")
    except Exception:
        return None
    return {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine)


def host_arch():
    import platform
    return "x64" if platform.machine().endswith("64") else "x86"


def build_script(mode="apitrace", arch="x86", resolved=None):
    """Return the cdb script as a list of lines, one command per line.

    `arch` decides where arguments are read from -- see the note on APITRACE.

    THIS MUST BE A SCRIPT FILE (`-cf`), NOT A `-c` STRING. Semicolon-separated
    commands do not survive `bu SYM "quoted; command; string"`: cdb's splitter
    loses track inside the quotes, and the first symbol it cannot resolve
    swallows the entire remainder of the line -- including the `g` that runs the
    target. Observed exactly once, as:

        Couldn't resolve error at 'kernel32!CreateProcessA ".echo; .printf ...

    with 20 modules and 191 memory regions captured and not a single API hit,
    because `g` was never reached. One command per line is necessary but NOT
    sufficient: a failing line still aborted the rest, which is why the
    breakpoints below use `bm` rather than `bu`.

    `resolved` is diagnostics only (which symbols the probe could see); the script
    hooks every candidate module regardless, because `bm` makes a miss free.
    """
    if arch not in ("x86", "x64"):
        die("arch must be x86 or x64")
    table = {"apitrace": APITRACE, "oep": OEPHUNT}.get(mode)
    if table is None:
        die("mode must be apitrace or oep")
    lines = [
        '.echo === MODULES ===', 'lm',
        '.echo === MEMORY MAP (initial) ===', '!address',
        '.echo === BREAKPOINTS ===',
    ]
    for name, mods, args in table:
        # Hook EVERY candidate module, not just the first that resolved. kernel32
        # forwards most of these to KERNELBASE, and whether a given binary's import
        # lands on the kernel32 stub or straight on KERNELBASE depends on API sets.
        # Hooking only KERNEL32!CreateFileW gave the control 0 file hits while
        # GetProcAddress and VirtualProtect fired 109 times. `bm` makes the extra
        # breakpoints free: a module that is absent just defers.
        fmts = ", ".join(f for _, f in args)
        exprs = ", ".join(arg_expr(n, arch) for n, _ in args)
        action = r'.printf \"%s(%s)\\n\", %s' % (name, fmts, exprs)
        # `bm`, NOT `bu`. Measured, all three on one target:
        #   ambiguous symbol  -> bu aborts the script; bm sets a bp on each match
        #   module not loaded -> bu defers; bm defers ("Setting a deferred breakpoint")
        #   symbol absent     -> bu aborts the script; bm defers harmlessly
        # `bu` cost two debugging rounds here: KERNEL32!CreateProcessA does not
        # exist on Win11 and KERNELBASE!RegSetValueExA is ambiguous, and each one
        # silently killed the `g` further down the script.
        #
        # One wart to know about: an ambiguous match can bind a neighbouring
        # function too -- `bm KERNELBASE!RegSetValueExA` also resolves to
        # KERNELBASE!CancelProcessEapAuthPacket, which will print the
        # RegSetValueExA label if it is ever called. Check `bl` in the log before
        # citing a single surprising hit.
        for mod in mods:
            lines.append('bm %s!%s "%s; gc"' % (mod, name, action))
    lines += [
        '.echo === BPLIST ===', 'bl',
        '.echo === RUN ===',
        'g',                      # run; each logging bp prints and continues
        '.echo === STACK AT EXIT ===', 'kv',
        '.echo === MEMORY MAP (final) ===', '!address',
        '.echo === DONE ===',
        'q',
    ]
    return lines


def cmd_where(a):
    cdb = find_cdb()
    if not cdb:
        print("cdb.exe NOT FOUND.")
        print("Install just the debuggers, not the whole SDK:")
        print("  winsdksetup.exe /features OptionId.WindowsDesktopDebuggers /quiet /norestart")
        print("Looked in:")
        for p in CDB_HINTS:
            print("  %s" % p)
        return 1
    print("cdb: %s" % cdb)
    pr = subprocess.run([cdb, "-version"], capture_output=True, text=True)
    first = (pr.stdout or pr.stderr or "").strip().splitlines()
    for line in first[:4]:
        print("  %s" % line)
    arch = "x64" if os.sep + "x64" + os.sep in cdb else "x86"
    print("\narch: %s" % arch)
    print("A 32-bit target needs the x86 cdb and a 64-bit target the x64 one;")
    print("mismatching them gives a confusing 'not a valid Win32 application'.")
    return 0


def _run_cdb(cdb, target, script, out_dir, timeout=180, args=None):
    os.makedirs(out_dir, exist_ok=True)
    log = os.path.join(out_dir, "cdb.log")
    script_path = os.path.join(out_dir, "cdb.script")
    with open(script_path, "w", encoding="ascii", errors="replace") as fh:
        fh.write("\n".join(script) + "\n")
    # NO -g HERE, EVER. The initial-command script runs at the INITIAL breakpoint,
    # and -g skips exactly that breakpoint -- so with -g the script never executes,
    # the target runs free to completion, and cdb exits 0 with a log full of
    # ModLoad lines and not one of our markers. That looked like a parser bug for a
    # while; it was the command line. -G (skip the final break) is harmless because
    # the script ends in `q`. -o follows child processes. -cf reads the script from
    # a file, one command per line (see build_script for why -c cannot be used).
    cmd = [cdb, "-o", "-G", "-cf", script_path, target] + list(args or [])
    pr = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    text = (pr.stdout or "") + ("\n--- stderr ---\n" + pr.stderr if pr.stderr else "")
    with open(log, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(text)
    return log, text, pr.returncode


RE_XHIT = re.compile(r"^[0-9a-f`]+\s+([A-Za-z0-9_]+![A-Za-z0-9_@?]+)", re.I)


def probe_symbols(cdb, target, out_dir, mode="apitrace", timeout=180):
    """Ask cdb which candidate symbols actually exist, before setting any bp.

    Returns (resolved, loaded_modules, unhookable). A symbol in an unloaded module
    cannot be probed, so it is kept on its declared module and left to `bu`'s
    deferred resolution; one whose module IS loaded but which `x` cannot find is
    dropped, because setting it would abort the whole script.
    """
    table = {"apitrace": APITRACE, "oep": OEPHUNT}[mode]
    cands = []
    lines = [".echo === LM ===", "lm", ".echo === X ==="]
    for name, mods, _ in table:
        for m in mods:
            cands.append((name, m))
            lines += [".echo --- %s!%s" % (m, name), "x %s!%s" % (m, name)]
    lines += [".echo === END ===", "q"]

    os.makedirs(out_dir, exist_ok=True)
    sp = os.path.join(out_dir, "probe.script")
    with open(sp, "w", encoding="ascii", errors="replace") as fh:
        fh.write("\n".join(lines) + "\n")
    pr = subprocess.run([cdb, "-G", "-cf", sp, target],
                        capture_output=True, text=True, timeout=timeout)
    text = (pr.stdout or "")
    with open(os.path.join(out_dir, "probe.log"), "w",
              encoding="utf-8", errors="replace") as fh:
        fh.write(text)

    loaded, cur, found = set(), None, {}
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^--- (\S+)!(\S+)$", s)
        if m:
            cur = (m.group(2), m.group(1))
            continue
        mm = re.match(r"^[0-9a-f`]+\s+[0-9a-f`]+\s+(\S+)\s", s)
        if mm:
            loaded.add(mm.group(1).lower())
        xm = RE_XHIT.match(s.replace("0:000> ", ""))
        if xm and cur:
            found.setdefault(cur[0], xm.group(1))

    resolved, unhookable = {}, []
    for name, mods, _ in table:
        if name in found:
            resolved[name] = found[name]
            continue
        # not found: is any declared module actually loaded?
        if any(m.lower() in loaded for m in mods):
            unhookable.append("%s (tried %s; module loaded, symbol absent)"
                              % (name, "/".join(mods)))
        else:
            resolved[name] = "%s!%s" % (mods[0], name)   # defer, module not up yet
    return resolved, loaded, unhookable


# What whoami.exe actually does, measured -- not what it seemed like it should do.
# The first version of this control expected CreateFileA/W and failed, which read
# as a broken breakpoint table; whoami simply does not call them on the traced
# path. GetProcAddress and VirtualProtect fire in any loader-driven process, and
# GetProcAddress carries a string argument, so one check covers symbol
# resolution, breakpoint firing, %p formatting, %ma string formatting and the `gc`
# continuation all at once.
CONTROL_EXPECT = ["GetProcAddress"]


def cmd_control(a):
    """Drive cdb against a known-benign Windows binary, on the host.

    This is the regression harness for the breakpoint table and the parser. Three
    defects in the dynamic monitors were only ever caught because a control with
    known behaviour disagreed with the output; the debugger needs the same.
    """
    target = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                          "System32", "whoami.exe")
    if not os.path.isfile(target):
        die("control target missing: %s" % target)
    # the rail: only a file under %WINDIR% may be run here
    win = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows"))
    if not os.path.normcase(target).startswith(win):
        die("refusing to run %s on the host -- Rule 1. Debug samples in the VM." % target)

    arch = pe_arch(target) or host_arch()
    cdb = cdb_for(arch) or find_cdb() or die("cdb.exe not found -- run `dbg.py where`")
    out_dir = os.path.join(OUT, "debug", "control")
    print("[*] cdb    : %s" % cdb)
    print("[*] target : %s   (benign, under %%WINDIR%%)" % target)
    print("[*] arch   : %s" % arch)
    try:
        resolved, loaded, unhookable = probe_symbols(cdb, target, out_dir, "apitrace")
    except subprocess.TimeoutExpired:
        die("symbol probe timed out")
    print("[*] probe  : %d/%d symbols hookable, %d modules loaded"
          % (len(resolved), len(APITRACE), len(loaded)))
    for u in unhookable:
        print("    [drop] %s" % u)

    script = build_script("apitrace", arch, resolved)
    try:
        log, text, rc = _run_cdb(cdb, target, script, out_dir, timeout=240)
    except subprocess.TimeoutExpired:
        die("cdb timed out -- the control should finish in seconds")
    print("[*] log    : %s  (%d bytes, rc=%s)" % (log, len(text), rc))

    parsed = parse_log(text)
    save(out_dir, parsed)
    print()
    report(parsed)
    hits = {c["api"] for c in parsed["apis"]}
    missing = [e for e in CONTROL_EXPECT if e not in hits]
    print("\n--- control verdict ---")
    if not parsed["modules"]:
        print("FAIL: no modules parsed -- `lm` output or the parser is wrong")
        return 1
    if not parsed["memmap"]:
        print("FAIL: no memory map parsed -- `!address` output or the parser is wrong")
        return 1
    if missing:
        print("FAIL: expected %s among the hits and saw none." % missing)
        print("      Modules and the memory map parsed, so cdb ran; this points at")
        print("      the breakpoint table or at the script aborting before `g`.")
        print("      Check for a 'RUN' section and for 'Couldn't resolve'/'Ambiguous'")
        print("      in %s" % log)
        return 1
    # a string argument proves %ma actually dereferenced and printed
    strings_ok = [c for c in parsed["apis"]
                  if c["api"] == "GetProcAddress" and re.search(r"[A-Za-z]{4}", c["args"])]
    if not strings_ok:
        print("FAIL: GetProcAddress fired but printed no readable string --")
        print("      %ma formatting or the argument register is wrong for this arch.")
        return 1
    if "RUN" not in parsed["sections"]:
        print("FAIL: no RUN section -- the script aborted before `g`.")
        return 1
    print("PASS: modules, memory map, breakpoints, execution and string")
    print("      formatting all verified (%d API hits, e.g. %s)."
          % (len(parsed["apis"]), strings_ok[0]["args"][:46]))
    return 0


RE_API = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*$")
RE_MOD = re.compile(r"^[0-9a-f`]+\s+[0-9a-f`]+\s+(\S+)\s+(.*)$", re.I)
RE_ADDR = re.compile(r"^\s*([0-9a-f`]+)\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+(.*)$", re.I)


def parse_log(text):
    """cdb writes plain text; split it on the .echo markers we planted."""
    sec, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^=== (.+?) ===\s*$", line.strip())
        if m:
            cur = m.group(1)
            sec.setdefault(cur, [])
            continue
        if cur:
            sec[cur].append(line)

    apis = []
    for line in sec.get("RUN", []):
        m = RE_API.match(line.strip())
        if m:
            apis.append({"api": m.group(1), "args": m.group(2)})

    modules = []
    for line in sec.get("MODULES", []):
        m = RE_MOD.match(line.strip())
        if m and not line.lower().startswith("start"):
            modules.append({"name": m.group(1), "detail": m.group(2).strip()})

    memmap = []
    for line in sec.get("MEMORY MAP (initial)", []):
        m = RE_ADDR.match(line)
        if m and "BaseAddr" not in line:
            memmap.append({"base": m.group(1), "end": m.group(2),
                           "size": m.group(3), "detail": m.group(4).strip()})

    rwx = [r for r in memmap if "EXECUTE_READWRITE" in r["detail"].upper()]
    return {"apis": apis, "modules": modules, "memmap": memmap, "rwx": rwx,
            "stack": [l for l in sec.get("STACK AT EXIT", []) if l.strip()],
            "sections": sorted(sec)}


def save(out_dir, parsed):
    os.makedirs(out_dir, exist_ok=True)
    for name in ("apis", "modules", "memmap", "rwx", "stack"):
        with open(os.path.join(out_dir, name + ".json"), "w", encoding="utf-8") as fh:
            json.dump(parsed[name], fh, indent=1)


def report(parsed):
    print("sections parsed : %s" % ", ".join(parsed["sections"]) or "(none)")
    print("modules         : %d" % len(parsed["modules"]))
    print("memory regions  : %d   (RWX: %d)" % (len(parsed["memmap"]), len(parsed["rwx"])))
    print("API hits        : %d" % len(parsed["apis"]))
    counts = {}
    for c in parsed["apis"]:
        counts[c["api"]] = counts.get(c["api"], 0) + 1
    for api, n in sorted(counts.items(), key=lambda kv: -kv[1])[:15]:
        print("   %-28s %d" % (api, n))


def _load(a, name):
    d = None
    if "--dir" in a:
        d = a[a.index("--dir") + 1]
    d = d or os.path.join(OUT, "debug", "control")
    p = os.path.join(d, name + ".json")
    if not os.path.isfile(p):
        die("no %s -- run `dbg.py control` or `dbg.py parse <cdb.log>` first" % p)
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def cmd_apis(a):
    rows = _load(a, "apis")
    for i, c in enumerate(rows, 1):
        print("%4d  %-28s %s" % (i, c["api"], c["args"][:90]))
    print("\n%d call(s). Order is execution order -- that is the point of a trace." % len(rows))


def cmd_memmap(a):
    rows, rwx = _load(a, "memmap"), _load(a, "rwx")
    print("=== RWX regions (%d) -- look here first ===" % len(rwx))
    for r in rwx:
        print("  %s - %s  %s  %s" % (r["base"], r["end"], r["size"], r["detail"][:60]))
    print("\n%d regions total. Full list in memmap.json." % len(rows))


def cmd_modules(a):
    rows = _load(a, "modules")
    for r in rows:
        print("  %-24s %s" % (r["name"], r["detail"][:70]))
    print("\n%d module(s)." % len(rows))


def cmd_script(a):
    mode = a[0] if a else "apitrace"
    arch = a[1] if len(a) > 1 else host_arch()
    print("$$ arch=%s  (x86 reads args off the stack, x64 from rcx/rdx/r8/r9)" % arch)
    print("\n".join(build_script(mode, arch)))


def cmd_parse(a):
    if not a:
        die("usage: dbg.py parse <cdb.log> [--dir <outdir>]")
    with open(a[0], encoding="utf-8", errors="replace") as fh:
        parsed = parse_log(fh.read())
    out_dir = a[a.index("--dir") + 1] if "--dir" in a else os.path.dirname(os.path.abspath(a[0]))
    save(out_dir, parsed)
    report(parsed)
    print("\nwrote JSON to %s" % out_dir)


CMDS = {"where": cmd_where, "control": cmd_control, "script": cmd_script,
        "parse": cmd_parse, "apis": cmd_apis, "memmap": cmd_memmap,
        "modules": cmd_modules}


def main(argv):
    a = list(argv[1:])
    if not a or a[0] not in CMDS:
        print(__doc__)
        print("commands: %s" % ", ".join(sorted(CMDS)))
        return 2
    return CMDS[a[0]](a[1:]) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

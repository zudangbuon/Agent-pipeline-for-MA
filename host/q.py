#!/usr/bin/env python3
"""
Query the static-triage dump. Runs on the HOST, reads only JSON/text artifacts.
The agent calls this instead of cat-ing whole dumps, so context stays small.

  python q.py summary
  python q.py top [N]                  top-scored functions, one line each
  python q.py func <ea|name>           pseudocode + apis/strings/callers/callees
  python q.py strings <regex> [N]      matching strings + referencing functions
  python q.py tag <tagname> [N]        strings by tag (url|ip|cmd|ransom|regkey|...)
  python q.py api <substr>             which functions call a matching import
  python q.py cat <category>           functions in a capability category
  python q.py callers <ea>             direct callers
  python q.py callees <ea>             direct callees
  python q.py imports [dllsubstr]      imports grouped by DLL
  python q.py capa [N]                 capa rules, if capa.json present

Env: TRIAGE_OUT (default: ../out next to this script)
"""
import json, os, re, sys, textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("TRIAGE_OUT") or os.path.join(os.path.dirname(HERE), "out")


def load(name, default=None):
    p = os.path.join(OUT, name)
    if not os.path.exists(p):
        if default is not None:
            return default
        sys.exit("missing %s -- run the dumper in the VM and copy the out/ dir here" % p)
    with open(p, encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def fline(f):
    bits = []
    if f.get("cats"):
        bits.append(",".join(f["cats"]))
    if f.get("decompiled"):
        bits.append("src")
    return "%-12s %-34s score=%-4d size=%-6d xrefs=%-4d %s" % (
        f["ea"], (f["name"] or "")[:34], f["score"], f["size"], f["nxrefs"], " ".join(bits))


def raw_sections():
    """Section table measured over the RAW FILE BYTES, from pe_meta.json.

    Ghidra reports entropy over the loaded memory BLOCK, which is zero-padded
    out to the section's virtual size. For a packed section that is mostly
    padding the number collapses: UPX1 in Lab01-02 is H=7.067 over its 1536
    raw bytes but H=3.378 over its 4096-byte virtual block, and Lab01-03's
    payload section reads 7.362 raw vs 1.778 virtual. Both packed samples
    therefore looked clean. Entropy only means anything over the bytes that
    are actually in the file, so prefer pe_meta when it is available and say
    which source produced the numbers.
    """
    pm = load("pe_meta.json", None)
    if not pm or not pm.get("sections"):
        return None, "ghidra (virtual blocks -- entropy understated for packed files)"
    out = []
    for sec in pm["sections"]:
        perm = sec.get("perm") or ""
        out.append({
            "name": sec["name"], "start": sec["vaddr"],
            "size": sec.get("rawsize", 0), "vsize": sec.get("vsize", 0),
            "entropy": sec["entropy"],
            "perm_x": "x" in perm, "perm_w": "w" in perm,
        })
    return out, "pe_meta (raw file bytes)"


def pack_signals(m, funcs):
    """Structural tells that the real code is not visible yet.

    Entropy alone is NOT enough. Lab03-01.exe (PMA ch.3) is packed with
    PEncrypt yet its highest section entropy is 6.4 -- below any sane
    threshold -- because the payload is small and only lightly encoded.
    What gave it away was the shape: a single import (ExitProcess), two
    functions, a 512-byte .text, and a 6 KB writable .data with HIGHER
    entropy than the code section. Judge the shape, not the number, or
    this tool will call a packed sample unpacked.
    """
    out = []
    raw, _src = raw_sections()
    secs = raw if raw is not None else (m.get("sections") or [])
    # drop the synthetic blocks Ghidra adds for x86 PEs
    secs = [s for s in secs if s["name"].lower() not in ("tdb", "headers")]

    # A section with far more virtual than raw size is the space a packer
    # unpacks into. Lab01-03's first section is 12288 B virtual with ZERO
    # bytes on disk -- nothing to execute until something writes it.
    for s in secs:
        vs, rs = s.get("vsize", 0), s.get("size", 0)
        if vs > 0x1000 and rs == 0:
            out.append("%s has %d B of virtual space and NOTHING on disk -- "
                       "pure unpack target" % (s["name"], vs))
        elif vs > max(rs, 1) * 4 and vs > 0x1000:
            out.append("%s is %d B virtual vs %d B raw -- room to unpack into"
                       % (s["name"], vs, rs))
    nimp = sum(len(v) for v in (m.get("imports_by_dll") or {}).values())
    nfun = len(funcs or [])

    for s in secs:
        if s["entropy"] > 7.0:
            out.append("%s entropy %.3f > 7.0" % (s["name"], s["entropy"]))
        if s["perm_w"] and s["perm_x"]:
            out.append("%s is writable AND executable" % s["name"])

    # A small function/import count only means "packed" if something in the file
    # is actually hidden. Lab01-01.dll recovers just 5 functions and is NOT
    # packed -- it is a tiny socket backdoor whose densest section is H=1.9.
    # Nothing in it is compressed or encrypted, so there is no hidden payload
    # to be the reason for the small count. Gate the structural signals on at
    # least one section being dense enough to hide code in.
    hmax = max([s["entropy"] for s in secs] or [0.0])
    if hmax >= 6.0:
        if nimp and nimp <= 10:
            out.append("only %d imported symbol(s), and %s reaches H=%.3f -- "
                       "the imports are resolved at runtime"
                       % (nimp, max(secs, key=lambda s: s["entropy"])["name"], hmax))
        if nfun and nfun <= 5:
            out.append("only %d function(s) recovered, and %s reaches H=%.3f"
                       % (nfun, max(secs, key=lambda s: s["entropy"])["name"], hmax))

    code = [s for s in secs if s["perm_x"]]
    data = [s for s in secs if not s["perm_x"] and s["perm_w"]]
    if code and data:
        c = max(code, key=lambda s: s["size"])
        d = max(data, key=lambda s: s["size"])
        if d["size"] > c["size"] and d["entropy"] > c["entropy"] + 1.0:
            out.append("%s (%d B, H=%.3f) is bigger AND denser than code %s "
                       "(%d B, H=%.3f) -- the payload lives in data"
                       % (d["name"], d["size"], d["entropy"],
                          c["name"], c["size"], c["entropy"]))
    return out


def resolve(funcs, key):
    key = key.strip()
    for f in funcs:
        if f["ea"].lower() == key.lower() or f["name"] == key:
            return f
    k = key.lower().lstrip("0x").lstrip("0")
    for f in funcs:
        if f["ea"].lower().lstrip("0x").lstrip("0") == k:
            return f
    for f in funcs:
        if key.lower() in (f["name"] or "").lower():
            return f
    return None


def cmd_summary(_):
    m = load("meta.json")
    print("input      : %s" % m.get("input"))
    print("sha256     : %s" % m.get("sha256"))
    print("md5        : %s" % m.get("md5"))
    print("filetype   : %s   bits=%s proc=%s" % (m.get("filetype"), m.get("bits"), m.get("proc")))
    print("ida        : %s   hexrays=%s" % (m.get("ida_version"), m.get("hexrays")))
    print("counts     : %s" % m.get("counts"))
    print("\nentry points:")
    for e in m.get("entries", [])[:10]:
        print("  %s %s" % (e["ea"], e["name"]))
    _raw, _src = raw_sections()
    print("")
    print("sections   [entropy source: %s]" % _src)
    for s in (_raw if _raw is not None else m.get("sections", [])):
        flag = "  <-- high entropy" if s["entropy"] > 7.0 else ""
        print("  %-12s %-12s size=%-9d H=%-6s x=%-5s w=%-5s%s" % (
            s["name"], s["start"], s["size"], s["entropy"], s["perm_x"], s["perm_w"], flag))
    _sig = pack_signals(m, load("functions.json", []))
    if _sig:
        print("")
        print("PACKED / OBFUSCATED -- %d signal(s):" % len(_sig))
        for _r in _sig:
            print("  ! %s" % _r)
        print("  what you see below is the stub, not the malware.")
    print("\nimported DLLs:")
    for dll, names in sorted(m.get("imports_by_dll", {}).items()):
        print("  %-24s %d symbols" % (dll, len(names)))
    # capability rollup
    funcs = load("functions.json", [])
    roll = {}
    for f in funcs:
        for c in f.get("cats", []):
            roll[c] = roll.get(c, 0) + 1
    if roll:
        print("\ncapability categories (functions touching each):")
        for c, n in sorted(roll.items(), key=lambda kv: -kv[1]):
            print("  %-14s %d" % (c, n))
    strings = load("strings.json", [])
    tags = {}
    for s in strings:
        for t in s.get("tags", []):
            tags[t] = tags.get(t, 0) + 1
    if tags:
        print("\nstring tags:")
        for t, n in sorted(tags.items(), key=lambda kv: -kv[1]):
            print("  %-12s %d" % (t, n))


STR_RANK = {"url": 8, "ip": 7, "cmd": 7, "ransom": 8, "regkey": 4, "unc": 4,
            "sql": 5, "useragent": 4, "mutex": 3, "b64blob": 3, "path": 2, "email": 3}


def _order_functions(funcs, edges, entries):
    """Entry point first, then breadth-first along the call graph, then anything
    that scored but was never reached. Reading a binary in call order follows how
    the logic actually unfolds; reading it in score order jumps around."""
    scored = [f for f in funcs if f["score"] > 0]
    by_ea = dict((f["ea"], f) for f in scored)
    out, seen, adj = [], set(), {}
    for src, dst in edges:
        adj.setdefault(src, []).append(dst)
    queue = [e["ea"] for e in entries if e["ea"] in by_ea]
    if not queue and scored:
        queue = [scored[0]["ea"]]
    while queue:
        ea = queue.pop(0)
        if ea in seen or ea not in by_ea:
            continue
        seen.add(ea)
        out.append(by_ea[ea])
        queue.extend(sorted(adj.get(ea, []),
                            key=lambda k: -(by_ea.get(k, {}).get("score", 0))))
    for f in scored:
        if f["ea"] not in seen:
            out.append(f)
    return out


def cmd_plan(a):
    """Ordered walkthrough: what to open in Ghidra, in what order, and why."""
    limit = int(a[0]) if a else 12
    m = load("meta.json")
    funcs = load("functions.json")
    strings = load("strings.json", [])
    edges = load("callgraph.json", [])
    entries = m.get("entries", [])
    byea = dict((f["ea"], f) for f in funcs)
    name = os.path.basename(str(m.get("input") or "sample").replace("\\", "/"))
    n = [1]

    def head(title, section):
        print("")
        print("-" * 78)
        print("STEP %-3d %-44s [%s]" % (n[0], title, section))
        print("-" * 78)
        n[0] += 1

    print("=" * 78)
    print("STATIC ANALYSIS WALKTHROUGH   --   %s" % name)
    print("=" * 78)
    print("engine : %s   decompiler=%s   %s"
          % (m.get("engine") or m.get("ida_version"), m.get("hexrays"), m.get("counts")))
    print("\nAddresses are Ghidra addresses. In the Listing window press G and type the")
    print("address without '0x'. Screenshot the window named at the end of each step.")

    head("File identity", "BACKGROUND + STATIC/File Hash")
    print("  file      : %s" % m.get("input"))
    print("  sha256    : %s" % m.get("sha256"))
    print("  md5       : %s" % m.get("md5"))
    print("  format    : %s   %s-bit %s" % (m.get("filetype"), m.get("bits"), m.get("proc")))
    if m.get("compiler"):
        print("  compiler  : %s" % m.get("compiler"))
    if m.get("image_base"):
        print("  imagebase : %s" % m.get("image_base"))
    print("  -> no screenshot needed; copy these values straight into the report")

    head("Sections, permissions and entropy", "STATIC/Packed + Entropy")
    _raw, _src = raw_sections()
    print("  entropy source: %s" % _src)
    for s in (_raw if _raw is not None else m.get("sections", [])):
        flag = ""
        if s["entropy"] > 7.0:
            flag += "   <-- high entropy: packed or encrypted"
        if s["perm_w"] and s["perm_x"]:
            flag += "   <-- writable AND executable"
        print("  %-10s %-12s size=%-9d H=%-6s x=%-5s w=%-5s%s"
              % (s["name"], s["start"], s["size"], s["entropy"], s["perm_x"], s["perm_w"], flag))
    print("  Ghidra    : Window -> Memory Map")
    signals = pack_signals(m, funcs)
    if signals:
        print("")
        print("  PACKED / OBFUSCATED -- %d signal(s):" % len(signals))
        for r in signals:
            print("    ! %s" % r)
        print("  NOTE      : the real code is NOT visible yet. Every step below")
        print("              describes the unpacking stub, not the malware. Say")
        print("              so in the report, get the unpacked image from the")
        print("              dynamic run, and re-run this walkthrough on that.")

    head("Imported functions", "STATIC/Imported Functions")
    notable = {}
    for f in funcs:
        for site in f.get("api_sites", []):
            for c in site.get("cats", []):
                notable.setdefault(c, set()).add(site["api"])
    for dll, names in sorted((m.get("imports_by_dll") or {}).items()):
        print("  %-22s %d" % (dll, len(names)))
    if notable:
        print("\n  capability-bearing imports:")
        for cat, apis in sorted(notable.items()):
            print("    %-13s %s" % (cat, ", ".join(sorted(x.split("!")[-1] for x in apis))[:92]))
    print("  Ghidra    : Symbol Tree -> Imports")

    head("Strings worth citing", "STATIC/Strings")
    interesting = [s for s in strings if s.get("tags")]
    interesting.sort(key=lambda s: -sum(STR_RANK.get(t, 1) for t in s["tags"]))
    for s in interesting[:18]:
        refs = ", ".join((byea.get(r, {}).get("name") or r) for r in s["refs"][:3])
        print("  %-11s %-16s %s" % (s["ea"], ",".join(s["tags"])[:16], repr(s["text"][:68])))
        if refs:
            print("              used by: %s" % refs)
    if not interesting:
        print("  (none tagged -- consistent with a packed or string-obfuscated sample)")
    print("  Ghidra    : Window -> Defined Strings")

    ordered = _order_functions(funcs, edges, entries)
    entry_eas = set(e["ea"] for e in entries)
    adj_in = {}
    for src, dst in edges:
        adj_in.setdefault(dst, []).append(src)
    for f in ordered[:limit]:
        addr = f["ea"][2:].rjust(8, "0")
        head("%s  %s" % (addr, f.get("name") or ""),
             "CODE/program flow" if f["ea"] in entry_eas else "CODE/CALLs + loops")
        why = []
        if f["ea"] in entry_eas:
            why.append("program entry point")
        if f.get("cats"):
            why.append("capabilities: " + ", ".join(f["cats"]))
        if f.get("nxrefs"):
            why.append("%d xref(s)" % f["nxrefs"])
        callers = adj_in.get(f["ea"], [])
        if callers:
            why.append("called by " + ", ".join((byea.get(c, {}).get("name") or c) for c in callers[:3]))
        print("  Why       : %s" % ("; ".join(why) or "scored above the cutoff"))
        sites = f.get("api_sites") or []
        if sites:
            print("  Look at   :")
            for s in sites[:10]:
                print("      %-11s %s" % (s["ea"], s["api"]))
        elif f.get("apis"):
            print("  Calls     : %s" % ", ".join(x.split("!")[-1] for x in f["apis"][:10]))
        if f.get("strings"):
            print("  Strings   : %s" % "; ".join(repr(x[:46]) for x in f["strings"][:4]))
        print("  Ghidra    : G -> %s    then read the Decompile window" % addr)
        print("  Screenshot: Decompile window (plus Listing if you cite an opcode)")
        print("  Full body : q.py func %s" % f["ea"])

    head("Write up the summary", "ANALYSIS SUMMARY")
    print("    Key host IOCs     : paths and hashes from the dynamic run")
    print("    Key network IOCs  : needs FakeNet, or decrypt the config statically")
    print("    Key functionality : one line per function walked above")
    print("    Purpose           : your conclusion, each claim citing an address")
    print("    Persistence       : from the dynamic run")
    print("")
    print("  A claim without an address is a guess -- label it as one.")
    print("\n%d of %d scored functions shown (pass a number to show more)."
          % (min(limit, len(ordered)), len(ordered)))


def cmd_top(a):
    n = int(a[0]) if a else 30
    funcs = load("functions.json")
    shown = [f for f in funcs if f["score"] > 0][:n]
    for f in shown:
        print(fline(f))
    print("\n(%d of %d functions have score>0; decompiled bodies marked 'src')"
          % (len([f for f in funcs if f['score'] > 0]), len(funcs)))


def cmd_func(a):
    if not a:
        sys.exit("usage: q.py func <ea|name>")
    funcs = load("functions.json")
    f = resolve(funcs, a[0])
    if not f:
        sys.exit("no function matching %r" % a[0])
    print("=" * 70)
    print(fline(f))
    print("=" * 70)
    if f.get("apis"):
        print("\nAPIs called:")
        for x in f["apis"]:
            print("  " + x)
    if f.get("strings"):
        print("\nStrings referenced:")
        for x in f["strings"]:
            print("  " + repr(x))
    edges = load("callgraph.json", [])
    callers = sorted({src for src, dst in edges if dst == f["ea"]})
    callees = sorted({dst for src, dst in edges if src == f["ea"]})
    byea = {x["ea"]: x for x in funcs}
    if callers:
        print("\nCallers:")
        for c in callers[:25]:
            print("  %s %s" % (c, (byea.get(c, {}).get("name") or "")))
    if callees:
        print("\nCallees:")
        for c in callees[:40]:
            print("  %s %s" % (c, (byea.get(c, {}).get("name") or "")))
    p = os.path.join(OUT, "pseudocode", "%s.c" % f["ea"])
    if os.path.exists(p):
        print("\n--- pseudocode ---")
        with open(p, encoding="utf-8", errors="replace") as fh:
            print(fh.read())
    else:
        print("\n(no pseudocode dumped for this function -- it scored below the "
              "decompile cutoff; re-run the dumper with TRIAGE_MAX_DECOMPILE higher)")


def cmd_strings(a):
    if not a:
        sys.exit("usage: q.py strings <regex> [N]")
    rx = re.compile(a[0], re.I)
    n = int(a[1]) if len(a) > 1 else 60
    strings = load("strings.json")
    funcs = {f["ea"]: f for f in load("functions.json", [])}
    hit = 0
    for s in strings:
        if rx.search(s["text"]):
            hit += 1
            if hit > n:
                continue
            refs = ", ".join("%s %s" % (r, (funcs.get(r, {}).get("name") or "")) for r in s["refs"][:4])
            print("%-12s %-22s %s" % (s["ea"], ",".join(s["tags"])[:22], repr(s["text"][:150])))
            if refs:
                print("             refs: %s" % refs)
    print("\n%d matches (showed %d)" % (hit, min(hit, n)))


def cmd_tag(a):
    if not a:
        sys.exit("usage: q.py tag <tagname> [N]")
    tag, n = a[0], int(a[1]) if len(a) > 1 else 60
    strings = load("strings.json")
    funcs = {f["ea"]: f for f in load("functions.json", [])}
    hits = [s for s in strings if tag in s.get("tags", [])]
    for s in hits[:n]:
        refs = ", ".join("%s %s" % (r, (funcs.get(r, {}).get("name") or "")) for r in s["refs"][:4])
        print("%-12s %s" % (s["ea"], repr(s["text"][:170])))
        if refs:
            print("             refs: %s" % refs)
    print("\n%d strings tagged %r (showed %d)" % (len(hits), tag, min(len(hits), n)))


def cmd_api(a):
    if not a:
        sys.exit("usage: q.py api <substr>")
    needle = a[0].lower()
    amap = load("api_map.json")
    funcs = {f["ea"]: f for f in load("functions.json", [])}
    for label in sorted(amap):
        if needle in label.lower():
            print("%s" % label)
            for ea in amap[label][:30]:
                print("    %s %s" % (ea, (funcs.get(ea, {}).get("name") or "")))


def cmd_cat(a):
    if not a:
        sys.exit("usage: q.py cat <category>")
    cat = a[0]
    funcs = load("functions.json")
    hits = [f for f in funcs if cat in f.get("cats", [])]
    for f in hits:
        print(fline(f))
    print("\n%d functions in category %r" % (len(hits), cat))


def _dir(a, want_callers):
    if not a:
        sys.exit("usage: q.py callers|callees <ea>")
    funcs = load("functions.json")
    f = resolve(funcs, a[0])
    ea = f["ea"] if f else a[0]
    edges = load("callgraph.json", [])
    byea = {x["ea"]: x for x in funcs}
    res = sorted({src for src, dst in edges if dst == ea}) if want_callers else \
          sorted({dst for src, dst in edges if src == ea})
    for c in res:
        g = byea.get(c)
        print(fline(g) if g else c)
    print("\n%d %s of %s" % (len(res), "callers" if want_callers else "callees", ea))


def cmd_imports(a):
    m = load("meta.json")
    needle = a[0].lower() if a else None
    for dll, names in sorted(m.get("imports_by_dll", {}).items()):
        if needle and needle not in dll.lower():
            continue
        print("%s  (%d)" % (dll, len(names)))
        print(textwrap.fill(", ".join(names), 100, initial_indent="    ", subsequent_indent="    "))


def cmd_capa(a):
    n = int(a[0]) if a else 80
    data = load("capa.json", {})
    if not data:
        sys.exit("no capa.json in %s" % OUT)
    rules = data.get("rules", data)
    rows = []
    for name, r in rules.items():
        meta = r.get("meta", {})
        ns = meta.get("namespace", "")
        atk = [t.get("id", "") for t in meta.get("att&ck", [])] if isinstance(meta.get("att&ck"), list) else []
        rows.append((ns, name, ",".join(atk)))
    for ns, name, atk in sorted(rows)[:n]:
        print("%-38s %-46s %s" % (ns[:38], name[:46], atk))
    print("\n%d capa rules matched" % len(rows))


CMDS = {
    "summary": cmd_summary, "plan": cmd_plan, "top": cmd_top, "func": cmd_func, "strings": cmd_strings,
    "tag": cmd_tag, "api": cmd_api, "cat": cmd_cat, "imports": cmd_imports, "capa": cmd_capa,
    "callers": lambda a: _dir(a, True), "callees": lambda a: _dir(a, False),
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print(__doc__)
        print("OUT dir: %s" % OUT)
        sys.exit(0 if len(sys.argv) < 2 else 2)
    CMDS[sys.argv[1]](sys.argv[2:])

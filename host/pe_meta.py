#!/usr/bin/env python3
"""pe_meta.py -- fill the STATIC ANALYSIS rows of the course report template.

    python host/pe_meta.py <sample> [--json out.json]

Covers the six template rows that Ghidra does not give us:

    Imp Hash            imphash, computed the way pefile/VirusTotal compute it
    PE Section Hashes   md5 + sha256 + entropy of each section's RAW bytes
    Compile Time        COFF TimeDateStamp, and whether it is obviously faked
    Icon Graphic        which icon resources exist, and their sizes
    Signed?             presence and size of the Authenticode certificate
    File Properties     VERSIONINFO strings + file header characteristics

Pure standard library -- no pefile, no external install. This matters because
the host must stay able to parse a sample with nothing extra installed, and
because `pip install pefile` on an analysis host is one more supply-chain step.

It PARSES. It never executes, never loads, never maps the sample.
"""
import sys, os, json, struct, hashlib, math, datetime

# ------------------------------------------------------------------ primitives

def u8(b, o):  return b[o]
def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    n = float(len(data))
    h = 0.0
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log(p, 2)
    return round(h, 3)


def cstr(b, o, limit=256):
    end = b.find(b"\x00", o, o + limit)
    if end < 0:
        end = min(o + limit, len(b))
    return b[o:end].decode("latin-1")


MACHINE = {0x014c: "x86", 0x8664: "x86-64", 0x01c0: "ARM", 0xaa64: "ARM64",
           0x01c4: "ARMNT", 0x0200: "IA64"}
SUBSYSTEM = {0: "unknown", 1: "native(driver)", 2: "GUI", 3: "console",
             9: "WinCE GUI", 10: "EFI application", 14: "XBOX"}

# IMAGE_FILE_* characteristics
CHARS = [(0x0001, "RELOCS_STRIPPED"), (0x0002, "EXECUTABLE_IMAGE"),
         (0x0004, "LINE_NUMS_STRIPPED"), (0x0008, "LOCAL_SYMS_STRIPPED"),
         (0x0010, "AGGRESSIVE_WS_TRIM"), (0x0020, "LARGE_ADDRESS_AWARE"),
         (0x0080, "BYTES_REVERSED_LO"), (0x0100, "32BIT_MACHINE"),
         (0x0200, "DEBUG_STRIPPED"), (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
         (0x0800, "NET_RUN_FROM_SWAP"), (0x1000, "SYSTEM"), (0x2000, "DLL"),
         (0x4000, "UP_SYSTEM_ONLY"), (0x8000, "BYTES_REVERSED_HI")]

# IMAGE_SCN_* section flags worth reporting
SCN = [(0x00000020, "CODE"), (0x00000040, "INITIALIZED_DATA"),
       (0x00000080, "UNINITIALIZED_DATA"), (0x02000000, "DISCARDABLE"),
       (0x04000000, "NOT_CACHED"), (0x08000000, "NOT_PAGED"),
       (0x10000000, "SHARED"), (0x20000000, "EXECUTE"),
       (0x40000000, "READ"), (0x80000000, "WRITE")]

RT = {1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG",
      6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT", 9: "RT_ACCELERATOR",
      10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
      14: "RT_GROUP_ICON", 16: "RT_VERSION", 17: "RT_DLGINCLUDE",
      19: "RT_PLUGPLAY", 20: "RT_VXD", 21: "RT_ANICURSOR", 22: "RT_ANIICON",
      23: "RT_HTML", 24: "RT_MANIFEST"}


def flags(value, table):
    return [name for bit, name in table if value & bit]


# ------------------------------------------------------------------- PE walking

class PE(object):
    def __init__(self, path):
        self.path = path
        self.imphash_source = None
        with open(path, "rb") as fh:
            self.d = fh.read()
        d = self.d
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise ValueError("not an MZ image")
        self.pe_off = u32(d, 0x3c)
        if self.pe_off + 24 > len(d) or d[self.pe_off:self.pe_off + 4] != b"PE\0\0":
            raise ValueError("no PE signature at e_lfanew=0x%x" % self.pe_off)

        coff = self.pe_off + 4
        self.machine = u16(d, coff)
        self.nsections = u16(d, coff + 2)
        self.timestamp = u32(d, coff + 4)
        self.opt_size = u16(d, coff + 16)
        self.characteristics = u16(d, coff + 18)

        opt = coff + 20
        self.magic = u16(d, opt)
        self.bits = 64 if self.magic == 0x20b else 32
        self.linker = (u8(d, opt + 2), u8(d, opt + 3))
        self.entry_rva = u32(d, opt + 16)
        if self.bits == 64:
            self.image_base = u64(d, opt + 24)
            self.subsystem = u16(d, opt + 68)
            self.dll_chars = u16(d, opt + 70)
            ndd_off, dd_off = opt + 108, opt + 112
        else:
            self.image_base = u32(d, opt + 28)
            self.subsystem = u16(d, opt + 68)
            self.dll_chars = u16(d, opt + 70)
            ndd_off, dd_off = opt + 92, opt + 96
        self.ndd = u32(d, ndd_off)

        self.dirs = []
        for i in range(min(self.ndd, 16)):
            self.dirs.append((u32(d, dd_off + i * 8), u32(d, dd_off + i * 8 + 4)))

        self.sections = []
        sec = opt + self.opt_size
        for i in range(self.nsections):
            o = sec + i * 40
            if o + 40 > len(d):
                break
            nm = cstr(d, o, 8).rstrip(chr(0)).strip()
            # FSG and several other packers blank the section names outright.
            # An empty name printed as "" reads like a parser failure, so label
            # it: a nameless section IS a finding, not missing data.
            if not nm:
                nm = "<unnamed%d>" % i
            self.sections.append({
                "name": nm,
                "vsize": u32(d, o + 8), "vaddr": u32(d, o + 12),
                "rawsize": u32(d, o + 16), "rawptr": u32(d, o + 20),
                "flags": u32(d, o + 36),
            })

    # --- rva helpers
    def rva_to_off(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                delta = rva - s["vaddr"]
                if delta < s["rawsize"]:
                    return s["rawptr"] + delta
                return None
        # not inside a section: before the first one it is a header offset
        if self.sections and rva < self.sections[0]["vaddr"]:
            return rva
        return None

    def at(self, rva, n):
        o = self.rva_to_off(rva)
        if o is None or o >= len(self.d):
            return b""
        return self.d[o:o + n]

    # --- imports / imphash
    def imports(self):
        """Returns [(dll, name_or_ordinal, is_ordinal)] in table order.

        Order matters: imphash is defined over the import table as laid out in
        the file, so sorting it would produce a hash that matches nothing.
        """
        out = []
        if len(self.dirs) < 2:
            return out
        rva, size = self.dirs[1]
        if not rva:
            return out
        step = 8 if self.bits == 64 else 4
        i = 0
        while True:
            desc = self.at(rva + i * 20, 20)
            if len(desc) < 20:
                break
            oft, name_rva, first = u32(desc, 0), u32(desc, 12), u32(desc, 16)
            if not name_rva and not first:
                break
            dll = cstr(self.d, self.rva_to_off(name_rva) or 0, 128) if name_rva else ""
            thunk_rva = oft or first
            j = 0
            while thunk_rva and j < 4096:
                raw = self.at(thunk_rva + j * step, step)
                if len(raw) < step:
                    break
                val = u64(raw, 0) if step == 8 else u32(raw, 0)
                if val == 0:
                    break
                ordinal_bit = (1 << 63) if step == 8 else (1 << 31)
                if val & ordinal_bit:
                    out.append((dll, val & 0xffff, True))
                else:
                    nm = self.at(val + 2, 128)
                    out.append((dll, nm.split(b"\x00")[0].decode("latin-1"), False))
                j += 1
            i += 1
            if i > 256:
                break
        return out

    def imphash(self):
        """The pefile/VirusTotal algorithm, reimplemented.

        Each entry is 'dll.func', both lowercased, with the dll's extension
        dropped only for .dll/.ocx/.sys; an import by ordinal becomes
        'dll.ord<N>'. Joined with ',' and MD5'd. Getting any of these details
        wrong yields a hash that silently matches nothing, so this follows the
        reference implementation rather than guessing.
        """
        # pefile resolves an import-by-ordinal to its well-known NAME via its
        # ordlookup tables (ws2_32 ordinal 115 -> WSAStartup), so a sample that
        # imports sockets by ordinal gets a different hash than "ws2_32.ord115".
        # Verified against pefile on 10 binaries: 7 EXEs matched, and all 3
        # mismatches were DLLs importing WS2_32 by ordinal. A wrong imphash is
        # worse than none -- it silently matches nothing on VirusTotal -- so
        # defer to pefile whenever it is importable and only fall back to this
        # parser when it is not, labelling the result when we do.
        try:
            import pefile  # noqa: F401
        except ImportError:
            pefile = None
        if pefile is not None:
            try:
                ref = pefile.PE(self.path, fast_load=True)
                ref.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                ih = ref.get_imphash() or None
                ref.close()
                if ih:
                    self.imphash_source = "pefile"
                    return ih, len(self.imports())
            except Exception:
                pass

        self.imphash_source = "pe_meta (ordinal imports NOT name-resolved)"
        parts = []
        for dll, name, is_ord in self.imports():
            base = dll.lower()
            stem, ext = os.path.splitext(base)
            if ext in (".dll", ".ocx", ".sys"):
                base = stem
            fn = ("ord%d" % name) if is_ord else str(name).lower()
            parts.append("%s.%s" % (base, fn))
        if not parts:
            return None, 0
        s = ",".join(parts)
        return hashlib.md5(s.encode("ascii", "ignore")).hexdigest(), len(parts)

    def exports(self):
        out = []
        if len(self.dirs) < 1:
            return out
        rva, size = self.dirs[0]
        if not rva:
            return out
        hdr = self.at(rva, 40)
        if len(hdr) < 40:
            return out
        nnames, names_rva, ords_rva = u32(hdr, 24), u32(hdr, 32), u32(hdr, 36)
        for i in range(min(nnames, 4096)):
            nr = self.at(names_rva + i * 4, 4)
            if len(nr) < 4:
                break
            o = self.rva_to_off(u32(nr, 0))
            if o is None:
                continue
            out.append(cstr(self.d, o, 128))
        return out

    # --- resources
    def resources(self):
        """Walk the three-level resource tree: type -> name/id -> language."""
        if len(self.dirs) < 3:
            return []
        base, _ = self.dirs[2]
        if not base:
            return []
        found = []

        def walk(off, level, type_id, name_id):
            hdr = self.at(base + off, 16)
            if len(hdr) < 16:
                return
            nnamed, nid = u16(hdr, 12), u16(hdr, 14)
            for k in range(nnamed + nid):
                ent = self.at(base + off + 16 + k * 8, 8)
                if len(ent) < 8:
                    return
                nm, child = u32(ent, 0), u32(ent, 4)
                if level == 0:
                    t = nm & 0x7fffffff if not (nm & 0x80000000) else None
                    nt, nn = t, name_id
                elif level == 1:
                    nt, nn = type_id, (nm & 0x7fffffff)
                else:
                    nt, nn = type_id, name_id
                if child & 0x80000000:
                    if level < 2:
                        walk(child & 0x7fffffff, level + 1, nt, nn)
                else:
                    leaf = self.at(base + child, 16)
                    if len(leaf) >= 8:
                        found.append({
                            "type": RT.get(nt, str(nt)) if nt is not None else "named",
                            "id": nn, "rva": u32(leaf, 0), "size": u32(leaf, 4)})

        walk(0, 0, None, None)
        return found

    def versioninfo(self):
        """Best-effort VERSIONINFO StringFileInfo extraction.

        Rather than decode the whole VS_VERSIONINFO structure (which is
        padding-sensitive and routinely malformed in malware), scan the blob
        for UTF-16 key/value runs. Good enough to quote in a report, and it
        does not fall over on a deliberately corrupt resource.
        """
        for r in self.resources():
            if r["type"] != "RT_VERSION":
                continue
            blob = self.at(r["rva"], min(r["size"], 65536))
            if not blob:
                continue
            try:
                text = blob.decode("utf-16-le", "ignore")
            except Exception:
                continue
            runs = [t for t in text.split("\x00") if len(t.strip()) > 1]
            keys = ("CompanyName", "FileDescription", "FileVersion", "InternalName",
                    "LegalCopyright", "OriginalFilename", "ProductName",
                    "ProductVersion", "Comments", "LegalTrademarks")
            out = {}
            for i, tok in enumerate(runs):
                if tok in keys and i + 1 < len(runs) and runs[i + 1] not in keys:
                    out[tok] = runs[i + 1].strip()
            if out:
                return out
        return {}


# --------------------------------------------------------------------- reporting

def analyse(path):
    pe = PE(path)
    d = pe.d
    rep = {}

    rep["file"] = os.path.abspath(path)
    rep["file_name"] = os.path.basename(path)
    rep["file_size"] = len(d)
    rep["md5"] = hashlib.md5(d).hexdigest()
    rep["sha1"] = hashlib.sha1(d).hexdigest()
    rep["sha256"] = hashlib.sha256(d).hexdigest()
    rep["file_entropy"] = entropy(d)

    st = os.stat(path)
    rep["fs_timestamps"] = {
        "modified": datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "created": datetime.datetime.fromtimestamp(st.st_ctime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    # --- compile time
    ts = pe.timestamp
    ct = {"raw": ts, "hex": "0x%08x" % ts}
    if ts == 0:
        ct["utc"] = None
        ct["note"] = "zero -- stripped, or a reproducible build"
    elif ts > 0xf0000000:
        ct["utc"] = None
        ct["note"] = "not a unix time -- Delphi/other linker, or deliberately faked"
    else:
        dtv = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        ct["utc"] = dtv.strftime("%Y-%m-%d %H:%M:%S UTC")
        now = datetime.datetime.now(datetime.timezone.utc)
        if dtv > now:
            ct["note"] = "IN THE FUTURE -- faked"
        elif dtv.year < 1995:
            ct["note"] = "implausibly old -- faked"
    rep["compile_time"] = ct

    rep["header"] = {
        "machine": MACHINE.get(pe.machine, "0x%04x" % pe.machine),
        "bits": pe.bits,
        "subsystem": SUBSYSTEM.get(pe.subsystem, str(pe.subsystem)),
        "image_base": "0x%x" % pe.image_base,
        "entry_point": "0x%x" % (pe.image_base + pe.entry_rva),
        "entry_rva": "0x%x" % pe.entry_rva,
        "linker": "%d.%d" % pe.linker,
        "characteristics": "0x%04x" % pe.characteristics,
        "characteristics_flags": flags(pe.characteristics, CHARS),
        "is_dll": bool(pe.characteristics & 0x2000),
        "is_driver": SUBSYSTEM.get(pe.subsystem) == "native(driver)",
    }

    # --- imphash
    ih, ncount = pe.imphash()
    rep["imphash"] = ih
    rep["imphash_source"] = pe.imphash_source
    rep["import_count"] = ncount
    rep["ordinal_imports"] = sum(1 for _, _, is_ord in pe.imports() if is_ord)
    by_dll = {}
    for dll, name, is_ord in pe.imports():
        by_dll.setdefault(dll, []).append(("ord%d" % name) if is_ord else name)
    rep["imports_by_dll"] = by_dll
    rep["exports"] = pe.exports()

    # --- per-section hashes
    secs = []
    for s in pe.sections:
        raw = d[s["rawptr"]:s["rawptr"] + s["rawsize"]] if s["rawsize"] else b""
        secs.append({
            "name": s["name"],
            "vaddr": "0x%x" % (pe.image_base + s["vaddr"]),
            "vsize": s["vsize"],
            "rawsize": s["rawsize"],
            "entropy": entropy(raw),
            "md5": hashlib.md5(raw).hexdigest() if raw else None,
            "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "flags": "0x%08x" % s["flags"],
            "perm": "".join([c for c, bit in (("r", 0x40000000), ("w", 0x80000000),
                                              ("x", 0x20000000)) if s["flags"] & bit]),
            "flag_names": flags(s["flags"], SCN),
        })
    rep["sections"] = secs

    # a section whose virtual size vastly exceeds its raw size is where a packer
    # unpacks into; worth stating explicitly rather than leaving in the numbers
    rep["section_notes"] = []
    for s in pe.sections:
        if s["vsize"] > max(s["rawsize"], 1) * 4 and s["vsize"] > 0x1000:
            rep["section_notes"].append(
                "%s: virtual %d B vs raw %d B -- room to unpack into"
                % (s["name"], s["vsize"], s["rawsize"]))
        if (s["flags"] & 0x20000000) and (s["flags"] & 0x80000000):
            rep["section_notes"].append("%s: writable AND executable" % s["name"])

    # --- signature
    sig = {"signed": False}
    if len(pe.dirs) > 4:
        rva, size = pe.dirs[4]
        # the Security directory is a FILE OFFSET, not an RVA -- the one
        # data directory that breaks the rule. Treating it as an RVA makes
        # every signed binary look unsigned.
        if rva and size:
            sig = {"signed": True, "cert_offset": "0x%x" % rva, "cert_size": size,
                   "note": "Authenticode blob present. This tool does NOT verify the "
                           "chain or that it matches the file -- a present signature "
                           "is not a valid signature."}
    rep["signature"] = sig

    # --- icon / resources
    res = pe.resources()
    rep["resources"] = res
    icons = [r for r in res if r["type"] in ("RT_ICON", "RT_GROUP_ICON")]
    rep["icon"] = {
        "has_icon": bool(icons),
        "count": len(icons),
        "entries": [{"type": r["type"], "id": r["id"], "size": r["size"]} for r in icons],
    } if icons else {"has_icon": False,
                     "note": "no icon resource -- the file shows the generic "
                             "Windows default in Explorer"}
    rep["version_info"] = pe.versioninfo()
    rep["manifest"] = any(r["type"] == "RT_MANIFEST" for r in res)
    return rep


def human(rep):
    L = []
    a = L.append
    a("=" * 78)
    a("PE METADATA  --  %s" % rep["file_name"])
    a("=" * 78)
    a("")
    a("[STATIC/File Size]      %d bytes" % rep["file_size"])
    a("[STATIC/File Hash]      md5    %s" % rep["md5"])
    a("                        sha1   %s" % rep["sha1"])
    a("                        sha256 %s" % rep["sha256"])
    a("[STATIC/Imp Hash]       %s   (%d imports)"
      % (rep["imphash"] or "(no import table)", rep["import_count"]))
    a("                        source: %s" % (rep.get("imphash_source") or "n/a"))
    if rep.get("ordinal_imports") and rep.get("imphash_source", "").startswith("pe_meta"):
        a("                        !! %d import(s) by ordinal and pefile is not"
          % rep["ordinal_imports"])
        a("                           installed -- this hash will NOT match")
        a("                           VirusTotal. Do not pivot on it.")

    ct = rep["compile_time"]
    line = ct["utc"] or ("%s  <- %s" % (ct["hex"], ct.get("note", "unparsable")))
    a("[STATIC/Compile Time]   %s" % line)
    if ct["utc"] and ct.get("note"):
        a("                        !! %s" % ct["note"])

    h = rep["header"]
    a("[STATIC/File Header]    %s %d-bit, subsystem=%s, %s"
      % (h["machine"], h["bits"], h["subsystem"],
         "DLL" if h["is_dll"] else ("driver" if h["is_driver"] else "EXE")))
    a("                        imagebase %s  entry %s  linker %s"
      % (h["image_base"], h["entry_point"], h["linker"]))
    a("                        characteristics %s = %s"
      % (h["characteristics"], ", ".join(h["characteristics_flags"])))

    s = rep["signature"]
    if s["signed"]:
        a("[STATIC/Signed?]        certificate present, %d bytes at %s"
          % (s["cert_size"], s["cert_offset"]))
        a("                        NOT verified -- presence is not validity")
    else:
        a("[STATIC/Signed?]        no  (no Authenticode certificate)")

    ic = rep["icon"]
    if ic["has_icon"]:
        a("[STATIC/Icon Graphic]   %d icon resource(s): %s" % (
            ic["count"], ", ".join("%s#%s %dB" % (e["type"], e["id"], e["size"])
                                   for e in ic["entries"][:6])))
    else:
        a("[STATIC/Icon Graphic]   none -- generic Windows default icon")

    vi = rep["version_info"]
    if vi:
        a("[STATIC/File Properties]")
        for k in sorted(vi):
            a("                        %-18s %s" % (k, vi[k]))
    else:
        a("[STATIC/File Properties] no VERSIONINFO resource -- no company, product")
        a("                        or version strings. Normal for malware, abnormal")
        a("                        for a file claiming to be a Microsoft binary.")
    a("                        manifest: %s" % ("yes" if rep["manifest"] else "no"))

    a("")
    a("[STATIC/PE Section Hashes + Entropy]    file entropy H=%s" % rep["file_entropy"])
    a("  %-9s %-12s %9s %9s %-6s %-5s %s" %
      ("name", "vaddr", "vsize", "rawsize", "H", "perm", "md5"))
    for s in rep["sections"]:
        a("  %-9s %-12s %9d %9d %-6s %-5s %s" %
          (s["name"], s["vaddr"], s["vsize"], s["rawsize"], s["entropy"],
           s["perm"], s["md5"] or "(no raw data)"))
    for n in rep["section_notes"]:
        a("  !! %s" % n)

    a("")
    a("[STATIC/Imported Functions]")
    for dll in sorted(rep["imports_by_dll"]):
        names = rep["imports_by_dll"][dll]
        a("  %-18s %2d   %s" % (dll, len(names), ", ".join(names[:8])
                                + (" ..." if len(names) > 8 else "")))
    if rep["exports"]:
        a("[STATIC/Exported Functions]  %d: %s"
          % (len(rep["exports"]), ", ".join(rep["exports"][:12])))
    else:
        a("[STATIC/Exported Functions]  none")

    a("")
    a("[STATIC/Open Source Research]  look these up by HASH, never by upload:")
    a("  https://www.virustotal.com/gui/file/%s" % rep["sha256"])
    a("  https://bazaar.abuse.ch/browse.php?search=sha256%%3A%s" % rep["sha256"])
    a("  imphash pivot (finds siblings built from the same source tree):")
    a("    https://www.virustotal.com/gui/search/imphash%%3A%s" % (rep["imphash"] or ""))
    return "\n".join(L)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    path = argv[0]
    out_json = None
    if "--json" in argv:
        out_json = argv[argv.index("--json") + 1]
    if not os.path.isfile(path):
        print("ERROR: no such file: %s" % path)
        return 1
    try:
        rep = analyse(path)
    except ValueError as e:
        print("ERROR: %s" % e)
        return 1
    print(human(rep))
    if out_json:
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1, sort_keys=True)
        print("\n[wrote %s]" % out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""
Minimal dependency-free PE reader: exports, characteristics, machine type.

The analysis VM has Python 3.5 and no internet, so pefile is not available and
cannot be installed. This parses the headers directly. Python 3.5 compatible --
no f-strings.

  python pe_exports.py <out.json> <file-or-dir> [more...]

For a directory it walks it and reports every PE found. The point is to answer,
for a malware DLL, HOW it is meant to be loaded:
  DllRegisterServer present  -> regsvr32 <dll>
  ServiceMain / install*     -> install as a service
  anything else              -> rundll32 <dll>,<Export>
A DLL with no exports at all still runs its DllMain when loaded, so
`rundll32 <dll>,#1` or a loader stub is the fallback.
"""
import json
import os
import struct
import sys

IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_SYSTEM = 0x1000
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
MACHINE = {0x014c: "x86", 0x8664: "x64", 0x01c0: "ARM", 0xaa64: "ARM64", 0x0200: "IA64"}
SUBSYSTEM = {1: "native(driver)", 2: "GUI", 3: "console", 9: "WinCE", 10: "EFI"}


class NotPE(Exception):
    pass


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def parse(path):
    with open(path, "rb") as fh:
        b = fh.read()
    if len(b) < 0x40 or b[0:2] != b"MZ":
        raise NotPE("no MZ header")
    pe = u32(b, 0x3C)
    if pe <= 0 or pe + 24 > len(b) or b[pe:pe + 4] != b"PE\0\0":
        raise NotPE("no PE signature")

    machine = u16(b, pe + 4)
    nsec = u16(b, pe + 6)
    timestamp = u32(b, pe + 8)
    opt_size = u16(b, pe + 20)
    chars = u16(b, pe + 22)
    opt = pe + 24
    magic = u16(b, opt)
    if magic == 0x20b:      # PE32+
        bits, dd_off = 64, opt + 112
    elif magic == 0x10b:    # PE32
        bits, dd_off = 32, opt + 96
    else:
        raise NotPE("unknown optional header magic 0x%x" % magic)

    subsystem = u16(b, opt + 68)
    nvad = u32(b, dd_off - 4)
    exp_rva = u32(b, dd_off) if nvad >= 1 else 0
    exp_size = u32(b, dd_off + 4) if nvad >= 1 else 0

    # section table -> RVA to file offset
    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        s = sec_off + i * 40
        if s + 40 > len(b):
            break
        sections.append({
            "name": b[s:s + 8].rstrip(b"\0").decode("ascii", "replace"),
            "vsize": u32(b, s + 8), "vaddr": u32(b, s + 12),
            "rawsize": u32(b, s + 16), "rawptr": u32(b, s + 20),
        })

    def rva2off(rva):
        for s in sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s["rawptr"] + (rva - s["vaddr"])
        return None

    exports, ordinal_base, fwd = [], None, []
    if exp_rva and exp_size:
        eo = rva2off(exp_rva)
        if eo is not None and eo + 40 <= len(b):
            ordinal_base = u32(b, eo + 16)
            n_funcs = u32(b, eo + 20)
            n_names = u32(b, eo + 24)
            a_funcs = rva2off(u32(b, eo + 28))
            a_names = rva2off(u32(b, eo + 32))
            a_ords = rva2off(u32(b, eo + 36))
            if a_names is not None and a_ords is not None:
                for i in range(min(n_names, 4096)):
                    try:
                        name_rva = u32(b, a_names + i * 4)
                        no = rva2off(name_rva)
                        if no is None:
                            continue
                        end = b.index(b"\0", no)
                        nm = b[no:end].decode("ascii", "replace")
                        ordv = u16(b, a_ords + i * 2) + (ordinal_base or 0)
                        entry = {"name": nm, "ordinal": ordv}
                        if a_funcs is not None:
                            f_rva = u32(b, a_funcs + (ordv - (ordinal_base or 0)) * 4)
                            # an RVA inside the export directory means a forwarder
                            if exp_rva <= f_rva < exp_rva + exp_size:
                                fo = rva2off(f_rva)
                                if fo is not None:
                                    entry["forwarder"] = b[fo:b.index(b"\0", fo)].decode("ascii", "replace")
                            entry["rva"] = "0x%x" % f_rva
                        exports.append(entry)
                    except Exception:
                        continue
            if n_funcs and not n_names:
                exports.append({"name": None, "ordinal": ordinal_base,
                                "note": "%d function(s) exported by ordinal only" % n_funcs})

    is_dll = bool(chars & IMAGE_FILE_DLL)
    is_sys = bool(chars & IMAGE_FILE_SYSTEM) or subsystem == 1
    names = [e["name"] for e in exports if e.get("name")]
    low = [n.lower() for n in names]

    if is_sys:
        how = "kernel driver -- needs a service install + load; NOT supported by detonate.ps1"
    elif not is_dll:
        how = "executable -- launch directly"
    elif "dllregisterserver" in low:
        how = "regsvr32 /s <dll>"
    elif any(n.startswith("servicemain") for n in low):
        how = "install as a service (ServiceMain present)"
    elif any("install" in n for n in low):
        cand = [n for n in names if "install" in n.lower()][0]
        how = 'rundll32 <dll>,%s   (install-style export)' % cand
    elif names:
        how = "rundll32 <dll>,%s" % names[0]
    else:
        how = "no named exports -- rundll32 <dll>,#1 loads it so DllMain still runs"

    return {
        "path": path,
        "size": os.path.getsize(path),
        "bits": bits,
        "machine": MACHINE.get(machine, "0x%x" % machine),
        "subsystem": SUBSYSTEM.get(subsystem, str(subsystem)),
        "timestamp": timestamp,
        "characteristics": "0x%04x" % chars,
        "is_dll": is_dll,
        "is_driver": is_sys,
        "sections": [s["name"] for s in sections],
        "export_count": len(exports),
        "exports": exports[:200],
        "suggested_launch": how,
    }


def main(out_path, targets):
    results, errors = [], []
    files = []
    for t in targets:
        if os.path.isdir(t):
            for root, _dirs, fs in os.walk(t):
                for f in fs:
                    files.append(os.path.join(root, f))
        else:
            files.append(t)
    for f in files:
        try:
            results.append(parse(f))
        except NotPE as e:
            errors.append({"path": f, "error": str(e)})
        except Exception as e:
            errors.append({"path": f, "error": "%s: %s" % (type(e).__name__, e)})
    with open(out_path, "w") as fh:
        json.dump({"pe_files": results, "not_pe": errors}, fh, indent=1)
    print("[pe_exports] %d PE file(s), %d skipped -> %s" % (len(results), len(errors), out_path))
    for r in results:
        kind = "DRIVER" if r["is_driver"] else ("DLL" if r["is_dll"] else "EXE")
        print("  %-5s %-28s %-4s exports=%-4d  %s" % (
            kind, os.path.basename(r["path"])[:28], r["machine"],
            r["export_count"], r["suggested_launch"]))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2:])

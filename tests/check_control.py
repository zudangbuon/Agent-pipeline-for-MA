#!/usr/bin/env python3
"""Check a control detonation against what the control is known to have done.

  python tests/check_control.py <control_expect.json> <out/dynamic/TAG>

Prints one line per check. A FAIL names the artifact that should have carried the
evidence, so the output says which monitor went blind rather than just "something
is wrong".

Two checks are deliberately inverted:

  ifeo_nested_value  expected ABSENT. It asserts a KNOWN blind spot -- Snap-Reg
                     does not descend into subkeys. If it starts appearing, the
                     snapshot got deeper and that is a change to record, not a
                     failure. Reported as CHANGED, not FAIL.
  hklm_*/service     need admin. On an unelevated run their absence is correct,
                     and the script says SKIP (needs admin) rather than FAIL --
                     reading `elevated=` out of detonate.log to decide.

Exit status is 0 only when nothing FAILED.
"""
import csv
import io
import json
import os
import re
import sys


def load(d, name, default=None):
    """Artifacts are written by PowerShell with a UTF-8 BOM; utf-8-sig handles it.

    A plain json.load() raises on the BOM and every file reads as empty, which looks
    exactly like a run that captured nothing.
    """
    p = os.path.join(d, name)
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        return default
    try:
        with io.open(p, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return default


def read_text(d, name):
    p = os.path.join(d, name)
    if not os.path.exists(p):
        return ""
    with io.open(p, encoding="utf-8-sig", errors="replace") as fh:
        return fh.read()


def procmon_rows(d):
    """Parse procmon.csv with a real CSV reader.

    The Detail column contains quoted commas, so splitting on ',' silently returns
    the wrong columns -- that mistake once hid a successful process replacement.
    """
    p = os.path.join(d, "procmon.csv")
    if not os.path.exists(p):
        return []
    with io.open(p, encoding="utf-8-sig", errors="replace", newline="") as fh:
        return list(csv.DictReader(fh))


def flat(obj):
    """Every string in a nested structure, for substring searching."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out.extend(flat(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(flat(v))
    elif obj is not None:
        out.append(str(obj))
    return out


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: python tests/check_control.py <control_expect.json> "
                 "<out/dynamic/TAG>")
    exp = json.load(io.open(sys.argv[1], encoding="utf-8"))
    d = sys.argv[2]
    if not os.path.isdir(d):
        sys.exit("no such run directory: %s" % d)

    marker, host, uri = exp["marker"], exp["host"], exp["uri"]

    # ---- run context, read rather than assumed
    log = read_text(d, "detonate.log")
    summary = load(d, "summary.json", {}) or {}
    m = re.search(r"elevated=(\w+)", log)
    elevated = (m.group(1).lower() == "true") if m else None
    fakenet = bool(summary.get("fakenet"))
    fakenet_up = "FakeNet-NG up" in log

    print("run      : %s" % d)
    print("elevated : %s%s" % (elevated, "" if m else "  (NOT RECORDED in detonate.log)"))
    print("fakenet  : summary=%s  log says up=%s" % (fakenet, fakenet_up))
    # the key is timeout_sec, not timeout -- summary.json names it that way
    print("mode     : %s   timeout=%ss" % (summary.get("mode"),
                                           summary.get("timeout_sec", "?")))
    print()

    reg = load(d, "registry.json", {}) or {}
    reg_txt = " | ".join(flat(reg))
    dropped_txt = " | ".join(flat(load(d, "dropped.json", []) or []))
    autoruns_txt = " | ".join(flat(load(d, "autoruns.json", {}) or {}))
    fn_log = read_text(d, "fakenet.log")
    rows = procmon_rows(d)

    paths = [(r.get("Path") or "") for r in rows]
    ops = [((r.get("Operation") or ""), (r.get("Path") or ""), (r.get("Detail") or ""))
           for r in rows]

    def have(hay, *needles):
        return all(n.lower() in hay.lower() for n in needles)

    results = {
        "dropped_file":
            have(dropped_txt, marker + "_dropped.txt"),
        "ephemeral_file":
            any(marker + "_ephemeral" in p for p in paths) and
            any(marker + "_ephemeral" in p and
                ("SetDispositionInformationFile" in o or "CreateFile" in o)
                for o, p, _ in ops),
        "hkcu_run":
            have(reg_txt, marker + "_hkcu"),
        "hklm_run":
            have(reg_txt, marker + "_hklm"),
        "ifeo_subkey":
            have(reg_txt, marker + "_victim.exe"),
        "ifeo_nested_value":
            bool(re.search(re.escape(marker) + r"_victim\.exe[^|]*Debugger",
                           reg_txt, re.I)),
        "service":
            have(autoruns_txt, marker + "_svc"),
        "child_process":
            any(o == "Process Create" and re.search(r"PID:\s*\d+", det)
                for o, _, det in ops),
        "dns":
            host.lower() in fn_log.lower() and
            bool(re.search(r"(DNS|request for domain).*" + re.escape(host),
                           fn_log, re.I)),
        "http":
            bool(re.search(r"GET\s+" + re.escape(uri), fn_log, re.I)) and
            host.lower() in fn_log.lower(),
    }

    width = max(len(c["id"]) for c in exp["checks"])
    failed, skipped, changed, passed = 0, 0, 0, 0

    for c in exp["checks"]:
        cid = c["id"]
        got = results.get(cid, False)
        inverted = c.get("expected_result") == "ABSENT"

        if c.get("needs_admin") and elevated is False:
            status, note = "SKIP", "needs admin; run was unelevated"
            skipped += 1
        elif c.get("needs_fakenet") and not (fakenet and fakenet_up):
            status, note = "SKIP", "needs FakeNet; it was not up this run"
            skipped += 1
        elif inverted:
            if got:
                status, note = "CHANGED", "now VISIBLE -- snapshot got deeper, update CLAUDE.md"
                changed += 1
            else:
                status, note = "ok", "absent, as expected (known blind spot)"
                passed += 1
        elif got:
            status, note = "PASS", ""
            passed += 1
        else:
            status, note = "FAIL", "not found in %s" % c["artifact"]
            failed += 1

        print("  [%-7s] %-*s  step %d  %s" % (status, width, cid, c["step"], note))

    print()
    print("passed %d   failed %d   skipped %d   changed %d"
          % (passed, failed, skipped, changed))

    if failed:
        print()
        print("A FAIL means a monitor did not record something the control is known to")
        print("have done. Check what the guest-side noise filter removed before")
        print("concluding the behaviour did not happen:")
        print("    procmon_dropped.json in the run directory")
    if changed:
        print()
        print("A CHANGED is not a failure -- it means coverage improved and the notes")
        print("are now out of date.")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

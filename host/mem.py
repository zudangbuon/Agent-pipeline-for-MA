#!/usr/bin/env python3
r"""mem.py -- query a memory image for the report's MEMORY ANALYSIS row.

    set MEM_IMAGE=..\samples-host\for610\day4\great.vmem
    python host/mem.py info
    python host/mem.py proc            # rogue processes, exited + unlinked flagged
    python host/mem.py inject          # code injection, with the noise separated out
    python host/mem.py net             # network artifacts, non-system first
    python host/mem.py cmdline
    python host/mem.py plan            # step-by-step + what to screenshot

Wraps Volatility 3 the way q.py wraps Ghidra and dyn.py wraps the detonation:
verbose on disk, terse on stdout. Plugin output is cached as JSON under
out/memory/<tag>/ because a 2 GB image takes minutes per plugin -- the first call
pays for it, every later one is instant. Use --refresh to re-run a plugin.

It READS an image. Nothing is executed.
"""
import sys, os, json, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "out")


def vol_exe():
    for c in (shutil.which("vol"), shutil.which("vol.exe"),
              os.path.join(os.path.dirname(sys.executable), "Scripts", "vol.exe")):
        if c and os.path.isfile(c):
            return c
    die("vol.exe not found -- pip install volatility3")


def die(msg, code=2):
    print("ERROR: %s" % msg, file=sys.stderr)
    sys.exit(code)


def image():
    p = os.environ.get("MEM_IMAGE")
    if not p:
        die("set MEM_IMAGE to the image path (or pass --image <file>)")
    if not os.path.isfile(p):
        die("no such image: %s" % p)
    return p


def tag(img):
    return os.path.splitext(os.path.basename(img))[0]


def run(plugin, refresh=False, extra=()):
    """Run a volatility plugin, cache its JSON, return a list of dicts."""
    img = image()
    cache_dir = os.path.join(OUT, "memory", tag(img))
    os.makedirs(cache_dir, exist_ok=True)
    cache = os.path.join(cache_dir, plugin.replace(".", "_") + ".json")
    if os.path.isfile(cache) and not refresh and os.path.getsize(cache) > 0:
        with open(cache, encoding="utf-8") as fh:
            return json.load(fh)

    cmd = [vol_exe(), "-q", "-r", "json", "-f", img, plugin] + list(extra)
    print("[*] running %s (first time on this image -- this is the slow part)"
          % plugin, file=sys.stderr)
    pr = subprocess.run(cmd, capture_output=True, text=True)
    if pr.returncode != 0 and not pr.stdout.strip():
        die("%s failed:\n%s" % (plugin, (pr.stderr or "")[-1500:]))
    try:
        rows = json.loads(pr.stdout)
    except Exception:
        die("%s produced no parseable JSON. stderr tail:\n%s"
            % (plugin, (pr.stderr or "")[-1500:]))
    with open(cache, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    return rows


# Windows processes that are normal on any desktop. Unlike dyn.py's NOISE_PROCS
# this list is never used to hide something with a suspicious parent -- see proc().
OS_PROCS = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.ex",
    "fontdrvhost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "conhost.exe",
    "RuntimeBroker.", "RuntimeBroker.exe", "ShellExperienc", "SearchUI.exe",
    "SearchIndexer.", "ApplicationFra", "WmiPrvSE.exe", "WmiApSrv.exe",
    "dllhost.exe", "spoolsv.exe", "msdtc.exe", "VSSVC.exe", "TabTip.exe",
    "WUDFHost.exe", "LogonUI.exe", "userinit.exe", "audiodg.exe", "dasHost.exe",
    "vmtoolsd.exe", "vmacthlp.exe", "VGAuthService.", "VGAuthService.exe",
    "MsMpEng.exe", "NisSrv.exe", "SecurityHealth", "smartscreen.ex",
    "backgroundTask", "SystemSettings", "Taskmgr.exe", "notepad.exe",
}


OS_PROCS_LC = {n.lower() for n in OS_PROCS}


def is_os_proc(name):
    """Case-insensitive, and tolerant of Volatility's 14-char name truncation.

    The prefix fallback fires ONLY at exactly 14 characters, which is where
    EPROCESS.ImageFileName actually truncates. An earlier version allowed any
    prefix of 8+ chars, which would have hidden a sample named `svchost.ex`
    behind the real `svchost.exe` -- masquerading is the main thing this list
    must not swallow. Measured on themida.img: `lsass.exe.exe` (13 chars, a
    masquerade) is correctly NOT matched against `lsass.exe`.
    """
    n = str(name or "").strip().lower()
    if n in OS_PROCS_LC:
        return True
    if len(n) != 14:
        return False
    return any(k.startswith(n) for k in OS_PROCS_LC)


def norm(r, *names):
    for n in names:
        if n in r:
            return r[n]
    return None


def cmd_info(a):
    rows = run("windows.info")
    want = {"Kernel Base", "DTB", "Is64Bit", "IsPAE", "NTBuildLab", "Major/Minor",
            "KeNumberProcessors", "SystemTime", "NtSystemRoot", "NtProductType",
            "NtMajorVersion", "NtMinorVersion", "Symbols"}
    print("image: %s" % image())
    for r in rows:
        k, v = norm(r, "Variable"), norm(r, "Value")
        if k in want:
            if k == "Symbols":
                v = os.path.basename(str(v))
            print("  %-20s %s" % (k, v))
    print("\nnext: mem.py proc / inject / net / cmdline / plan")


def _procs():
    live = run("windows.pslist")
    scan = run("windows.psscan")
    by_pid = {}
    for r in live:
        pid = norm(r, "PID")
        by_pid[pid] = dict(r, _live=True)
    for r in scan:
        pid = norm(r, "PID")
        if pid in by_pid:
            by_pid[pid]["_scan"] = True
        else:
            by_pid[pid] = dict(r, _live=False, _scan=True)
    return by_pid


def cmd_proc(a):
    by_pid = _procs()
    pids = set(by_pid)
    interesting, noise = [], []
    for pid, r in sorted(by_pid.items(), key=lambda kv: kv[0] or 0):
        name = (norm(r, "ImageFileName") or "?")
        ppid = norm(r, "PPID")
        exit_t = norm(r, "ExitTime")
        flags = []
        if not r.get("_live"):
            flags.append("UNLINKED from pslist (psscan only)")
        if exit_t and str(exit_t) not in ("N/A", "None", ""):
            flags.append("EXITED %s" % exit_t)
        if ppid not in pids and ppid not in (0, None):
            flags.append("PARENT %s GONE" % ppid)
        row = (pid, ppid, name, norm(r, "CreateTime"), flags)
        (noise if is_os_proc(name) and not flags else interesting).append(row)

    print("=== processes worth looking at (%d) ===" % len(interesting))
    for pid, ppid, name, ct, flags in interesting:
        print("%-6s ppid=%-6s %-16s %s" % (pid, ppid, name, ct))
        for f in flags:
            print("       <== %s" % f)
    print("\n=== %d OS/benign processes hidden (names only) ===" % len(noise))
    print("   " + ", ".join(sorted({n for _, _, n, _, _ in noise})))
    print("\nA process hidden here had NO exit, NO unlink and a live parent.")
    print("Anything with a flag is shown above regardless of its name.")


# malfind's "MZ header" note fires on a zero-filled VAD that Windows 10 maps into
# many ordinary processes. Measured on great.vmem: 17 regions across 16 processes,
# including notepad++.exe, Taskmgr.exe, vmtoolsd.exe, explorer.exe and cmd.exe --
# all with the SAME dump. A real PE has "PE\0\0" at e_lfanew; this has nothing.
NOISE_DUMP_HEAD = "4d 5a 00 00 00 00 00 00"


def _is_zeroed_mz(hexdump):
    h = " ".join(str(hexdump or "").split())
    if not h.lower().startswith(NOISE_DUMP_HEAD):
        return False
    body = h.lower().replace(NOISE_DUMP_HEAD, "", 1)
    kept = [b for b in body.split() if b not in ("00", "d0")]
    return len(kept) <= 2


def cmd_inject(a):
    rows = run("windows.malware.malfind")
    real, suspect_noise = [], []
    for r in rows:
        hd = norm(r, "Hexdump", "hexdump") or ""
        # the JSON renderer gives Start VPN as an int; the vadinfo --address flag
        # below wants hex, so print hex and save the reader a conversion
        vpn = norm(r, "Start VPN")
        vpn = hex(vpn) if isinstance(vpn, int) else vpn
        rec = (norm(r, "PID"), norm(r, "Process"), vpn,
               norm(r, "Protection"), norm(r, "Notes", "Note") or "-",
               " ".join(str(hd).split())[:47])
        (suspect_noise if _is_zeroed_mz(hd) else real).append(rec)

    print("=== regions with actual content (%d) ===" % len(real))
    if not real:
        print("  none")
    for pid, proc, vpn, prot, note, hd in real:
        print("%-6s %-16s %-12s %-24s %-10s %s" % (pid, proc, vpn, prot, note, hd))

    print("\n=== zero-filled MZ-like regions, treated as noise (%d) ===" % len(suspect_noise))
    if suspect_noise:
        print("   processes: " + ", ".join(sorted({p for _, p, _, _, _, _ in suspect_noise})))
    print("""
Why the split: on Windows 10 the "MZ header" note fires on a zero-filled VAD that
is mapped into ordinary processes. Measured on great.vmem it hit notepad++.exe,
Taskmgr.exe, vmtoolsd.exe, explorer.exe and cmd.exe with an identical dump. An MZ
with no "PE\\0\\0" behind it is not a PE.

A region in the first list is NOT automatically injection either. RWX pages full of
real code are normal for a .NET/JIT process (SearchUI.exe, any CLR host) and for
tools that rewrite PEs. Confirm with: who owns the process, does its parent make
sense, and is there a matching file on disk. Then dump it and look:

   vol -f <image> -o <dir> windows.vadinfo --pid <pid> --dump --address <vpn>""")


def cmd_net(a):
    rows = run("windows.netscan")
    by_pid = _procs()
    hot, rest = [], []
    for r in rows:
        pid = norm(r, "PID")
        owner = norm(r, "Owner") or ""
        state = str(norm(r, "State") or "")
        rec = (norm(r, "Proto"), norm(r, "LocalAddr"), norm(r, "LocalPort"),
               norm(r, "ForeignAddr"), norm(r, "ForeignPort"), state, pid, owner,
               norm(r, "Created"))
        p = by_pid.get(pid, {})
        odd = (not is_os_proc(owner)) or state.upper() in ("ESTABLISHED", "SYN_SENT") \
              or not p.get("_live", True)
        (hot if odd else rest).append(rec)

    for label, group in (("non-system / established", hot), ("system listeners", rest)):
        print("\n=== %s (%d) ===" % (label, len(group)))
        for proto, la, lp, fa, fp, st, pid, own, ct in group[:40]:
            print("%-6s %-24s:%-6s -> %-24s:%-6s %-12s %-6s %-14s %s"
                  % (proto, la, lp, fa, fp, st, pid, own, ct))
        if len(group) > 40:
            print("   ... %d more" % (len(group) - 40))
    if not hot:
        print("\nNo established connection and nothing owned by a non-system process.")
        print("That is weak evidence: the image is one instant. The C2 may have been")
        print("contacted before or after it, or never answered.")


def cmd_cmdline(a):
    rows = run("windows.cmdline")
    by_pid = _procs()
    print("=== command lines (non-system, or flagged) ===")
    for r in rows:
        pid, proc = norm(r, "PID"), norm(r, "Process") or ""
        args = norm(r, "Args") or "-"
        p = by_pid.get(pid, {})
        flagged = (not p.get("_live", True)) or (
            norm(p, "ExitTime") and str(norm(p, "ExitTime")) not in ("N/A", "None", ""))
        if is_os_proc(proc) and not flagged:
            continue
        print("%-6s %-16s %s" % (pid, proc, args))
        if str(args).strip() == "-":
            print("       <== no command line recoverable (scrubbed, or never had one)")


def cmd_plan(a):
    img = image()
    print("=" * 78)
    print("MEMORY ANALYSIS WALKTHROUGH  --  %s" % os.path.basename(img))
    print("=" * 78)
    info = {norm(r, "Variable"): norm(r, "Value") for r in run("windows.info")}
    print("""
STEP 1  Image identity                                   [MEMORY/environment]
  image     : %s
  size      : %d bytes
  OS        : %s  (Is64Bit=%s  IsPAE=%s)
  captured  : %s
  -> no screenshot needed; copy into the report

STEP 2  Rogue processes                                  [MEMORY/rogue processes]
  python host/mem.py proc
  Screenshot the flagged block. What matters is not an odd name but an odd
  SHAPE: exited, unlinked from pslist, or a parent that no longer exists.

STEP 3  Command lines                                    [MEMORY/rogue processes]
  python host/mem.py cmdline
  A process whose command line is "-" while its siblings have one is worth a
  note. A cmd.exe running a .bat out of %%TEMP%% is a self-delete, nearly always.

STEP 4  Code injection                                   [MEMORY/code injection]
  python host/mem.py inject
  Read the noise warning before citing anything. Then dump the region and
  confirm it is a PE before calling it injection.

STEP 5  Network artifacts                                [MEMORY/network artifacts]
  python host/mem.py net
  Memory holds sockets the live monitors missed, including for dead processes.

STEP 6  Correlate with the timeline
  Line up CreateTime / ExitTime against the image's own capture time. A parent
  that exits exactly when a child starts is a handoff, not a coincidence.

STEP 7  Write it up                                      [ANALYSIS SUMMARY]
  Every claim cites a PID plus an offset or a timestamp. Say which plugin
  produced it -- psscan and pslist disagreeing IS the finding, not a problem.
""" % (img, os.path.getsize(img), info.get("NTBuildLab"), info.get("Is64Bit"),
       info.get("IsPAE"), info.get("SystemTime")))


CMDS = {"info": cmd_info, "proc": cmd_proc, "inject": cmd_inject,
        "net": cmd_net, "cmdline": cmd_cmdline, "plan": cmd_plan}


def main(argv):
    args = list(argv[1:])
    if "--image" in args:
        i = args.index("--image")
        os.environ["MEM_IMAGE"] = args[i + 1]
        del args[i:i + 2]
    if not args or args[0] not in CMDS:
        print(__doc__)
        print("commands: %s" % ", ".join(sorted(CMDS)))
        return 2
    return CMDS[args[0]](args[1:]) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

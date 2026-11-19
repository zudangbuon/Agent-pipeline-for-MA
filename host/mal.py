#!/usr/bin/env python3
"""
mal.py -- host-side orchestrator. The agent drives the analysis VM through this,
never through raw vmrun, so the safety rails always apply.

  python mal.py vms                       list VMs / snapshots / power state
  python mal.py check                     verify every precondition, change nothing
  python mal.py snapshot-clean [name]     create the clean baseline snapshot
  python mal.py revert [name]             revert to the clean snapshot
  python mal.py setup-guest [--no-fakenet]
                                          push detonate.ps1 (+ FakeNet) into the guest
  python mal.py shell <cmd> [args...]     run a program in the guest (debugging)
  python mal.py shot [out.png]            screenshot the VM console
  python mal.py push <hostfile> <guestpath>
  python mal.py pull <guestpath> <hostdir>
  python mal.py static <sample>           RETIRED -- static runs on the host, see below
  python mal.py detonate <sample> [--timeout N] [--mode basic|full]

Rails enforced in code, not in prose:
  * detonate refuses to run without the clean snapshot
  * detonate refuses if the VM has a bridged/NAT (internet-reachable) NIC
  * detonate refuses if HGFS shared folders are enabled -- a revert cannot undo
    what the guest wrote to the host through a share
  * detonate ALWAYS reverts afterwards, including on error or Ctrl-C, and the
    revert is VERIFIED (see revert_verified) instead of assumed
  * pull refuses extensions outside the allowlist and files over the size cap,
    so a sample or dropped payload cannot be carried back to the host
  * nothing here ever executes a sample on the host

`static` is retired: it drove IDA in the guest, which has no IDAPython. Static
analysis runs on the host -- host/ghidra_dump.py + host/pe_meta.py.
"""
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "out")
VMDIR = os.path.join(ROOT, "vm")
CFG_PATH = os.environ.get("MAL_CONFIG") or os.path.join(HERE, "config.json")


# --------------------------------------------------------------------- plumbing
def cfg():
    with open(CFG_PATH, encoding="utf-8") as fh:
        c = json.load(fh)
    c["guest_user"] = os.environ.get("GUEST_USER") or c.get("guest_user") or ""
    c["guest_pass"] = os.environ.get("GUEST_PASS") or c.get("guest_pass") or ""
    return c


def die(msg, code=2):
    print("REFUSED: %s" % msg if code == 3 else "ERROR: %s" % msg, file=sys.stderr)
    sys.exit(code)


def audit(line):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "audit.log"), "a", encoding="utf-8") as fh:
        fh.write("%s  %s\n" % (dt.datetime.now().isoformat(timespec="seconds"), line))


def vmrun(c, *args, creds=False, timeout=600, check=True, quiet=False):
    cmd = [c["vmrun"], "-T", "ws"]
    if creds:
        if not c["guest_user"]:
            die("guest credentials missing -- set GUEST_USER and GUEST_PASS in the environment")
        cmd += ["-gu", c["guest_user"], "-gp", c["guest_pass"]]
    cmd += list(args)
    shown = [("***" if cmd[i - 1] == "-gp" else a) for i, a in enumerate(cmd)]
    if not quiet:
        print("  $ %s" % " ".join(('"%s"' % s if " " in s else s) for s in shown[3:] if s))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        die("vmrun timed out after %ss: %s" % (timeout, " ".join(shown[3:])))
    out = (p.stdout or "") + (p.stderr or "")
    if check and p.returncode != 0:
        die("vmrun failed (%d): %s" % (p.returncode, out.strip()))
    return out.strip()


def sha256_file(path):
    """Hashing reads bytes; it never executes. Safe on the host."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_vmx(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def nic_types(vmx_text):
    out = {}
    for m in re.finditer(r'^ethernet(\d+)\.connectionType\s*=\s*"([^"]+)"',
                         vmx_text, re.I | re.M):
        out["ethernet%s" % m.group(1)] = m.group(2).lower()
    present = set(m.group(1) for m in re.finditer(
        r'^ethernet(\d+)\.present\s*=\s*"TRUE"', vmx_text, re.I | re.M))
    return {k: v for k, v in out.items() if k.replace("ethernet", "") in present}


def snapshots(c):
    txt = vmrun(c, "listSnapshots", c["vmx"], quiet=True)
    names = []
    for line in txt.splitlines()[1:]:
        if line.strip():
            names.append(line.strip())
    return names


def is_running(c):
    txt = vmrun(c, "list", quiet=True)
    return os.path.normcase(c["vmx"]) in os.path.normcase(txt)


def ensure_running(c, gui=True):
    if not is_running(c):
        print("[*] starting VM")
        vmrun(c, "start", c["vmx"], "gui" if gui else "nogui", timeout=300)
        print("[*] waiting for VMware Tools")
        vmrun(c, "runProgramInGuest", c["vmx"],
              "C:\\Windows\\System32\\cmd.exe", "/c", "exit",
              creds=True, timeout=300, check=False, quiet=True)


def guest_mkdir(c, path):
    vmrun(c, "createDirectoryInGuest", c["vmx"], path, creds=True, check=False, quiet=True)


def screenshot(c, dest):
    """Screenshot the console. vmcli's MKS module needs NO guest credentials, which
    makes it the only way to see inside the VM before a guest login is usable.
    vmrun's captureScreen is a guest operation and does need credentials."""
    os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
    if os.path.exists(dest):
        try:
            os.remove(dest)
        except OSError:
            pass
    vmcli = c.get("vmcli")
    if vmcli and os.path.isfile(vmcli):
        subprocess.run([vmcli, c["vmx"], "MKS", "captureScreenshot", os.path.abspath(dest)],
                       capture_output=True, text=True, timeout=120)
        if os.path.exists(dest):
            return True
    if c["guest_user"]:
        vmrun(c, "captureScreen", c["vmx"], os.path.abspath(dest),
              creds=True, check=False, quiet=True)
    return os.path.exists(dest)



def shared_folders(vmx_text):
    """[(hostPath, writable)] for every sharedFolderN entry in the .vmx."""
    paths, write = {}, {}
    for m in re.finditer(r'^sharedFolder(\d+)\.hostPath\s*=\s*"([^"]*)"',
                         vmx_text, re.I | re.M):
        paths[m.group(1)] = m.group(2)
    for m in re.finditer(r'^sharedFolder(\d+)\.writeAccess\s*=\s*"([^"]*)"',
                         vmx_text, re.I | re.M):
        write[m.group(1)] = m.group(2).strip().upper() == "TRUE"
    return [(paths[k], write.get(k, False)) for k in sorted(paths, key=int)]


def touches_analysis_tree(host_path):
    """Does this host path reach the pipeline, its artifacts or the report?

    True if it IS the tree, is inside it, or CONTAINS it -- a share on the drive
    root reaches the coursework just as well as one aimed straight at it.
    """
    if not host_path:
        return False
    # .lower() rather than relying on normcase alone: these checks are also run from
    # a non-Windows shell, where normcase is the identity and a lowercase hostPath
    # would silently stop matching.
    a = os.path.normcase(host_path).replace("\\", "/").rstrip("/").lower()
    b = os.path.normcase(os.path.abspath(ROOT)).replace("\\", "/").rstrip("/").lower()
    if not a:
        return False
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def revert_verified(c, name=None):
    """Revert to a snapshot and PROVE the revert happened.

    Returns True only when vmrun exited 0, said nothing error-shaped, and the
    snapshot is still there afterwards.

    Rule 4 ("dynamic analysis always reverts") is only as strong as this function.
    The mandatory revert runs inside a `finally`, where a helper that raises would
    mask the original failure, so it cannot use vmrun(check=True). The earlier
    version passed check=False and then set `reverted = True` unconditionally, so a
    revert that failed with a non-zero exit code logged `reverted=True` and never
    printed REVERT FAILED -- the single outcome this rail exists to make loud.
    """
    name = name or c["clean_snapshot"]
    cmd = [c["vmrun"], "-T", "ws", "revertToSnapshot", c["vmx"], name]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        print("    revert timed out after 600s", file=sys.stderr)
        return False
    except OSError as e:
        print("    revert could not be launched: %s" % e, file=sys.stderr)
        return False
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    if p.returncode != 0:
        print("    vmrun exited %d: %s" % (p.returncode, out or "(no output)"),
              file=sys.stderr)
        return False
    # vmrun can exit 0 while declining the operation, so read what it actually said.
    if out and re.search(r"\b(error|unable|cannot|could not|failed|failure)\b", out, re.I):
        print("    vmrun exited 0 but reported: %s" % out, file=sys.stderr)
        return False
    try:
        snaps = snapshots(c)
    except SystemExit:
        print("    could not list snapshots after the revert -- unverified",
              file=sys.stderr)
        return False
    if name not in snaps:
        print("    snapshot %r is gone after the revert (have: %s)"
              % (name, ", ".join(snaps) or "none"), file=sys.stderr)
        return False
    return True

# ----------------------------------------------------------------------- checks
def verify_isolation(c):
    """Return (ok, findings). Never auto-fixes -- the human decides."""
    findings, ok = [], True
    vmx = read_vmx(c["vmx"])
    nics = nic_types(vmx)
    allowed = set(t.lower() for t in c["allowed_net_types"])
    if not nics:
        findings.append(("ok", "no NIC present -- fully air-gapped"))
    for name, t in sorted(nics.items()):
        if t in allowed:
            findings.append(("ok", "%s = %s (isolated)" % (name, t)))
        else:
            ok = False
            findings.append(("FAIL", "%s = %s -- can reach the internet; "
                                     "set it to hostonly before detonating" % (name, t)))
    shares = shared_folders(vmx)
    if re.search(r'^isolation\.tools\.hgfs\.disable\s*=\s*"TRUE"', vmx, re.I | re.M):
        findings.append(("ok", "shared folders (HGFS) disabled%s"
                         % (" (%d sharedFolder entry/entries remain in the .vmx but are "
                            "inert)" % len(shares) if shares else "")))
    else:
        # A share is the one containment hole a revert cannot close: the files live on
        # the HOST, so reverting the guest does not undo what the guest wrote through
        # it. This .vmx shipped exactly that twice, aimed at this coursework tree, and
        # detonations ran against notes that claimed HGFS was off. FAIL, not warn.
        ok = False
        findings.append(("FAIL", 'isolation.tools.hgfs.disable is not "TRUE" -- the guest '
                                 "can write to the host through HGFS and a snapshot revert "
                                 "does NOT undo that. Add it to the .vmx (VM powered off)."))
        for path, writable in shares:
            lvl = "FAIL" if (writable or touches_analysis_tree(path)) else "warn"
            why = []
            if writable:
                why.append("WRITABLE")
            if touches_analysis_tree(path):
                why.append("reaches the analysis tree %s -- a sample could encrypt or "
                           "alter the pipeline, the artifacts and the report" % ROOT)
            findings.append((lvl, 'share hostPath="%s"%s'
                             % (path, " [" + "; ".join(why) + "]" if why else "")))
    for key, label in [("isolation.tools.copy.disable", "clipboard copy"),
                       ("isolation.tools.paste.disable", "clipboard paste"),
                       ("isolation.tools.dnd.disable", "drag-and-drop")]:
        if re.search(r'^%s\s*=\s*"TRUE"' % re.escape(key), vmx, re.I | re.M):
            findings.append(("ok", "%s disabled" % label))
        else:
            findings.append(("warn", "%s not disabled (add %s = \"TRUE\" to the .vmx)"
                             % (label, key)))
    snaps = snapshots(c)
    if c["clean_snapshot"] in snaps:
        findings.append(("ok", "clean snapshot %r exists" % c["clean_snapshot"]))
    else:
        ok = False
        findings.append(("FAIL", "no snapshot named %r (have: %s) -- run "
                                 "`mal.py snapshot-clean` from a known-good state"
                         % (c["clean_snapshot"], ", ".join(snaps) or "none")))
    m = re.search(r'^numvcpus\s*=\s*"(\d+)"', vmx, re.I | re.M)
    if m and int(m.group(1)) < 2:
        findings.append(("warn", "numvcpus = %s -- many samples treat a single core as "
                                 "a sandbox tell and stay dormant; 2+ is better" % m.group(1)))
    return ok, findings


def cmd_check(c, a):
    print("vmx        : %s" % c["vmx"])
    print("running    : %s" % is_running(c))
    print("creds      : %s" % ("set (GUEST_USER=%s)" % c["guest_user"] if c["guest_user"]
                               else "MISSING -- set GUEST_USER / GUEST_PASS"))
    print("snapshots  : %s" % (", ".join(snapshots(c)) or "none"))
    print()
    ok, findings = verify_isolation(c)
    for level, msg in findings:
        print("  [%-4s] %s" % (level, msg))
    print()
    print("detonate allowed: %s" % ("YES" if ok and c["guest_user"] else "NO"))
    return 0 if ok else 1


def cmd_vms(c, a):
    print("=== running ===")
    print(vmrun(c, "list", quiet=True))
    print("\n=== configured vm ===")
    print(c["vmx"])
    print("snapshots: %s" % (", ".join(snapshots(c)) or "none"))


# ------------------------------------------------------------------- snapshots
def cmd_snapshot_clean(c, a):
    name = a[0] if a else c["clean_snapshot"]
    if name in snapshots(c):
        die("snapshot %r already exists -- delete it in the VMware UI if you really "
            "want to re-baseline" % name, 3)
    print("[*] creating snapshot %r" % name)
    print("    This becomes the state every detonation reverts to. Make sure the guest")
    print("    is clean, patched the way you want, and has your tooling installed.")
    vmrun(c, "snapshot", c["vmx"], name, timeout=600)
    audit("snapshot-clean %s" % name)
    print("[+] done. snapshots: %s" % ", ".join(snapshots(c)))


def cmd_revert(c, a):
    name = a[0] if a else c["clean_snapshot"]
    if name not in snapshots(c):
        die("no snapshot named %r" % name)
    print("[*] reverting to %r" % name)
    ok = revert_verified(c, name)
    audit("revert %s verified=%s" % (name, ok))
    if not ok:
        die("revert to %r could not be VERIFIED -- treat the VM as dirty and revert it "
            "by hand in the VMware UI" % name)
    print("[+] reverted (verified)")


# ------------------------------------------------------------- file transfer
def cmd_push(c, a):
    if len(a) < 2:
        die("usage: mal.py push <hostfile> <guestpath>")
    src, dst = a[0], a[1]
    if not os.path.isfile(src):
        die("no such file: %s" % src)
    ensure_running(c)
    guest_mkdir(c, os.path.dirname(dst) or c["guest_root"])
    vmrun(c, "copyFileFromHostToGuest", c["vmx"], os.path.abspath(src), dst, creds=True)
    audit("push %s -> %s" % (src, dst))
    print("[+] pushed %s -> %s" % (src, dst))


def _pull_one(c, gpath, hostdir, fatal=True, skipped=None):
    """Pull one guest file subject to the extension allowlist and size cap.

    fatal=True  -- an explicit `mal.py pull`: refusing is the whole point.
    fatal=False -- bulk collection after a detonation: a single oversized or
                   disallowed artifact must not throw away every other artifact
                   from a run that cannot be repeated cheaply. Skip it, record why.
    """
    def refuse(msg):
        if skipped is not None:
            skipped.append((os.path.basename(gpath), msg))
        if fatal:
            die(msg, 3)
        print("  [skip] %s -- %s" % (os.path.basename(gpath), msg))
        return None

    ext = os.path.splitext(gpath)[1].lower()
    allow = set(x.lower() for x in c["pull_allow_ext"])
    if ext not in allow:
        return refuse("extension %r not in pull_allow_ext %s (rail: no binary may "
                      "reach the host)" % (ext, sorted(allow)))
    os.makedirs(hostdir, exist_ok=True)
    dest = os.path.join(hostdir, os.path.basename(gpath))
    vmrun(c, "copyFileFromGuestToHost", c["vmx"], gpath, dest, creds=True,
          check=False, quiet=True)
    if not os.path.exists(dest):
        return None
    mb = os.path.getsize(dest) / (1024 * 1024)
    if mb > c["pull_max_mb"]:
        os.remove(dest)
        return refuse("%.1f MB exceeds the %s MB cap -- deleted" % (mb, c["pull_max_mb"]))
    return dest


def cmd_pull(c, a):
    if len(a) < 2:
        die("usage: mal.py pull <guestpath> <hostdir>")
    ensure_running(c)
    got = _pull_one(c, a[0], a[1])
    if not got:
        die("nothing pulled -- does %s exist in the guest?" % a[0])
    audit("pull %s -> %s" % (a[0], got))
    print("[+] %s (%d bytes)" % (got, os.path.getsize(got)))


def guest_listdir(c, gdir):
    txt = vmrun(c, "listDirectoryInGuest", c["vmx"], gdir, creds=True,
                check=False, quiet=True)
    names = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("directory list"):
            continue
        names.append(line)
    return names


def pull_dir(c, gdir, hostdir, label=""):
    names = guest_listdir(c, gdir)
    allow = set(x.lower() for x in c["pull_allow_ext"])
    got, skipped = [], 0
    for n in names:
        if os.path.splitext(n)[1].lower() not in allow:
            skipped += 1
            continue
        d = _pull_one(c, gdir.rstrip("\\") + "\\" + n, hostdir)
        if d:
            got.append(d)
    print("[+] %s: pulled %d file(s)%s" % (label or gdir, len(got),
          (", skipped %d non-allowlisted" % skipped) if skipped else ""))
    return got


# ----------------------------------------------------------------- guest setup
def fakenet_zip(c):
    """Host-side FakeNet-NG bundle, or None."""
    p = c.get("fakenet_zip") or os.path.join(ROOT, "vendor", "fakenet3.5.zip")
    return p if os.path.isfile(p) else None


def install_fakenet(c):
    """Push FakeNet-NG into the guest and unpack it there.

    detonate reverts FIRST and calls setup-guest SECOND, so everything installed
    here survives the revert. That is the hook for guest tooling -- `clean-nodefender`
    is the one known-good baseline and must not be retaken just to add a tool.

    Without FakeNet the guest's DNS and TCP go nowhere, `--mode full` records
    fakenet=False, and the template's Network Artifacts row has no C2 host to report.
    """
    zp = fakenet_zip(c)
    if not zp:
        print("[!] no FakeNet bundle on the host (expected %s)"
              % os.path.join(ROOT, "vendor", "fakenet3.5.zip"))
        print("    --mode full will run WITHOUT a fake internet: connections just fail "
              "and no C2 host is recoverable.")
        return False
    root = c["guest_root"]
    gzip_path = root + "\\tools\\fakenet.zip"
    gtools = root + "\\tools"
    installer = os.path.join(VMDIR, "install_fakenet.ps1")
    if not os.path.isfile(installer):
        print("[!] missing %s -- skipping FakeNet install" % installer)
        return False
    print("[*] installing FakeNet-NG in the guest (%.1f MB)"
          % (os.path.getsize(zp) / (1024.0 * 1024.0)))
    guest_mkdir(c, gtools)
    vmrun(c, "copyFileFromHostToGuest", c["vmx"], os.path.abspath(zp), gzip_path,
          creds=True, quiet=True)
    vmrun(c, "copyFileFromHostToGuest", c["vmx"], installer,
          root + "\\install_fakenet.ps1", creds=True, quiet=True)
    # The installer writes tools\fakenet_path.txt only on success; detonate.ps1 reads
    # that marker, so a failed install degrades to fakenet=False instead of pretending.
    vmrun(c, "runProgramInGuest", c["vmx"], "-interactive", c["guest_python"],
          "-ExecutionPolicy", "Bypass", "-File", root + "\\install_fakenet.ps1",
          "-Zip", gzip_path, "-Dest", gtools,
          creds=True, timeout=600, check=False, quiet=True)
    marker = guest_listdir(c, gtools)
    ok = any(n.lower() == "fakenet_path.txt" for n in marker)
    print("    %s" % ("[+] FakeNet staged under %s" % gtools if ok else
                      "[!] FakeNet install produced no fakenet_path.txt -- detonate will "
                      "report fakenet=False (see detonate.log)"))
    return ok


def cmd_setup_guest(c, a):
    # FakeNet is ~8 MB to push plus an in-guest unpack, and detonate calls this on every
    # run. Only a --mode full run can use it, so basic runs skip it and stay quick.
    want_fakenet = ("--no-fakenet" not in (a or [])) and c.get("install_fakenet", True)
    ensure_running(c)
    root = c["guest_root"]
    for d in [root, root + "\\samples", root + "\\out", root + "\\dyn",
              root + "\\tools"]:
        guest_mkdir(c, d)
    # Only detonate.ps1 goes in. vm/run_triage.ps1 and vm/dump_static.py are dead --
    # IDA Freeware 7.0 has no IDAPython at any version -- and pushing them every run just
    # put two unusable scripts next to a live sample.
    for fn in ["detonate.ps1"]:
        src = os.path.join(VMDIR, fn)
        if not os.path.isfile(src):
            print("[!] missing %s -- skipped" % src)
            continue
        vmrun(c, "copyFileFromHostToGuest", c["vmx"], src, root + "\\" + fn,
              creds=True, quiet=True)
        print("[+] %s -> %s\\%s" % (fn, root, fn))
    if want_fakenet:
        install_fakenet(c)
    else:
        print("[*] skipping FakeNet (basic mode or --no-fakenet): no fake internet, so "
              "a C2 host is not recoverable from this run")
    audit("setup-guest fakenet=%s" % want_fakenet)
    print("\n[*] guest ready. Procmon must be in the baseline snapshot; FakeNet is "
          "pushed on every run by the call above.")


def cmd_shell(c, a):
    if not a:
        die("usage: mal.py shell <program> [args...]")
    ensure_running(c)
    out = vmrun(c, "runProgramInGuest", c["vmx"], "-interactive", a[0], *a[1:],
                creds=True, check=False)
    print(out or "(no output -- vmrun does not capture guest stdout; "
                 "write to a file and pull it)")


def cmd_shot(c, a):
    ensure_running(c)
    dest = os.path.abspath(a[0]) if a else os.path.join(OUT, "screen.png")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if screenshot(c, dest):
        print("[+] %s" % dest)
    else:
        die("screenshot failed -- is the VM powered on?")


# --------------------------------------------------------------------- static
def cmd_static(c, a):
    """Retired. Kept as a command so it fails loudly instead of being rediscovered.

    It used to push the sample into the guest and drive IDA through run_triage.ps1.
    IDA Freeware 7.0 has no IDAPython, so that path could never work -- and it failed
    only after a 3600 s timeout, with a live sample already in the guest.
    """
    die("`mal.py static` is retired -- IDA Freeware in the guest has no IDAPython.\n"
        "        Static analysis runs ON THE HOST; Ghidra parses the sample, never runs it:\n"
        "          set JAVA_HOME=D:\\tools\\jdk\\jdk-25.0.5+8\n"
        "          set GHIDRA_INSTALL_DIR=D:\\tools\\ghidra\\ghidra_12.2_PUBLIC\n"
        "          python host\\ghidra_dump.py <sample> out\\static\\<tag>\n"
        "          python host\\pe_meta.py <sample> --json out\\static\\<tag>\\pe_meta.json\n"
        "        then:\n"
        "          set TRIAGE_OUT=out\\static\\<tag>  &&  python host\\q.py summary\n"
        "        pe_meta.py is not optional: without it the packing verdict is measured\n"
        "        over Ghidra's zero-padded blocks and a packed sample reads as clean.", 3)


# -------------------------------------------------------------------- dynamic
def cmd_detonate(c, a):
    args, sample, timeout, mode = list(a), None, c["detonate_timeout_sec"], "basic"
    in_guest, elevated, in_place, zip_password = False, False, None, None
    dll_export, sample_args = None, None
    i = 0
    while i < len(args):
        if args[i] == "--timeout":
            timeout = int(args[i + 1]); i += 2
        elif args[i] == "--mode":
            mode = args[i + 1]; i += 2
        elif args[i] == "--elevated":
            elevated = True; i += 1
        elif args[i] == "--zip-password":
            zip_password = args[i + 1]; i += 2
        elif args[i] == "--dll-export":
            dll_export = args[i + 1]; i += 2
        elif args[i] == "--sample-args":
            # A sample gated on argv looks exactly like an inert one. Lab01-01.exe
            # needs argv[1] == "WARNING_THIS_WILL_DESTROY_YOUR_MACHINE".
            sample_args = args[i + 1]; i += 2
        elif args[i] == "--in-place":
            in_place = True; i += 1
        elif args[i] == "--copy":
            in_place = False; i += 1
        elif args[i] == "--guest-sample":
            # sample already lives inside the VM (e.g. the course lab collection);
            # nothing is pushed, and no sample byte ever touches the host
            sample, in_guest = args[i + 1], True; i += 2
        elif args[i] == "--yes":
            i += 1
        else:
            sample = args[i]; i += 1
    if not sample:
        die("usage: mal.py detonate (<hostfile> | --guest-sample <guestpath>) "
            "[--timeout N] [--mode basic|full] [--elevated] [--in-place] "
            "[--sample-args <argv>] [--dll-export <name>] [--zip-password <pw>]")
    if not in_guest and not os.path.isfile(sample):
        die("no such file: %s\n        (if the sample is already inside the VM, "
            "use --guest-sample \"C:\\\\path\\\\in\\\\guest.exe\")" % sample)
    if mode not in ("basic", "full"):
        die("--mode must be basic or full")
    # A sample already in the guest sits next to its companion files (PMA labs ship
    # an .exe beside its .dll), so running it where it lies is the right default.
    if in_place is None:
        in_place = in_guest

    # ---- rails, before anything moves
    ok, findings = verify_isolation(c)
    if not ok:
        print("Preconditions not met:", file=sys.stderr)
        for level, msg in findings:
            if level == "FAIL":
                print("  [FAIL] %s" % msg, file=sys.stderr)
        die("refusing to detonate", 3)
    for level, msg in findings:
        if level == "warn":
            print("  [warn] %s" % msg)

    root = c["guest_root"]
    if in_guest:
        # hashing happens in the guest; detonate.ps1 records it in summary.json
        sha = None
        base = os.path.basename(sample.replace("\\", "/")) or "sample"
        tag = re.sub(r"[^A-Za-z0-9_.-]", "_", base)[:40]
        gsample = sample
    else:
        sha = sha256_file(sample)
        tag = sha[:12]
        gsample = "%s\\samples\\%s.bin" % (root, tag)
    gdyn = "%s\\dyn\\%s" % (root, tag)
    # One directory per run. Reusing a per-sample directory silently mixes fresh
    # artifacts with leftovers from an earlier run, which reads as real results.
    run_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    hostdir = os.path.join(OUT, "dynamic", "%s-%s" % (tag, run_id))

    print("\n[*] sample  : %s%s" % (sample, "  (already in guest)" if in_guest else ""))
    print("[*] sha256  : %s" % (sha or "(computed in guest)"))
    print("[*] mode    : %s   timeout: %ss   in-place: %s   elevated: %s"
          % (mode, timeout, in_place, elevated))
    if sample_args:
        print("[*] args    : %r" % sample_args)
    print("[*] the VM WILL be reverted to %r when this finishes" % c["clean_snapshot"])
    audit("detonate START %s (%s) mode=%s timeout=%s" % (tag, sha or "in-guest", mode, timeout))

    reverted = False
    try:
        print("\n[*] reverting to a clean state before detonation")
        if not revert_verified(c):
            die("could not verify the revert to %r -- refusing to detonate on an "
                "unverified baseline" % c["clean_snapshot"], 3)
        ensure_running(c)
        cmd_setup_guest(c, [] if mode == "full" else ["--no-fakenet"])
        guest_mkdir(c, gdyn)

        if in_guest:
            print("[*] sample already in guest -- nothing pushed")
        else:
            print("[*] pushing sample")
            vmrun(c, "copyFileFromHostToGuest", c["vmx"], os.path.abspath(sample),
                  gsample, creds=True, quiet=True)

        print("[*] detonating -- guest monitors are running; this takes ~%ss" % (timeout + 40))
        extra = []
        if in_place:
            extra.append("-InPlace")
        if elevated:
            extra.append("-Elevated")
        if not in_place:
            # The sample is stored in the guest as .bin; tell the guest what extension
            # to restore at launch, or a script sample is simply not executable.
            orig_ext = os.path.splitext(sample)[1]
            if orig_ext:
                extra += ["-LaunchExt", orig_ext]
        if zip_password:
            extra += ["-ZipPassword", zip_password]
        if dll_export:
            extra += ["-DllExport", dll_export]
        if sample_args:
            extra += ["-SampleArgs", sample_args]
        vmrun(c, "runProgramInGuest", c["vmx"], "-interactive", c["guest_python"],
              "-ExecutionPolicy", "Bypass", "-File", root + "\\detonate.ps1",
              "-Sample", gsample, "-Out", gdyn, "-Mode", mode,
              "-TimeoutSec", str(timeout), *extra,
              creds=True, timeout=timeout + 900, check=False)

        os.makedirs(hostdir, exist_ok=True)
        print("[*] collecting text artifacts (binaries are blocked by the pull rail)")
        skipped = []
        got = []
        for f in ["summary.json", "procmon.csv", "fakenet.log", "network.json",
                  "processes.json", "files.json", "registry.json", "dropped.json",
                  "dropped_text.json", "autoruns.json", "procmon_dropped.json",
                  "detonate.log"]:
            if _pull_one(c, gdyn + "\\" + f, hostdir, fatal=False, skipped=skipped):
                got.append(f)
        print("    collected: %s" % (", ".join(got) or "nothing"))
        if skipped:
            with open(os.path.join(hostdir, "SKIPPED.txt"), "w", encoding="utf-8") as fh:
                for name, why in skipped:
                    fh.write("%s: %s\n" % (name, why))
        screenshot(c, os.path.join(hostdir, "screen.png"))
        with open(os.path.join(hostdir, "sample.txt"), "w", encoding="utf-8") as fh:
            fh.write("original_name: %s\nsource: %s\nsha256: %s\nmode: %s\ntimeout: %s\n"
                     % (os.path.basename(sample.replace("\\", "/")),
                        "in-guest" if in_guest else sample,
                        sha or "see summary.json (hashed in guest)", mode, timeout))
    finally:
        print("\n[*] reverting VM (mandatory, runs even on error)")
        reverted = revert_verified(c)
        audit("detonate END %s reverted=%s" % (tag, reverted))
        if not reverted:
            print("!!! REVERT FAILED -- treat the VM as infected. Do not reuse it. "
                  "Revert manually in the VMware UI before anything else.", file=sys.stderr)

    print("\n[+] artifacts: %s" % hostdir)
    print("    query with:  python host\\dyn.py --dir %s summary" % hostdir)


CMDS = {
    "vms": cmd_vms, "check": cmd_check, "snapshot-clean": cmd_snapshot_clean,
    "revert": cmd_revert, "setup-guest": cmd_setup_guest, "shell": cmd_shell,
    "shot": cmd_shot, "push": cmd_push, "pull": cmd_pull,
    "static": cmd_static, "detonate": cmd_detonate,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0)
    name = sys.argv[1]
    if name not in CMDS:
        print(__doc__)
        die("unknown command %r" % name)
    conf = cfg()
    if not os.path.isfile(conf["vmrun"]):
        die("vmrun not found at %s" % conf["vmrun"])
    if not os.path.isfile(conf["vmx"]):
        die("vmx not found at %s" % conf["vmx"])
    rc = CMDS[name](conf, sys.argv[2:])
    sys.exit(rc or 0)

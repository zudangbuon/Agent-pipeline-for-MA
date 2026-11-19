"""Synthetic dynamic artifacts to smoke-test host/dyn.py."""
import json, os, sys, csv

d = sys.argv[1]
os.makedirs(d, exist_ok=True)


def w(name, obj):
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1)


w("summary.json", {
    "sample": r"C:\triage\samples\deadbeefcafe.bin", "mode": "full", "timeout_sec": 120,
    "launch_error": None, "is_pe": True, "launched_pid": 4812,
    "procmon": True, "fakenet": True,
    "counts": {"dropped_new": 3, "dropped_modified": 1, "deleted": 0, "reg_new": 2,
               "reg_changed": 1, "new_processes": 3, "new_services": 1, "new_tasks": 1,
               "tcp_endpoints": 2, "dns_names": 2},
    "killed_pids": [4812, 5120], "finished": "2026-11-06T10:00:00"})

w("processes.json", [
    {"pid": 4812, "ppid": 3300, "name": "sample.exe",
     "path": r"C:\triage\dyn\deadbeefcafe\run\sample.exe", "cmdline": r'"...\run\sample.exe"'},
    {"pid": 5120, "ppid": 4812, "name": "svchost.exe",
     "path": r"C:\Users\lab\AppData\Roaming\svchost.exe", "cmdline": r'"...\Roaming\svchost.exe" -k netsvc'},
    {"pid": 5300, "ppid": 4812, "name": "cmd.exe",
     "path": r"C:\Windows\System32\cmd.exe",
     "cmdline": "cmd.exe /c vssadmin delete shadows /all /quiet"}])

w("dropped.json", [
    {"path": r"C:\Users\lab\AppData\Roaming\svchost.exe", "size": 184320, "state": "new",
     "sha256": "b" * 64, "magic": "4d5a9000"},
    {"path": r"C:\Users\lab\AppData\Roaming\config.dat", "size": 512, "state": "new",
     "sha256": "c" * 64, "magic": "7b227569"},
    {"path": r"C:\Users\lab\AppData\Microsoft\Windows\Start Menu\Programs\Startup\upd.lnk",
     "size": 940, "state": "new", "sha256": "d" * 64, "magic": "4c000000"},
    {"path": r"C:\Users\lab\Documents\notes.txt", "size": 2048, "state": "modified",
     "sha256": "e" * 64, "magic": "48656c6c"}])

w("files.json", [{"path": r"C:\Users\lab\AppData\Roaming\svchost.exe", "size": 184320,
                  "sha256": "b" * 64}])

w("registry.json", {
    "new": [
        {"key": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run::Updater",
         "value": r"C:\Users\lab\AppData\Roaming\svchost.exe"},
        {"key": r"HKLM:\SYSTEM\CurrentControlSet\Services\NetSvcHelper", "value": "(subkey)"}],
    "changed": [
        {"key": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon::Shell",
         "before": "explorer.exe", "after": r"explorer.exe, C:\ProgramData\x.exe"}]})

w("network.json", {
    "endpoints": [
        {"remote": "185.0.113.42", "port": 443, "hits": 18, "first_seen_sec": 6, "pids": "5120"},
        {"remote": "10.0.0.5", "port": 8080, "hits": 4, "first_seen_sec": 44, "pids": "5120"}],
    "dns": [
        {"name": "cdn.evil-example.net", "data": "185.0.113.42", "type": "A"},
        {"name": "backup.evil-example.net", "data": "185.0.113.99", "type": "A"}],
    "raw_samples": [{"t": 6, "remote": "185.0.113.42", "port": 443, "state": "Established", "pid": 5120}]})

w("autoruns.json", {
    "new_services": [{"Name": "NetSvcHelper", "DisplayName": "Network Service Helper",
                      "PathName": r"C:\ProgramData\x.exe", "StartMode": "Auto", "State": "Running"}],
    "new_tasks": [{"Name": "UpdateCheck", "Path": "\\", "State": "Ready",
                   "Action": r"C:\Users\lab\AppData\Roaming\svchost.exe /silent"}],
    "deleted_files": []})

with open(os.path.join(d, "sample.txt"), "w", encoding="utf-8") as fh:
    fh.write("original_name: invoice.bin\nsha256: %s\nmode: full\ntimeout: 120\n" % ("a" * 64))

rows = [
    ("10:00:01.1", "sample.exe", "4812", "CreateFile", r"C:\Users\lab\AppData\Roaming\svchost.exe", "SUCCESS", "Overwrite"),
    ("10:00:01.3", "sample.exe", "4812", "WriteFile", r"C:\Users\lab\AppData\Roaming\svchost.exe", "SUCCESS", "Length: 184320"),
    ("10:00:02.0", "sample.exe", "4812", "RegSetValue", r"HKCU\...\CurrentVersion\Run\Updater", "SUCCESS", "Type: REG_SZ"),
    ("10:00:03.4", "svchost.exe", "5120", "TCP Connect", "185.0.113.42:443", "SUCCESS", "Length: 0"),
    ("10:00:05.9", "cmd.exe", "5300", "Process Create", r"C:\Windows\System32\vssadmin.exe", "SUCCESS", "PID: 5444"),
    ("10:00:07.2", "sample.exe", "4812", "QueryNameInformationFile", r"C:\triage\dyn\run\sample.exe", "SUCCESS", ""),
]
with open(os.path.join(d, "procmon.csv"), "w", encoding="utf-8", newline="") as fh:
    wr = csv.writer(fh)
    wr.writerow(["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"])
    wr.writerows(rows)

print("fake dynamic artifacts written to", d)

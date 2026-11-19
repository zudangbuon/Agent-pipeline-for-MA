#!/usr/bin/env python3
"""Decrypt brbbot's config -- on the host, without running the sample.

    python -I out/decrypt_brbconfig.py <brbbot.exe>          # from the PE resource
    python -I out/decrypt_brbconfig.py --raw <brbconfig.tmp> # from a dropped file

The key is compiled into the binary. FUN_140002940 (write) and FUN_140002c50 (read)
both derive it the same way:

    CryptCreateHash(hProv, 0x8003, 0, 0, &hHash)            // CALG_MD5
    CryptHashData(hHash, "YnJiYm90", 8, 0)                  // hardcoded passphrase
    CryptDeriveKey(hProv, 0x6801, hHash, 0x800000, &hKey)   // CALG_RC4, 128-bit

CryptDeriveKey with CALG_RC4 at 128 bits and an MD5 hash takes the whole 16-byte
digest, so the key is exactly MD5("YnJiYm90").

It PARSES. It never executes, never loads, never maps the sample as code.
"""
import sys, hashlib

PASSPHRASE = b"YnJiYm90"


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def config_resource(path):
    """Return (name, bytes) of the single CONFIG resource."""
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    img = pe.get_memory_mapped_image()
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tname = getattr(t, "name", None) or t.id
        for d in t.directory.entries:
            dname = getattr(d, "name", None) or d.id
            for l in d.directory.entries:
                off, sz = l.data.struct.OffsetToData, l.data.struct.Size
                return ("%s/%s rva=0x%x size=%d" % (tname, dname, off, sz),
                        img[off:off + sz])
    raise SystemExit("no resource directory in %s" % path)


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    if argv[1] == "--raw":
        if len(argv) < 3:
            raise SystemExit("--raw needs a file")
        label, blob = argv[2], open(argv[2], "rb").read()
    else:
        label, blob = config_resource(argv[1])

    key = hashlib.md5(PASSPHRASE).digest()
    plain = rc4(key, blob)

    print("source    : %s" % label)
    print("size      : %d bytes" % len(blob))
    print("sha256    : %s" % hashlib.sha256(blob).hexdigest().upper())
    print("cipher    : %s" % blob.hex())
    print("passphrase: %r" % PASSPHRASE)
    print("rc4 key   : %s   (= MD5 of the passphrase)" % key.hex())
    print("plaintext : %s" % plain.decode("ascii", "replace"))
    print()
    for field in plain.decode("ascii", "replace").rstrip(";").split(";"):
        if "=" in field:
            k, v = field.split("=", 1)
            print("  %-8s = %s" % (k, v))


if __name__ == "__main__":
    main(sys.argv)

#!/usr/bin/env python3
"""Test slot16 formulas against all verified nonzero observations."""
import json, os, sys, hashlib, hmac, struct

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# SM3 implementation
from _sm3 import sm3

# Load observations
data = json.load(open("slot16_newphone_verified.json", encoding="utf-8"))
k18 = bytes.fromhex(data["meta"]["k18_pskHash"])
device_id = data["meta"]["device_id"]
print(f"k18 = {k18.hex()}")
print(f"device_id = {device_id}")

# Extract nonzero slot16 observations
obs_list = []
for o in data["obs"]:
    s = o.get("slot16", "")
    if s == "00000000000000000000000000000000":
        continue
    # Extract _rticket from query
    import re
    m = re.search(r'_rticket=(\d+)', o["query"])
    if m:
        obs_list.append({
            "slot16": bytes.fromhex(s),
            "_rticket": m.group(1),
            "ts": re.search(r'ts=(\d+)', o["query"]).group(1) if re.search(r'ts=(\d+)', o["query"]) else None,
            "query": o["query"],
        })

print(f"Loaded {len(obs_list)} nonzero slot16 observations\n")

# Embedded keys from SO
# .data section (file offset 0x1ec960, 80 bytes = 5 x 16 bytes)
# .rodata section (file offset 0x17baa0, 32 bytes = 2 x 16 bytes)
so = open("bin/libmetasec_ov.so", "rb").read()

# K1-K5 at file offset 0x1ec960 (from findings)
K1 = so[0x1ec960:0x1ec960+16]
K2 = so[0x1ec960+16:0x1ec960+32]
K3 = so[0x1ec960+32:0x1ec960+48]
K4 = so[0x1ec960+48:0x1ec960+64]
K5 = so[0x1ec960+64:0x1ec960+80]

# K6-K7 at file offset 0x17baa0 (from findings)
K6 = so[0x17baa0:0x17baa0+16]
K7 = so[0x17baa0+16:0x17baa0+32]

# 32-byte key at 0x19b520
K32 = so[0x19b520:0x19b520+32]

print("Embedded keys:")
print(f"  K1 = {K1.hex()}")
print(f"  K2 = {K2.hex()}")
print(f"  K3 = {K3.hex()}")
print(f"  K4 = {K4.hex()}")
print(f"  K5 = {K5.hex()}")
print(f"  K6 = {K6.hex()}")
print(f"  K7 = {K7.hex()}")
print(f"  K32 = {K32.hex()}")
print()

# All keys to try
all_keys = [
    ("K1", K1), ("K2", K2), ("K3", K3), ("K4", K4), ("K5", K5),
    ("K6", K6), ("K7", K7), ("K32_first16", K32[:16]), ("K32_last16", K32[16:]),
    ("k18", k18),
]

def hmac_sm3(key, msg):
    return _hmac_generic(sm3, 64, key, msg)

def _hmac_generic(hfn, block, key, msg):
    if len(key) > block:
        key = hfn(key)
    key = key + b"\x00" * (block - len(key))
    o = bytes(k ^ 0x5c for k in key)
    i = bytes(k ^ 0x36 for k in key)
    return hfn(o + hfn(i + msg))

def bswap4(b):
    return b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))

def transforms(dig):
    """Return candidate 16-byte outputs from a digest."""
    return {
        "[:16]": dig[:16],
        "[-16:]": dig[-16:],
        "bswap4[:16]": bswap4(dig[:16]),
        "bswap4[-16:]": bswap4(dig[-16:]),
    }

def test_formula(label, fn):
    """Test a formula against all observations. Returns match count."""
    matches = 0
    for obs in obs_list:
        try:
            result = fn(obs)
            if result == obs["slot16"]:
                matches += 1
        except Exception:
            pass
    return matches

# ── Test all formulas ──
formulas = {}

# 1. Hash of k18 + _rticket
for hname, hfn in [("md5", lambda x: hashlib.md5(x).digest()), ("sm3", sm3)]:
    for sep in ["", b"|", b"\x00"]:
        label = f"{hname}(k18{'+sep' if sep else ''}+_rticket)"
        formulas[label] = lambda obs, hfn=hfn, sep=sep: hfn(k18 + sep + obs["_rticket"].encode())[:16]

        label = f"{hname}(_rticket{'+sep' if sep else ''}+k18)"
        formulas[label] = lambda obs, hfn=hfn, sep=sep: hfn(obs["_rticket"].encode() + sep + k18)[:16]

# 2. HMAC with k18 as key, _rticket as msg
for hname, hfn in [("hmac-md5", lambda k,m: hmac.new(k, m, hashlib.md5).digest()),
                     ("hmac-sha256", lambda k,m: hmac.new(k, m, hashlib.sha256).digest()),
                     ("hmac-sm3", hmac_sm3)]:
    label = f"{hname}(k18, _rticket)[:16]"
    formulas[label] = lambda obs, hfn=hfn: hfn(k18, obs["_rticket"].encode())[:16]

    label = f"{hname}(_rticket, k18)[:16]"
    formulas[label] = lambda obs, hfn=hfn: hfn(obs["_rticket"].encode(), k18)[:16]

# 3. SM3(k18 || _rticket || 0x30)[:16] (like #19 formula)
formulas["sm3(k18||_rticket||0x30)[:16]"] = lambda obs: sm3(k18 + obs["_rticket"].encode() + b'\x30')[:16]

# 4. XOR of k18 with hash of _rticket
formulas["k18 ^ md5(_rticket)"] = lambda obs: bytes(a ^ b for a, b in zip(k18, hashlib.md5(obs["_rticket"].encode()).digest()))
formulas["k18 ^ sm3(_rticket)[:16]"] = lambda obs: bytes(a ^ b for a, b in zip(k18, sm3(obs["_rticket"].encode())[:16]))

# 5. Try each embedded key as HMAC key
for kn, kv in all_keys:
    for hname, hfn in [("hmac-md5", lambda k,m: hmac.new(k, m, hashlib.md5).digest()),
                         ("hmac-sha256", lambda k,m: hmac.new(k, m, hashlib.sha256).digest()),
                         ("hmac-sm3", hmac_sm3)]:
        label = f"{hname}({kn}, _rticket)[:16]"
        formulas[label] = lambda obs, hfn=hfn, kv=kv: hfn(kv, obs["_rticket"].encode())[:16]

        label = f"{hname}({kn}, k18+_rticket)[:16]"
        formulas[label] = lambda obs, hfn=hfn, kv=kv: hfn(kv, k18 + obs["_rticket"].encode())[:16]

# 6. SM3 with embedded keys
for kn, kv in all_keys:
    formulas[f"sm3({kn}||_rticket)[:16]"] = lambda obs, kv=kv: sm3(kv + obs["_rticket"].encode())[:16]
    formulas[f"sm3({kn}||k18||_rticket)[:16]"] = lambda obs, kv=kv: sm3(kv + k18 + obs["_rticket"].encode())[:16]
    formulas[f"sm3(k18||{kn}||_rticket)[:16]"] = lambda obs, kv=kv: sm3(k18 + kv + obs["_rticket"].encode())[:16]

# 7. XOR of embedded key with hash
for kn, kv in all_keys:
    formulas[f"{kn} ^ md5(_rticket)"] = lambda obs, kv=kv: bytes(a ^ b for a, b in zip(kv, hashlib.md5(obs["_rticket"].encode()).digest()))

# 8. AES-ECB with embedded keys
try:
    from Crypto.Cipher import AES
    for kn, kv in all_keys:
        formulas[f"AES-ECB({kn}, _rticket_padded)[:16]"] = lambda obs, kv=kv: AES.new(kv, AES.MODE_ECB).encrypt(
            obs["_rticket"].encode().ljust(16, b'\x00')[:16])[:16]
except ImportError:
    pass

# 9. Device ID combinations
did = device_id.encode()
formulas["sm3(did||_rticket)[:16]"] = lambda obs: sm3(did + obs["_rticket"].encode())[:16]
formulas["sm3(k18||did||_rticket)[:16]"] = lambda obs: sm3(k18 + did + obs["_rticket"].encode())[:16]
formulas["md5(k18||did||_rticket)"] = lambda obs: hashlib.md5(k18 + did + obs["_rticket"].encode()).digest()

# 10. _rticket as little-endian bytes
formulas["sm3(k18||_rticket_le8)[:16]"] = lambda obs: sm3(k18 + struct.pack("<Q", int(obs["_rticket"])))[:16]
formulas["md5(k18||_rticket_le8)"] = lambda obs: hashlib.md5(k18 + struct.pack("<Q", int(obs["_rticket"]))).digest()

# 11. SM3 of query string with k18
formulas["sm3(query||k18||0x30)[:16]"] = lambda obs: sm3(obs["query"].encode() + k18 + b'\x30')[:16]

# Run all tests
print("Testing formulas...")
results = []
for label, fn in formulas.items():
    matches = test_formula(label, fn)
    if matches:
        results.append((label, matches))

results.sort(key=lambda x: -x[1])
for label, matches in results:
    pct = matches / len(obs_list) * 100
    flag = " <<< SOLVED!" if matches == len(obs_list) else ""
    print(f"  {label}: {matches}/{len(obs_list)} ({pct:.0f}%){flag}")

if not any(m == len(obs_list) for _, m in results):
    print("\n[-] No formula matches all observations.")
    print("    slot16 is NOT a simple hash/HMAC of k18 + _rticket + embedded keys.")

    # Print one observation for manual analysis
    print(f"\nSample observation:")
    o = obs_list[0]
    print(f"  slot16 = {o['slot16'].hex()}")
    print(f"  _rticket = {o['_rticket']}")
    print(f"  ts = {o['ts']}")
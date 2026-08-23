#!/usr/bin/env python3
"""Try to find the PSK_state by using the two-layer model: slot16 = PSK_state XOR hash(_rticket)."""
import os, struct, hashlib, json, re

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Load observations
data = json.load(open("slot16_newphone_verified.json", encoding="utf-8"))
k18 = bytes.fromhex(data["meta"]["k18_pskHash"])

# Extract nonzero slot16 observations
obs_list = []
for o in data["obs"]:
    s = o.get("slot16", "")
    if s == "00000000000000000000000000000000":
        continue
    m = re.search(r'_rticket=(\d+)', o["query"])
    if m:
        obs_list.append({
            "slot16": bytes.fromhex(s),
            "_rticket": m.group(1),
        })

print(f"Loaded {len(obs_list)} nonzero slot16 observations\n")

# If slot16 = PSK_state XOR hash(_rticket), then:
# PSK_state = slot16 XOR hash(_rticket)
# This should be the same for ALL observations

# Test various hash functions
for hname, hfn in [
    ("md5", lambda x: hashlib.md5(x).digest()),
    ("sha256", lambda x: hashlib.sha256(x).digest()[:16]),
    ("sha1", lambda x: hashlib.sha1(x).digest()[:16]),
]:
    for fmt in ["ascii", "le8", "be8"]:
        if fmt == "ascii":
            rt_bytes = lambda obs: obs["_rticket"].encode()
        elif fmt == "le8":
            rt_bytes = lambda obs: struct.pack("<Q", int(obs["_rticket"]))
        elif fmt == "be8":
            rt_bytes = lambda obs: struct.pack(">Q", int(obs["_rticket"]))

        # Compute PSK_state = slot16 XOR hash(_rticket) for each observation
        psk_states = []
        for obs in obs_list:
            h = hfn(rt_bytes(obs))
            psk = bytes(a ^ b for a, b in zip(obs["slot16"], h))
            psk_states.append(psk)

        # Check if all PSK_states are the same
        if all(psk == psk_states[0] for psk in psk_states):
            print(f"FOUND: slot16 = PSK_state XOR {hname}(_rticket [{fmt}])")
            print(f"  PSK_state = {psk_states[0].hex()}")
            print()

# Also try: slot16 = PSK_state XOR _rticket_bytes
for fmt_name, rt_fn in [
    ("ascii_padded", lambda obs: obs["_rticket"].encode().ljust(16, b'\x00')[:16]),
    ("le8_padded", lambda obs: struct.pack("<Q", int(obs["_rticket"])).ljust(16, b'\x00')),
    ("be8_padded", lambda obs: struct.pack(">Q", int(obs["_rticket"])).ljust(16, b'\x00')),
]:
    psk_states = []
    for obs in obs_list:
        psk = bytes(a ^ b for a, b in zip(obs["slot16"], rt_fn(obs)))
        psk_states.append(psk)
    if all(psk == psk_states[0] for psk in psk_states):
        print(f"FOUND: slot16 = PSK_state XOR _rticket [{fmt_name}]")
        print(f"  PSK_state = {psk_states[0].hex()}")
        print()

# If slot16 = AES_ECB(PSK_state, _rticket_padded), try to find PSK_state
# by checking if PSK_state = AES_ECB_decrypt(slot16, _rticket_padded)
try:
    from Crypto.Cipher import AES
    for fmt_name, rt_fn in [
        ("ascii_padded", lambda obs: obs["_rticket"].encode().ljust(16, b'\x00')[:16]),
    ]:
        for obs in obs_list[:3]:
            for obs2 in obs_list[:3]:
                if obs["_rticket"] == obs2["_rticket"]:
                    continue
                # Try: slot16 = AES_ECB(PSK_state, _rticket)
                # PSK_state = AES_ECB_decrypt(slot16, _rticket)
                # But we need the same PSK_state for both observations
                # This is hard to check without knowing PSK_state
                pass
except ImportError:
    pass

# Try: slot16 = first_16_bytes_of(MD5(PSK_state || _rticket))
# If this is the case, we can't easily reverse it.
# But we can check if there's a relationship between slot16 values.

# Try: slot16 = HMAC(key=PSK_state, msg=_rticket)[:16]
# If this is the case, slot16 values for different _rticket should be unrelated.

# Let's try a different approach: compute the XOR of consecutive slot16 values
print("=== XOR of consecutive slot16 values ===")
for i in range(min(len(obs_list) - 1, 5)):
    s1 = obs_list[i]["slot16"]
    s2 = obs_list[i + 1]["slot16"]
    xor = bytes(a ^ b for a, b in zip(s1, s2))
    print(f"  [{i}] XOR [{i+1}]: {xor.hex()}")

# Also XOR the _rticket values
print("\n=== XOR of _rticket differences ===")
for i in range(min(len(obs_list) - 1, 5)):
    r1 = int(obs_list[i]["_rticket"])
    r2 = int(obs_list[i + 1]["_rticket"])
    diff = r1 ^ r2
    print(f"  [{i}] _rticket XOR [{i+1}]: 0x{diff:016x}")

# Try: slot16 XOR _rticket difference
print("\n=== slot16 XOR _rticket_hash ===")
for i in range(min(len(obs_list) - 1, 5)):
    s1 = obs_list[i]["slot16"]
    s2 = obs_list[i + 1]["slot16"]
    slot_xor = bytes(a ^ b for a, b in zip(s1, s2))

    r1 = int(obs_list[i]["_rticket"])
    r2 = int(obs_list[i + 1]["_rticket"])
    rt_xor = struct.pack("<Q", r1 ^ r2)

    # If slot16 = PSK_state XOR MD5(_rticket), then:
    # slot16_1 XOR slot16_2 = MD5(_rticket_1) XOR MD5(_rticket_2)
    md5_1 = hashlib.md5(obs_list[i]["_rticket"].encode()).digest()
    md5_2 = hashlib.md5(obs_list[i + 1]["_rticket"].encode()).digest()
    md5_xor = bytes(a ^ b for a, b in zip(md5_1, md5_2))

    print(f"  [{i}]→[{i+1}]:")
    print(f"    slot16 XOR: {slot_xor.hex()}")
    print(f"    MD5(_rticket) XOR: {md5_xor.hex()}")
    print(f"    match: {slot_xor == md5_xor}")

# Check if slot16 = MD5(PSK_state || _rticket) by checking if
# there's a simple relationship between consecutive slot16 values
# In MD5, changing the last few bytes of the input produces unpredictable output
# So consecutive slot16 values should be unrelated if MD5 is used

# But if slot16 = PSK_state XOR _rticket (or some simple function),
# consecutive slot16 values should show a pattern

# Let's check if slot16 values are correlated with _rticket values
print("\n=== Correlation check ===")
# If slot16 = PSK_state XOR hash(_rticket), then:
# The XOR of two slot16 values = XOR of two hash(_rticket) values
# This is independent of PSK_state

# Test: slot16_1 XOR slot16_2 vs MD5(_rticket_1) XOR MD5(_rticket_2)
import hashlib
for i in range(len(obs_list)):
    for j in range(i + 1, len(obs_list)):
        s_xor = bytes(a ^ b for a, b in zip(obs_list[i]["slot16"], obs_list[j]["slot16"]))
        m_xor = bytes(a ^ b for a, b in zip(
            hashlib.md5(obs_list[i]["_rticket"].encode()).digest(),
            hashlib.md5(obs_list[j]["_rticket"].encode()).digest()))
        if s_xor == m_xor:
            print(f"  MATCH [{i}][{j}]: slot16 XOR = MD5(_rticket) XOR")
            break
    else:
        continue
    break
else:
    print("  No match: slot16 XOR != MD5(_rticket) XOR for any pair")

# Try SM3
from _sm3 import sm3
for i in range(len(obs_list)):
    for j in range(i + 1, len(obs_list)):
        s_xor = bytes(a ^ b for a, b in zip(obs_list[i]["slot16"], obs_list[j]["slot16"]))
        m_xor = bytes(a ^ b for a, b in zip(
            sm3(obs_list[i]["_rticket"].encode())[:16],
            sm3(obs_list[j]["_rticket"].encode())[:16]))
        if s_xor == m_xor:
            print(f"  MATCH [{i}][{j}]: slot16 XOR = SM3(_rticket)[:16] XOR")
            break
    else:
        continue
    break
else:
    print("  No match: slot16 XOR != SM3(_rticket)[:16] XOR for any pair")

# Try AES approach: if slot16 = AES_ECB(PSK_state, _rticket_padded),
# then slot16_1 XOR slot16_2 is not simply related to _rticket_1 XOR _rticket_2

# Try: is slot16 just the first 16 bytes of MD5(k18 || _rticket)?
# Already tested and failed.

# Let's try a new approach: maybe the PSK_state is the k18 itself,
# and slot16 = MD5(k18 || _rticket || some_constant)
for const in [b'', b'\x00', b'\x30', b'\x01', b'\xff']:
    all_match = True
    for obs in obs_list:
        computed = hashlib.md5(k18 + obs["_rticket"].encode() + const).digest()
        if computed != obs["slot16"]:
            all_match = False
            break
    if all_match:
        print(f"FOUND: slot16 = MD5(k18 || _rticket || {const.hex()})")
        break
else:
    print("  No match: slot16 != MD5(k18 || _rticket || constant)")

# Try SM3 variant
for const in [b'', b'\x00', b'\x30', b'\x01']:
    all_match = True
    for obs in obs_list:
        computed = sm3(k18 + obs["_rticket"].encode() + const)[:16]
        if computed != obs["slot16"]:
            all_match = False
            break
    if all_match:
        print(f"FOUND: slot16 = SM3(k18 || _rticket || {const.hex()})[:16]")
        break
else:
    print("  No match: slot16 != SM3(k18 || _rticket || constant)[:16]")

# Print first observation for reference
print(f"\nReference: first obs slot16={obs_list[0]['slot16'].hex()}, _rticket={obs_list[0]['_rticket']}")
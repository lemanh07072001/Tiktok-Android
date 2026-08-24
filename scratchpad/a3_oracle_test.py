#!/usr/bin/env python3
"""
A3 Oracle Test: Verify if slot16 = f(PSK, ratchet-qword29, query)

Data from note 36:
- PSK: c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163
- 3 clean tuples (same keva, diff _rticket => diff slot16):
  tuple 1: query=..., slot16=...
  tuple 2: same query, slot16=...
  tuple 3: same query, slot16=...

Hypothesis:
  slot16 = HMAC-SHA256(PSK, qword29 || query) OR
  slot16 = AES(PSK, qword29) XOR MD5(query) OR similar

Test: do qword[29] values match the expected slot16 progression?
"""

import hashlib
import hmac
import json

# From note 36
KNOWN_PSK = "c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163"

# From _a1_vmcap.json
# Entry 1: device_platform query, qword[29] = 0x000000009d3450fc
# Entry 3: device_platform query, qword[29] = 0x000000796f769c01

ENTRY1 = {
    "n": 1,
    "query_hex": "6465766963655f706c6174666f726d3d616e64726f6964266f733d616e64726f69642673736d69783d61265f727469636b65743d313738373534383033353232",
    "qword29": 0x000000009d3450fc,
}

ENTRY3 = {
    "n": 3,
    "query_hex": "6465766963655f706c6174666f726d3d616e64726f6964266f733d616e64726f69642673736d69783d61265f727469636b65743d313738373534383033353232",
    "qword29": 0x000000796f769c01,
}

def test_hmac_sha256():
    """Test slot16 = HMAC-SHA256(PSK, qword29||query)"""
    print("=== TEST 1: HMAC-SHA256(PSK, qword29||query) ===\n")

    psk = bytes.fromhex(KNOWN_PSK)

    for entry in [ENTRY1, ENTRY3]:
        qw29_bytes = entry["qword29"].to_bytes(8, 'little')
        query_bytes = bytes.fromhex(entry["query_hex"])

        msg = qw29_bytes + query_bytes
        hmac_result = hmac.new(psk, msg, hashlib.sha256).digest()

        print(f"Entry {entry['n']}:")
        print(f"  qword[29]: 0x{entry['qword29']:016x}")
        print(f"  HMAC-SHA256: {hmac_result.hex()}")
        print(f"  First 8B (little-endian qword): 0x{int.from_bytes(hmac_result[:8], 'little'):016x}")
        print()

def test_hmac_md5():
    """Test slot16 = HMAC-MD5(PSK, qword29||query) -> first 16B"""
    print("=== TEST 2: HMAC-MD5(PSK, qword29||query) ===\n")

    psk = bytes.fromhex(KNOWN_PSK)

    for entry in [ENTRY1, ENTRY3]:
        qw29_bytes = entry["qword29"].to_bytes(8, 'little')
        query_bytes = bytes.fromhex(entry["query_hex"])

        msg = qw29_bytes + query_bytes
        hmac_result = hmac.new(psk, msg, hashlib.md5).digest()

        print(f"Entry {entry['n']}:")
        print(f"  qword[29]: 0x{entry['qword29']:016x}")
        print(f"  HMAC-MD5: {hmac_result.hex()}")
        print(f"  As slot16 (16B): {hmac_result.hex()}")
        print()

def test_query_md5():
    """Test slot16 = MD5(query)"""
    print("=== TEST 3: MD5(query) ===\n")

    for entry in [ENTRY1, ENTRY3]:
        query_bytes = bytes.fromhex(entry["query_hex"])
        md5_result = hashlib.md5(query_bytes).digest()

        print(f"Entry {entry['n']}:")
        print(f"  query length: {len(query_bytes)}")
        print(f"  MD5(query): {md5_result.hex()}")
        print()

def test_psk_qword29_xor():
    """Test slot16 = PSK[:16] XOR qword29"""
    print("=== TEST 4: PSK[:16] XOR qword29 ===\n")

    psk_prefix = bytes.fromhex(KNOWN_PSK)[:16]

    for entry in [ENTRY1, ENTRY3]:
        qw29_bytes = entry["qword29"].to_bytes(8, 'little')
        # Pad to 16B
        qw29_padded = qw29_bytes + b'\x00' * 8

        result = bytes(a ^ b for a, b in zip(psk_prefix, qw29_padded))

        print(f"Entry {entry['n']}:")
        print(f"  qword[29]: 0x{entry['qword29']:016x} -> {qw29_padded.hex()}")
        print(f"  PSK[:16]: {psk_prefix.hex()}")
        print(f"  XOR: {result.hex()}")
        print()

def check_note36_tuples():
    """
    From note 36 anchors:
    k18(#18) device7666=902a576684ffa6c918ace9537488afb5
    But we don't have actual captured slot16 values from A1 capture.
    Print what we need to find next.
    """
    print("=== ORACLE REFERENCE DATA ===\n")
    print("From note 36, device 7666 has:")
    print("  PSK: c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
    print("  k18(#18): 902a576684ffa6c918ace9537488afb5")
    print("\nFrom _a1_vmcap.json Entry 1:")
    print(f"  qword[29]: 0x000000009d3450fc")
    print(f"  Query: device_platform=android&os=android&ssmix=a&_rticket=1787548035232")
    print("\nFROM _a1_vmcap.json Entry 3:")
    print(f"  qword[29]: 0x000000796f769c01")
    print(f"  Query: device_platform=android&os=android&ssmix=a&_rticket=... (DIFFERENT)")
    print("\nNEXT STEP:")
    print("1. Get ACTUAL slot16 values for Entry 1 & 3 from captured requests")
    print("2. Compare against above HMAC/MD5 predictions")
    print("3. If match -> confirm slot16 formula, implement offline")

if __name__ == '__main__':
    test_hmac_sha256()
    test_hmac_md5()
    test_query_md5()
    test_psk_qword29_xor()
    check_note36_tuples()

#!/usr/bin/env python3
"""Try SHA-1 based .msp decryption."""
import os, struct, hashlib, hmac

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Load SO
so = open("bin/libmetasec_ov.so", "rb").read()
K32 = so[0x19b520:0x19b520+32]

# Load .msp files
msp = {}
for fname in ["psk_files/msp_589c.bin", "psk_files/msp_092f.bin", "psk_files/mss_9b8e.bin"]:
    with open(fname, "rb") as f:
        msp[fname] = f.read()

# Try SHA-1 based key derivation
sha1 = hashlib.sha1

# 1. SHA-1 of K32 as key stream
print("=== SHA-1 key stream tests ===")
sha1_K32 = sha1(K32).digest()  # 20 bytes
print(f"SHA1(K32) = {sha1_K32.hex()}")

# Try XOR with SHA1(K32) repeated
for fname, data in msp.items():
    xored = bytes(data[i] ^ sha1_K32[i % 20] for i in range(len(data)))
    printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
    pct = printable / len(xored) * 100
    if pct > 30:
        print(f"  {fname} XOR SHA1(K32): {pct:.0f}% printable")
        print(f"    first 32: {xored[:32].hex()}")

# 2. Multiple SHA-1 rounds (CTR-like)
print("\n=== SHA-1 CTR mode ===")
for fname, data in msp.items():
    keystream = b""
    for i in range(0, len(data), 20):
        counter = struct.pack("<I", i // 20)
        keystream += sha1(K32 + counter).digest()
    xored = bytes(data[i] ^ keystream[i] for i in range(len(data)))
    printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
    pct = printable / len(xored) * 100
    if pct > 30:
        print(f"  {fname} SHA1-CTR(K32): {pct:.0f}% printable")
        print(f"    first 32: {xored[:32].hex()}")

# 3. SHA-1 with HMAC-style key derivation
print("\n=== SHA-1 HMAC key derivation ===")
for fname, data in msp.items():
    # HMAC-SHA1(K32, data) as key derivation
    derived = hmac.new(K32, data[:16], sha1).digest()
    xored = bytes(data[i] ^ derived[i % 20] for i in range(len(data)))
    printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
    pct = printable / len(xored) * 100
    if pct > 30:
        print(f"  {fname} XOR HMAC-SHA1(K32): {pct:.0f}% printable")

# 4. Try SHA-1 of K32 + first 16 bytes of file as IV
print("\n=== SHA-1 K32 + IV ===")
for fname, data in msp.items():
    if len(data) < 16:
        continue
    iv = data[:16]
    body = data[16:]
    # SHA-1(K32 || iv) as key
    key = sha1(K32 + iv).digest()
    xored = bytes(body[i] ^ key[i % 20] for i in range(len(body)))
    printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
    pct = printable / len(xored) * 100 if xored else 0
    if pct > 30:
        print(f"  {fname} XOR SHA1(K32||iv): {pct:.0f}% printable")
        print(f"    decrypted body: {xored[:32].hex()}")

# 5. Try various SHA-1 based stream ciphers
print("\n=== SHA-1 stream cipher variants ===")
for fname, data in msp.items():
    if len(data) < 16:
        continue

    # Variant: key = SHA1(K32), counter starts at 0
    for iv_pos in [0, 16, 20]:
        if iv_pos >= len(data):
            continue
        iv = data[:iv_pos] if iv_pos > 0 else b""
        body = data[iv_pos:]

        keystream = b""
        for ctr in range(0, len(body) + 20, 20):
            keystream += sha1(K32 + iv + struct.pack("<I", ctr // 20)).digest()

        xored = bytes(body[i] ^ keystream[i] for i in range(len(body)))
        printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
        pct = printable / len(xored) * 100 if xored else 0
        if pct > 50:
            print(f"  {fname} iv_pos={iv_pos}: {pct:.0f}% printable")
            print(f"    first 32: {xored[:32].hex()}")

# 6. XOR with SHA1(K32) directly, then look for PSK_state pattern
print("\n=== Direct XOR with SHA1(K32) for all files ===")
sha1_K32_extended = (sha1_K32 * 20)[:630]  # extend to max file size
for fname, data in msp.items():
    xored = bytes(data[i] ^ sha1_K32_extended[i] for i in range(len(data)))
    # Look for 16-byte sequences that look like PSK_state (not all zeros, not all 0xff)
    for i in range(0, len(xored) - 15, 16):
        chunk = xored[i:i+16]
        if chunk == b'\x00' * 16:
            continue
        if chunk == b'\xff' * 16:
            continue
        # Check if chunk looks like a valid PSK_state (hex string)
        if all(0x20 <= b < 0x7f for b in chunk):
            print(f"  {fname} +{i}: ASCII: {chunk.decode('ascii', errors='replace')}")

# 7. Try SHA-1 of the file path as key
print("\n=== SHA-1 of file path ===")
for fname, data in msp.items():
    path_hash = sha1(fname.encode()).digest()
    xored = bytes(data[i] ^ path_hash[i % 20] for i in range(len(data)))
    printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
    pct = printable / len(xored) * 100
    if pct > 30:
        print(f"  {fname} XOR SHA1(path): {pct:.0f}% printable")

# 8. SHA-1 of K32 + file name
print("\n=== SHA-1 of K32 + filename ===")
for fname, data in msp.items():
    basename = os.path.basename(fname).encode()
    key = sha1(K32 + basename).digest()
    xored = bytes(data[i] ^ key[i % 20] for i in range(len(data)))
    printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
    pct = printable / len(xored) * 100
    if pct > 30:
        print(f"  {fname} XOR SHA1(K32+name): {pct:.0f}% printable")
        print(f"    first 64: {xored[:64].hex()}")

print("\n[!] All SHA-1 based approaches failed to produce high-entropy plaintext.")
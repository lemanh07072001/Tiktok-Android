#!/usr/bin/env python3
"""Try to find the PSK_state by analyzing .msp files and testing formulas."""
import os, struct, hashlib, hmac

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Load SO
so = open("bin/libmetasec_ov.so", "rb").read()

# Embedded keys
K1 = so[0x1ec960:0x1ec960+16]
K2 = so[0x1ec960+16:0x1ec960+32]
K3 = so[0x1ec960+32:0x1ec960+48]
K4 = so[0x1ec960+48:0x1ec960+64]
K5 = so[0x1ec960+64:0x1ec960+80]
K6 = so[0x17baa0:0x17baa0+16]
K7 = so[0x17baa0+16:0x17baa0+32]
K32 = so[0x19b520:0x19b520+32]

# Load .msp files
msp_files = {}
for fname in ["psk_files/msp_589c.bin", "psk_files/msp_092f.bin", "psk_files/mss_9b8e.bin"]:
    with open(fname, "rb") as f:
        msp_files[fname] = f.read()

# Try XOR with each key
print("=== Trying XOR with embedded keys ===")
for fname, data in msp_files.items():
    print(f"\n{fname} ({len(data)} bytes):")
    for kname, key in [("K1", K1), ("K2", K2), ("K3", K3), ("K4", K4), ("K5", K5),
                        ("K6", K6), ("K7", K7), ("K32[:16]", K32[:16]), ("K32[16:]", K32[16:])]:
        # XOR with repeating key
        xored = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        # Check for printable ASCII
        printable = sum(1 for b in xored if 0x20 <= b < 0x7f)
        pct = printable / len(xored) * 100
        if pct > 30:
            print(f"  {kname}: {pct:.0f}% printable")
            # Show first 32 bytes
            hex_str = xored[:32].hex()
            ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in xored[:32])
            print(f"    {ascii_str}")

# Try to find the SHA-1 of the file (for integrity check)
print("\n=== SHA-1 checks ===")
for fname, data in msp_files.items():
    # Check if last 20 bytes = SHA1(data[:-20])
    if len(data) >= 20:
        body = data[:-20]
        sha1_of_body = hashlib.sha1(body).digest()
        stored = data[-20:]
        if sha1_of_body == stored:
            print(f"  {fname}: SHA1(body) matches last 20 bytes!")
        else:
            print(f"  {fname}: SHA1(body) != last 20 bytes")

        # Try SHA1 with various keys
        for kname, key in [("K1", K1), ("K2", K2), ("K32", K32)]:
            # HMAC-SHA1
            h = hmac.new(key, body, hashlib.sha1).digest()
            if h == stored:
                print(f"  {fname}: HMAC-SHA1({kname}, body) matches!")
            # SHA1(key || body)
            h = hashlib.sha1(key + body).digest()
            if h == stored:
                print(f"  {fname}: SHA1({kname} || body) matches!")

# Try to decrypt the .msp files using AES
print("\n=== AES decryption attempts ===")
try:
    from Crypto.Cipher import AES
    for fname, data in msp_files.items():
        if len(data) < 16:
            continue
        for kname, key in [("K1", K1), ("K2", K2), ("K3", K3), ("K32[:16]", K32[:16])]:
            try:
                # AES-ECB
                cipher = AES.new(key, AES.MODE_ECB)
                dec = cipher.decrypt(data[:len(data) - len(data) % 16])
                printable = sum(1 for b in dec if 0x20 <= b < 0x7f)
                pct = printable / len(dec) * 100
                if pct > 30:
                    print(f"  {fname} AES-ECB({kname}): {pct:.0f}% printable")
                    print(f"    {dec[:48]}")
            except Exception:
                pass

            try:
                # AES-CBC with null IV
                cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * 16)
                dec = cipher.decrypt(data[:len(data) - len(data) % 16])
                printable = sum(1 for b in dec if 0x20 <= b < 0x7f)
                pct = printable / len(dec) * 100
                if pct > 30:
                    print(f"  {fname} AES-CBC({kname}): {pct:.0f}% printable")
                    print(f"    {dec[:48]}")
            except Exception:
                pass
except ImportError:
    print("  pycryptodome not available, skipping AES")

# Try to find the PSK_state by looking for 16-byte values that appear in multiple .msp files
print("\n=== Common 16-byte sequences across .msp files ===")
all_16byte = {}
for fname, data in msp_files.items():
    for i in range(0, len(data) - 15):
        chunk = data[i:i+16]
        all_16byte.setdefault(chunk, []).append((fname, i))

# Find chunks that appear in at least 2 files
shared = {k: v for k, v in all_16byte.items() if len(v) >= 2}
print(f"  {len(shared)} chunks appear in >= 2 files")
for chunk, locations in list(shared.items())[:5]:
    print(f"  {chunk.hex()} at {locations}")

# Check if any embedded key appears in the .msp files
print("\n=== Embedded key presence in .msp files ===")
for kname, key in [("K1", K1), ("K2", K2), ("K3", K3), ("K4", K4), ("K5", K5),
                    ("K6", K6), ("K7", K7)]:
    for fname, data in msp_files.items():
        if key in data:
            print(f"  {kname} found in {fname}")
        if key[::-1] in data:  # reversed
            print(f"  {kname} (reversed) found in {fname}")

print("\n=== k18 presence in .msp files ===")
k18 = bytes.fromhex("902a576684ffa6c918ace9537488afb5")
for fname, data in msp_files.items():
    if k18 in data:
        print(f"  k18 found in {fname}")
    # Check if k18 XORed with something appears
    for kname, key in [("K1", K1), ("K2", K2)]:
        xored = bytes(a ^ b for a, b in zip(k18, key))
        if xored in data:
            print(f"  k18^{kname} found in {fname}")
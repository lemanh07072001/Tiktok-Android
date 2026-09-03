#!/usr/bin/env python3
"""Extract strings from large op=18 data definition entries."""
import os, struct, json

os.chdir(os.path.dirname(os.path.abspath(__file__)))

SO = "bin/libmetasec_ov.so"
EXEC_TRACE = "exec_trace.json"
XOR_KEY = 0x6a9091b9

so = open(SO, "rb").read()
exec_trace = json.load(open(EXEC_TRACE))
offsets = exec_trace["exec_offsets"]

# Find op=18 entries with large data slots
entries = []
for i, (addr_off, opword) in enumerate(offsets):
    op_idx = opword & 0x3f
    if op_idx != 18:
        continue

    if i + 1 < len(offsets):
        next_addr = offsets[i + 1][0]
    else:
        next_addr = addr_off + 1000

    data_slots = (next_addr - addr_off - 8) // 8
    if data_slots > 50:  # Large data definitions
        entries.append((i, addr_off, opword, data_slots))

print(f"Found {len(entries)} large op=18 entries (data_slots > 50)\n")

# For each large entry, read the data slots and try to extract strings
for idx, addr_off, opword, data_slots in entries:
    operand = struct.unpack_from("<I", so, addr_off + 4)[0]
    dec_operand = operand ^ XOR_KEY
    print(f"=== Entry #{idx} at 0x{addr_off:x}, {data_slots} slots, dec_op=0x{dec_operand:08x} ===")

    # Read all data slots
    slots = []
    for s in range(min(data_slots, 20)):
        slot_addr = addr_off + 8 + s * 8
        slot_val = struct.unpack_from("<Q", so, slot_addr)[0]
        slots.append(slot_val)

    # Data slots are 8-byte values. Some might be pointers to strings.
    # Check if any slot looks like a file offset
    for s, val in enumerate(slots):
        if 0x17bc6c <= val < 0x194db4:
            # Points within bytecode range
            # Read the string at this offset
            try:
                end = so.index(b'\x00', val)
                string = so[val:end].decode('ascii', errors='replace')
                if len(string) >= 2:
                    print(f"  slot[{s}]=0x{val:08x} -> '{string}'")
            except:
                pass

    # Also try raw data slots for printable strings
    all_bytes = b""
    for s in range(min(data_slots, 100)):
        slot_addr = addr_off + 8 + s * 8
        slot_val = struct.unpack_from("<Q", so, slot_addr)[0]
        all_bytes += struct.pack("<Q", slot_val)

    # Find printable strings
    current = b""
    for b in all_bytes:
        if 0x20 <= b < 0x7f:
            current += bytes([b])
        else:
            if len(current) >= 4:
                print(f"  string: '{current.decode('ascii', errors='replace')}'")
            current = b""
    if len(current) >= 4:
        print(f"  string: '{current.decode('ascii', errors='replace')}'")

    print()
#!/usr/bin/env python3
"""Decode nested bytecode entries inside op=40 data block at 0x188a88."""
import struct, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

SO = "bin/libmetasec_ov.so"
so = open(SO, "rb").read()

BLOCK_ADDR = 0x188a88
BLOCK_SIZE = 27360
block = so[BLOCK_ADDR:BLOCK_ADDR + BLOCK_SIZE]

HEADER_MAGIC = 0x003f956c
XOR_KEY = 0x6a9091b9
OP40_XOR_KEY = 0x0cad5f8f

# Find all bytecode headers
header_positions = []
pos = 0
while True:
    pos = block.find(struct.pack("<I", HEADER_MAGIC), pos)
    if pos == -1:
        break
    header_positions.append(pos)
    pos += 1

print(f"Found {len(header_positions)} bytecode headers in op=40 data block\n")

# Decode each nested entry
entries = []
for i, pos in enumerate(header_positions):
    header = struct.unpack_from("<I", block, pos)[0]
    opword = struct.unpack_from("<I", block, pos + 4)[0]
    op_idx = opword & 0x3f
    operand = struct.unpack_from("<I", block, pos + 4)[0]
    dec_operand = opword ^ OP40_XOR_KEY  # op=40 specific XOR

    # Determine entry size: next header or end of block
    if i + 1 < len(header_positions):
        next_pos = header_positions[i + 1]
    else:
        next_pos = BLOCK_SIZE
    entry_size = next_pos - pos
    data_slots = (entry_size - 8) // 8

    # Read data slots
    slots = []
    for s in range(min(data_slots, 50)):  # max 50 slots
        slot_addr = pos + 8 + s * 8
        slot_val = struct.unpack_from("<Q", block, slot_addr)[0]
        slots.append(slot_val)

    entries.append({
        'i': i,
        'offset': pos,
        'header': header,
        'opword': opword,
        'op_idx': op_idx,
        'operand': operand,
        'dec_operand': dec_operand,
        'data_slots': data_slots,
        'slots': slots,
        'entry_size': entry_size,
    })

# Opcode frequency
from collections import Counter
op_freq = Counter(e['op_idx'] for e in entries)
print("=== Opcode frequency in nested bytecode ===")
for op, count in op_freq.most_common():
    print(f"  op={op:2d}: {count:3d}x")

# Print first 20 entries
print("\n=== First 20 nested entries ===")
for e in entries[:20]:
    slots_str = " ".join(f"0x{s:016x}" for s in e['slots'][:3])
    if len(e['slots']) > 3:
        slots_str += f" ... (+{len(e['slots'])-3})"
    print(f"  [{e['i']:3d}] +0x{e['offset']:04x} op={e['op_idx']:2d} "
          f"opword=0x{e['opword']:08x} dec_op=0x{e['dec_operand']:08x} "
          f"slots={e['data_slots']} {slots_str}")

# Look for string data in the block
print("\n=== Looking for strings in the block ===")
# Find printable ASCII sequences
ascii_strings = []
current = b""
for b in block:
    if 0x20 <= b < 0x7f:
        current += bytes([b])
    else:
        if len(current) >= 4:
            ascii_strings.append(current.decode('ascii'))
        current = b""
if len(current) >= 4:
    ascii_strings.append(current.decode('ascii'))

for s in ascii_strings[:30]:
    print(f"  '{s}'")

# Try to find patterns: look for op=18 entries (data definitions with strings)
print("\n=== Op=18 entries (data definitions) in nested bytecode ===")
op18_entries = [e for e in entries if e['op_idx'] == 18]
print(f"Found {len(op18_entries)} op=18 entries")
for e in op18_entries[:10]:
    print(f"  [{e['i']:3d}] +0x{e['offset']:04x} slots={e['data_slots']} "
          f"opword=0x{e['opword']:08x}")

# Look for op=1 entries (control flow)
print("\n=== Op=1 entries (control flow) in nested bytecode ===")
op1_entries = [e for e in entries if e['op_idx'] == 1]
print(f"Found {len(op1_entries)} op=1 entries")
for e in op1_entries[:5]:
    print(f"  [{e['i']:3d}] +0x{e['offset']:04x} slots={e['data_slots']} "
          f"opword=0x{e['opword']:08x}")

# Check if any entry has op=40 (nested encrypted blocks!)
op40_nested = [e for e in entries if e['op_idx'] == 40]
print(f"\n=== Op=40 entries in nested bytecode: {len(op40_nested)} ===")
for e in op40_nested[:5]:
    print(f"  [{e['i']:3d}] +0x{e['offset']:04x} slots={e['data_slots']} "
          f"opword=0x{e['opword']:08x} dec_op=0x{e['dec_operand']:08x}")
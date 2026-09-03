#!/usr/bin/env python3
"""Extract and analyze op=40 entries from the SO binary."""
import json, struct, os, sys
from collections import Counter

os.chdir(os.path.dirname(os.path.abspath(__file__)))

SO = "bin/libmetasec_ov.so"
EXEC_TRACE = "exec_trace.json"
XOR_KEY = 0x6a9091b9
OP40_XOR_KEY = 0x0cad5f8f

so = open(SO, "rb").read()
exec_trace = json.load(open(EXEC_TRACE))
offsets = exec_trace["exec_offsets"]

# Find all op=40 entries
op40_entries = []
for addr_off, opword in offsets:
    op_idx = opword & 0x3f
    if op_idx == 40:
        op40_entries.append((addr_off, opword))

print(f"Total op=40 entries in exec_trace: {len(op40_entries)}")

# Analyze each op=40 entry
for i, (addr_off, opword) in enumerate(op40_entries):
    header = struct.unpack_from("<I", so, addr_off)[0]
    operand = struct.unpack_from("<I", so, addr_off + 4)[0]
    dec_operand = opword ^ OP40_XOR_KEY  # opcode-specific XOR key

    # Data slots: read next 8 bytes at a time until next entry or end
    # Find the next entry's address
    next_addr = None
    for a, _ in offsets:
        if a > addr_off:
            next_addr = a
            break
    if next_addr is None:
        next_addr = addr_off + 8 + 3420 * 8  # max data slots for op=40

    data_size = next_addr - addr_off - 8
    data_slots = data_size // 8

    print(f"\n[{i}] addr=0x{addr_off:x} opword=0x{opword:08x} "
          f"op_idx={opword & 0x3f} operand=0x{operand:08x} "
          f"dec_operand=0x{dec_operand:08x} data_slots={data_slots}")

    if data_slots <= 10:
        # Print data slots for small entries
        for s in range(data_slots):
            slot_addr = addr_off + 8 + s * 8
            slot_val = struct.unpack_from("<Q", so, slot_addr)[0]
            print(f"  slot[{s}]: 0x{slot_val:016x}")
    else:
        # For large entries, print first and last few slots
        for s in range(5):
            slot_addr = addr_off + 8 + s * 8
            slot_val = struct.unpack_from("<Q", so, slot_addr)[0]
            print(f"  slot[{s}]: 0x{slot_val:016x}")
        print(f"  ... ({data_slots - 10} more slots)")
        for s in range(data_slots - 5, data_slots):
            slot_addr = addr_off + 8 + s * 8
            slot_val = struct.unpack_from("<Q", so, slot_addr)[0]
            print(f"  slot[{s}]: 0x{slot_val:016x}")

# Now look at the big op=40 data block at 0x188a88
print("\n\n=== Big op=40 data block at 0x188a88 ===")
BLOCK_ADDR = 0x188a88
# Read 27360 bytes (3420 * 8)
block_data = so[BLOCK_ADDR:BLOCK_ADDR+27360]
print(f"Block size: {len(block_data)} bytes")
print(f"Unique bytes: {len(set(block_data))}/256")

# Look for bytecode headers (0x003f956c) in the block
header_pattern = struct.pack("<I", 0x003f956c)
header_positions = []
pos = 0
while True:
    pos = block_data.find(header_pattern, pos)
    if pos == -1:
        break
    header_positions.append(pos)
    pos += 1

print(f"Bytecode headers found: {len(header_positions)}")
for pos in header_positions[:10]:
    print(f"  at offset +0x{pos:x}: header=0x{struct.unpack_from('<I', block_data, pos)[0]:08x} "
          f"next_qword=0x{struct.unpack_from('<Q', block_data, pos+4)[0]:016x}")

# Try to decrypt using op=40 handler algorithm
# The handler does: address = regfile_value * sxth(operand) + sxth(operand)
# Then XOR byte with 0xed
# For static analysis, we don't know regfile_value
# But we can try XORing the entire block with 0xed
print("\n=== Trying XOR 0xed on the block ===")
xored = bytes(b ^ 0xed for b in block_data)
header_pos_xor = []
pos = 0
while True:
    pos = xored.find(header_pattern, pos)
    if pos == -1:
        break
    header_pos_xor.append(pos)
    pos += 1
print(f"Bytecode headers in XORed block: {len(header_pos_xor)}")

# The op=40 handler uses a different XOR key for the opword (0x0cad5f8f)
# Let's check if the data slots look like encrypted bytecode
# Each op=40 entry has a specific operand, and the decrypted operand tells us
# the sxth(operand) value used in the address calculation

# Let's check the relationship between consecutive op=40 entries
print("\n=== Op=40 entry relationships ===")
for i in range(min(len(op40_entries) - 1, 5)):
    addr1, opw1 = op40_entries[i]
    addr2, opw2 = op40_entries[i + 1]
    operand1 = struct.unpack_from("<I", so, addr1 + 4)[0]
    operand2 = struct.unpack_from("<I", so, addr2 + 4)[0]
    dec_op1 = opw1 ^ OP40_XOR_KEY
    dec_op2 = opw2 ^ OP40_XOR_KEY
    print(f"  [{i}]→[{i+1}]: gap={addr2 - addr1}, "
          f"dec_op1=0x{dec_op1:08x} dec_op2=0x{dec_op2:08x} "
          f"sxth1={struct.unpack('<h', struct.pack('<H', dec_op1 & 0xffff))[0]} "
          f"sxth2={struct.unpack('<h', struct.pack('<H', dec_op2 & 0xffff))[0]}")
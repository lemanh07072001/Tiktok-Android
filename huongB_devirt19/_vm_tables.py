#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _vm_tables.py — dump the VM opcode table and bytecode referenced by the VM at 0x55950.
# The VM uses:
#   x30 = 0x52924  (opcode handler table, 64 entries x 8 bytes)
#   x7  = 0x1f0000 (external data table)
#   x23 = bytecode pointer (self-modifying, XOR-decrypted)
#   x24 = VM register file (32 x 8-byte slots)
import struct, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
SO = "bin/libmetasec_ov.so"

with open(SO, "rb") as f:
    so = f.read()

# ── Opcode handler table at 0x52924 ──
# The dispatch does: and w16, w16, #0x3f; ldr x15, [table + w16*8]; sub x15, x15, base; br x15
# So the table has 64 entries of 8 bytes each, each is base+offset of handler
TABLE = 0x52924
BASE_ADDR = 0x400000  # typical .so base, but we need the actual load base
# The handlers are relative to some base. Let's read the raw values.

print("=== Opcode Handler Table at 0x%x ===" % TABLE)
print("(64 entries x 8 bytes = handler addresses)")
print()
for i in range(64):
    off = TABLE + i * 8
    if off + 8 > len(so):
        break
    val = struct.unpack_from("<Q", so, off)[0]
    # Check if it looks like a valid code address (0x400000-0x600000 range)
    in_range = 0x400000 <= val < 0x700000
    marker = " <-- CODE" if in_range else ""
    print(f"  [{i:2d}]  0x{val:016x}{marker}")

# ── External table at 0x1f0000 ──
# The dispatch also does: ldr x17, [x7, #0xe0]
# So x7 points to 0x1f0000, and it reads from offset 0xe0
print(f"\n=== External Table at 0x1f0000 (first 0x200 bytes) ===")
for off in range(0x1f0000, 0x1f0200, 8):
    val = struct.unpack_from("<Q", so, off)[0]
    print(f"  0x{off:x}: 0x{val:016x}")

# ── Look for bytecode near the VM function ──
# The bytecode is referenced through x23. We need to find where x23 is initialized.
# Let's look at the function prologue (0x55890).
print(f"\n=== Code at 0x55890 (function prologue?) ===")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
for i in md.disasm(so[0x55890:0x55950], 0x55890):
    print(f"  0x{i.address:x}: {i.mnemonic:8s} {i.op_str}")

# ── Look for data sections that might be bytecode ──
# The ADRP instructions reference pages 0x52000 and 0x1f0000
# Let's scan for large data blocks near these addresses
print(f"\n=== Data at 0x52000-0x52924 (before opcode table) ===")
# Check if it's code or data
for off in range(0x52000, min(0x52924, 0x52100), 8):
    val = struct.unpack_from("<Q", so, off)[0]
    print(f"  0x{off:x}: 0x{val:016x}")

# ── Find the bytecode pool ──
# The bytecode is typically in .rodata or .data sections
# Let's search for patterns that look like XOR-encrypted bytecode
# Each opcode is 8 bytes: [4B opcode word] [4B XOR-encrypted operand]
# The opcode word has specific bit patterns (register indices)
print(f"\n=== Searching for bytecode-like data... ===")
# Look at the section headers
import re
# Parse ELF sections
elf_header = so[:64]
if elf_header[:4] == b'\x7fELF':
    e_shoff = struct.unpack_from("<Q", elf_header, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", elf_header, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", elf_header, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", elf_header, 0x3E)[0]

    # Get section name string table
    shstr_off = e_shoff + e_shstrndx * e_shentsize
    shstr_sh = so[shstr_off:shstr_off + e_shentsize]
    shstr_offset = struct.unpack_from("<Q", shstr_sh, 0x18)[0]

    print(f"\n=== ELF Sections ===")
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh = so[sh_off:sh_off + e_shentsize]
        sh_name = struct.unpack_from("<I", sh, 0)[0]
        sh_type = struct.unpack_from("<I", sh, 4)[0]
        sh_addr = struct.unpack_from("<Q", sh, 0x10)[0]
        sh_size = struct.unpack_from("<Q", sh, 0x20)[0]

        # Read name
        name = so[shstr_offset + sh_name:].split(b'\0')[0].decode('latin1', errors='replace')

        if sh_size > 0 and sh_addr > 0:
            print(f"  [{i:2d}] {name:20s} addr=0x{sh_addr:08x} size=0x{sh_size:x} type={sh_type}")
            # Check if 0x52924 or 0x55950 falls in this section
            if sh_addr <= TABLE < sh_addr + sh_size:
                print(f"        *** OPCODE TABLE is in this section!")
            if sh_addr <= 0x55950 < sh_addr + sh_size:
                print(f"        *** VM FUNCTION is in this section!")
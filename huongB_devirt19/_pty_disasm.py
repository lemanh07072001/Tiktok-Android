#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _pty_disasm.py — disassemble the Pitaya signing bytecode module.
#
# Module: embedded static in libmetasec_ov.so at va 0x17bc6c-0x195000 (~103KB, 1207 blocks).
# Each block starts with header 0x003f956c (opcode 44 with operand 0x3f95).
# Format per instruction word (LE u32): op = word & 0x3f, operand = word >> 6.
#
# Opcodes verified live: 44(header/dispatch),42,18,38,15 dominant.
# This is NOT WASM — it's ByteDance Pitaya custom bytecode.
import struct, sys

BASE_VA = 0x17bc6c

def load():
    return open("sign_bytecode.bin", "rb").read()

# Opcode name guesses from handler analysis (region 0x5xxxx handlers)
OPNAMES = {
    44: "BLOCK_HDR/dispatch",
    42: "table_lookup",     # handler reads struct fields, bounds check
    18: "strtod/float",     # strtod path
    38: "cmp_micro",        # float/int compare micro-op chain
    15: "load/signext",     # sign-extend/load micro-op chain
    0:  "op0", 1: "op1", 5: "op5", 7: "cond_branch",
    30: "op30", 31: "op31", 37: "op37", 40: "op40",
    48: "op48", 51: "op51", 52: "op52", 63: "op63",
}

def disasm_blocks(data, max_blocks=20):
    hdr = 0x003f956c
    i = 0
    blocks = []
    # find all block starts
    starts = []
    while i + 4 <= len(data):
        w = struct.unpack_from("<I", data, i)[0]
        if w == hdr:
            starts.append(i)
        i += 4
    print(f"[*] {len(starts)} blocks, module {len(data)} bytes\n")
    for bi, s in enumerate(starts[:max_blocks]):
        e = starts[bi+1] if bi+1 < len(starts) else len(data)
        va = BASE_VA + s
        print(f"=== block {bi} @ va 0x{va:x} (len {e-s}) ===")
        off = s
        while off < e:
            w = struct.unpack_from("<I", data, off)[0]
            op = w & 0x3f
            operand = w >> 6
            name = OPNAMES.get(op, f"op{op}")
            print(f"  0x{BASE_VA+off:06x}: {w:08x}  op={op:2d} operand=0x{operand:x}  {name}")
            off += 4
        print()

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    disasm_blocks(load(), n)

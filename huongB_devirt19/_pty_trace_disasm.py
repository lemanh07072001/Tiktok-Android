#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _pty_trace_disasm.py — disassemble ONLY the actually-executed signing opcodes.
#
# Uses exec_trace.json (639 real opcodes captured live) to filter the 103KB module
# down to the true instruction stream — separating opcodes from inline data.
#
# Executed opcode frequency (live): op40(14625) op18(8855) op38(6396) op15(3386)
#   op1(785) op63(773) op44(685) op30(358) op37(189) op42(96)...
import json, struct

BASE_VA = 0x17bc6c
# Opcode semantics from handler analysis + live behavior
OPS = {
    40: "LOAD/MOV",       # most frequent — data movement
    18: "FLOAT/strtod",   # float ops
    38: "COMPARE",        # cmp micro-op chain (cset)
    15: "LOAD_SX",        # sign-extend/load micro-op
    44: "BLOCK/dispatch", # block header + next-block dispatch
    1:  "op1",
    63: "op63",
    30: "op30",
    37: "op37",
    42: "TABLE_LOOKUP",
    55: "op55", 12: "op12", 48: "op48", 7: "COND_BRANCH", 9: "op9",
}

def main():
    tr = json.load(open("exec_trace.json"))
    offs = tr["exec_offsets"]   # [[offset, word], ...] sorted by offset
    print(f"[*] {len(offs)} executed opcodes, {tr['total_events']} total events\n")
    from collections import Counter
    hist = Counter(w & 0x3f for _, w in offs)
    print("[*] executed opcode histogram:")
    for op, c in hist.most_common():
        print(f"    op {op:2d} ({OPS.get(op,'?'):14s}): {c}")
    print(f"\n[*] executed instruction stream (by address):")
    for off, w in offs:
        op = w & 0x3f
        operand = w >> 6
        print(f"  0x{off:06x}: {w:08x}  op={op:2d} operand=0x{operand:07x}  {OPS.get(op,'op%d'%op)}")

if __name__ == "__main__":
    main()

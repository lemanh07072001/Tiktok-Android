#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Watchpoint on the [x23] bcptr slot to find what NULLs it.
import os, json, struct
os.chdir(os.path.dirname(os.path.abspath(__file__)))
import _vm_unicorn_v4 as V
from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn.arm64_const import *

so = open(V.SO,"rb").read()
cap = V.load_capture(0)
uc, base = V.setup(so, cap)

x23_slot = int(cap["cpur"]["x23"],16)   # 0x6fc728c770 — holds bcptr
print(f"[watch] x23 slot = 0x{x23_slot:x}")

last_pc = [0]
def code_hook(uc, addr, size, ud):
    last_pc[0] = addr
uc.hook_add(UC_HOOK_CODE, code_hook)

def wr_hook(uc, access, addr, size, value, ud):
    if x23_slot <= addr < x23_slot+8:
        pc = last_pc[0]-base
        print(f"[WRITE] *0x{addr:x} <- 0x{value:x} (size {size}) from pc=0x{pc:x}")
uc.hook_add(UC_HOOK_MEM_WRITE, wr_hook, begin=x23_slot, end=x23_slot+8)

# Also watch dispatches to correlate
disp = [0]
def disp_hook(uc, addr, size, ud):
    code = uc.mem_read(addr, size)
    if struct.unpack_from("<I", code, 0)[0] == 0xd61f01e0:
        disp[0]+=1
        x23 = uc.reg_read(UC_ARM64_REG_X23)
        try:
            bc = struct.unpack_from("<Q", uc.mem_read(x23,8))[0]
            print(f"  --dispatch #{disp[0]} bcptr=0x{(bc-base)&0xffffffffffffffff:x}--")
        except: print(f"  --dispatch #{disp[0]} bcptr=ERR--")
uc.hook_add(UC_HOOK_CODE, disp_hook)

entry = base + V.VM_ENTRY
try:
    uc.emu_start(entry, 0, count=3000)
except Exception as e:
    print(f"[stop] {e}")

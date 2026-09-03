#!/usr/bin/env python3
# Probe: emulate enclosing fn 0x13848c (builds object-graph + calls F), instrument to
# DISCOVER the object contract: which vtable-methods x0/x1/x2 expose, and which keva
# key-IDs get queried. Escaped calls (blr into tagged/invalid ptr) are logged + returned
# gracefully so F never traps and we observe the full call sequence.
import struct, sys
from unicorn import *
from unicorn.arm64_const import *
import _vm_emu as M

ENCLOSE = 0x13848c          # enclosing fn (prologue stp x28,x19)
KEVA_GET = 0x11a64c         # keva accessor (root-fn calls with w0=0x10003)
SEG1_END = 0x1d1808         # end of executable segment
STUB_LO, STUB_HI = M.STUB_BASE, M.STUB_BASE+0x100000

# tagged device-context object regions
X0R=0x21000000; X1R=0x22000000; X2R=0x23000000
REGS={X0R:'x0',X1R:'x1',X2R:'x2'}

e=M.Emu(trace_native=False)
uc=e.uc
for r in (X0R,X1R,X2R):
    uc.mem_map(r,0x100000)
    # fill each region: every 8B slot = tag|offset  (tag high byte distinguishes region)
    tag = (r>>24)&0xff
    buf=b''.join(struct.pack('<Q',(0xC0000000_00000000|(tag<<48)|i)) for i in range(0x20000))
    uc.mem_write(r,buf)

escaped=[]      # (target, lr, x0,x1,x2,x3)
keva=[]         # (lr, w0,w1,x2,x3,x4)
reads=[]        # (region, off, pc)
MAXLOG=120

def in_code(pc): return 0x1000<=pc<SEG1_END
def is_stub(pc): return STUB_LO<=pc<STUB_HI

def hk_code(uc,address,size,user):
    # keva-get logging
    if address==KEVA_GET:
        if len(keva)<MAXLOG:
            keva.append((uc.reg_read(UC_ARM64_REG_LR),
                         uc.reg_read(UC_ARM64_REG_X0)&0xffffffff,
                         uc.reg_read(UC_ARM64_REG_X1)&0xffffffff,
                         uc.reg_read(UC_ARM64_REG_X2),
                         uc.reg_read(UC_ARM64_REG_X3),
                         uc.reg_read(UC_ARM64_REG_X4)))
        return
    # escaped execution (blr into tagged/invalid pointer) -> log + graceful return
    if not in_code(address) and not is_stub(address):
        lr=uc.reg_read(UC_ARM64_REG_LR)
        if len(escaped)<MAXLOG:
            escaped.append((address,lr,
                            uc.reg_read(UC_ARM64_REG_X0),
                            uc.reg_read(UC_ARM64_REG_X1),
                            uc.reg_read(UC_ARM64_REG_X2),
                            uc.reg_read(UC_ARM64_REG_X3)))
        # return: x0=0, PC=LR
        uc.reg_write(UC_ARM64_REG_X0,0)
        uc.reg_write(UC_ARM64_REG_PC,lr)
        return

def hk_read(uc,access,address,size,value,user):
    for r in (X0R,X1R,X2R):
        if r<=address<r+0x100000:
            if len(reads)<MAXLOG:
                reads.append((REGS[r],address-r,uc.reg_read(UC_ARM64_REG_PC)))
            return

uc.hook_add(UC_HOOK_CODE,hk_code)
uc.hook_add(UC_HOOK_MEM_READ,hk_read)

# OUT / slot16 lands via object writes; also watch a scratch
print(f"emulating enclosing fn {ENCLOSE:#x} with tagged x0/x1/x2 ...")
ret=e.call(ENCLOSE,[X0R,X1R,X2R],count_limit=3_000_000)
print(f"ret x0={ret:#x}")
print(f"\n=== keva-get calls ({len(keva)}) [lr, w0=key-id, w1, x2,x3,x4] ===")
for i,(lr,w0,w1,x2,x3,x4) in enumerate(keva):
    print(f"  keva[{i}] from {lr:#x}: id={w0:#x} w1={w1:#x} x2={x2:#x} x3={x3:#x} x4={x4:#x}")
print(f"\n=== escaped calls ({len(escaped)}) [target, caller-lr, x0..x3] ===")
for i,(tgt,lr,x0,x1,x2,x3) in enumerate(escaped[:60]):
    print(f"  esc[{i}] tgt={tgt:#x} lr={lr:#x} x0={x0:#x} x1={x1:#x} x2={x2:#x} x3={x3:#x}")
print(f"\n=== first reads from x0/x1/x2 regions ({len(reads)}) [region, offset, pc] ===")
for i,(rg,off,pc) in enumerate(reads[:40]):
    print(f"  rd[{i}] {rg}+{off:#x} @pc={pc:#x}")

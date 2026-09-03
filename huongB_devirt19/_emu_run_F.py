#!/usr/bin/env python3
# Chạy thử interpreter F @0x52924, quan sát: native-call, ghi OUT, điểm dừng.
import struct, sys
from unicorn import *
from unicorn.arm64_const import *
import _vm_emu as M

e=M.Emu(trace_native=True)
uc=e.uc

PROG=0x191f40; TABA=0x1e0530; TABB=0x1e0560
IN=M.INPUT_BASE; OUT=M.OUT_BASE

# input object-graph: fill với marker 8B mỗi slot = 0xAA00_0000_0000_00ii
buf=b''.join(struct.pack('<Q',0xAA00000000000000|i) for i in range(512))
uc.mem_write(IN,buf)
uc.mem_write(OUT,b'\0'*0x400)

# trace writes to OUT
writes=[]
def hk_w(uc,access,address,size,value,user):
    if OUT<=address<OUT+0x400:
        writes.append((address-OUT,size,value))
uc.hook_add(UC_HOOK_MEM_WRITE,hk_w)

# trace instruction count + last pc
state={'n':0,'last':0}
def hk_c(uc,address,size,user):
    state['n']+=1; state['last']=address
uc.hook_add(UC_HOOK_CODE,hk_c)

print("calling F interpreter 0x52924 ...")
ret=e.call(0x52924,[PROG,IN,TABA,TABB,OUT],count_limit=5_000_000)
print(f"ret x0={ret:#x}  instr executed={state['n']}  last pc={state['last']:#x}")
print(f"native calls (blr x8) count={len(e.native_log)}")
for i,(x8,x0) in enumerate(e.native_log[:20]):
    print(f"  native[{i}] fn={x8:#x} arg0={x0:#x}")
print(f"OUT writes count={len(writes)}")
# dump OUT buffer first 64 bytes
out=uc.mem_read(OUT,64)
print("OUT[0:32]:",out[:32].hex())
print("OUT[32:64]:",out[32:64].hex())

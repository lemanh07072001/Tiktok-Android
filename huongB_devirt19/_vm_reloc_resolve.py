#!/usr/bin/env python3
# Deobfuscate libmetasec VM pointer tables. FINDING (2026-09-03): obfuscated R_AARCH64_RELATIVE
# addends are inflated by a per-GROUP bias; the VM dispatch cluster tables (0x1db360/0x1db430)
# use bias 0xa00000 → real_module_addr = addend - 0xa00000 (verified: resolves to valid .text
# VM-handler code + bytecode continuations). NOTE: only ~12% of all 1745 out-of-module addends
# use 0xa00000; other groups use other biases (min addend 0x3f5638, max 0x14aa9e8) → multi-bias.
import struct, sys
SO=sys.argv[1] if len(sys.argv)>1 else 'bin/libmetasec_ov.so'
data=open(SO,'rb').read(); MOD=0x1fe1e0
e_shoff=struct.unpack_from('<Q',data,0x28)[0]; e_shes=struct.unpack_from('<H',data,0x3a)[0]; e_shn=struct.unpack_from('<H',data,0x3c)[0]
for i in range(e_shn):
    o=e_shoff+i*e_shes
    _,typ,_,_,off,size,_,_,_,_=struct.unpack_from('<IIQQQQIIQQ',data,o)
    if typ==4 and size>0x1000: RO,RS=off,size; break
ADD={}
for k in range(RS//24):
    r_off,r_info,r_add=struct.unpack_from('<QQq',data,RO+k*24)
    if (r_info&0xffffffff)==1027: ADD[r_off]=r_add
def resolve(addend, bias=0xa00000):
    return addend-bias if addend>=bias else addend
def table(tbl_va, n, bias=0xa00000):
    return [resolve(ADD.get(tbl_va+i*8,0),bias) for i in range(n)]
if __name__=='__main__':
    for tv in (0x1db360,0x1db430):
        print(f"table 0x{tv:x}:", [hex(x) for x in table(tv,25)])

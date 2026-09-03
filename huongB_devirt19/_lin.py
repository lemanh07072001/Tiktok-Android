#!/usr/bin/env python3
# _lin.py <lo> <hi> — linear capstone disasm of libmetasec, NO stop at ret (for CFF trampolines).
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
SO='bin/libmetasec_ov.so'
data=open(SO,'rb').read()
e_phoff=struct.unpack_from('<Q',data,0x20)[0]; e_es=struct.unpack_from('<H',data,0x36)[0]; e_pn=struct.unpack_from('<H',data,0x38)[0]
SEGS=[]
for i in range(e_pn):
    o=e_phoff+i*e_es
    if struct.unpack_from('<I',data,o)[0]==1:
        p_off,p_va,_,p_fsz,_=struct.unpack_from('<QQQQQ',data,o+8); SEGS.append((p_va,p_fsz,p_off))
def v2f(v):
    for va,fsz,fo in SEGS:
        if va<=v<va+fsz: return fo+(v-va)
    return None
lo=int(sys.argv[1],16); hi=int(sys.argv[2],16)
note=sys.argv[3] if len(sys.argv)>3 else ''
fo=v2f(lo); code=data[fo:fo+(hi-lo)]
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=False
print("=== %s  %#x..%#x ==="%(note,lo,hi))
for i in md.disasm(code, lo):
    print("  0x%06x  %-8s %s"%(i.address, i.mnemonic, i.op_str))

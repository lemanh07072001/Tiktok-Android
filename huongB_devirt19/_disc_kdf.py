#!/usr/bin/env python3
# Hướng C — thí nghiệm phân loại (a)/(b): disasm hàm cha 0x13848c + seedgen 0x10ac2c.
# Mục tiêu: liệt kê MỌI bl/blr trong hàm cha, phân loại đích:
#   - bl tới crypto-core tĩnh (AES 0x1591bc / SHA 0x15bb00 / SM3 0xa07c8 / MD5?)  → (a) offline-crackable
#   - blr [reg] (virtual dispatch)                                                  → (b) runtime vtable
# In cả chuỗi để thấy: seedgen -> ??? -> F(0x1384e4 bl 0x52924).
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SO='bin/libmetasec_ov.so'
data=open(SO,'rb').read()

# ELF: map file-offset == vaddr for PT_LOAD (module VMA == file VMA per _vm_emu.py)
def u16(o): return struct.unpack_from('<H',data,o)[0]
def u32(o): return struct.unpack_from('<I',data,o)[0]
def u64(o): return struct.unpack_from('<Q',data,o)[0]
e_phoff=u64(0x20); e_phes=u16(0x36); e_phn=u16(0x38)
SEGS=[]
for i in range(e_phn):
    o=e_phoff+i*e_phes
    if u32(o)==1:
        p_off,p_va,_,p_fsz,p_msz=struct.unpack_from('<QQQQQ',data,o+8)
        SEGS.append((p_va,p_off,p_fsz))
def va2off(va):
    for p_va,p_off,p_fsz in SEGS:
        if p_va<=va<p_va+p_fsz: return p_off+(va-p_va)
    return None

md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True

KNOWN={0x1591bc:'AES_core',0x10d068:'AES_enc_facade',0x10d124:'AES_dec_facade',
       0x15bb00:'SHA_core',0xa07c8:'SM3_core',0x52924:'VM_interp(F)',
       0x11a64c:'keva_get',0x10ac2c:'seedgen',0x10ac80:'idxVM',0x5594c:'native_call'}

def disasm_fn(start, maxlen=0x600, label=''):
    off=va2off(start)
    if off is None:
        print(f"[!] {start:#x} not in file"); return []
    code=data[off:off+maxlen]
    calls=[]
    print(f"\n===== {label} @ {start:#x} =====")
    for ins in md.disasm(code, start):
        m=ins.mnemonic; op=ins.op_str
        tag=''
        if m in ('bl','b'):
            try:
                tgt=int(op,16)
                nm=KNOWN.get(tgt,'')
                if nm: tag=f'   <-- {nm}'
                calls.append((ins.address,m,tgt,nm))
            except: pass
        elif m in ('blr','br'):
            tag='   <-- INDIRECT (virtual dispatch)'
            calls.append((ins.address,m,None,'INDIRECT'))
        # stop heuristics: ret at top level is not reliable; print window only
        print(f"  {ins.address:#08x}: {m:6} {op}{tag}")
        if ins.address-start>maxlen-8: break
    return calls

c1=disasm_fn(0x13848c, 0x160, 'enclosing-fn (object-graph + F call)')
c2=disasm_fn(0x10ac2c, 0x120, 'seedgen wrapper')
print("\n===== CALL SUMMARY (enclosing-fn) =====")
for a,m,t,n in c1:
    print(f"  {a:#x}: {m} {'->'+hex(t) if t is not None else '[reg]'} {n}")

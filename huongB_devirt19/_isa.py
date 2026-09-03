#!/usr/bin/env python3
# Dựng ISA của devirt-VM: disasm từng handler, tìm phép ALU lõi tác động lên register-file (x24).
# handler_thật = decoded_entry − 0x9b374. In ~30 lệnh đầu mỗi handler + đánh dấu op số học.
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
SO='bin/libmetasec_ov.so'; data=open(SO,'rb').read()
def u16(o): return struct.unpack_from('<H',data,o)[0]
def u32(o): return struct.unpack_from('<I',data,o)[0]
def u64(o): return struct.unpack_from('<Q',data,o)[0]
e_phoff=u64(0x20); e_phes=u16(0x36); e_phn=u16(0x38)
SEGS=[]
for i in range(e_phn):
    o=e_phoff+i*e_phes
    if u32(o)==1:
        p_off,p_va,_,p_fsz,p_msz=struct.unpack_from('<QQQQQ',data,o+8); SEGS.append((p_va,p_off,p_fsz))
def va2off(va):
    for p_va,p_off,p_fsz in SEGS:
        if p_va<=va<p_va+p_fsz: return p_off+(va-p_va)
    return None
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
BIAS=0x9b374
# decoded entries (từ _vm_static_decode x30=0x52924)
ENTRY={0x01:0x0f488c,0x03:0x0f34bc,0x04:0x0f52fc,0x05:0x0f5544,0x0f:0x0f4a88,0x11:0x0f50b8,
0x13:0x0f4c98,0x14:0x0f6454,0x16:0x0f76b8,0x19:0x0f66f8,0x1a:0x0f62a8,0x1e:0x0f40e0,
0x21:0x0f4f68,0x24:0x0f5348,0x25:0x0f4db0,0x26:0x0f3dc8,0x28:0x0f6b58,0x29:0x0f55c0,
0x30:0x0f46c0,0x31:0x0f780c,0x32:0x0f7c04,0x34:0x0f7288,0x35:0x0f58c8,0x36:0x0f5128,
0x37:0x0f42b8,0x38:0x0f3f2c,0x39:0x0f7090,0x3b:0x0f7584,0x3c:0x0f5a38,0x3d:0x0f7d74,0x3f:0x0f6d24}
ALUMN={'add','sub','eor','orr','and','lsl','lsr','asr','ror','mul','madd','bic','orn','eon','rev','clz','extr','rbit','umulh','smulh','mvn','adc','sbc'}
import sys
ops = [int(x,0) for x in sys.argv[1:]] or [0x25,0x34,0x21,0x30,0x31,0x14,0x1a,0x26,0x0f,0x01,0x24,0x19,0x37,0x38]
for op in ops:
    ent=ENTRY.get(op)
    if ent is None:
        print(f"op {op:#x}: no entry"); continue
    h=(ent-BIAS)&0xffffffffffffffff
    off=va2off(h); code=data[off:off+0x400]
    lines=[]
    for ins in md.disasm(code,h):
        lines.append((ins.address,ins.mnemonic,ins.op_str))
        if ins.mnemonic=='ret': break
        if ins.address-h>0x3f0: break
    # tìm các lệnh chạm register-file (x24) hoặc index (x25); và ALU op quanh đó
    print(f"\n=== op {op:#04x}  handler {h:#x}  (len {len(lines)} ins) ===")
    for i,(a,m,o) in enumerate(lines):
        touch24 = 'x24' in o
        isalu = m in ALUMN
        if touch24 or isalu:
            # in cả ngữ cảnh: chỉ dòng liên quan
            mark = ' <RF>' if touch24 else (' *' if isalu else '')
            print(f"   {a:#08x}: {m} {o}{mark}")

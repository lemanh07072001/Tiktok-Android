#!/usr/bin/env python3
# Với mỗi trong 41 call-site của VM-interp 0x52924, lùi lại tìm x0 (program pointer) qua adrp+add.
# Cũng lấy x4 (OUT) và x1 (frame) khi thấy. Mục tiêu: liệt kê tập PROGRAM phân biệt → tìm KDF.
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
        p_off,p_va,_,p_fsz,p_msz=struct.unpack_from('<QQQQQ',data,o+8)
        SEGS.append((p_va,p_off,p_fsz))
def va2off(va):
    for p_va,p_off,p_fsz in SEGS:
        if p_va<=va<p_va+p_fsz: return p_off+(va-p_va)
    return None
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True

CALLSITES=[0x4fc1c,0x5f1dc,0x76600,0x766e0,0x768ec,0x817b8,0x818ec,0x819f0,0x81f48,
0x936f4,0x93860,0x95a98,0x962f4,0x9a1fc,0x9a274,0x9a908,0x9b3d8,0x9fd70,0x9ff18,
0xb5bcc,0xb5cac,0xb5d30,0xb5dbc,0xb5f2c,0xbc1c0,0xbd3a4,0xc1e6c,0xcff9c,0xe04ac,
0xe0ec0,0x10ac80,0x116bc8,0x116c54,0x117e6c,0x1279a0,0x1384e4,0x1426c0,0x144b7c,
0x144c04,0x144cf8,0x145ef8]

def recover_args(callva, back=0x90):
    off=va2off(callva-back)
    code=data[off:off+back+4]
    # track adrp results and final add into x0..x4
    reg_page={}   # reg -> page base
    args={}       # regnum -> value  (for x0..x4)
    for ins in md.disasm(code, callva-back):
        if ins.address>callva: break
        m=ins.mnemonic; ops=ins.op_str
        if m=='adrp':
            parts=ops.split(', ')
            rd=parts[0]; imm=int(parts[1].lstrip('#'),16)
            reg_page[rd]=imm
        elif m=='add':
            parts=ops.split(', ')
            if len(parts)==3 and parts[1] in reg_page and parts[2].startswith('#'):
                rd=parts[0]; base=reg_page[parts[1]]; imm=int(parts[2][1:],16)
                # if rd is xN we care
                if rd in ('x0','x2','x3','x4','x1'):
                    args[rd]=base+imm
                reg_page[rd]=base+imm  # chain
        elif m=='mov':
            parts=ops.split(', ')
            # mov x1, sp etc — mark as frame
            if len(parts)==2 and parts[0] in ('x1','x4'):
                args[parts[0]]=parts[1]
    return args

seen_prog={}
rows=[]
for cs in CALLSITES:
    a=recover_args(cs)
    prog=a.get('x0')
    rows.append((cs,prog,a.get('x2'),a.get('x3'),a.get('x4')))
    if prog is not None:
        seen_prog.setdefault(prog,[]).append(cs)
print("call-site   x0(prog)   x2(tblA)   x3(tblB)   x4(out)")
for cs,p,t2,t3,o in rows:
    ps = f'{p:#x}' if isinstance(p,int) else str(p)
    t2s= f'{t2:#x}' if isinstance(t2,int) else str(t2)
    t3s= f'{t3:#x}' if isinstance(t3,int) else str(t3)
    os_= f'{o:#x}' if isinstance(o,int) else str(o)
    print(f"  {cs:#08x}  {ps:>10}  {t2s:>10}  {t3s:>10}  {os_:>10}")
print(f"\n=== DISTINCT PROGRAMS ({len(seen_prog)}) ===")
for p,css in sorted(seen_prog.items()):
    print(f"  prog {p:#x}: {len(css)} call-site(s)  e.g. {hex(css[0])}")

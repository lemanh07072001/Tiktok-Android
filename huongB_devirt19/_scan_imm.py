import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
so='bin/libmetasec_ov.so'
imms=[int(x,0) for x in sys.argv[1:]] or [0x57,0x27]
f=open(so,'rb'); e=ELFFile(f)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
rows=[]
for s in e.iter_segments():
    if s['p_type']!='PT_LOAD' or not (s['p_flags']&1): continue
    v=s['p_vaddr']; o=s['p_offset']; fsz=s['p_filesz']
    f.seek(o); data=f.read(fsz)
    for i in md.disasm(data,v):
        if i.mnemonic in ('add','sub','orr','cmp','eor') and '#' in i.op_str:
            try: val=int(i.op_str.split('#')[1].split(',')[0].rstrip(']!'),0)
            except: continue
            if val in imms and ('w' in i.op_str.split(',')[0]):
                rows.append((i.address,i.mnemonic,i.op_str,val))
# cluster: show 0x57 hits with a nearby 0x30 or 0x0a within +-8 instrs (approx by addr within 64 bytes)
by=sorted(rows,key=lambda r:r[0])
print("total imm hits:",len(by))
for a,mn,ops,val in by:
    print("0x%06x  %-4s %-24s (#0x%x)"%(a,mn,ops,val))

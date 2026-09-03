import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
so='bin/libmetasec_ov.so'
target_fileoff=int(sys.argv[1],0)   # file offset of the rodata symbol
f=open(so,'rb'); e=ELFFile(f)
segs=[s for s in e.iter_segments() if s['p_type']=='PT_LOAD']
def o2v(off):
    for s in segs:
        o=s['p_offset']; fsz=s['p_filesz']; v=s['p_vaddr']
        if o<=off<o+fsz: return v+(off-o)
    return None
def v2o(va):
    for s in segs:
        o=s['p_offset']; fsz=s['p_filesz']; v=s['p_vaddr']
        if v<=va<v+fsz: return o+(va-v)
    return None
TVA=o2v(target_fileoff)
print("target rodata VA = 0x%x (file 0x%x)"%(TVA, target_fileoff))
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=False
hits=[]
for s in segs:
    if not (s['p_flags'] & 0x1): continue  # exec only
    v=s['p_vaddr']; o=s['p_offset']; fsz=s['p_filesz']
    f.seek(o); data=f.read(fsz)
    reg={}
    for i in md.disasm(data,v):
        if i.mnemonic=='adrp':
            try:
                rd=i.op_str.split(',')[0].strip()
                page=int(i.op_str.split('#')[1],0)
                reg[rd]=page
            except: pass
        elif i.mnemonic in ('add','ldr','ldrb') and '#' in i.op_str:
            parts=[p.strip() for p in i.op_str.split(',')]
            # add xd, xn, #imm  |  ldr xd,[xn,#imm]
            base=None; imm=None; rd=parts[0]
            for p in parts:
                if p.startswith('x') and p in reg: base=reg[p]
            m=i.op_str.split('#')
            if len(m)>1:
                try: imm=int(m[1].rstrip(']!'),0)
                except: imm=None
            if base is not None and imm is not None and base+imm==TVA:
                hits.append((i.address,i.mnemonic,i.op_str))
            if i.mnemonic=='add' and rd in reg: pass
print("HITS referencing target:")
for h in hits[:40]: print("  0x%05x  %-6s %s"%h)
print("total",len(hits))

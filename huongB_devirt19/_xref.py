import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
so='bin/libmetasec_ov.so'
target=int(sys.argv[1],0)
mnemos=set(sys.argv[2].split(',')) if len(sys.argv)>2 else {'bl'}
f=open(so,'rb'); e=ELFFile(f)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=False
hits=[]
for s in e.iter_segments():
    if s['p_type']!='PT_LOAD': continue
    if not (s['p_flags'] & 0x1): continue   # exec only
    va=s['p_vaddr']; off=s['p_offset']; fsz=s['p_filesz']
    data=s.data() if hasattr(s,'data') else None
    f.seek(off); data=f.read(fsz)
    for i in md.disasm(data, va):
        if i.mnemonic in mnemos:
            try: t=int(i.op_str,16)
            except: continue
            if t==target:
                hits.append((i.address,i.mnemonic,i.op_str))
for a,m,o in hits:
    print('0x%05x  %-6s %s'%(a,m,o))
print('# %d xref(s) to 0x%x via {%s}'%(len(hits),target,','.join(sorted(mnemos))))

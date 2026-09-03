import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
so='bin/libmetasec_ov.so'
va0=int(sys.argv[1],0); va1=int(sys.argv[2],0)
f=open(so,'rb'); e=ELFFile(f)
# map va->file offset via PT_LOAD
def v2o(va):
    for s in e.iter_segments():
        if s['p_type']!='PT_LOAD': continue
        vaddr=s['p_vaddr']; msz=s['p_memsz']; off=s['p_offset']; fsz=s['p_filesz']
        if vaddr<=va<vaddr+fsz:
            return off+(va-vaddr)
    return None
o=v2o(va0)
f.seek(o); data=f.read(va1-va0)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=False
for i in md.disasm(data,va0):
    mark=''
    if i.mnemonic=='bl': mark=' <== CALL'
    if i.mnemonic.startswith('str') or i.mnemonic.startswith('stp'): mark=' <== STORE'
    if i.address==0x9fdac or 'x0' in i.op_str[:3]: 
        if not mark: mark=''
    print('0x%05x  %-8s %s%s'%(i.address,i.mnemonic,i.op_str,mark))

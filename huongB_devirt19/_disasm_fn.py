import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SO="bin/libmetasec_ov.so"
f=open(SO,"rb"); elf=ELFFile(f)
segs=[]
for s in elf.iter_segments():
    if s['p_type']=='PT_LOAD':
        segs.append((s['p_vaddr'], s['p_offset'], s['p_filesz']))
def v2o(va):
    for vaddr,off,sz in segs:
        if vaddr<=va<vaddr+sz: return off+(va-vaddr)
    return None
data=open(SO,"rb").read()
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dis(lo,hi,note=""):
    o=v2o(lo); print("=== %s  disasm 0x%x..0x%x (off 0x%x) ==="%(note,lo,hi,o))
    code=data[o:o+(hi-lo)]
    for ins in md.disasm(code,lo):
        mark=""
        if ins.mnemonic=="bl": mark=" <-- BL"
        if ins.mnemonic in ("stp","str","stur") : mark=" [store]"
        if ins.mnemonic in ("stp",) and ('x29' in ins.op_str and 'x30' in ins.op_str): mark=" <== PROLOGUE"
        print("  0x%06x  %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,mark))
args=sys.argv[1:]
if len(args)>=2: dis(int(args[0],16),int(args[1],16),args[2] if len(args)>2 else "")
else:
    # SM3-caller function region
    dis(0xa0140,0xa0300,"SM3-caller-around-0xa02ac")

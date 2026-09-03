# _dis.py — capstone disassembler over the live-decrypted code dump (module-relative addrs).
import sys,json
from capstone import *
from capstone.arm64 import *
meta=json.load(open('_code_dump_meta.json'))
BASE=int(meta['base'],16)
data=open('_code_dump.bin','rb').read()  # dump starts at module base (offset 0)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
def dis(off,n=40):
    code=data[off:off+n*4]
    out=[]
    for ins in md.disasm(code, off):
        out.append(ins)
    return out
def show(off,n=40,label=''):
    print("==== func @0x%x %s ===="%(off,label))
    cnt=0
    for ins in dis(off,n):
        # annotate adrp+page, bl targets
        extra=''
        if ins.mnemonic=='bl':
            extra=' -> 0x%x'%ins.operands[0].imm if ins.operands and ins.operands[0].type==ARM64_OP_IMM else ''
        if ins.mnemonic in ('adrp',):
            extra=' (page 0x%x)'%(ins.operands[1].imm if len(ins.operands)>1 else 0)
        print("  0x%06x: %-8s %s%s"%(ins.address,ins.mnemonic,ins.op_str,extra))
        cnt+=1
    if cnt==0: print("  [n=0]")
    print()
if __name__=='__main__':
    for a in sys.argv[1:]:
        show(int(a,16), 44)

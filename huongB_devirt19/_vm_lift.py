#!/usr/bin/env python3
# _vm_lift.py — reconstruct the full 32-register file evolution from a _vm_trace*.json and
# annotate each step (classify load-imm / shift / insert / mix) to lift opcode semantics.
import json, sys

def load(f):
    d=json.load(open(f)); rows=[]
    for m in d:
        if m.get('t')=='tr': rows.extend(m['rows'])
    rows.sort(key=lambda r:r['s']); return rows

def u64(hexle):  # 8-byte little-endian hex -> int
    b=bytes.fromhex(hexle); return int.from_bytes(b,'little')

def classify(old, new):
    if old is None: return 'INIT'
    if new==0: return 'zero'
    # shift right by 8/16 (bytes)?
    for k in (8,16,24,32,40,48,56):
        if new==(old>>k): return 'shr%d'%k
        if new==((old<<k)&((1<<64)-1)): return 'shl%d'%k
    # rotate?
    for k in range(1,64):
        if new==(((old>>k)|(old<<(64-k)))&((1<<64)-1)): return 'ror%d'%k
        if new==(((old<<k)|(old>>(64-k)))&((1<<64)-1)): return 'rol%d'%k
    return '?'

def main():
    f=sys.argv[1] if len(sys.argv)>1 else '_vm_trace600_out.json'
    rows=load(f)
    rf=[None]*32
    print('=== %s : %d steps ==='%(f,len(rows)))
    for r in rows:
        s=r['s']; pc=r['pc']; notes=[]
        for reg,val in r['d']:
            old=rf[reg]; nv=u64(val)
            cls=classify(old,nv)
            oldh='%016x'%old if old is not None else '--'
            notes.append('r%d:%s->%s[%s]'%(reg,oldh,val,cls))
            rf[reg]=nv
        if notes:
            print('s%-4d %-9s %s'%(s,pc,' '.join(notes)))
    # final regfile
    print('--- final regfile ---')
    for i in range(0,32,4):
        print('  r%-2d..%-2d '%(i,i+3)+' '.join(('%016x'%rf[j] if rf[j] is not None else '--') for j in range(i,min(i+4,32))))

if __name__=='__main__': main()

#!/usr/bin/env python3
# Opcode census cho 35 VM program. Với mỗi program [start,next): đọc word 32-bit, histogram op=word&0x3f.
# F(0x191f40) marshaller phải trội op18(0x12)/op42(0x2a)/op44(0x2c). KDF crypto phải nhiều op khác (ALU).
import struct
SO='bin/libmetasec_ov.so'; data=open(SO,'rb').read()
def u16(o): return struct.unpack_from('<H',data,o)[0]
def u32o(o): return struct.unpack_from('<I',data,o)[0]
def u64(o): return struct.unpack_from('<Q',data,o)[0]
e_phoff=u64(0x20); e_phes=u16(0x36); e_phn=u16(0x38)
SEGS=[]
for i in range(e_phn):
    o=e_phoff+i*e_phes
    if u32o(o)==1:
        p_off,p_va,_,p_fsz,p_msz=struct.unpack_from('<QQQQQ',data,o+8)
        SEGS.append((p_va,p_off,p_fsz))
def va2off(va):
    for p_va,p_off,p_fsz in SEGS:
        if p_va<=va<p_va+p_fsz: return p_off+(va-p_va)
    return None

PROGS=sorted([0x17bbf0,0x17c0a0,0x17c750,0x17c880,0x17cbd0,0x17d9d0,0x17dd00,0x17de80,0x17e530,
0x17f940,0x17f9c0,0x1814f0,0x184780,0x184ed0,0x1863e0,0x186480,0x1864f0,0x186600,0x1873c0,
0x187e50,0x188370,0x188ee0,0x189250,0x189e30,0x18a510,0x18b020,0x18cd10,0x18f430,0x18fa80,
0x190140,0x1909b0,0x191f40,0x193130,0x193bf0,0x193e70])
# end of blob: use start of next program; last program ends at end-of-seg-or +0x2000
ENDCAP=0x196000

NAMES={0x18f430:'seedgen',0x191f40:'F/marshal',0x1864f0:'report'}

def census(start,end):
    off=va2off(start)
    n=(end-start)//4
    from collections import Counter
    c=Counter()
    for i in range(n):
        w=struct.unpack_from('<I',data,off+i*4)[0]
        c[w&0x3f]+=1
    return c,n

print(f"{'prog':>10} {'size':>6} {'name':>10}  top-opcodes(op:count)")
for idx,p in enumerate(PROGS):
    end=PROGS[idx+1] if idx+1<len(PROGS) else ENDCAP
    c,n=census(p,end)
    top=c.most_common(6)
    tp=' '.join(f'{op:#04x}:{cnt}' for op,cnt in top)
    # ALU-ish score: fraction NOT in {0x12,0x2a,0x2c}
    marsh=c.get(0x12,0)+c.get(0x2a,0)+c.get(0x2c,0)
    frac_alu=1-(marsh/max(1,n))
    print(f"{p:#010x} {(end-p):>6} {NAMES.get(p,''):>10}  aluFrac={frac_alu:.2f}  {tp}")

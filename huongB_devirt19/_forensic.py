import json, collections
LINES=open('_vm_trace11.out.jsonl').read().splitlines()
trig=json.loads(LINES[0])
E=[json.loads(l) for l in LINES[1:] if l.strip()]; E.sort(key=lambda e:e['seq'])

slot16=trig['slot16']  # 6c109094bc9ab89e050fbd3e2ca6b99e
# candidate needles: slot16 halves, byteswapped halves, buffer ptr
def bswap(hx):
    b=bytes.fromhex(hx); return b[::-1].hex()
w0=slot16[:16]; w1=slot16[16:]
needles={
 'slot16_w0':w0,'slot16_w1':w1,
 'slot16_w0_bswap':bswap(w0),'slot16_w1_bswap':bswap(w1),
 'bufptr_77e4e63fa0':'77e4e63fa0',
}
print("slot16 =",slot16)
print("needles:",needles)

# search every regfile
hits=collections.defaultdict(list)
allrf=[('trig',trig['rf'])]+[(str(e['seq']),e['rf']) for e in E]
for tag,rfl in allrf:
    for r,v in enumerate(rfl):
        for nm,nd in needles.items():
            if nd in v:
                hits[nm].append((tag,r,v))
print("\n=== needle hits ===")
for nm in needles:
    print(f"  {nm}: {len(hits[nm])} hits", hits[nm][:6])

# bc histogram: which bytecode addrs dominate + loop detection
bc_hist=collections.Counter(e['bc'] for e in E)
print("\n=== top 15 bc by frequency (bc, op, count) ===")
op_of={}
for e in E: op_of[e['bc']]=e['op']
for bc,c in bc_hist.most_common(15):
    print(f"  bc={bc}(0x{bc:x}) op{op_of[bc]:2d}  x{c}")

# tail 25 steps with full changed-reg diff (excluding r31 pc)
NREG=32
def rf(e): return [int(x,16) for x in e['rf']]
print("\n=== tail 25 steps (seq op bc | sem-changed) ===")
for i in range(len(E)-26,len(E)):
    e=E[i]; cur=rf(e)
    nxt=rf(E[i+1]) if i+1<len(E) else None
    ch=[]
    if nxt:
        for r in range(NREG):
            if r!=31 and cur[r]!=nxt[r]: ch.append(f"r{r}:{cur[r]:x}->{nxt[r]:x}")
    print(f"  {e['seq']:3d} op{e['op']:2d} bc0x{e['bc']:x} | {' , '.join(ch) if ch else '(last/none)'}")

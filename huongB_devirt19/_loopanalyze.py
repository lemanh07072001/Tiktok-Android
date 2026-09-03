import json
LINES=open('_vm_trace11.out.jsonl').read().splitlines()
E=[json.loads(l) for l in LINES[1:] if l.strip()]; E.sort(key=lambda e:e['seq'])
NREG=32
def rf(e): return [int(x,16) for x in e['rf']]
def semdiff(i):
    cur=rf(E[i]); nxt=rf(E[i+1]) if i+1<len(E) else None
    ch=[]
    if nxt:
        for r in range(NREG):
            if r!=31 and cur[r]!=nxt[r]: ch.append((r,cur[r],nxt[r]))
    return ch

# 1) The 281x op40 loop @0x190778 : find all seq at that bc, show first 6 + last 3
target=0x190778
idxs=[i for i,e in enumerate(E) if e['bc']==target]
print(f"=== op40 loop @0x{target:x}: {len(idxs)} iters, seqs {idxs[0]}..{idxs[-1]} contiguous? {idxs==list(range(idxs[0],idxs[0]+len(idxs)))} ===")
for k in list(range(6))+[len(idxs)-2,len(idxs)-1]:
    i=idxs[k]
    ch=semdiff(i)
    print(f"  iter{k:3d} seq{E[i]['seq']} | "+' , '.join(f"r{r}:{o:x}->{n:x}" for r,o,n in ch))

# what surrounds this loop (the 3 before, 3 after)
lo=idxs[0]; hi=idxs[-1]
print("\n--- 3 steps BEFORE loop ---")
for i in range(lo-3,lo):
    print(f"  seq{E[i]['seq']} op{E[i]['op']} bc0x{E[i]['bc']:x} | "+' , '.join(f"r{r}:{o:x}->{n:x}" for r,o,n in semdiff(i)))
print("--- 3 steps AFTER loop ---")
for i in range(hi+1,hi+4):
    print(f"  seq{E[i]['seq']} op{E[i]['op']} bc0x{E[i]['bc']:x} | "+' , '.join(f"r{r}:{o:x}->{n:x}" for r,o,n in semdiff(i)))

# 2) The 6x round loop 0x190a98..0x190d4c — show the full body of round 0 and round 5
print("\n=== 6x round loop: dump body of iteration 0 and iteration 5 ===")
body_bcs=[0x190a98,0x190ac4,0x190b1c,0x190b64,0x190b84,0x190bac,0x190bf0,0x190c14,0x190c88,0x190cc4,0x190d00,0x190d28,0x190d4c]
# find seq ranges: all steps whose bc in [0x190a98 .. 0x190e00]
loopidx=[i for i,e in enumerate(E) if 0x190a98<=e['bc']<=0x190e00]
print(f"  loop region steps: {len(loopidx)} (seq {E[loopidx[0]]['seq']}..{E[loopidx[-1]]['seq']})")
# print first 22 steps of the region (≈ 1 full round) and note back-edge
for i in loopidx[:24]:
    print(f"  seq{E[i]['seq']:3d} op{E[i]['op']:2d} bc0x{E[i]['bc']:x} | "+' , '.join(f"r{r}:{o:x}->{n:x}" for r,o,n in semdiff(i)))

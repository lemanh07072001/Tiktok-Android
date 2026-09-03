#!/usr/bin/env python3
# _difflift.py — differential register-delta lifter over _vm_trace11.out.jsonl
# Grounded on captured trace only. For each step N: diff rf@N vs rf@N+1 to find
# which VM register(s) changed = the write performed by handler at step N.
import json, sys, collections

LINES = open('_vm_trace11.out.jsonl').read().splitlines()
trig = json.loads(LINES[0])
entries = [json.loads(l) for l in LINES[1:] if l.strip()]
entries.sort(key=lambda e: e['seq'])
NREG = 32

# opcode -> semantic label (from disasm, prior sessions)
OPSEM = {
 18:'LD.u64  reg[d]=*(u64*)(reg[base]+imm16)',
 40:'LD.i32  reg[d]=sext32(*(i32*)(reg[base]+imm16))',
 63:'LD.u8   reg[d]=*(u8*)(reg[base]+sext16(imm))',
 30:'ADDi    reg[d]=(i32)reg[base]+sext16(imm)',
 44:'SUBDISP 2nd-level (ASR/EOR/ALU hidden)',
 15:'op15    ?',1:'op1     ?',38:'op38    ?',37:'op37    ?',
  5:'op5     ?',42:'op42    ?',48:'op48 store?',55:'op55 ?',
  7:'op7 ?',9:'op9 ?',17:'op17 multi-variant',
}

def rf(e): return [int(x,16) for x in e['rf']]

# Build per-step deltas
steps=[]
for i,e in enumerate(entries):
    cur=rf(e)
    nxt=rf(entries[i+1]) if i+1<len(entries) else None
    changed=[]
    if nxt is not None:
        for r in range(NREG):
            if cur[r]!=nxt[r]:
                changed.append((r,cur[r],nxt[r]))
    steps.append(dict(seq=e['seq'],op=e['op'],bc=e['bc'],iw=e['iw'],changed=changed))

# reg31 = PC mirror; strip it from "semantic" changed set
def sem_changed(st):
    return [c for c in st['changed'] if c[0]!=31]

# Summary stats
op_hist=collections.Counter(s['op'] for s in steps)
nchg=collections.Counter(len(sem_changed(s)) for s in steps)
print("=== op histogram ===", dict(sorted(op_hist.items())))
print("=== #sem-changed-regs per step ===", dict(sorted(nchg.items())))

# Which dest regs are written, by op
dest_by_op=collections.defaultdict(collections.Counter)
for s in steps:
    for (r,o,n) in sem_changed(s):
        dest_by_op[s['op']][r]+=1
print("\n=== dest-reg written per op (reg:count) ===")
for op in sorted(dest_by_op):
    print(f"  op{op:2d} {OPSEM.get(op,'?')[:24]:24s} -> {dict(dest_by_op[op].most_common(6))}")

# Dump first 40 steps as linear listing
print("\n=== first 40 steps (seq op bc | dest: old->new) ===")
for s in steps[:40]:
    sc=sem_changed(s)
    ds=' , '.join(f"r{r}:{o:x}->{n:x}" for (r,o,n) in sc) if sc else '(no sem write)'
    print(f"  {s['seq']:3d} op{s['op']:2d} bc{s['bc']:7d} | {ds}")

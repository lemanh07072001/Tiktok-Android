#!/usr/bin/env python3
# Parse _hook_dump.js output (Python dict repr per line) and analyze the 16 producer captures.
# Goal: identify which arg is the CONSTANT PSK (32B) and which is the VARYING seed, verify out==outAtStore,
# and confirm the 3 schedule tables + round0 state are present, so we can reimplement F offline.
import ast, sys, collections

path = sys.argv[1] if len(sys.argv) > 1 else '_hookdump_2026-08-27.log'
recs = []
for line in open(path):
    line = line.strip()
    if "'t': 'DUMP'" not in line:
        continue
    try:
        recs.append(ast.literal_eval(line))
    except Exception as e:
        print('PARSE FAIL:', e); continue

print(f'== {len(recs)} DUMP records ==\n')

# 1) per-arg: reg value + first 16 bytes of pointed mem, across records -> spot constant vs varying
print('== ARG analysis (x0..x7): reg ptr + pointed mem[0:32hex] ==')
for i in range(8):
    regs = []
    mems = []
    for r in recs:
        a = r['args'][i]
        regs.append(a['r'])
        mems.append(a['mem'])
    uniq_mem = collections.Counter(m for m in mems if m)
    nptr = sum(1 for m in mems if m)
    tag = ''
    if nptr:
        if len(uniq_mem) == 1:
            tag = 'CONSTANT-mem'
        elif len(uniq_mem) >= max(2, len(recs)-2):
            tag = 'VARYING-mem'
        else:
            tag = f'{len(uniq_mem)} distinct mems'
    print(f'  x{i}: {nptr}/{len(recs)} look like ptr; {tag}')
    if nptr and len(uniq_mem) <= 4:
        for m, c in uniq_mem.most_common():
            print(f'        mem={m[:64]} (x{c})')

print()
# 2) output consistency
print('== OUTPUT (32B at [x9+8]) per record ==')
for idx, r in enumerate(recs):
    out = r.get('out'); oas = r.get('outAtStore')
    same = 'same' if out == oas else 'DIFF'
    kw = r.get('known')
    print(f'  #{r["n"]:2}: out={out}  ({same} as store)  known={kw}')

print()
# 3) tables + round0 presence
print('== state presence ==')
for r in recs:
    t = r.get('tables'); r0 = r.get('round0')
    tlen = len(t)//2 if t else 0
    print(f'  #{r["n"]:2}: tables={tlen}B  round0={"yes" if r0 else "NO"}  x9={r.get("x9")}  sp={r.get("spStore")}')

# 4) dump the full first record's tables split into 3, for manual inspection
if recs:
    r = recs[0]
    t = r.get('tables')
    print('\n== record #1 schedule tables (3x256B) ==')
    if t:
        for k, name in enumerate(['T0(sp)   ','T1(sp+100)','T2(sp+200)']):
            seg = t[k*512:(k+1)*512]
            print(f'  {name}: {seg}')
    print('\n== record #1 round0 regs x0..x28 ==')
    r0 = r.get('round0')
    if r0:
        for i in range(29):
            print(f'    x{i}={r0.get("x"+str(i))}', end='  ')
            if i % 4 == 3: print()
        print()
        print('    sp=', r0.get('sp'))

#!/usr/bin/env python3
# Deeper analysis: diff the 3 schedule tables across records to separate KEY(constant) vs MESSAGE(varying),
# render T2 as ASCII, and correlate the varying input with the varying output bytes.
import ast, sys, collections

path = sys.argv[1] if len(sys.argv) > 1 else '_hookdump_2026-08-27.log'
recs = [ast.literal_eval(l.strip()) for l in open(path) if "'t': 'DUMP'" in l]
print(f'== {len(recs)} records ==\n')

def words(hexstr):  # 4-byte little-endian words as list of hex (as stored)
    return [hexstr[i:i+8] for i in range(0, len(hexstr), 8)]

def tables(r):
    t = r['tables']
    return [t[0:512], t[512:1024], t[1024:1536]]  # T0, T1, T2 (256B each)

# 1) per-table: which of the 64 words are CONSTANT across all records vs VARY
print('== table word variability (64 words each; C=constant across 16 recs, .=varies) ==')
for ti, name in enumerate(['T0','T1','T2']):
    cols = []
    ref = words(tables(recs[0])[ti])
    varymask = []
    for wi in range(64):
        vals = set(words(tables(r)[ti])[wi] for r in recs)
        varymask.append('C' if len(vals)==1 else '.')
    print(f'  {name}: '+''.join(varymask))
    nconst = varymask.count('C')
    print(f'       {nconst}/64 constant, {64-nconst}/64 vary')

# 2) render T2 as ASCII for first 3 records (message content)
print('\n== T2 as bytes->ascii (message), records 1..3 ==')
def to_ascii(hexstr):
    b = bytes.fromhex(hexstr)
    return ''.join(chr(c) if 32<=c<127 else '.' for c in b)
for r in recs[:3]:
    t2 = tables(r)[2]
    print(f'  #{r["n"]}: {to_ascii(t2)}')

# 3) T0/T1 constant portions (KEY) — show record 1
print('\n== T0 words (record 1) ==')
print('  ', words(tables(recs[0])[0]))
print('== T1 first 16 words (record 1) ==')
print('  ', words(tables(recs[0])[1])[:16])

# 4) output correlation: constant prefix length
print('\n== output common-prefix across all records ==')
outs = [r['out'] for r in recs]
cp = 0
while cp < len(outs[0]) and all(o[cp]==outs[0][cp] for o in outs):
    cp += 1
print(f'  common prefix = {cp} hex chars = {cp//2} bytes: {outs[0][:cp]}')

# 5) Also show, per record, the varying tail of T2 ascii vs output tail — do same messages give same out?
print('\n== message(T2 ascii, trimmed) -> output tail (bytes 8..32) ==')
seen = {}
for r in recs:
    t2a = to_ascii(tables(r)[2]).rstrip('.')
    tail = r['out'][16:]
    key = t2a
    seen.setdefault(key, []).append(r['n'])
    print(f'  #{r["n"]:2}: msg[:48]={t2a[:48]!r}  outTail={tail}')
print(f'\n  distinct T2-messages: {len(seen)} / {len(recs)}')

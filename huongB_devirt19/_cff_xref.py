#!/usr/bin/env python3
# _cff_xref.py — reconstruct the CFF-broken call-graph by resolving indirect `blr xN` where xN is
# materialized via adrp+add (or adrp+ldr) within a short window. Raw instruction decode (bypasses
# capstone data-in-code desync). Goal: find callers of seed-gen 0x10ac2c (= producer F), and enumerate
# all resolved indirect targets so F's entry can be reached from a known anchor.
import struct, sys
data = open('_code_dump.bin', 'rb').read()
BASE = 0x732e601000
TEXT_LO, TEXT_HI = 0x30e00, min(0x17baa0, len(data))

def sxt(v, b): return v - (1 << b) if v & (1 << (b - 1)) else v

def rd(off): return struct.unpack_from('<I', data, off)[0]

def is_adrp(w):
    if (w >> 24) & 0x9f != 0x90: return None
    rd_ = w & 0x1f
    immlo = (w >> 29) & 3; immhi = (w >> 5) & 0x7ffff
    imm = sxt((immhi << 2) | immlo, 21) << 12
    return rd_, imm  # imm is page-relative offset (add to PC&~0xfff)

def is_add_imm(w):
    if (w & 0xff000000) != 0x91000000: return None  # ADD 64-bit imm, sh=0..1
    sh = (w >> 22) & 1; imm12 = (w >> 10) & 0xfff
    rd_ = w & 0x1f; rn = (w >> 5) & 0x1f
    return rd_, rn, imm12 << (12 if sh else 0)

def is_ldr_imm(w):
    # LDR Xt,[Xn,#imm] unsigned offset: 1111 1001 01 imm12 Rn Rt = 0xF9400000
    if (w & 0xffc00000) != 0xf9400000: return None
    imm12 = (w >> 10) & 0xfff; rn = (w >> 5) & 0x1f; rt = w & 0x1f
    return rt, rn, imm12 * 8

def is_blr(w):
    if (w & 0xfffffc1f) == 0xd63f0000: return (w >> 5) & 0x1f
    return None

def is_br(w):
    if (w & 0xfffffc1f) == 0xd61f0000: return (w >> 5) & 0x1f
    return None

def resolve_reg_at(callsite_off, reg, window=24):
    """Walk backward from callsite to find adrp(reg)+add(reg) or adrp(reg)+ldr(reg) building `reg`."""
    add_imm = None; add_seen_reg = reg
    for k in range(1, window + 1):
        o = callsite_off - 4 * k
        if o < TEXT_LO: break
        w = rd(o)
        a = is_add_imm(w)
        if a and a[0] == add_seen_reg:
            add_imm = a[2]; add_seen_reg = a[1]; continue
        ap = is_adrp(w)
        if ap and ap[0] == add_seen_reg:
            page = ((BASE + o) & ~0xfff) + ap[1]
            if add_imm is not None:
                return page + add_imm  # adrp+add -> code ptr
            # adrp only (rare for call); return page
            return None
    return None

# 1) find all resolvable indirect calls
edges = {}   # callsite_off -> target_va
for off in range(TEXT_LO, TEXT_HI - 3, 4):
    w = rd(off)
    rn = is_blr(w)
    if rn is None:
        rn2 = is_br(w)
        if rn2 is None: continue
        rn = rn2
    if rn in (30, 31): continue
    tgt = resolve_reg_at(off, rn)
    if tgt is not None:
        edges[off] = tgt

print("resolved indirect blr/br edges: %d" % len(edges))
# 2) callers of seed-gen 0x10ac2c
SEED = BASE + 0x10ac2c
callers = [o for o, t in edges.items() if t == SEED]
print("edges -> seed-gen 0x10ac2c: %d  %s" % (len(callers), ['0x%x' % (o - BASE) for o in callers]))
# 3) histogram: which targets are hot (candidate dispatchers/producers)
from collections import Counter
tc = Counter(edges.values())
print("top resolved targets:")
for t, c in tc.most_common(15):
    print("   0x%06x  x%d" % (t - BASE, c))
# 4) dump edges near a queried target if given
if len(sys.argv) > 1:
    q = BASE + int(sys.argv[1], 16)
    print("callers of 0x%x:" % (q - BASE), ['0x%x' % (o - BASE) for o, t in edges.items() if t == q])

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re_recon.py — Reconnaissance tinh cho libmetasec_ov.so (ARM64, OLLVM-obfuscated).

Muc tieu: dinh vi cau truc dispatcher + code lien quan attestation/get_seed,
dac ta muc do obfuscation truoc khi RE sau blob 112B.

Dung: py re_recon.py <path-to-libmetasec_ov.so>
Phu thuoc: capstone, lief
"""
import sys, struct, re
from collections import Counter

try:
    import lief
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_IMM
    from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_INS_BR, ARM64_INS_BLR, ARM64_INS_LDR
except Exception as e:
    print("Thieu thu vien:", e); sys.exit(1)

LIB = sys.argv[1] if len(sys.argv) > 1 else None
if not LIB:
    print("Usage: py re_recon.py <libmetasec_ov.so>"); sys.exit(1)

print(f"=== RE RECON: {LIB} ===\n")

bin_ = lief.parse(LIB)
raw = open(LIB, "rb").read()

# ---- 1. Thong tin ELF co ban ----
print("[1] ELF co ban")
print(f"    kich thuoc file : {len(raw):,} bytes")
try:
    print(f"    machine         : {bin_.header.machine_type}")
    print(f"    entrypoint      : 0x{bin_.entrypoint:x}")
except Exception:
    pass

# section map: name -> (vaddr, offset, size)
secs = {}
for s in bin_.sections:
    if s.size:
        secs[s.name] = (s.virtual_address, s.offset, s.size)
text = secs.get(".text")
print(f"    .text           : vaddr=0x{text[0]:x} off=0x{text[1]:x} size=0x{text[2]:x} ({text[2]:,} B)")
for nm in (".rodata", ".data", ".data.rel.ro", ".got", ".got.plt", ".init_array"):
    if nm in secs:
        v, o, sz = secs[nm]
        print(f"    {nm:15s} : vaddr=0x{v:x} off=0x{o:x} size=0x{sz:x}")

# vaddr <-> file offset helpers (dung segment map cho chinh xac)
segs = []
for seg in bin_.segments:
    if seg.type == lief.ELF.Segment.TYPE.LOAD:
        segs.append((seg.virtual_address, seg.file_offset, seg.physical_size, seg.virtual_size))

def va_to_off(va):
    for vaddr, foff, fsz, vsz in segs:
        if vaddr <= va < vaddr + fsz:
            return foff + (va - vaddr)
    return None

def off_to_va(off):
    for vaddr, foff, fsz, vsz in segs:
        if foff <= off < foff + fsz:
            return vaddr + (off - foff)
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# ---- 2. Dispatcher @ 0x11c580 ----
DISP = 0x11c580
print(f"\n[2] Dispatcher JNI @ 0x{DISP:x} (offset trong .so)")
# 0x11c580 la file offset (tu RegisterNatives fnPtr - base). Kiem tra la va hay off.
disp_off = DISP  # gia dinh la file offset trong module
# doc 60 lenh dau
code = raw[disp_off:disp_off+60*4]
n = 0
indirect = 0
for insn in md.disasm(code, off_to_va(disp_off) or disp_off):
    print(f"    0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")
    if insn.id in (ARM64_INS_BR, ARM64_INS_BLR):
        indirect += 1
    n += 1
    if n >= 40:
        break

# ---- 3. Strings quan tam (attestation / integrity / seed / trust) ----
print(f"\n[3] Strings lien quan (attestation/integrity/seed/device)")
KEYWORDS = [b"safetyNet", b"SafetyNet", b"safety_net", b"integrity", b"Integrity",
            b"attest", b"Attest", b"get_seed", b"dyn_seed", b"seed",
            b"device_id", b"deviceToken", b"nonce", b"PlayIntegrity",
            b"basicIntegrity", b"ctsProfile", b"deviceRegister", b"device_register",
            b"license", b"ticket", b"gorgon", b"argus", b"khronos", b"ladon",
            b"boringssl", b"BoringSSL", b"cronet"]
found = {}
for kw in KEYWORDS:
    start = 0
    hits = []
    while True:
        i = raw.find(kw, start)
        if i < 0: break
        # trich chuoi C xung quanh
        lo = i
        while lo > 0 and 32 <= raw[lo-1] < 127: lo -= 1
        hi = i
        while hi < len(raw) and 32 <= raw[hi] < 127: hi += 1
        s = raw[lo:hi].decode("latin1", "replace")
        va = off_to_va(lo)
        hits.append((lo, va, s))
        start = i + 1
        if len(hits) >= 6: break
    if hits:
        found[kw.decode()] = hits

for kw, hits in found.items():
    print(f"    --- '{kw}' ({len(hits)} hit dau) ---")
    for off, va, s in hits[:4]:
        vas = f"va=0x{va:x}" if va is not None else "va=?"
        disp_s = s if len(s) <= 70 else s[:67] + "..."
        print(f"        off=0x{off:x} {vas}: {disp_s!r}")

# ---- 4. Xref cho string quan trong (ADRP+ADD tinh dia chi) ----
def find_string_xrefs(target_va, scan_limit=None):
    """Quet .text tim cap ADRP (Xn), ADD Xn,Xn,#imm tro toi target_va."""
    if target_va is None: return []
    tv0, to0, tsz0 = text
    code = raw[to0: to0 + (scan_limit or tsz0)]
    base_va = tv0
    xrefs = []
    # luu adrp gan nhat theo register
    adrp_val = {}   # reg -> (page_addr, insn_addr)
    for insn in md.disasm(code, base_va):
        if insn.id == ARM64_INS_ADRP:
            ops = insn.operands
            if len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
                adrp_val[ops[0].reg] = (ops[1].imm, insn.address)
        elif insn.id == ARM64_INS_ADD:
            ops = insn.operands
            if len(ops) == 3 and ops[2].type == ARM64_OP_IMM and ops[1].type == ARM64_OP_REG:
                src = ops[1].reg
                if src in adrp_val:
                    page, aaddr = adrp_val[src]
                    if page + ops[2].imm == target_va:
                        xrefs.append((insn.address, aaddr))
        elif insn.id == ARM64_INS_LDR:
            ops = insn.operands
            # ldr Xt, [Xn, #imm] sau adrp -> GOT-style, bo qua chi tinh ADD
    return xrefs

print(f"\n[4] Xref (ADRP+ADD) toi cac string then chot")
for kw in ("safetyNet", "integrity", "get_seed", "dyn_seed", "attest"):
    if kw in found:
        off, va, s = found[kw][0]
        xr = find_string_xrefs(va)
        print(f"    '{kw}' @ va=0x{va:x}: {len(xr)} xref" + (f"  -> " + ", ".join(f"0x{a:x}" for a,_ in xr[:6]) if xr else "  (khong tim thay ADRP+ADD)"))

# ---- 5. Dac ta obfuscation tren toan .text ----
print(f"\n[5] Dac ta obfuscation (.text)")
tv0, to0, tsz0 = text
code = raw[to0: to0 + tsz0]
mnem = Counter()
br_indirect = 0
blr_indirect = 0
total = 0
for insn in md.disasm(code, tv0):
    mnem[insn.mnemonic] += 1
    total += 1
    if insn.id == ARM64_INS_BR: br_indirect += 1
    if insn.id == ARM64_INS_BLR: blr_indirect += 1
print(f"    tong lenh giai ma      : {total:,}")
print(f"    BR  (indirect branch)  : {br_indirect:,}")
print(f"    BLR (indirect call)    : {blr_indirect:,}")
print(f"    Top 15 mnemonics:")
for m, c in mnem.most_common(15):
    print(f"        {m:8s} {c:>8,}")
print("\n=== HET RECON ===")

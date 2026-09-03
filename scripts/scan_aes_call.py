#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_aes_call.py — Scan TINH diem AES-CBC encrypt BEN TRONG ham ky 0x9af80.
  Muc tieu: tim offset (0x9af80+0x???) noi INNER report plaintext duoc dua vao AES,
  de hook_inner_report.py hook DUNG diem-truoc-AES. KHONG hardcode offset — tu scan + log.

  Reality (note 23): libmetasec OLLVM, symbol MA HOA, indirect-call (BLR) nhieu.
  => KHONG co import 'EVP_EncryptUpdate'/'AES_cbc_encrypt' de xref. Bat theo 2 tin hieu:
    (A) HW-AES: lenh ARM64 crypto-ext  AESE/AESMC/AESD/AESIMC  (inline AES round).
    (B) BL <imm> toi wrapper: resolve ten (neu PLT/JUMP_SLOT co ten) HOAC de-quy 1 tang
        xem ham dich co chua AESE khong  => "BL -> aes-wrapper".
    (C) BLR (indirect): KHONG resolve static duoc — chi liet ke de RECON runtime.

  Dung:
    py scripts/scan_aes_call.py <libmetasec_ov.so> [sign_off_hex=0x9af80] [range_hex=0x2000]
  Vi du:
    py scripts/scan_aes_call.py libmetasec_ov.so 0x9af80 0x2000

  Output: bang candidate xep hang (AESE truoc, roi BL->has_aese, roi BL-ten-crypto, roi BLR).
          Moi dong in ca offset tuong doi (sign+0x??) lan tuyet doi (de verify IDA).
"""
import sys
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

if len(sys.argv) < 2:
    print(__doc__); sys.exit(1)

LIB = sys.argv[1]
SIGN_OFF = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x9af80
RANGE = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x2000

bin_ = lief.parse(LIB)
raw = open(LIB, "rb").read()

secs = {s.name: (s.virtual_address, s.offset, s.size) for s in bin_.sections if s.size}
tv0, to0, tsz0 = secs[".text"]

# GOT/PLT: JUMP_SLOT vaddr -> symbol name (de nhan dien BL toi crypto ten-that neu co)
got_sym = {}
for r in bin_.relocations:
    try:
        nm = r.symbol.name if r.has_symbol else None
    except Exception:
        nm = None
    if nm:
        got_sym[r.address] = nm

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

AES_MNE = ("aese", "aesmc", "aesd", "aesimc")
CRYPTO_HINT = ("aes", "evp", "crypt", "cbc", "cipher")


def code_at(va, n):
    """Doc n byte code tai virtual address (map qua .text/.plt)."""
    for name in (".text", ".plt"):
        if name not in secs:
            continue
        v, o, s = secs[name]
        if v <= va < v + s:
            off = o + (va - v)
            return raw[off: off + n]
    return b""


def disasm(code, base_va):
    """Robust sweep: skip-4 khi capstone fail (ARM64 fixed 4B)."""
    off, N = 0, len(code)
    while off < N:
        advanced = False
        for insn in md.disasm(code[off:], base_va + off):
            yield insn
            off = insn.address - base_va + insn.size
            advanced = True
        if not advanced:
            off += 4


def fn_has_aese(entry_va, budget=0x600):
    """De-quy 1 tang: ham tai entry_va co chua lenh AESE khong (den ret/budget)."""
    code = code_at(entry_va, budget)
    if not code:
        return False
    for insn in disasm(code, entry_va):
        if insn.mnemonic in AES_MNE:
            return True
        if insn.mnemonic == "ret":
            break
    return False


def plt_target_name(va):
    """Neu va la PLT stub (adrp x16,GOT ; ldr x16,[x16,#off] ; br x16) -> tra ten symbol."""
    code = code_at(va, 16)
    if len(code) < 12:
        return None
    got_va = None
    page = None
    for insn in disasm(code, va):
        if insn.mnemonic == "adrp":
            try:
                page = int(insn.op_str.split(", ")[1], 0)
            except Exception:
                page = None
        elif insn.mnemonic == "ldr" and page is not None:
            # ldr x16, [x16, #imm]
            if "#" in insn.op_str:
                try:
                    imm = int(insn.op_str.split("#")[1].rstrip("]"), 0)
                    got_va = page + imm
                except Exception:
                    pass
        elif insn.mnemonic == "br":
            break
    if got_va is not None and got_va in got_sym:
        return got_sym[got_va]
    return None


# ── scan ──
base = SIGN_OFF
code = code_at(base, RANGE)
if not code:
    print(f"[!] khong doc duoc code tai 0x{base:x} (kiem tra .so + offset)"); sys.exit(2)

# ── GUARD: kiem tra capstone co DONG BO trong vung nay khong ──
#   Ham metasec obfuscate + literal-pool -> capstone linear-sweep DESYNC -> "BLR" phat hien = GIA.
#   (Da chung minh: aligned-sweep 0x9ecc0 chi decode 42/2048 insn -> offset scan-duoc la data misdecode.)
_aligned = list(md.disasm(code, base))
_cover = len(_aligned) / (RANGE // 4)
if _cover < 0.5:
    print(f"\n[!!! CANH BAO DESYNC] aligned-disasm chi phu {len(_aligned)}/{RANGE//4} insn ({_cover:.0%}).")
    print("    Vung nay capstone KHONG dong bo (obfuscate/literal-pool). Moi 'BLR' duoi day co the la DATA")
    print("    decode nham -> HOOK vao se HONG CODE/CRASH APP. => DUNG offset nay de hook.")
    print("    Thay the: (a) IDA/Ghidra lay offset BLR that; (b) Stalker runtime (dia chi thuc thi that);")
    print("    (c) neu chi can plaintext: capture X-Argus that roi DECRYPT offline bang OUTER key.\n")

aese_sites, bl_aes, bl_named, blr_sites = [], [], [], []

for insn in disasm(code, base):
    rel = insn.address - SIGN_OFF
    if insn.mnemonic in AES_MNE:
        aese_sites.append((insn.address, rel, insn.mnemonic + " " + insn.op_str))
    elif insn.mnemonic == "bl":
        try:
            tgt = int(insn.op_str, 0)
        except Exception:
            continue
        nm = plt_target_name(tgt) or got_sym.get(tgt)
        if nm and any(h in nm.lower() for h in CRYPTO_HINT):
            bl_named.append((insn.address, rel, tgt, nm))
        elif fn_has_aese(tgt):
            bl_aes.append((insn.address, rel, tgt, "(fn chua AESE)"))
    elif insn.mnemonic == "blr":
        blr_sites.append((insn.address, rel, insn.op_str))


def dump(title, rows, fmt):
    print(f"\n=== {title} ({len(rows)}) ===")
    for r in rows:
        print(fmt(r))


print(f"[scan] {LIB}")
print(f"[scan] sign_off=0x{SIGN_OFF:x} range=0x{RANGE:x}  .text va=0x{tv0:x}")

dump("A. HW-AES inline (AESE/AESMC) — UU TIEN 1: hook loop-head gan day",
     aese_sites,
     lambda r: f"  sign+0x{r[1]:<5x}  ABS 0x{r[0]:x}   {r[2]}")

dump("B. BL -> ham chua AESE (wrapper AES) — UU TIEN 2",
     bl_aes,
     lambda r: f"  sign+0x{r[1]:<5x}  ABS 0x{r[0]:x}   BL 0x{r[2]:x}  {r[3]}")

dump("C. BL -> symbol ten crypto (neu co) — UU TIEN 3",
     bl_named,
     lambda r: f"  sign+0x{r[1]:<5x}  ABS 0x{r[0]:x}   BL 0x{r[2]:x}  -> {r[3]}")

dump("D. BLR indirect — KHONG resolve static; RECON runtime neu A/B/C rong",
     blr_sites,
     lambda r: f"  sign+0x{r[1]:<5x}  ABS 0x{r[0]:x}   blr {r[2]}")

print("\n[huong dan]")
print("  1. Uu tien candidate A[0] (AESE dau tien) HOAC B[0] (BL->wrapper).")
print("  2. Mo IDA/Ghidra tai ABS o tren VERIFY: A = vong AES round; B = call encrypt.")
print("  3. Chay hook_inner_report.py MODE=recon voi AES_OFF=0x9af80+0x<rel> de dump reg,")
print("     nhan dien reg nao = plaintext ptr / len / IV / key.")
print("  4. Neu A/B/C rong (AES qua BLR/obfuscated): dung Stalker trong hook (xem file kia).")

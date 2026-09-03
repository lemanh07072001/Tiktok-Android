#!/usr/bin/env python3
# VM 0x55950 STATIC dispatch-table decoder — libmetasec_ov.so (aarch64, stripped)
# Zero môi trường: chỉ cần file .so. KHÔNG cần emulator/frida/mạng.
#
# Cơ chế (note 50): dispatch tail @0x55890 tính
#   table_ptr = *(0x1f00e0)                         # reloc R_AARCH64_RELATIVE, static=0x6b5fe0
#   f(x30)    = (((x30 & c9) | c10) + ((c11 | ~x30) & c12)) ^ c13     # mod 2^64
#   base      = (table_ptr + f(x30)) & MASK          # WRAP → VMA thật trong module
#   entry(op) = *(base + op*8)                        # con trỏ handler .text (module-relative)
#   handler   = entry - bias                          # bias=[x29-0x58] runtime; static bias=0
#
# x30 = "khóa ngữ cảnh" do preamble mỗi handler nạp (adrp+add). VD preamble @0x55950 → x30=0x52924.
# Đổi x30 → context/table khác. Đây là cách enumerate handler cho TỪNG context (kể cả context ARX slot16).
import struct, sys
from collections import Counter

SO = sys.argv[1] if len(sys.argv) > 1 else __file__.rsplit('/',1)[0] + '/bin/libmetasec_ov.so'
data = open(SO, 'rb').read()
MASK = (1 << 64) - 1

# --- ELF64 PT_LOAD segments: VMA -> file offset ---
e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
e_es    = struct.unpack_from('<H', data, 0x36)[0]
e_pn    = struct.unpack_from('<H', data, 0x38)[0]
SEGS = []
for i in range(e_pn):
    o = e_phoff + i*e_es
    if struct.unpack_from('<I', data, o)[0] == 1:  # PT_LOAD
        p_off, p_va, _, p_fsz, _ = struct.unpack_from('<QQQQQ', data, o+8)
        SEGS.append((p_va, p_fsz, p_off))
def v2f(v):
    for va, fsz, fo in SEGS:
        if va <= v < va+fsz: return fo + (v-va)
    return None
def rd64(v):
    fo = v2f(v)
    return struct.unpack_from('<Q', data, fo)[0] if fo is not None else None

# --- dispatch constants (0x55890..0x558f4), reconstructed from movk chains ---
C9  = 0x400 | (0x4 << 16) | (0x104 << 32)                      # 0x0000010400040400
C11 = 0x1040 | (0xa02 << 16) | (0x6040 << 32) | (0xa0 << 48)   # 0x00a060400a021040
C10 = (0x104 | (0x101 << 16)) & 0xffffffff                     # 0x01010104 (w10, zero-ext)
C12 = 0x1440 | (0xa06 << 16) | (0x6144 << 32) | (0xa0 << 48)   # 0x00a061440a061440
C13 = 0x21ec | (0xf4b5 << 16) | (0x9ebb << 32) | (0xff5f << 48)# 0xff5f9ebbf4b521ec
TABLE_PTR = 0x6b5fe0                                            # *(0x1f00e0) static (load base=0)

def f_x30(x30):
    t1 = ((x30 & C9) | C10) & MASK
    t2 = ((C11 | ((~x30) & MASK)) & C12) & MASK
    return (((t2 + t1) & MASK) ^ C13) & MASK

def table_base(x30):
    return (TABLE_PTR + f_x30(x30)) & MASK

def decode_context(x30, bias=0):
    """Trả (table_vma, {op: handler_vma}, trap_vma)."""
    base = table_base(x30)
    ents = [ (rd64((base + op*8) & MASK) or 0) for op in range(64) ]
    hands = [ (e - bias) & MASK for e in ents ]
    trap = Counter(hands).most_common(1)[0][0]
    m = { op: hands[op] for op in range(64) if hands[op] != trap }
    return base, m, trap

if __name__ == '__main__':
    # mặc định: context của preamble @0x55950
    X30 = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x52924
    base, m, trap = decode_context(X30)
    print(f"x30={X30:#x}  f(x30)={f_x30(X30):#018x}  table@{base:#x}  "
          f"inModule={base < 0x200000}  trap={trap:#x}  real_handlers={len(m)}")
    for op in sorted(m):
        print(f"  op{op:2d} 0x{op:02x} -> {m[op]:#08x}")

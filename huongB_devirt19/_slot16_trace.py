#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _slot16_trace.py — Decode slot16 bytecode from exec_trace.json + SO binary.
#
# Maps each opcode entry to its data slots, computes XOR-decrypted operands,
# and builds the full bytecode structure.
#
# Run: python _slot16_trace.py
import json, struct, os, sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))

SO = "bin/libmetasec_ov.so"
EXEC_TRACE = "exec_trace.json"
XOR_KEY = 0x6a9091b9

# ── Handler table (old lifter offsets → real handler = base + offset - predicate) ──
PREDICATE = 0x9b374
OLD_HANDLERS = {
    1: 0x0f488c, 3: 0x0f34bc, 4: 0x0f52fc, 5: 0x0f5544,
    6: 0x0f6914, 7: 0x0f56c4, 8: 0x0f5720, 9: 0x0f44bc,
    12: 0x0f2958, 13: 0x0f6f2c, 15: 0x0f4a88, 17: 0x0f50b8,
    18: 0x0f60a0, 19: 0x0f4c98, 20: 0x0f6454, 22: 0x0f76b8,
    23: 0x0f5e94, 24: 0x0f8070, 25: 0x0f66f8, 26: 0x0f62a8,
    28: 0x0f7e34, 30: 0x0f40e0, 33: 0x0f4f68, 36: 0x0f5348,
    37: 0x0f4db0, 38: 0x0f3dc8, 40: 0x0f6b58, 41: 0x0f55c0,
    42: 0x0f7470, 43: 0x0f79f0, 44: 0x0edec0, 45: 0x0f1ff8,
    46: 0x0f6a34, 47: 0x0f5c8c, 48: 0x0f46c0, 49: 0x0f780c,
    50: 0x0f7c04, 52: 0x0f7288, 53: 0x0f58c8, 54: 0x0f5128,
    55: 0x0f42b8, 56: 0x0f3f2c, 57: 0x0f7090, 59: 0x0f7584,
    60: 0x0f5a38, 61: 0x0f7d74, 63: 0x0f6d24,
}

def handler_offset(op_idx):
    """Get real handler offset from base."""
    old = OLD_HANDLERS.get(op_idx)
    if old is None:
        return None
    return (old - PREDICATE) & 0xffffffffffffffff


def main():
    so = open(SO, "rb").read()
    exec_trace = json.load(open(EXEC_TRACE))
    offsets = exec_trace["exec_offsets"]

    bc_start = min(a for a, _ in offsets)
    bc_end = max(a for a, _ in offsets) + 8
    print(f"Bytecode: 0x{bc_start:x} - 0x{bc_end:x} ({bc_end - bc_start} bytes)")
    print(f"Opcodes: {len(offsets)}")

    # Build bytecode structure
    from collections import Counter, defaultdict

    op_freq = Counter()
    data_slot_counts = defaultdict(list)  # opcode → [slot_counts]

    entries = []
    for i, (addr_off, opword) in enumerate(offsets):
        rel_off = addr_off - bc_start
        header = struct.unpack_from("<I", so, addr_off)[0]
        op_idx = opword & 0x3f
        operand = struct.unpack_from("<I", so, addr_off + 4)[0]
        dec_operand = operand ^ XOR_KEY
        h_off = handler_offset(op_idx)
        op_freq[op_idx] += 1

        # Determine data slot count: gap to next opcode address
        # (or to end of bytecode for last entry)
        if i + 1 < len(offsets):
            next_addr = offsets[i + 1][0]
        else:
            next_addr = bc_end
        gap = next_addr - addr_off
        data_slots = (gap - 8) // 8  # 8 bytes for header+opword, rest in 8-byte slots

        # Read data slots
        slots = []
        for s in range(data_slots):
            slot_addr = addr_off + 8 + s * 8
            slot_val = struct.unpack_from("<Q", so, slot_addr)[0]
            slots.append(slot_val)

        data_slot_counts[op_idx].append(data_slots)

        entries.append({
            'i': i,
            'addr': addr_off,
            'header': header,
            'opword': opword,
            'op_idx': op_idx,
            'operand': operand,
            'dec_operand': dec_operand,
            'handler_off': h_off,
            'data_slots': data_slots,
            'slots': slots,
        })

    # ── Report ──
    print(f"\n=== Opcode Frequency ===")
    for op, count in op_freq.most_common():
        h_off = handler_offset(op)
        slot_range = data_slot_counts[op]
        min_s, max_s = min(slot_range), max(slot_range)
        slot_str = f"{min_s}" if min_s == max_s else f"{min_s}-{max_s}"
        print(f"  op={op:2d} handler=0x{h_off:x} ({count:3d}x) data_slots={slot_str}")

    # ── First 30 entries detail ──
    print(f"\n=== First 30 Entries ===")
    for e in entries[:30]:
        slots_str = " ".join(f"0x{s:016x}" for s in e['slots'][:4])
        if len(e['slots']) > 4:
            slots_str += f" ... (+{len(e['slots'])-4})"
        print(f"  [{e['i']:3d}] 0x{e['addr']:x} op={e['op_idx']:2d} "
              f"opword=0x{e['opword']:08x} dec_op=0x{e['dec_operand']:08x} "
              f"slots={e['data_slots']} {slots_str}")

    # ── Pattern analysis ──
    print(f"\n=== Data Slot Analysis ===")
    for op in sorted(op_freq.keys()):
        slots_list = data_slot_counts[op]
        slot_dist = Counter(slots_list)
        h_off = handler_offset(op)
        print(f"  op={op:2d} handler=0x{h_off:x}: slot_counts={dict(slot_dist)}")

    # ── Key insight: what do the data slots contain? ──
    print(f"\n=== First 5 entries with data slots decoded ===")
    for e in entries[:5]:
        print(f"\n  [{e['i']}] op={e['op_idx']} at 0x{e['addr']:x}:")
        print(f"    header=0x{e['header']:08x} opword=0x{e['opword']:08x}")
        print(f"    decrypted operand: 0x{e['dec_operand']:08x} (idx={e['dec_operand'] & 0x3f})")
        if e['slots']:
            for s, val in enumerate(e['slots']):
                # Check if slot looks like a pointer, integer, or float
                kind = ""
                if val == 0:
                    kind = "zero"
                elif 0x6f00000000 <= val < 0x7000000000:
                    kind = f"so_ptr (off=0x{val - 0x6f5fe00000:x})"
                elif 0x6f00000000 <= val < 0x8000000000:
                    kind = "stack/heap ptr"
                elif val < 0x10000:
                    kind = f"small_int ({val})"
                elif val & 0xffff000000000000 == 0xffff000000000000:
                    kind = f"sign_ext ({val & 0xffffffff})"
                elif 0x3ff0000000000000 <= val <= 0x7ff0000000000000:
                    import struct as st
                    try:
                        fval = st.unpack('<d', st.pack('<Q', val))[0]
                        kind = f"float64 ({fval:.6g})"
                    except:
                        kind = "possible_float"
                print(f"    slot[{s}]: 0x{val:016x} {kind}")


if __name__ == "__main__":
    main()
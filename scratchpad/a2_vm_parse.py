#!/usr/bin/env python3
"""
A2.1: Parse A1 VM-entry captures, detect regfile layout
"""
import json
from dataclasses import dataclass

def hex_to_bytes(h):
    return bytes.fromhex(h)

def detect_regfile_layout(entries):
    """
    Compare entry 1 vs 3 (same query class, diff _rticket).
    Find stable qwords (frame pointers, saved regs) vs changing qwords (state).

    Return: {offset: {'qword_idx': int, 'size': 8, 'type': str, 'v1': int, 'v3': int}}
    """
    e1, e3 = entries[0], entries[2]
    s1 = hex_to_bytes(e1['stack'])
    s3 = hex_to_bytes(e3['stack'])

    layout = {}
    for i in range(0, min(len(s1), len(s3)), 8):
        qw_idx = i // 8
        if i + 8 <= len(s1):
            v1 = int.from_bytes(s1[i:i+8], 'little')
            v3 = int.from_bytes(s3[i:i+8], 'little')

            if v1 == v3:
                qtype = 'stable_pointer' if v1 > 0x700000000000 else 'stable_value'
            else:
                # Check if likely pointer (high bits set)
                if (v1 | v3) > 0x600000000000:
                    qtype = 'pointer_ratchet'
                else:
                    qtype = 'state_value'

            layout[i] = {
                'qword_idx': qw_idx,
                'size': 8,
                'type': qtype,
                'v1': v1,
                'v3': v3,
            }

    # Special: mark qword[29] as ratchet_counter (offset 232)
    if 232 in layout:
        layout[232]['name'] = 'ratchet_counter'

    return layout

@dataclass
class VMState:
    entry_num: int
    base_addr: int
    predicate: int
    regfile: dict   # {qword_idx: value}
    bytecode_ptr: int
    stack_snapshot: bytes

    def get_ratchet(self):
        """regfile[29] at offset 232"""
        return int.from_bytes(self.stack_snapshot[232:240], 'little')

def parse_a1_capture(json_path):
    """Return list of VMState objects from A1 capture"""
    with open(json_path) as f:
        entries = json.load(f)

    states = []
    for entry in entries:
        state = VMState(
            entry_num=entry['n'],
            base_addr=0x783d001000,
            predicate=0x9b374,
            regfile={},
            bytecode_ptr=int(entry['regs']['x23'], 16),
            stack_snapshot=hex_to_bytes(entry['stack']),
        )

        # Populate regfile as qwords (32 x 8-byte)
        stack = state.stack_snapshot
        for i in range(0, min(len(stack), 256), 8):
            idx = i // 8
            state.regfile[idx] = int.from_bytes(stack[i:i+8], 'little')

        states.append(state)

    return states

if __name__ == '__main__':
    # Test
    states = parse_a1_capture('huongB_devirt19/_a1_vmcap.json')
    print(f"Loaded {len(states)} VM entries")

    layout = detect_regfile_layout(json.load(open('huongB_devirt19/_a1_vmcap.json')))
    print(f"\nRegfile layout: {len(layout)} qwords")

    if 232 in layout:
        print(f"Ratchet at offset 232: e1={hex(layout[232]['v1'])}, e3={hex(layout[232]['v3'])}")

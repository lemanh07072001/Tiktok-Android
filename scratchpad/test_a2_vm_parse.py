#!/usr/bin/env python3
import json
import sys
sys.path.insert(0, '.')
from a2_vm_parse import detect_regfile_layout, parse_a1_capture

def test_detect_regfile_layout():
    """Entry 1 vs 3: same query, stack differs at qword[29]"""
    with open('../huongB_devirt19/_a1_vmcap.json') as f:
        entries = json.load(f)

    layout = detect_regfile_layout(entries)

    # Expected: qword[29] at offset 232, named 'ratchet_counter'
    assert 232 in layout, "Offset 232 should be in layout"
    assert layout[232].get('name') == 'ratchet_counter', f"Got: {layout[232]}"
    assert layout[232]['size'] == 8, "Qword should be 8 bytes"
    print("[PASS] test_detect_regfile_layout")

def test_parse_a1_all_entries():
    """Verify all 6 entries parse correctly"""
    states = parse_a1_capture('../huongB_devirt19/_a1_vmcap.json')

    assert len(states) == 6, f"Expected 6 entries, got {len(states)}"
    assert states[0].entry_num == 1
    assert states[2].entry_num == 3

    # Entry 1 & 3: same query, different ratchet
    ratch1 = states[0].get_ratchet()
    ratch3 = states[2].get_ratchet()
    assert ratch1 != ratch3, "Ratchet should differ per-request"
    assert ratch1 == 0x9d3450fc, f"Entry 1 ratchet: {hex(ratch1)}"
    assert ratch3 == 0x796f769c01, f"Entry 3 ratchet: {hex(ratch3)}"
    print("[PASS] test_parse_a1_all_entries")

if __name__ == '__main__':
    test_detect_regfile_layout()
    test_parse_a1_all_entries()
    print("\nAll tests PASSED!")

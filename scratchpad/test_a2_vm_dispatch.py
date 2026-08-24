#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from a2_vm_dispatch import VMDispatcher

def test_dispatch_decodes_first_op():
    """Load bytecode and decode first op"""
    with open('../huongB_devirt19/sign_bytecode.bin', 'rb') as f:
        bytecode = f.read()

    dispatcher = VMDispatcher()

    op, operands, next_ptr = dispatcher.decode_op(bytecode, 0)

    assert op is not None, "First opcode should decode"
    assert next_ptr == 8, f"Next ptr should be 8, got {next_ptr}"
    assert op in [1, 5, 15, 18, 31, 37, 38, 40, 42, 44, 46, 51], f"Op should be valid, got {op}"
    print(f"[PASS] test_dispatch_decodes_first_op: op{op} operands=0x{operands:x}")

def test_dispatch_scans_blocks():
    """Scan entire bytecode for blocks"""
    with open('../huongB_devirt19/sign_bytecode.bin', 'rb') as f:
        bytecode = f.read()

    dispatcher = VMDispatcher()
    blocks = dispatcher.scan_blocks(bytecode)

    assert len(blocks) > 0, "Should find blocks"
    assert blocks[0]['op'] in [1, 5, 15, 18, 31, 37, 38, 40, 42, 44, 46, 51], "First block should have valid opcode"
    print(f"[PASS] test_dispatch_scans_blocks: found {len(blocks)} instructions")

if __name__ == '__main__':
    test_dispatch_decodes_first_op()
    test_dispatch_scans_blocks()
    print("\nAll A2.2 tests PASSED!")

#!/usr/bin/env python3
"""
A2.5: Unicorn VM emulator adapter
Uses _vm_unicorn_v5.py from huongB_devirt19 to execute full VM bytecode.
"""
import sys
import json
import struct
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../huongB_devirt19'))
sys.path.insert(0, os.path.dirname(__file__))

from a2_vm_parse import parse_a1_capture, VMState

def run_vm_on_state(vm_state: VMState):
    """
    Execute VM on captured state using Unicorn emulator.

    Returns: {'regfile_after': dict, 'output': bytes, 'trace': list}
    """
    try:
        import _vm_unicorn_v4 as V
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError
        from unicorn.arm64_const import UC_ARM64_REG_X15, UC_ARM64_REG_X23
    except ImportError as e:
        print(f"[!] Unicorn import failed: {e}")
        print("[!] Install: pip install unicorn")
        return None

    try:
        # Load .so binary
        so_path = '../huongB_devirt19/bin/libmetasec_ov.so'
        with open(so_path, 'rb') as f:
            so = f.read()
        print(f"[+] Loaded .so: {len(so)} bytes")
    except FileNotFoundError:
        print(f"[!] .so not found at {so_path}")
        return None

    # Convert A1 VMState to capture format for V4/V5
    cap = {
        "cpur": {
            "x0": hex(vm_state.regfile.get(0, 0)),
            "x1": hex(vm_state.regfile.get(1, 0)),
            "x23": hex(vm_state.bytecode_ptr),
            "x24": hex(0x7800aa1660),  # regfile ptr (from A1 capture)
        },
        "bcPtr": hex(vm_state.bytecode_ptr),
        "regfile": {i: hex(vm_state.regfile.get(i, 0)) for i in range(32)},
    }

    # Setup Unicorn (reuse V4 setup)
    try:
        uc, base = V.setup(so, cap)
        print(f"[+] Unicorn setup: base=0x{base:x}")
    except Exception as e:
        print(f"[!] Unicorn setup failed: {e}")
        return None

    # Restore exact captured state
    x24 = vm_state.regfile.get(24, 0)
    if x24 > 0x700000000000:  # Valid pointer
        regfile_bytes = b''.join(
            vm_state.regfile.get(i, 0).to_bytes(8, 'little')
            for i in range(32)
        )
        try:
            uc.mem_write(x24, regfile_bytes)
            print(f"[+] Regfile restored at 0x{x24:x}")
        except Exception as e:
            print(f"[!] Regfile write failed: {e}")
            return None

    # Run emulation
    trace = []
    instruction_count = [0]
    dispatch_count = [0]

    def hook_code(uc, addr, size, ud):
        instruction_count[0] += 1
        if instruction_count[0] > 50000:
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)

    entry = base + V.VM_ENTRY
    try:
        print(f"[*] Running VM emulation from 0x{entry:x}...")
        uc.emu_start(entry, 0, count=0)
        print(f"[+] Emulation complete: {instruction_count[0]} insns")
    except UcError as e:
        print(f"[!] Emulation error: {e}")
        return None

    # Extract regfile after execution
    regfile_after = {}
    try:
        regfile_bytes = uc.mem_read(x24, 256)
        for i in range(32):
            regfile_after[i] = int.from_bytes(regfile_bytes[i*8:(i+1)*8], 'little')
    except Exception as e:
        print(f"[!] Regfile readback failed: {e}")
        regfile_after = vm_state.regfile.copy()

    return {
        'regfile_after': regfile_after,
        'instructions': instruction_count[0],
        'dispatches': dispatch_count[0],
        'trace': trace,
    }

if __name__ == '__main__':
    # Test: run VM on Entry 1
    states = parse_a1_capture('huongB_devirt19/_a1_vmcap.json')
    e1 = states[0]

    print(f"Entry {e1.entry_num}: base=0x{e1.base_addr:x}, ratchet=0x{e1.get_ratchet():x}\n")

    result = run_vm_on_state(e1)
    if result:
        print(f"\nResult: {result['instructions']} instructions executed")
        print(f"Regfile[29] before: 0x{e1.regfile[29]:x}")
        print(f"Regfile[29] after:  0x{result['regfile_after'].get(29, 0):x}")

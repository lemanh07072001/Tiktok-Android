#!/usr/bin/env python3
"""
A2 Analysis: Localize regfile & ratchet from A1 capture
"""
import json
import sys

def hex_to_bytes(h):
    """Hex string -> bytes"""
    return bytes.fromhex(h)

def bytes_to_int(b):
    """Little-endian bytes -> int"""
    return int.from_bytes(b, 'little')

def find_regfile(entries):
    """
    Regfile = 256B (32 qwords) buffer. Locate by:
    1. Stable stack offset across entries (same stack layout)
    2. Or stable deref pointer (x25, x27, x19/x21 candidates)
    """
    print("=== REGFILE LOCALIZATION ===\n")

    # Check derefs across entries
    print("Deref candidates (potential regfile pointers):")
    for i, entry in enumerate(entries):
        regs = entry['regs']
        derefs = entry['derefs']
        print(f"\nEntry {entry['n']}:")
        print(f"  x19={regs['x19']} -> {derefs.get('x19->', 'N/A')[:32]}...")
        print(f"  x21={regs['x21']} -> {derefs.get('x21->', 'N/A')[:32]}...")
        print(f"  x25={regs['x25']} -> {derefs.get('x25->', 'N/A')[:32]}...")
        print(f"  x27={regs['x27']} -> {derefs.get('x27->', 'N/A')[:32]}...")

        # x25/x27 likely bytecode (0x28fd8052 = ARM insn)
        if derefs.get('x25->', '').startswith('28fd8052'):
            print(f"  ** x25 = bytecode (ARM insn 28fd8052)")
        if derefs.get('x27->', '').startswith('880a00b0'):
            print(f"  ** x27 = bytecode (ARM insn 880a00b0)")

def compare_same_query(entries):
    """
    Find entries with same query, compare regfile/ratchet.
    Entry 1 & 3 both have device_platform (same class, diff _rticket)
    """
    print("\n=== SAME-QUERY COMPARISON (Entry 1 vs 3) ===\n")

    e1, e3 = entries[0], entries[2]  # Entry 1 & 3
    print(f"Entry {e1['n']}: query={e1['derefs']['x19->']}...")
    print(f"Entry {e3['n']}: query={e3['derefs']['x19->']}...")

    # Compare stack
    stack1 = e1['stack']
    stack3 = e3['stack']

    if stack1 == stack3:
        print("\n[!] Stack IDENTICAL -> regfile NOT modified per-request! (cached or static)")
    else:
        print("\n[+] Stack DIFFERS -> regfile modified per-request")
        # Find first difference
        for i in range(0, min(len(stack1), len(stack3)), 2):
            h1 = stack1[i:i+2]
            h3 = stack3[i:i+2]
            if h1 != h3:
                print(f"  First diff at offset {i//2}: {h1} vs {h3}")
                break

    # Compare x25/x27 derefs (bytecode pointers)
    print(f"\nx25: {e1['regs']['x25']} vs {e3['regs']['x25']}")
    if e1['regs']['x25'] != e3['regs']['x25']:
        print("  -> x25 CHANGES (ratchet candidate)")
    else:
        print("  -> x25 stable")

    print(f"\nx27: {e1['regs']['x27']} vs {e3['regs']['x27']}")
    if e1['regs']['x27'] != e3['regs']['x27']:
        print("  -> x27 CHANGES")
    else:
        print("  -> x27 stable")

    # Compare x23 (bytecode ptr)
    print(f"\nx23: {e1['regs']['x23']} vs {e3['regs']['x23']}")
    if e1['regs']['x23'] != e3['regs']['x23']:
        print("  -> x23 CHANGES (bytecode ptr ratchet)")
    else:
        print("  -> x23 stable")

def compare_psk_entries(entries):
    """
    Entry 4 has PSK data in x19 deref. Compare with entries that don't.
    """
    print("\n=== PSK DATA IDENTIFICATION ===\n")

    e4 = entries[3]
    psk_data = e4['derefs']['x19->']
    print(f"Entry 4 x19 deref (PSK candidate):")
    print(f"  {psk_data}")
    print(f"  Length: {len(psk_data)//2} bytes")

    # Check if this matches note 36 PSK material
    known_psk = "c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163"
    if psk_data.startswith(known_psk):
        print(f"\n[+] CONFIRMED: Entry 4 contains KNOWN PSK from note 36")
    else:
        print(f"\n[?] Not immediately recognized, but likely PSK/state material")

def analyze_stack_pattern(entries):
    """
    Stack layout analysis: find 256B regfile location in stack.
    Regfile = 32 qwords (32*8=256B). Look for patterns.
    """
    print("\n=== STACK PATTERN ANALYSIS ===\n")

    for entry in entries[:2]:  # First 2 entries
        stack_hex = entry['stack']
        stack_bytes = hex_to_bytes(stack_hex)
        print(f"Entry {entry['n']} stack (512B):")

        # Look for SM3 IV pattern (standard IV: 6f168073b9b21449...)
        sm3_iv = bytes.fromhex("6f168073b9b21449d742241700068ada")
        if sm3_iv in stack_bytes:
            offset = stack_bytes.find(sm3_iv)
            print(f"  Found SM3 IV at stack offset {offset}: likely SM3 input message")

        # Print first 64 bytes (8 qwords) as structure
        print("  First 64 bytes (8 qwords):")
        for i in range(0, 64, 8):
            qw = bytes_to_int(stack_bytes[i:i+8])
            print(f"    [{i//8}] 0x{qw:016x}")

def main():
    # Load capture
    with open('huongB_devirt19/_a1_vmcap.json') as f:
        entries = json.load(f)

    print(f"Loaded {len(entries)} VM entries\n")

    find_regfile(entries)
    compare_same_query(entries)
    compare_psk_entries(entries)
    analyze_stack_pattern(entries)

    print("\n=== NEXT STEPS ===")
    print("1. If stack DIFFERS: measure offset of regfile[29] (ratchet) in entry 1 vs 3")
    print("2. If x23 CHANGES: track bytecode ptr -> model ratchet progression")
    print("3. If PSK stable: regfile = static => only per-request ratchet input matters")
    print("4. Run A3 oracle test: hash(PSK + ratchet + query) vs captured slot16")

if __name__ == '__main__':
    main()

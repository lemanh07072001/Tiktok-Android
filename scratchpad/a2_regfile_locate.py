#!/usr/bin/env python3
"""
A2 Phase 2: Pinpoint regfile[29] (ratchet state) in stack
Strategy: SM3 compress 0xa0748 = first sign operation
  - Entry 1 & 3: device_platform (same query class, diff _rticket)
  - SM3 state = 256B (32 qwords, 8 state vars * 32B each for multi-round)
  - regfile[29] = per-request ratchet counter/state
"""
import json

def hex_to_bytes(h):
    return bytes.fromhex(h)

def bytes_to_int(b):
    return int.from_bytes(b, 'little')

def find_ratchet_offset(e1, e3):
    """
    Compare stacks to find changing bytes (ratchet).

    Hypothesis: regfile is 256B (32 qwords). Each register = 8 bytes.
    regfile[29] = qword 29 = bytes 232-240.

    But first, scan for pattern of changing bytes.
    """
    s1 = hex_to_bytes(e1['stack'])
    s3 = hex_to_bytes(e3['stack'])

    print("Stack size:", len(s1), "bytes\n")

    # Find all differing bytes
    diffs = []
    for i in range(min(len(s1), len(s3))):
        if s1[i] != s3[i]:
            diffs.append(i)

    print(f"Total differing bytes: {len(diffs)}")
    print(f"Ranges: ", end="")

    # Group continuous ranges
    ranges = []
    if diffs:
        start = diffs[0]
        prev = diffs[0]
        for d in diffs[1:]:
            if d != prev + 1:
                ranges.append((start, prev))
                start = d
            prev = d
        ranges.append((start, prev))

    for r in ranges:
        print(f"[{r[0]}-{r[1]}]", end=" ")
    print("\n")

    # For each range, check if it's a qword boundary (8-byte aligned)
    print("Analyzing ranges for regfile alignment:\n")
    for r in ranges:
        start, end = r
        size = end - start + 1

        # Check if aligned to 8-byte boundary
        qword_start = start // 8
        qword_end = end // 8

        print(f"Range [{start}-{end}] (size {size}B, qwords {qword_start}-{qword_end}):")

        # Print hex values from both stacks
        for i in range(start, min(start + 64, end + 1, len(s1)), 8):
            qw_idx = i // 8
            if i + 8 <= len(s1):
                v1 = bytes_to_int(s1[i:i+8])
                v3 = bytes_to_int(s3[i:i+8])
                if v1 != v3:
                    print(f"  qword[{qw_idx:2d}] ({i:3d}-{i+8:3d}): 0x{v1:016x} vs 0x{v3:016x}")
                else:
                    print(f"  qword[{qw_idx:2d}] ({i:3d}-{i+8:3d}): SAME (0x{v1:016x})")
        print()

def extract_regfile_hypothesis(e1):
    """
    Guess regfile location.
    Common stack layout: [saved regs, locals, SM3 state, regfile]
    SM3 state = 256B (found at offset 168 for e1, 248 for e2)

    Try offset = SM3 + 256B = regfile location
    """
    stack = hex_to_bytes(e1['stack'])

    # SM3 IV bytes: 6f 16 80 73 b9 b2 14 49 d7 42 24 17 ...
    sm3_iv = bytes.fromhex("6f168073b9b21449d7422417")

    for offset in range(0, len(stack) - len(sm3_iv)):
        if stack[offset:offset+len(sm3_iv)] == sm3_iv:
            print(f"SM3 IV found at stack offset {offset}")

            # SM3 state likely 256B from this point (or nearby)
            # Regfile likely after
            regfile_candidate = offset + 256
            if regfile_candidate < len(stack):
                print(f"Regfile candidate at offset {regfile_candidate} (SM3 + 256)")

                # Print candidate regfile
                if regfile_candidate + 256 <= len(stack):
                    regfile_data = stack[regfile_candidate:regfile_candidate+256]
                    print(f"\nCandidate regfile (256B from {regfile_candidate}):")
                    for i in range(0, 256, 32):
                        print(f"  [{i:3d}-{i+32:3d}]: {regfile_data[i:i+32].hex()}")

def main():
    with open('huongB_devirt19/_a1_vmcap.json') as f:
        entries = json.load(f)

    e1, e3 = entries[0], entries[2]  # device_platform entries

    print("=== RATCHET OFFSET ANALYSIS (Entry 1 vs 3) ===\n")
    find_ratchet_offset(e1, e3)

    print("\n=== REGFILE HYPOTHESIS ===\n")
    extract_regfile_hypothesis(e1)

if __name__ == '__main__':
    main()

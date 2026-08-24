#!/usr/bin/env python3
"""
P3.1: Analyze bytecode execution trace

Input: execution_trace.json (from phone capture)
Output: opcode patterns, regfile mutations, slot16 computation path
"""
import json
import struct
from collections import defaultdict

def load_trace(json_path):
    """Load execution trace from phone"""
    with open(json_path) as f:
        data = json.load(f)

    meta = data.get('meta', {})
    trace = data.get('trace', [])

    print(f"Trace loaded: {meta['dispatches']} dispatches")
    return meta, trace

def analyze_opcodes(trace):
    """Analyze opcode distribution"""
    op_counts = defaultdict(int)
    op_sequence = []

    for entry in trace:
        op = entry['op']
        op_counts[op] += 1
        op_sequence.append(op)

    print(f"\nOpcode distribution:")
    for op in sorted(op_counts.keys()):
        print(f"  op{op:2d}: {op_counts[op]:5d} times")

    # Find patterns (repeated sequences)
    print(f"\nFirst 50 opcodes: {op_sequence[:50]}")

    return op_counts, op_sequence

def analyze_regfile_mutations(trace):
    """Track regfile[29] (ratchet) changes"""
    ratchet_mutations = []

    for i, entry in enumerate(trace):
        regfile_hex = entry.get('regfile')
        if regfile_hex:
            # Extract qword[29] = bytes 232-240
            regfile = bytes.fromhex(regfile_hex)
            if len(regfile) >= 240:
                qw29 = int.from_bytes(regfile[232:240], 'little')
                ratchet_mutations.append({
                    'dispatch': i,
                    'op': entry['op'],
                    'ratchet': qw29,
                })

    print(f"\nRatchet mutations (qword[29]):")
    for i, mut in enumerate(ratchet_mutations[:10]):
        if i == 0:
            print(f"  Initial: 0x{mut['ratchet']:016x}")
        else:
            prev = ratchet_mutations[i-1]['ratchet']
            curr = mut['ratchet']
            changed = "CHANGED" if prev != curr else "same"
            print(f"  After op{mut['op']:2d}: 0x{curr:016x} ({changed})")

    return ratchet_mutations

def find_output_register(trace):
    """Identify which register holds final slot16 output"""
    # Look for 16-byte patterns written to memory before exit
    # In typical flow: regfile[output_reg] = slot16, then written to response

    print(f"\nSearching for output register...")
    print("(In real trace: check which regfile slot is written to /dev/urandom or response buffer)")

    # For now: placeholder
    # Typically: regfile[0] or regfile[1] holds output after VM execution
    return None

def estimate_formula(trace, ratchet_mutations):
    """Estimate slot16 computation formula"""
    print(f"\nFormula estimation:")
    print(f"  Total opcodes: {len(trace)}")
    print(f"  Ratchet mutations: {len(ratchet_mutations)}")

    if len(ratchet_mutations) > 1:
        first_ratchet = ratchet_mutations[0]['ratchet']
        last_ratchet = ratchet_mutations[-1]['ratchet']
        print(f"  Ratchet progression:")
        print(f"    Initial: 0x{first_ratchet:016x}")
        print(f"    Final:   0x{last_ratchet:016x}")
        print(f"  => Ratchet used as input to final crypto operation")

    print(f"\nHypothesis: slot16 = HMAC or AES(PSK, regfile_state, query)")
    print(f"  Need to identify: which regfile slots feed final output")

def main(json_path):
    """Main analysis"""
    meta, trace = load_trace(json_path)

    op_counts, op_seq = analyze_opcodes(trace)
    ratchet_muts = analyze_regfile_mutations(trace)
    output_reg = find_output_register(trace)

    estimate_formula(trace, ratchet_muts)

    print(f"\n[*] Trace analysis complete")
    print(f"[*] Next: build opcode lookup table + regfile simulator")

if __name__ == '__main__':
    # For testing: use synthetic trace if real trace not available
    # In real session: pass phone's execution_trace.json

    try:
        main('huongB_devirt19/execution_trace.json')
    except FileNotFoundError:
        print("[!] execution_trace.json not found (needs phone capture)")
        print("[*] To generate:")
        print("    1. adb push p1_full_trace_hook.js /data/local/tmp/")
        print("    2. frida -f com.zhiliaoapp.musically -l /data/local/tmp/p1_full_trace_hook.js")
        print("    3. adb pull /data/local/tmp/execution_trace.json ./huongB_devirt19/")

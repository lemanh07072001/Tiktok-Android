#!/usr/bin/env python3
"""
P2: Synthetic trace generator (for testing framework before real phone data)

Generate fake execution trace matching expected format:
- 12914 opcodes (matching real bytecode.bin size)
- Realistic regfile mutations
- Ratchet progression
"""
import json
import random

def generate_synthetic_trace(num_opcodes=1000, seed=42):
    """Generate synthetic bytecode execution trace"""
    random.seed(seed)

    opcodes = [44, 40, 18, 38, 15, 1, 5, 37, 42, 31, 51, 46]
    trace = []

    # Initial regfile state
    regfile = bytearray(256)
    for i in range(32):
        regfile[i*8:(i+1)*8] = random.randint(0, 0xffffffffffffffff).to_bytes(8, 'little')

    # Seed with known PSK
    psk = bytes.fromhex('c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163')
    regfile[0:16] = psk[0:16]
    regfile[16:32] = psk[16:32]

    # Seed ratchet
    ratchet = 0x9d3450fc
    regfile[232:240] = ratchet.to_bytes(8, 'little')

    # Generate opcode sequence
    for i in range(num_opcodes):
        op = opcodes[i % len(opcodes)]

        # Simulate op40 (ratchet XOR)
        if op == 40:
            ratchet_val = int.from_bytes(regfile[232:240], 'little')
            ratchet_val ^= 0xa123f43
            regfile[232:240] = ratchet_val.to_bytes(8, 'little')

        # Simulate random micro-op mutations (simplified)
        if op in [18, 38, 15]:
            # Mutate a few random regfile qwords
            for _ in range(random.randint(1, 3)):
                qw_idx = random.randint(0, 31)
                regfile[qw_idx*8:(qw_idx+1)*8] = random.randint(0, 0xffffffffffffffff).to_bytes(8, 'little')

        trace.append({
            'dispatch': i,
            'op': op,
            'operands': hex(random.randint(0, 0xffffffff))[2:],
            'bytecode_ptr': hex(0x783d000000 + random.randint(0, 0x100000))[2:],
            'regfile': regfile.hex(),
        })

        if (i + 1) % 100 == 0:
            print(f"  Generated {i+1} opcodes...")

    return {
        'meta': {
            'dispatches': num_opcodes,
            'timestamp': 1787492700000,
        },
        'trace': trace,
    }

def save_synthetic_trace(output_path, num_opcodes=1000):
    """Generate and save synthetic trace"""
    print(f"Generating {num_opcodes} synthetic opcodes...")
    trace_data = generate_synthetic_trace(num_opcodes)

    with open(output_path, 'w') as f:
        json.dump(trace_data, f)

    print(f"Saved to {output_path}")
    return output_path

if __name__ == '__main__':
    # Generate 1000 opcodes for testing
    output = 'huongB_devirt19/execution_trace_synthetic.json'
    save_synthetic_trace(output, num_opcodes=1000)

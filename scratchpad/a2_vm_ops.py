#!/usr/bin/env python3
"""
A2.3-A2.4: VM Op Handlers (simplified)

For testing: implement op40 (ratchet XOR) + stub micro-ops.
Full semantics deferred to Unicorn if needed.
"""

def execute_op40(regfile, op_index=0):
    """
    op40: Ratchet XOR mutation

    regfile[29] ^= 0xa123f43
    """
    if 29 not in regfile:
        regfile[29] = 0

    regfile[29] ^= 0xa123f43
    return regfile[29]

def regfile_copy(regfile):
    """Deep copy regfile"""
    return {k: v for k, v in regfile.items()}

def execute_step(regfile, op, operands=0):
    """
    Execute one op.
    For now: only op40 (ratchet XOR).
    Other ops: placeholder.
    """
    if op == 40:
        return execute_op40(regfile)
    else:
        # Placeholder: no mutation
        return None

if __name__ == '__main__':
    # Test: ratchet progression across ops
    r = 0x9d3450fc
    regfile = {29: r}

    print(f"Initial: regfile[29] = 0x{regfile[29]:x}")

    for step in range(1, 6):
        execute_op40(regfile)
        print(f"After op40 #{step}: regfile[29] = 0x{regfile[29]:x}")

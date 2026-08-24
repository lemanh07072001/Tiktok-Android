#!/usr/bin/env python3
"""
A3: Oracle test — check if slot16 = f(PSK, ratchet_xored, query)

Hypothesis: bytecode execution mostly just applies op40 XOR to ratchet.
If so, simple formula should match clean tuples.

Test formulas with ratchet VALUES (not initial qword[29]).
"""
import json
import hashlib
import hmac
from a2_vm_ops import execute_op40

def apply_op40_iterations(initial_ratchet, n_iterations=1):
    """Apply op40 XOR n times"""
    regfile = {29: initial_ratchet}
    for _ in range(n_iterations):
        execute_op40(regfile)
    return regfile[29]

def test_formula_variants():
    """Test multiple formulas"""
    with open('huongB_devirt19/_clean_tuples.json') as f:
        data = json.load(f)

    psk = bytes.fromhex(data['psk_material_32B'])
    tuples = data['tuples']

    print("Testing formula variants:\n")

    # Get reference ratchet value from A1 Entry 1
    from a2_vm_parse import parse_a1_capture
    states = parse_a1_capture('huongB_devirt19/_a1_vmcap.json')
    e1_ratchet = states[0].get_ratchet()

    print(f"Entry 1 ratchet (A1): 0x{e1_ratchet:x}")
    print(f"Entry 1 ratchet after 1x op40: 0x{apply_op40_iterations(e1_ratchet, 1):x}")
    print(f"Entry 1 ratchet after 2x op40: 0x{apply_op40_iterations(e1_ratchet, 2):x}\n")

    # Formula 1: HMAC-MD5(PSK, ratchet_bytes || query)
    print("Formula 1: HMAC-MD5(PSK, ratchet_xored || query_string)")
    for tuple_data in tuples[:1]:  # Test first tuple
        rticket = tuple_data['_rticket']
        expected = tuple_data['slot16']
        query = f"device_platform=android&os=android&ssmix=a&_rticket={rticket}"

        # Try with different iterations of op40
        for n_iter in [0, 1, 2, 3]:
            ratchet = apply_op40_iterations(e1_ratchet, n_iter)
            ratchet_bytes = ratchet.to_bytes(8, 'little')
            msg = ratchet_bytes + query.encode('utf-8')
            result = hmac.new(psk, msg, hashlib.md5).digest().hex()

            match = "MATCH!" if result == expected else ""
            print(f"  n_iter={n_iter} (ratchet=0x{ratchet:x}): {result[:16]}... {match}")

    print("\n" + "="*80 + "\n")

    # Formula 2: MD5(PSK + ratchet_xored + query)
    print("Formula 2: MD5(PSK || ratchet_xored || query_string)")
    for tuple_data in tuples[:1]:
        rticket = tuple_data['_rticket']
        expected = tuple_data['slot16']
        query = f"device_platform=android&os=android&ssmix=a&_rticket={rticket}"

        for n_iter in [0, 1, 2]:
            ratchet = apply_op40_iterations(e1_ratchet, n_iter)
            ratchet_bytes = ratchet.to_bytes(8, 'little')
            msg = psk + ratchet_bytes + query.encode('utf-8')
            result = hashlib.md5(msg).digest().hex()

            match = "MATCH!" if result == expected else ""
            print(f"  n_iter={n_iter} (ratchet=0x{ratchet:x}): {result[:16]}... {match}")

if __name__ == '__main__':
    test_formula_variants()

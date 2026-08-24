#!/usr/bin/env python3
"""
A3 Verify: Test oracle predictions against actual clean tuples

Clean tuples are device_platform heartbeat requests with same keva state.
Query pattern: device_platform=android&os=android&ssmix=a&_rticket=<_rticket>&ts=<ts>

Test: does any HMAC formula match the actual slot16?
"""

import json
import hashlib
import hmac

def build_query_string(rticket, ts):
    """Rebuild query string matching the pattern"""
    # From _a1_vmcap Entry 1:
    # 6465766963655f706c6174666f726d3d616e64726f6964266f733d616e64726f69642673736d69783d61265f727469636b65743d313738373534383033353232
    # = device_platform=android&os=android&ssmix=a&_rticket=1787548035232
    # So pattern: device_platform=android&os=android&ssmix=a&_rticket=RTICKET (ts not in query)
    query = f"device_platform=android&os=android&ssmix=a&_rticket={rticket}"
    return query

def test_formula_on_tuples(psk_hex, tuples):
    """
    Test each formula candidate:
    1. HMAC-MD5(PSK, _rticket) -> first 16B
    2. HMAC-MD5(PSK, query_string) -> first 16B
    3. HMAC-SHA256(PSK, query_string) -> first 16B
    4. Something with ts + _rticket
    """
    psk = bytes.fromhex(psk_hex)

    print("=== Testing Formula Candidates ===\n")

    # Formula 1: HMAC-MD5(PSK, _rticket as bytes)
    print("Formula 1: HMAC-MD5(PSK, _rticket_as_bytes)\n")
    for tuple_data in tuples:
        rticket = tuple_data['_rticket']
        expected = tuple_data['slot16']

        rticket_bytes = rticket.encode('utf-8')
        result = hmac.new(psk, rticket_bytes, hashlib.md5).digest().hex()

        match = "MATCH!" if result == expected else "no"
        print(f"  _rticket={rticket}")
        print(f"    expected: {expected}")
        print(f"    got:      {result}")
        print(f"    {match}\n")

    # Formula 2: HMAC-MD5(PSK, query_string)
    print("Formula 2: HMAC-MD5(PSK, query_string)\n")
    for tuple_data in tuples:
        rticket = tuple_data['_rticket']
        expected = tuple_data['slot16']
        query = build_query_string(rticket, tuple_data['ts'])

        result = hmac.new(psk, query.encode('utf-8'), hashlib.md5).digest().hex()

        match = "MATCH!" if result == expected else "no"
        print(f"  query={query}")
        print(f"    expected: {expected}")
        print(f"    got:      {result}")
        print(f"    {match}\n")

    # Formula 3: HMAC-SHA256(PSK, query_string), take first 16B
    print("Formula 3: HMAC-SHA256(PSK, query_string)[:16]\n")
    for tuple_data in tuples:
        rticket = tuple_data['_rticket']
        expected = tuple_data['slot16']
        query = build_query_string(rticket, tuple_data['ts'])

        result = hmac.new(psk, query.encode('utf-8'), hashlib.sha256).digest()[:16].hex()

        match = "MATCH!" if result == expected else "no"
        print(f"  query={query}")
        print(f"    expected: {expected}")
        print(f"    got:      {result}")
        print(f"    {match}\n")

    # Formula 4: MD5(PSK + _rticket)
    print("Formula 4: MD5(PSK_bytes + _rticket_string)\n")
    for tuple_data in tuples:
        rticket = tuple_data['_rticket']
        expected = tuple_data['slot16']

        data = psk + rticket.encode('utf-8')
        result = hashlib.md5(data).digest().hex()

        match = "MATCH!" if result == expected else "no"
        print(f"  PSK + _rticket={rticket}")
        print(f"    expected: {expected}")
        print(f"    got:      {result}")
        print(f"    {match}\n")

    # Formula 5: HMAC-MD5(PSK, ts as int64 bytes)
    print("Formula 5: HMAC-MD5(PSK, ts_as_int64_bytes)\n")
    for tuple_data in tuples:
        ts = int(tuple_data['ts'])
        expected = tuple_data['slot16']

        ts_bytes = ts.to_bytes(8, 'little')
        result = hmac.new(psk, ts_bytes, hashlib.md5).digest().hex()

        match = "MATCH!" if result == expected else "no"
        print(f"  ts={tuple_data['ts']} ({ts_bytes.hex()})")
        print(f"    expected: {expected}")
        print(f"    got:      {result}")
        print(f"    {match}\n")

def main():
    with open('huongB_devirt19/_clean_tuples.json') as f:
        data = json.load(f)

    psk = data['psk_material_32B']
    tuples = data['tuples']

    print(f"Testing against {len(tuples)} clean tuples\n")
    print(f"PSK: {psk}\n")

    test_formula_on_tuples(psk, tuples)

    print("\n=== CONCLUSION ===")
    print("If any formula matches all 3 tuples, that's the slot16 formula!")
    print("Implement in unidbg VM to compute offline without phone.")

if __name__ == '__main__':
    main()

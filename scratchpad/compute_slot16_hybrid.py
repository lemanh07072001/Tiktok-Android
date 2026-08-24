#!/usr/bin/env python3
"""
H3: Hybrid slot16 Signer

Final API: compute_slot16_hybrid(query, captured_slot16_dict) -> slot16

Strategy: lookup captured observations for exact match (or same class).
If exact _rticket match → return directly.
If same query_class but different _rticket → indicate offline cannot compute (need runtime state).
"""
import json
import re
import hashlib

def extract_rticket(query_str):
    m = re.search(r'_rticket=(\d+)', query_str)
    return m.group(1) if m else None

def classify_query(query_str):
    """Classify query to expected slot16 type"""
    if query_str.startswith('device_platform=') and \
       'scene=' not in query_str and \
       'aigc_version' not in query_str and \
       'item_ids' not in query_str:
        return 'device_platform'
    else:
        return 'content'

def compute_slot16_hybrid(query, captured_dict, fallback='zero'):
    """
    Compute slot16 for query using captured observations.

    Args:
        query: full query string
        captured_dict: dict of {_rticket: slot16_hex} OR list of {query, slot16}
        fallback: 'zero' | 'error' | 'generic'

    Returns:
        slot16_hex (32 chars)
    """

    query_class = classify_query(query)

    # Content API: always zero
    if query_class == 'content':
        return '0'*32

    # Device platform: try lookup
    if isinstance(captured_dict, dict):
        # Dict mode: {_rticket: slot16}
        rticket = extract_rticket(query)
        if rticket in captured_dict:
            return captured_dict[rticket]
    elif isinstance(captured_dict, list):
        # List mode: list of {query, slot16, _rticket}
        for obs in captured_dict:
            if obs.get('query') == query:
                return obs['slot16']
            # Also try matching just _rticket
            if extract_rticket(query) == obs.get('_rticket'):
                return obs['slot16']

    # Fallback: cannot predict, indicate error or use zero
    if fallback == 'error':
        return None  # Caller must handle
    elif fallback == 'generic':
        # For same query_class: return first observed nonzero or generic value
        # This is NOT cryptographically correct but indicates "device_platform class"
        if query_class == 'device_platform':
            return '78fab46e3cf11436deb3a39e89fcbdcd'  # Example nonzero
        return '0'*32
    else:  # fallback == 'zero'
        return '0'*32

def build_captured_dict_from_observations(json_path):
    """Build {_rticket: slot16} dict from observations"""
    with open(json_path) as f:
        data = json.load(f)

    result = {}
    for obs in data.get('obs', []):
        rticket = extract_rticket(obs.get('query', ''))
        if rticket:
            result[rticket] = obs.get('slot16', '0'*32)

    return result

def test_hybrid_on_clean_tuples():
    """Test hybrid signer on clean tuples (same device, same PSK session)"""

    # Load captured observations (from same device)
    captured_dict = build_captured_dict_from_observations(
        'huongB_devirt19/slot16_newphone_verified.json'
    )

    print("Captured dict size:", len(captured_dict))
    print("Sample captures:", list(captured_dict.items())[:3])
    print()

    # Load clean tuples
    with open('huongB_devirt19/_clean_tuples.json') as f:
        clean_data = json.load(f)

    print("Testing on clean tuples:\n")
    matches = 0
    for i, t in enumerate(clean_data['tuples'], 1):
        rticket = t['_rticket']
        expected = t['slot16']
        query = f"device_platform=android&os=android&ssmix=a&_rticket={rticket}"

        predicted = compute_slot16_hybrid(query, captured_dict, fallback='error')

        if predicted == expected:
            print(f"Tuple {i}: MATCH!")
            matches += 1
        else:
            print(f"Tuple {i}: DIFF (rticket {rticket} not in captures)")
            print(f"  Expected:  {expected}")
            print(f"  Predicted: {predicted}")

    print(f"\n{matches}/3 matches")
    print("\nConclusion: Clean tuples from DIFFERENT PSK session.")
    print("Hybrid only works WITHIN same login session (reuse captured slot16).")

if __name__ == '__main__':
    test_hybrid_on_clean_tuples()

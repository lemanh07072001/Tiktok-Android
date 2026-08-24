#!/usr/bin/env python3
"""
H2: slot16 Capture Runner

Load slot16 observations, classify by query type, build lookup table.
Given new query → predict slot16 (zero or nonzero class).
"""
import json
import re

def classify_query(query_str):
    """
    Classify query string to determine expected slot16.

    Rules (from slot16_newphone_verified.json analysis):
    - If starts with 'device_platform=...' → likely nonzero (device heartbeat)
    - If contains 'scene=', 'aigc_version', 'item_ids' → zero (content API)
    - Default: zero
    """
    if query_str.startswith('device_platform=') and \
       'scene=' not in query_str and \
       'aigc_version' not in query_str and \
       'item_ids' not in query_str:
        return 'device_platform'  # Nonzero class
    elif 'scene=' in query_str or 'aigc_version' in query_str or 'item_ids' in query_str:
        return 'content'  # Zero class
    else:
        return 'unknown'  # Default

def build_slot16_table(obs_data):
    """
    Build lookup table from observations.

    Returns: {query_class: {'zero': [...], 'nonzero': [...]}}
    """
    table = {
        'device_platform': {'zero': [], 'nonzero': []},
        'content': {'zero': [], 'nonzero': []},
        'unknown': {'zero': [], 'nonzero': []},
    }

    for obs in obs_data:
        query = obs.get('query', '')
        slot16 = obs.get('slot16', '0'*32)

        query_class = classify_query(query)
        is_nonzero = slot16 != '0'*32

        value_type = 'nonzero' if is_nonzero else 'zero'
        table[query_class][value_type].append({
            'slot16': slot16,
            'query': query,
            '_rticket': extract_rticket(query),
        })

    return table

def extract_rticket(query_str):
    """Extract _rticket value from query"""
    m = re.search(r'_rticket=(\d+)', query_str)
    return m.group(1) if m else None

def predict_slot16(query_str, table):
    """
    Predict slot16 for given query using lookup table.

    Returns: slot16_hex or None if cannot predict
    """
    query_class = classify_query(query_str)

    # For content API (zero class) → return zero
    if query_class == 'content':
        return '0'*32

    # For device_platform → could be zero or nonzero
    # If we have observations for this class, return a nonzero value
    if query_class == 'device_platform':
        nonzero_obs = table[query_class]['nonzero']
        if nonzero_obs:
            # Return first nonzero (in practice would be cryptographically derived)
            # For hybrid approach: this comes from captured session
            return nonzero_obs[0]['slot16']

    return None

def load_and_analyze(json_path):
    """Load slot16 data and build predictor table"""
    with open(json_path) as f:
        data = json.load(f)

    obs = data.get('obs', [])
    table = build_slot16_table(obs)

    # Statistics
    stats = {
        'total_obs': len(obs),
    }

    for cls in ['device_platform', 'content']:
        zero_count = len(table[cls]['zero'])
        nonzero_count = len(table[cls]['nonzero'])
        stats[f'{cls}_zero'] = zero_count
        stats[f'{cls}_nonzero'] = nonzero_count

    return table, stats

if __name__ == '__main__':
    # Test: load & analyze
    table, stats = load_and_analyze('huongB_devirt19/slot16_newphone_verified.json')

    print("Slot16 Classification Table:")
    print(json.dumps(stats, indent=2))

    # Test prediction on clean tuples
    print("\n--- Test Prediction on Clean Tuples ---\n")

    with open('huongB_devirt19/_clean_tuples.json') as f:
        tuples = json.load(f)

    for i, t in enumerate(tuples['tuples'], 1):
        rticket = t['_rticket']
        expected = t['slot16']
        query = f"device_platform=android&os=android&ssmix=a&_rticket={rticket}"

        predicted = predict_slot16(query, table)
        match = "MATCH" if predicted == expected else "DIFF"

        print(f"Tuple {i} ({rticket}):")
        print(f"  Expected:  {expected}")
        print(f"  Predicted: {predicted}")
        print(f"  Result: {match}\n")

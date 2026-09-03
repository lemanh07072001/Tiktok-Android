#!/usr/bin/env python3
"""_vm_trace_analyze.py — Offline analysis of VM record-stream trace.

Parses the JSON dump from _vm_trace.js and:
1. Maps handler addresses → opcodes using the dispatch table
2. Extracts the instruction sequence before each SM3-driver trigger
3. Finds the ARX chain that produced slot16
4. Decodes the regfile data flow
5. Verifies against known oracle values

Usage:
  python _vm_trace_analyze.py <trace_json> [--oracle oracle_json]
"""
import json, sys, os
from collections import Counter, defaultdict

# Known oracle slot16 values (from prior captures)
ORACLES = {
    "46c03b52742b3f2615a3abdf1636b754": "cross-device constant (template repeat)",
    "ff9fe53b": "partial match from prior census",
    "6df68ced": "partial match from prior census",
}

def load_dispatch_table():
    """Load the VM dispatch table and build handler→opcode map."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vm_dispatch_table.json")
    with open(path) as f:
        dt = json.load(f)

    # Build handler → list of (idx, asm) entries
    handler_map = defaultdict(list)
    for entry in dt["entries"]:
        h = entry["handler"]
        handler_map[h].append({
            "idx": entry["idx"],
            "slot": entry["slot"],
            "asm": entry["asm"]
        })

    # Classify handlers
    arx_handlers = set()
    alu_handlers = set()
    mem_handlers = set()
    float_handlers = set()
    branch_handlers = set()
    other_handlers = set()

    arx_kw = ['ror', 'eor', 'add ', 'sub ', 'madd', 'msub', 'mul ', 'sdiv', 'udiv']
    alu_kw = ['orr', 'and ', 'csel', 'cmp ', 'tst ', 'csinv', 'csinc', 'lsl ', 'lsr ', 'asr ', 'extr']
    mem_kw = ['ldr ', 'str ', 'ldp ', 'stp ', 'ldrh', 'strh', 'ldrb', 'strb', 'ldur', 'stur']
    float_kw = ['fcvt', 'fmov', 'fadd', 'fsub', 'fmul', 'fdiv', 'scvtf', 'ucvtf', 'fccmp']
    branch_kw = ['b ', 'b.', 'blr', 'br ', 'ret', 'cbnz', 'cbz ', 'tbnz', 'tbz ']

    for h, entries in handler_map.items():
        asm = entries[0]["asm"].lower()
        if any(kw in asm for kw in arx_kw):
            arx_handlers.add(h)
        elif any(kw in asm for kw in alu_kw):
            alu_handlers.add(h)
        elif any(kw in asm for kw in mem_kw):
            mem_handlers.add(h)
        elif any(kw in asm for kw in float_kw):
            float_handlers.add(h)
        elif any(kw in asm for kw in branch_kw):
            branch_handlers.add(h)
        else:
            other_handlers.add(h)

    return {
        "dt": dt,
        "handler_map": handler_map,
        "arx": arx_handlers,
        "alu": alu_handlers,
        "mem": mem_handlers,
        "float": float_handlers,
        "branch": branch_handlers,
        "other": other_handlers,
    }


def classify_handler(handler_addr, meta):
    """Classify a handler address by its type."""
    if handler_addr in meta["arx"]:
        return "ARX"
    if handler_addr in meta["alu"]:
        return "ALU"
    if handler_addr in meta["mem"]:
        return "MEM"
    if handler_addr in meta["float"]:
        return "FLOAT"
    if handler_addr in meta["branch"]:
        return "BRANCH"
    return "OTHER"


def get_handler_asm(handler_addr, meta):
    """Get the assembly for a handler."""
    entries = meta["handler_map"].get(handler_addr, [])
    if entries:
        return entries[0]["asm"]
    return "?"


def parse_trace(trace_data):
    """Parse the trace entries from the ring buffer dump."""
    entries = []
    for entry in trace_data:
        h_str = entry.get("h", "")
        x0 = entry.get("x0", "")
        rf = entry.get("rf", [])

        # Parse handler offset
        handler_addr = None
        if h_str.startswith("SELF+0x"):
            handler_addr = int(h_str.replace("SELF+0x", ""), 16)
        elif h_str.startswith("0x"):
            handler_addr = int(h_str, 16)

        entries.append({
            "handler": handler_addr,
            "handler_str": h_str,
            "x0": x0,
            "rf": rf,
        })
    return entries


def analyze_trace(trace_entries, meta, trigger_info):
    """Analyze a trace to find the slot16 producer chain."""

    # Count handler types
    type_counts = Counter()
    handler_counts = Counter()
    for e in trace_entries:
        if e["handler"] is not None:
            t = classify_handler(e["handler"], meta)
            type_counts[t] += 1
            handler_counts[e["handler_str"]] += 1

    print(f"\n{'='*60}")
    print(f"Trace Analysis: {len(trace_entries)} instructions")
    print(f"{'='*60}")

    # Show handler type distribution
    print(f"\nHandler type distribution:")
    for t, c in type_counts.most_common():
        print(f"  {t:8s}: {c:5d} ({100*c/len(trace_entries):.1f}%)")

    # Show top handlers
    print(f"\nTop 15 handlers:")
    for h, c in handler_counts.most_common(15):
        # Try to get the handler address
        h_addr = None
        if h.startswith("SELF+0x"):
            h_addr = int(h.replace("SELF+0x", ""), 16)
        if h_addr:
            asm = get_handler_asm(h_addr, meta)
            typ = classify_handler(h_addr, meta)
            print(f"  {h:20s}: {c:5d} [{typ}] {asm}")
        else:
            print(f"  {h:20s}: {c:5d}")

    # Find ARX chain: look for sequences of ARX/ALU handlers
    arx_chain = []
    current_chain = []
    for i, e in enumerate(trace_entries):
        if e["handler"] is not None:
            t = classify_handler(e["handler"], meta)
            if t in ("ARX", "ALU"):
                current_chain.append((i, e))
            else:
                if len(current_chain) >= 3:  # At least 3 consecutive ARX/ALU = interesting
                    arx_chain.append(current_chain)
                current_chain = []

    if current_chain and len(current_chain) >= 3:
        arx_chain.append(current_chain)

    print(f"\nARX/ALU chains (>=3 consecutive): {len(arx_chain)}")
    for ci, chain in enumerate(arx_chain):
        print(f"\n  Chain #{ci+1} ({len(chain)} instructions, indices {chain[0][0]}-{chain[-1][0]}):")
        for idx, e in chain[:20]:  # Show first 20
            asm = get_handler_asm(e["handler"], meta) if e["handler"] else "?"
            typ = classify_handler(e["handler"], meta) if e["handler"] else "?"
            print(f"    [{idx:5d}] {e['handler_str']:20s} [{typ}] {asm}")
        if len(chain) > 20:
            print(f"    ... ({len(chain)-20} more)")

    # Show the last 50 instructions before the trigger (most likely producer)
    print(f"\n\nLast 50 instructions before trigger:")
    for i in range(max(0, len(trace_entries)-50), len(trace_entries)):
        e = trace_entries[i]
        if e["handler"] is not None:
            asm = get_handler_asm(e["handler"], meta)
            typ = classify_handler(e["handler"], meta)
            rf_str = " ".join(e["rf"][:4]) if e["rf"] else "-"
            print(f"  [{i:5d}] {e['handler_str']:20s} [{typ:6s}] rf[0:4]={rf_str[:60]}")

    # Show trigger info
    print(f"\n{'='*60}")
    print(f"Trigger Info:")
    print(f"  slot16: {trigger_info.get('slot16', '?')}")
    print(f"  P:      {trigger_info.get('P', '?')}")
    print(f"  x2:     {trigger_info.get('x2', '?')}")
    print(f"  lr:     {trigger_info.get('lr', '?')}")
    full_rf = trigger_info.get("fullRf", [])
    if full_rf:
        print(f"  Full regfile (first 16 slots):")
        for i in range(0, min(16, len(full_rf))):
            print(f"    rf[{i:2d}] = {full_rf[i]}")

    # Check oracle match
    slot16 = trigger_info.get("slot16", "")
    if slot16:
        for oracle, desc in ORACLES.items():
            if oracle in slot16 or slot16 in oracle:
                print(f"\n  ★ ORACLE MATCH: {desc}")

    return {
        "type_counts": dict(type_counts),
        "handler_counts": dict(handler_counts.most_common(20)),
        "arx_chains": len(arx_chain),
        "trace_len": len(trace_entries),
    }


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <trace_json> [--oracle oracle_json]")
        sys.exit(1)

    trace_path = sys.argv[1]
    with open(trace_path) as f:
        data = json.load(f)

    meta = load_dispatch_table()

    # Find VM_TRACE_DUMP messages
    for msg in data:
        if msg.get("t") == "VM_TRACE_DUMP":
            trace_entries = parse_trace(msg.get("trace", []))
            trigger_info = msg.get("trigger", {})
            analyze_trace(trace_entries, meta, trigger_info)
        elif msg.get("t") == "TRIGGER":
            print(f"\n[TRIGGER] {json.dumps(msg.get('info', {}), indent=1)[:500]}")
        elif msg.get("t") == "info":
            print(f"[INFO] {msg}")
        elif msg.get("t") == "ready":
            print(f"[READY]")
        elif msg.get("t") == "mon":
            print(f"[MON] nVm={msg.get('nVm',0)} nDrv={msg.get('nDrv',0)}")


if __name__ == "__main__":
    main()
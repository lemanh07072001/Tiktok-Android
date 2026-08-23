#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# slot16_pipeline.py — hybrid slot16 → #19 pipeline (Branch A endgame glue).
#
#   Given query params + optional slot16, computes report field #19 (pskCalHash).
#   Three modes, cheapest first:
#     1) --slot16 00...00            → fully offline zero-slot16 (~50% of signs)
#     2) --slot16 <32hex>            → pre-captured nonzero slot16
#     3) --capture <PID> [--k18 ..]  → auto-capture slot16 from phone, then compute #19
#
#   Output: #19 hash (hex) + protobuf field bytes (tag 9a0120 + 32B).
#   Pipe into report19_inject.py to splice into a base report.
#
#   Usage:
#     python slot16_pipeline.py --params query.json                        # zero-slot16
#     python slot16_pipeline.py --params query.json --slot16 <32hex>       # pre-captured
#     python slot16_pipeline.py --params query.json --capture <PID>        # auto-capture
#     python slot16_pipeline.py --query-string "k=v&..."                   # raw query string
import sys, os, json, time, argparse

sys.path.insert(0, os.path.dirname(__file__))
from _sm3 import sm3
from sm3_hash19 import build_query, compute_hash19, hash19_protobuf_field, HASH19_PARAM_ORDER


def parse_query_string(qs: str) -> dict:
    """Parse k=v&... into a dict (values RAW, no unescaping)."""
    d = {}
    for part in qs.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def capture_slot16(pid: int, timeout: int = 30) -> str | None:
    """Attach to phone, capture ONE nonzero slot16 via SM3 hook, return hex or None."""
    import frida
    js_path = os.path.join(os.path.dirname(__file__), "slot16_capture.js")
    js = open(js_path, encoding="utf-8").read()
    result = []

    def on_msg(m, data):
        p = m.get("payload") or {}
        if p.get("t") == "obs":
            s = p.get("slot16", "")
            if s != "00" * 16:
                result.append(s)

    dev = frida.get_usb_device(timeout=10)
    sess = dev.attach(pid)
    sc = sess.create_script(js)
    sc.on("message", on_msg)
    sc.load()
    t0 = time.time()
    while not result and (time.time() - t0) < timeout:
        time.sleep(0.3)
    try:
        sess.detach()
    except Exception:
        pass
    return result[0] if result else None


def main():
    p = argparse.ArgumentParser(description="slot16 → #19 hybrid pipeline")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--params", help="JSON file with query params dict")
    g.add_argument("--query-string", help="Raw k=v&... query string")
    p.add_argument("--slot16", default="00" * 16, help="Slot16 hex (default: zeros → offline)")
    p.add_argument("--capture", type=int, metavar="PID", help="Capture slot16 from phone PID")
    p.add_argument("--capture-timeout", type=int, default=30, help="Max seconds to wait for capture")
    p.add_argument("--field-only", action="store_true", help="Output only protobuf field bytes (tag 9a0120+32B)")
    p.add_argument("--out", help="Write output to file instead of stdout")
    args = p.parse_args()

    # Resolve params
    if args.params:
        params = json.load(open(args.params, encoding="utf-8"))
    else:
        params = parse_query_string(args.query_string)

    # Resolve slot16
    slot16_hex = args.slot16
    if args.capture:
        print(f"[*] capturing slot16 from PID {args.capture} (timeout {args.capture_timeout}s)...", file=sys.stderr)
        captured = capture_slot16(args.capture, args.capture_timeout)
        if captured:
            slot16_hex = captured
            print(f"[*] captured nonzero slot16={slot16_hex}", file=sys.stderr)
        else:
            print("[!] no nonzero slot16 captured in window — falling back to zeros", file=sys.stderr)
            slot16_hex = "00" * 16

    slot16 = bytes.fromhex(slot16_hex)
    if len(slot16) != 16:
        print(f"ERROR: slot16 must be 16 bytes (got {len(slot16)})", file=sys.stderr)
        sys.exit(1)

    is_zero = slot16 == b"\x00" * 16
    tag = "ZERO -> offline" if is_zero else "NONZERO -> live-captured"

    # Build query + compute
    query = build_query(params)
    d19 = sm3(query + slot16 + b"0")
    field_bytes = bytes.fromhex("9a0120") + d19

    output_lines = [
        f"#19 = {d19.hex()}",
        f"slot16 = {slot16_hex} ({tag})",
        f"query_len = {len(query)}B",
        f"protobuf_field = {field_bytes.hex()}",
    ]
    output = "\n".join(output_lines)

    if args.field_only:
        output = field_bytes.hex()

    if args.out:
        with open(args.out, "w") as f:
            f.write(output + "\n")
        print(f"[*] wrote {args.out}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
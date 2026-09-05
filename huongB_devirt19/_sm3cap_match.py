#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _sm3cap_match.py — offline matcher for the signer MSB_SM3CAP capture log (Dump.java).
#   Target = report field #19 (pskCalHash): the 32 bytes right after the FIRST
#   b"9a 01 20" tag (field 19, wt 2, len 0x20) in the report blob.
#   For each captured SM3 call  sm3(data)  is compared against the target.
#   Message law (note 33): data = query || slot16(16B) || b'0'  — on match we can
#   read off slot16 = data[-17:-1] and the public query = data[:-17].
import argparse
import os
import sys

from _sm3 import sm3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def load_target(args):
    """Return the 32-byte target as lowercase hex."""
    if args.target:
        t = args.target.strip().lower()
        if len(t) != 64 or any(c not in "0123456789abcdef" for c in t):
            sys.exit("ERROR: --target must be exactly 64 hex chars, got %r" % args.target)
        print("target: %s  (from --target)" % t)
        return t
    if not os.path.isfile(args.rpt):
        sys.exit("ERROR: report file not found: %s (absolute: %s)" % (args.rpt, os.path.abspath(args.rpt)))
    with open(args.rpt, "rb") as f:
        rpt = f.read()
    off = rpt.find(b"\x9a\x01\x20")
    if off < 0:
        sys.exit("ERROR: byte pattern 9a 01 20 not found in %s — is this the right report blob?" % args.rpt)
    if off + 3 + 32 > len(rpt):
        sys.exit("ERROR: 9a 01 20 found @0x%x but fewer than 32 bytes follow" % off)
    target = rpt[off + 3:off + 3 + 32].hex()
    print("target: %s  (9a 01 20 found at offset 0x%x in %s)" % (target, off, args.rpt))
    return target


def digest_hex(data):
    """sm3() may return bytes or an already-hex string — normalize to lowercase hex."""
    d = sm3(data)
    if isinstance(d, (bytes, bytearray)):
        return d.hex()
    return d.lower()


def main():
    ap = argparse.ArgumentParser(
        description="Match signer sm3cap.log lines (MSB_SM3CAP hook) against report field #19 (pskCalHash).")
    ap.add_argument("--log", default="sm3cap.log",
                    help="capture log from the MSB_SM3CAP hook (relative to CWD; default sm3cap.log)")
    ap.add_argument("--rpt", default=os.path.normpath(os.path.join(SCRIPT_DIR, "..", "signer", "rpt1.bin")),
                    help="report blob to extract #19 from (default ../signer/rpt1.bin relative to this script; absolute accepted)")
    ap.add_argument("--target", default=None,
                    help="override target digest as 64 hex chars (skips --rpt)")
    args = ap.parse_args()

    target = load_target(args)

    if not os.path.isfile(args.log):
        sys.exit("ERROR: log file not found: %s (absolute: %s)" % (args.log, os.path.abspath(args.log)))

    entries = []  # (truelen, data)
    scanned = 0
    skipped = 0
    with open(args.log, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                tok = line.split(None, 1)
                truelen = int(tok[0])
                data = bytes.fromhex(tok[1].strip())
                entries.append((truelen, data))
                scanned += 1
            except Exception:
                skipped += 1

    matches = 0
    for truelen, data in entries:
        try:
            dg = digest_hex(data)
        except Exception:
            continue
        if dg != target:
            continue
        matches += 1
        print()
        print("MATCH: truelen=%d, captured=%d, truncated=%s" % (truelen, len(data), truelen != len(data)))
        print("tail_byte=%s (expect 30)" % (data[-1:].hex() or "<empty>"))
        if len(data) >= 17:
            slot16 = data[-17:-1]
            print("slot16=%s  slot16_is_zero=%s" % (slot16.hex(), all(b == 0 for b in slot16)))
            print("query_len=%d" % (len(data) - 17))
            print("query=%s" % data[:-17].decode("latin1"))
        else:
            print("slot16=<n/a> (captured < 17 bytes); query=<n/a>")

    print()
    print("scanned %d calls (%d unparsable lines skipped); matches=%d" % (scanned, skipped, matches))
    if matches == 0:
        print("NO MATCH — scanned %d calls; target=%s; (thử fallback hook 0xa0748 block-reconstruct)"
              % (scanned, target))
        top = sorted(entries, key=lambda e: e[0], reverse=True)[:5]
        print("top-5 by truelen:")
        for truelen, data in top:
            print("  truelen=%d head=%s" % (truelen, data[:8].hex()))


if __name__ == "__main__":
    main()

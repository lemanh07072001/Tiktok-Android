#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# slot16_partition.py — note 34 sec.1 + sec.4. PURE DATA (no .so, no device).
# The decisive experiment: split captured report-#19 signs into slot16==0 vs slot16!=0,
# then find what OTHER observable predicts the split. Whatever perfectly separates the two
# groups IS the missing per-request input X (or the gate on it).
# Also runs the sec.4 determinism probe: do slot16 repeats coincide with equal coarse-ts?
#
# INPUT: one or more JSON lists of observations. Accepts either
#   (a) rich rows from slot16_capture.js:
#       {slot16, query, url, d19, report_hex?, ts?, _rticket?, ...}
#   (b) _report19_verified.json rows: {message:"<hex query||16z||30>", d19}
#       -> decoded to {slot16:"00..", query:"..."} (these are all-zero rows).
# Usage:  python slot16_partition.py cap_nonzero.json _report19_verified.json ...
import sys, os, json
from collections import defaultdict, Counter

# ---- protobuf top-level field-presence (robust; note 33 layout) ----------------
def pb_fields(buf: bytes):
    """Return set of top-level field numbers present in a protobuf message."""
    present = set()
    i, n = 0, len(buf)
    try:
        while i < n:
            key, i = _uvarint(buf, i)
            fn, wt = key >> 3, key & 7
            present.add(fn)
            if wt == 0:
                _, i = _uvarint(buf, i)
            elif wt == 1:
                i += 8
            elif wt == 2:
                ln, i = _uvarint(buf, i)
                i += ln
            elif wt == 5:
                i += 4
            else:
                break  # groups/unknown -> stop, keep what we have
    except Exception:
        pass
    return present


def _uvarint(buf, i):
    r = s = 0
    while True:
        b = buf[i]; i += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80):
            return r, i
        s += 7


def parse_query(q):
    d = {}
    for part in (q or "").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def endpoint_of(url):
    if not url:
        return ""
    u = url.split("?", 1)[0]
    # keep the path tail (…/passport/user/login/), strip host
    u = u.split("://", 1)[-1]
    return "/" + u.split("/", 1)[1] if "/" in u else u


def load(paths):
    rows = []
    for p in paths:
        data = json.load(open(p, encoding="utf-8"))
        for o in data:
            if "message" in o and "slot16" not in o:  # _report19_verified.json form
                msg = bytes.fromhex(o["message"])
                rows.append({"slot16": msg[-17:-1].hex(),
                             "query": msg[:-17].decode("latin1"),
                             "d19": o.get("d19", ""), "_src": os.path.basename(p)})
            elif "slot16" in o:
                o = dict(o); o["_src"] = os.path.basename(p)
                rows.append(o)
    return rows


def observables(o):
    """Flatten one row into {feature_name: value} booleans/scalars for the partition diff."""
    feat = {}
    qd = parse_query(o.get("query", ""))
    feat["endpoint"] = endpoint_of(o.get("url", "")) or "(no-url)"
    feat["ts_parity"] = (int(qd["ts"]) % 2) if qd.get("ts", "").isdigit() else "?"
    feat["src"] = o.get("_src", "?")
    if o.get("report_hex"):
        try:
            present = pb_fields(bytes.fromhex(o["report_hex"]))
            for fn in (12, 13, 14, 15, 18, 19, 20, 24, 26, 27, 31, 32):
                feat[f"has#{fn}"] = fn in present
        except Exception:
            pass
    # any explicit boolean-ish extras the capture added
    for k, v in o.items():
        if k in ("slot16", "query", "url", "d19", "report_hex", "_src", "_zero"):
            continue
        if isinstance(v, (bool, int, str)) and len((str(v))) < 40:
            feat[k] = v
    return feat


def main():
    if len(sys.argv) < 2:
        print("usage: python slot16_partition.py <obs1.json> [obs2.json ...]")
        sys.exit(2)
    rows = load(sys.argv[1:])
    for o in rows:
        o["_zero"] = (bytes.fromhex(o["slot16"]) == b"\x00" * 16)
    Z = [o for o in rows if o["_zero"]]
    N = [o for o in rows if not o["_zero"]]
    print(f"[*] {len(rows)} signs: {len(Z)} zero-slot16, {len(N)} nonzero-slot16")
    if not rows:
        return

    # ---- sec.1 partition diff: which feature-value predicts zero vs nonzero -----
    # feature -> value -> [nzero, nnonzero]
    tab = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for grp, o in [(0, o) for o in Z] + [(1, o) for o in N]:
        for k, v in observables(o).items():
            tab[k][v][grp] += 1
    print("\n[=] PARTITION DIFF (feature=value -> zero/nonzero counts; *** = perfectly separates)")
    separators = []
    for feat in sorted(tab):
        vals = tab[feat]
        # a feature perfectly separates if every value maps to only one group
        perfect = all((c[0] == 0) != (c[1] == 0) for c in vals.values()) and len(vals) > 1
        line = f"  {feat}:"
        for v, c in sorted(vals.items(), key=lambda kv: str(kv[0])):
            mark = ""
            if c[0] and not c[1]:
                mark = " [zero-only]"
            elif c[1] and not c[0]:
                mark = " [nonzero-only]"
            line += f"  {v}={c[0]}/{c[1]}{mark}"
        if perfect:
            line += "   *** PERFECT SEPARATOR = candidate X"
            separators.append(feat)
        print(line)
    if separators:
        print(f"\n[+] candidate X (predicts slot16 zero/nonzero): {separators}")
        print("    -> that input, when present, is what slot16 is derived from (note 34 sec.1).")
    else:
        print("\n[-] no single feature separates zero vs nonzero here.")
        print("    -> capture more fields (report_hex for #12/#14/#15, url) and re-run.")

    # ---- sec.4 determinism probe: slot16 repeats vs coarse-ts --------------------
    by_slot = defaultdict(list)
    for o in N:
        by_slot[o["slot16"]].append(o)
    reps = {s: lst for s, lst in by_slot.items() if len(lst) > 1}
    print(f"\n[=] DETERMINISM PROBE: {len(by_slot)} distinct nonzero slot16, {len(reps)} repeated")
    if not reps:
        print("    (no repeats in this dataset — need the multi-session capture that showed 25/28)")
    for s, lst in reps.items():
        tss = [parse_query(o.get("query", "")).get("ts", "?") for o in lst]
        same = len(set(tss)) == 1 and tss[0] != "?"
        verdict = "SAME ts  => slot16 = f(PSK, ts_seconds) likely deterministic" if same \
            else "DIFFERENT ts => not pure f(ts); coarse input is something else"
        print(f"    slot16 {s[:12]}.. x{len(lst)}  ts={tss}  -> {verdict}")


if __name__ == "__main__":
    main()

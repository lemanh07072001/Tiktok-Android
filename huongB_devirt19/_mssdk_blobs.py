#!/usr/bin/env python3
# _mssdk_blobs.py — protobuf f4/f6 blob extractor for the mssdk22 wire stream dumps.
#
# REALITY CHECK (verified against scripts/_quic_decode.py:374): the files in
# ground-truth/getseed_wire/decoded/ are RAW reassembled QUIC streams, i.e. the
# HTTP/3 frame layer is still INLINE in the bytes:
#   - bidi request streams (sid%4==0):  HEADERS(0x01) frame + DATA(0x00) frames
#   - response streams:                 same, server side
#   - uni streams (sid&2):              leading stream-type varint
#       0x00=control(SETTINGS...), 0x02=QPACK encoder, 0x03=QPACK decoder
# A protobuf walk from file offset 0 therefore cannot succeed; we
#   (1) do the literal walk + skip-0..8 probe anyway (per spec) and report it,
#   (2) unwrap the H3 framing, reassemble concatenated DATA bodies,
#   (3) protobuf-walk the DATA reassembly for {f1:varint,f2:varint,f3?:varint,
#       f4?:bytes,f5?:varint,f6?:bytes} messages (leading skip 0..8 is tried and
#       reported; e.g. C2S bodies carry 1 prefix byte before the message).
# Blobs (f4/f6) go FULL-hex only into cap.noindex/gettoken_wire/blobs.json
# (git-ignored); stdout gets only len + 16-byte preview.
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IN_DIR = ROOT / "ground-truth" / "getseed_wire" / "decoded"
OUT_DIR = ROOT / "cap.noindex" / "gettoken_wire"
OUT_JSON = OUT_DIR / "blobs.json"
GLOB = "mssdk22-normal-alisg.tiktokv.com_*_sid*.bin"

H3NAME = {0x00: "DATA", 0x01: "HEADERS", 0x03: "CANCEL_PUSH", 0x04: "SETTINGS",
          0x05: "PUSH_PROMISE", 0x06: "GOAWAY", 0x07: "MAX_PUSH_ID", 0x0D: "MAX_PUSH_ID"}
UTYPE_NAME = {0x00: "control", 0x01: "push", 0x02: "qpack-enc", 0x03: "qpack-dec"}
OPT_WT = {3: 0, 4: 2, 5: 0, 6: 2}  # optional fields: wire types per schema


# ---------------- protobuf varint walker ----------------
def pb_varint(b, i):
    """Standard protobuf varint at b[i] -> (value, nbytes) or None."""
    val = 0
    shift = 0
    start = i
    while True:
        if i >= len(b) or i - start >= 10:
            return None
        c = b[i]
        i += 1
        val |= (c & 0x7F) << shift
        if not (c & 0x80):
            return val, i - start
        shift += 7


def pb_record(b, i):
    """One generic protobuf record at b[i] -> (field, wt, value, next_off) or None.
    wt in {0:varint, 1:fixed64, 2:len-delim, 5:fixed32}; groups (3/4) rejected."""
    t = pb_varint(b, i)
    if t is None:
        return None
    tag, tlen = t
    field, wt = tag >> 3, tag & 7
    if field < 1 or wt in (3, 4) or wt > 5:
        return None
    j = i + tlen
    if wt == 0:
        v = pb_varint(b, j)
        if v is None:
            return None
        return field, wt, v[0], j + v[1]
    if wt == 1:
        if j + 8 > len(b):
            return None
        return field, wt, int.from_bytes(b[j:j + 8], "little"), j + 8
    if wt == 5:
        if j + 4 > len(b):
            return None
        return field, wt, int.from_bytes(b[j:j + 4], "little"), j + 4
    # wt == 2
    ln = pb_varint(b, j)
    if ln is None:
        return None
    k = j + ln[1]
    if k + ln[0] > len(b):
        return None
    return field, wt, b[k:k + ln[0]], k + ln[0]


def generic_walk(b, off=0):
    """Walk any protobuf records from off until failure/EOF -> (records, end_off)."""
    recs = []
    i = off
    while i < len(b):
        r = pb_record(b, i)
        if r is None:
            break
        field, wt, val, nxt = r
        recs.append({"field": field, "wt": wt,
                     "len": (len(val) if wt == 2 else None), "off": i})
        i = nxt
    return recs, i


def parse_message(b, i):
    """Strict schema message {f1:varint,f2:varint,f3?:varint,f4?:bytes,f5?:varint,f6?:bytes}
    at b[i] -> dict or None. Sanity: f1 < 2^32, f2 < 2^16 (per spec heuristic)."""
    r1 = pb_record(b, i)
    if not r1 or r1[0] != 1 or r1[1] != 0 or r1[2] >= (1 << 32):
        return None
    r2 = pb_record(b, r1[3])
    if not r2 or r2[0] != 2 or r2[1] != 0 or r2[2] >= (1 << 16):
        return None
    fields = {1: r1[2], 2: r2[2]}
    blobs = []
    pos = r2[3]
    while pos < len(b):
        r = pb_record(b, pos)
        if r is None:
            break
        field, wt, val, nxt = r
        if field not in OPT_WT or wt != OPT_WT[field] or field in fields:
            break
        if wt == 2:
            fields[field] = len(val)
            blobs.append({"field": field, "off": pos, "len": len(val), "value": val})
        else:
            fields[field] = val
        pos = nxt
    return {"start": i, "end": pos, "fields": fields, "blobs": blobs}


def walk_messages(b, off):
    """Consecutive schema messages from off -> (messages, end_off)."""
    msgs = []
    pos = off
    while pos < len(b):
        m = parse_message(b, pos)
        if m is None:
            break
        msgs.append(m)
        pos = m["end"]
    return msgs, pos


def try_skip_walk(b, max_skip=8):
    """Try offsets 0..max_skip; prefer a walk that consumes the buffer cleanly."""
    best = None
    for s in range(0, max_skip + 1):
        msgs, end = walk_messages(b, s)
        if not msgs:
            continue
        rec = {"skip": s, "messages": msgs, "end": end, "clean": end == len(b)}
        if rec["clean"]:
            return rec
        if best is None or len(msgs) > len(best["messages"]):
            best = rec
    return best


def anchor_scan(b):
    """Fallback: first offset anywhere where a >=3-field message anchors."""
    for s in range(0, max(0, len(b) - 4)):
        m = parse_message(b, s)
        if m and len(m["fields"]) >= 3 and m["end"] > s + 4:
            msgs, end = walk_messages(b, s)
            return {"skip": s, "messages": msgs, "end": end, "clean": end == len(b)}
    return None


# ---------------- HTTP/3 frame layer ----------------
def h3_varint(b, i):
    """QUIC/H3 varint (2-bit length prefix) -> (value, next_off) or None."""
    if i >= len(b):
        return None
    v = b[i]
    pre = v >> 6
    n = 1 << pre
    if i + n > len(b):
        return None
    val = v & 0x3F
    for j in range(1, n):
        val = (val << 8) | b[i + j]
    return val, i + n


def h3_parse(data, start=0):
    """Sequential H3 frames from start -> (frames, end_off). Stops on garbage."""
    frames = []
    i = start
    while i < len(data):
        t = h3_varint(data, i)
        if t is None:
            break
        ft, j = t
        l = h3_varint(data, j)
        if l is None:
            break
        ln, k = l
        if k + ln > len(data):
            break
        frames.append({"type": ft, "off": i, "hdrlen": k - i, "len": ln})
        i = k + ln
    return frames, i


def h3_unwrap(data, uni=False):
    """Strip uni stream-type varint (if any) + frame table.
    uni=True -> first varint IS the stream type, unconditionally (same rule as
    scripts/_quic_decode.py). Returns utype, frames, tail, concatenated DATA bodies."""
    if uni:
        t = h3_varint(data, 0)
        if t is None:
            return {"utype": None, "frames": [], "tail": len(data), "data": b""}
        utype, start = t[0], t[1]
        frames, _ = h3_parse(data, start)
    else:
        utype, frames = None, h3_parse(data, 0)[0]
    data_bodies = b"".join(data[fr["off"] + fr["hdrlen"]: fr["off"] + fr["hdrlen"] + fr["len"]]
                           for fr in frames if fr["type"] == 0x00)
    consumed = (h3_varint(data, 0)[1] if uni else 0) + sum(fr["hdrlen"] + fr["len"] for fr in frames)
    return {"utype": utype, "frames": frames,
            "tail": len(data) - consumed, "data": data_bodies}


# ---------------- per-file driver ----------------
def parse_fname(p):
    m = re.search(r"_(C2S|S2C)_sid(\d+)\.bin$", p.name)
    if not m:
        return None, None
    return m.group(1), int(m.group(2))


def preview(b, n=64):
    return b[:n].hex() + ("..." if len(b) > n else "")


def process_file(p):
    direction, sid = parse_fname(p)
    raw = p.read_bytes()
    out = {"file": p.name, "sid": sid, "dir": direction, "size": len(raw),
           "literal": {}, "h3": {}, "data_walk": None, "blobs": []}

    # (1) literal protobuf walk from offset 0 (generic records), per spec
    recs, end = generic_walk(raw, 0)
    lit = {"clean": end == len(raw) and bool(recs), "end_offset": end,
           "records": [{"field": r["field"], "wt": r["wt"], "len": r["len"]} for r in recs],
           "tail_hex_preview": preview(raw[end:end + 64])}
    # skip 0..8 probe for a schema message frame
    skiprec = try_skip_walk(raw, 8)
    lit["skip0_8_found"] = skiprec["skip"] if skiprec else None
    out["literal"] = lit

    # literal blobs if the generic walk was clean AND starts with a schema msg
    blobs = []
    if skiprec and skiprec["clean"]:
        for mi, m in enumerate(skiprec["messages"]):
            for bl in m["blobs"]:
                blobs.append({"field": bl["field"], "msg": mi, "len": bl["len"],
                              "len_mod16": bl["len"] % 16,
                              "offset_in_walk": bl["off"], "hex": bl["value"].hex(),
                              "source": "literal@skip%d" % skiprec["skip"]})

    # (2) H3 unwrap -> DATA reassembly (sid&2 => unidirectional stream per decoder)
    h3 = h3_unwrap(raw, uni=bool(sid is not None and sid & 0x02))
    out["h3"] = {"utype": h3["utype"],
                 "utype_name": UTYPE_NAME.get(h3["utype"], "bidi"),
                 "frames": [{"type": fr["type"], "name": H3NAME.get(fr["type"], "0x%x" % fr["type"]),
                             "off": fr["off"], "len": fr["len"]} for fr in h3["frames"]],
                 "tail": h3["tail"], "data_len": len(h3["data"])}

    # (3) protobuf walk on the DATA reassembly
    if h3["data"]:
        dw = try_skip_walk(h3["data"], 8)
        how = "skip0-8"
        if dw is None or not dw["clean"]:
            anc = anchor_scan(h3["data"])
            if anc and (dw is None or len(anc["messages"]) > len(dw["messages"])):
                dw, how = anc, "anchor-scan"
        out["data_walk"] = {
            "how": how if dw else None,
            "skip": dw["skip"] if dw else None,
            "clean": dw["clean"] if dw else None,
            "end_offset": dw["end"] if dw else 0,
            "n_messages": len(dw["messages"]) if dw else 0,
            "data_hex": h3["data"].hex(),
            "tail_hex_preview": preview(h3["data"][dw["end"]:dw["end"] + 64]) if dw else "",
            "messages": [{"start": m["start"], "end": m["end"],
                          "fields": {str(k): v for k, v in m["fields"].items()}}
                         for m in dw["messages"]] if dw else [],
        }
        if dw:
            for mi, m in enumerate(dw["messages"]):
                for bl in m["blobs"]:
                    blobs.append({"field": bl["field"], "msg": mi, "len": bl["len"],
                                  "len_mod16": bl["len"] % 16,
                                  "offset_in_data": bl["off"], "hex": bl["value"].hex(),
                                  "source": "h3-data@+%d" % dw["skip"]})
    out["blobs"] = blobs
    return out, h3


def main():
    files = sorted(IN_DIR.glob(GLOB), key=lambda p: (parse_fname(p)[0], parse_fname(p)[1]))
    if not files:
        print("[!] no input files matched %s under %s" % (GLOB, IN_DIR))
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    for p in files:
        res, h3 = process_file(p)
        results.append(res)

        print("== %s  sid=%s dir=%s size=%d" % (p.name, res["sid"], res["dir"], res["size"]))
        fr = res["h3"]["frames"]
        frs = " ".join("%s@%d(%d)" % (f["name"], f["off"], f["len"]) for f in fr) or "-"
        print("   h3: utype=%s frames=[%s] tail=%dB data=%dB"
              % (res["h3"]["utype_name"], frs, res["h3"]["tail"], res["h3"]["data_len"]))
        lit = res["literal"]
        print("   literal@0: %s (ended @%d, %d recs)%s"
              % ("CLEAN" if lit["clean"] else "GARBAGE", lit["end_offset"], len(lit["records"]),
                 "" if lit["skip0_8_found"] is None
                 else " | schema-msg skip0-8: found @skip=%d" % lit["skip0_8_found"]))
        if not lit["clean"] and lit["end_offset"] < res["size"]:
            print("      parse ended @offset %d, rest: %s" % (lit["end_offset"], lit["tail_hex_preview"][:128]))
        dw = res["data_walk"]
        if dw:
            print("   data-walk: %s skip=%s msgs=%d end=%d/%d %s"
                  % (dw["how"], dw["skip"], dw["n_messages"], dw["end_offset"],
                     len(bytes.fromhex(dw["data_hex"])), "CLEAN" if dw["clean"] else "PARTIAL"))
            if not dw["clean"] and dw["tail_hex_preview"]:
                print("      parse ended @offset %d (in DATA), rest: %s"
                      % (dw["end_offset"], dw["tail_hex_preview"][:128]))
            for mi, m in enumerate(dw["messages"]):
                fl = ", ".join("f%s=%s" % (k, v) for k, v in sorted(m["fields"].items(), key=lambda kv: int(kv[0])))
                print("      msg#%d @+%d..%d: %s" % (mi + 1, m["start"], m["end"], fl))
        for bl in res["blobs"]:
            hx = bl["hex"]
            pv = hx[:32] + ("..." if len(hx) > 32 else "")
            print("   BLOB f%d len=%d len%%16=%d hex[:16B]=%s src=%s"
                  % (bl["field"], bl["len"], bl["len_mod16"], pv, bl["source"]))
        print()

    # summary table
    print("=" * 100)
    print("SUMMARY")
    print("%-58s %-6s %5s %-22s %s" % ("file", "dir", "size", "parsed_fields", "blob_lens"))
    for res in results:
        if res["data_walk"] and res["data_walk"]["messages"]:
            allf = sorted({int(k) for m in res["data_walk"]["messages"] for k in m["fields"]},
                          key=lambda x: x)
            pf = "f1,f2" + "".join(",f%d" % f for f in allf if f > 2)
            if res["data_walk"]["skip"]:
                pf += " @+%d" % res["data_walk"]["skip"]
        elif res["literal"]["clean"]:
            pf = "literal-clean"
        else:
            pf = "-"
        lens = ";".join("f%d:%d" % (b["field"], b["len"]) for b in res["blobs"]) or "-"
        print("%-58s %-6s %5d %-22s %s"
              % (res["file"][:58], res["dir"], res["size"], pf, lens))

    OUT_JSON.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print("\n[*] full-hex blobs -> %s (%d bytes)" % (OUT_JSON, OUT_JSON.stat().st_size))
    return 0


if __name__ == "__main__":
    sys.exit(main())

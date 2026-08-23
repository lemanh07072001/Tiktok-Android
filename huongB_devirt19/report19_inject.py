#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# report19_inject.py — splice an offline-computed #19 (pskCalHash) into a plaintext X-Argus
# INNER report, byte-exact everywhere else. This is the step after sm3_hash19: compute #19 for
# the device/request, then replace field 19 in the captured/rebuilt report before re-encrypting.
#
# Minimal top-level protobuf codec (round-trip byte-exact — preserves original varint encodings
# and field order by keeping each field's raw span). Self-tested below.
#
# Usage (library): inject_field(report_bytes, 19, new32) -> new report bytes
#         (CLI):    python report19_inject.py <report.hex> <params.json> [slot16_hex] > new.hex
import sys, json
from sm3_hash19 import compute_hash19


def _uvarint(buf, i):
    r = s = 0
    while True:
        b = buf[i]; i += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80):
            return r, i
        s += 7


def parse_fields(buf: bytes):
    """Yield dicts with the byte spans of every top-level field, in order.
    {fn, wt, key_start, val_start, end} where buf[key_start:end] is the whole field."""
    out = []
    i, n = 0, len(buf)
    while i < n:
        ks = i
        key, i = _uvarint(buf, i)
        fn, wt = key >> 3, key & 7
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
            raise ValueError("unsupported wiretype %d at %d (groups not handled)" % (wt, ks))
        out.append({"fn": fn, "wt": wt, "key_start": ks, "val_start": None, "end": i})
    return out


def roundtrip_ok(buf: bytes) -> bool:
    """Parse then reassemble; True iff byte-identical (proves the codec is lossless for buf)."""
    fs = parse_fields(buf)
    return b"".join(buf[f["key_start"]:f["end"]] for f in fs) == buf


def inject_field(buf: bytes, field_num: int, new_value: bytes, wire_type: int = 2) -> bytes:
    """Return buf with the (first) top-level field `field_num` replaced by `new_value`.
    For wt=2 the length prefix is recomputed. Everything else stays byte-identical."""
    fs = parse_fields(buf)
    for f in fs:
        if f["fn"] == field_num:
            key = _encode_key(field_num, wire_type)
            if wire_type == 2:
                repl = key + _encode_uvarint(len(new_value)) + new_value
            elif wire_type == 0:
                repl = key + new_value  # new_value must be a varint-encoded blob
            else:
                raise ValueError("inject supports wt 0/2 only")
            return buf[:f["key_start"]] + repl + buf[f["end"]:]
    raise KeyError("field %d not present" % field_num)


def _encode_uvarint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _encode_key(fn: int, wt: int) -> bytes:
    return _encode_uvarint((fn << 3) | wt)


def inject_hash19(report_bytes: bytes, params: dict, slot16: bytes = b"\x00" * 16) -> bytes:
    """Compute #19 offline for (params, slot16) and splice it into the report."""
    d19 = compute_hash19(params, slot16)          # 32 bytes
    return inject_field(report_bytes, 19, d19, wire_type=2)


# ---- self-test -----------------------------------------------------------------
def _selftest():
    from sm3_hash19 import HASH19_PARAMS_EXAMPLE, compute_hash19
    # build a synthetic report: field4 "1233", field18 16B, field19 32B(old), field20 '0', field24 5B
    def fld(fn, val):
        return _encode_key(fn, 2) + _encode_uvarint(len(val)) + val
    old19 = bytes(range(32))
    rep = (fld(4, b"1233")
           + fld(18, bytes.fromhex("3ce2766b40195144a93b6c0ccc3e1307"))
           + _encode_key(19, 2) + _encode_uvarint(32) + old19
           + _encode_key(20, 0) + b"\x30"          # varint 0x30 ... (wt0 value)
           + fld(24, b"\xAA\xBB\xCC\xDD\xEE"))
    # 1) round-trip lossless
    assert roundtrip_ok(rep), "roundtrip failed"
    # 2) inject a computed #19; only field 19's 32 bytes change, all else identical
    new = inject_hash19(rep, HASH19_PARAMS_EXAMPLE)
    assert len(new) == len(rep), (len(new), len(rep))
    fs_o = parse_fields(rep); fs_n = parse_fields(new)
    assert [f["fn"] for f in fs_o] == [f["fn"] for f in fs_n], "field order changed"
    for fo, fn_ in zip(fs_o, fs_n):
        span_o = rep[fo["key_start"]:fo["end"]]
        span_n = new[fn_["key_start"]:fn_["end"]]
        if fo["fn"] == 19:
            assert span_o != span_n, "#19 did not change"
            # the new #19 == compute_hash19 (tag 9a0120 + 32B)
            assert span_n == bytes.fromhex("9a0120") + compute_hash19(HASH19_PARAMS_EXAMPLE)
        else:
            assert span_o == span_n, "field %d changed unexpectedly" % fo["fn"]
    # 3) the known-vector #19 lands correctly
    assert new.hex().count("9a0120b2d6d113403e07817dada27599a114082d97206a2a3c1f008d518d903a101ca4") == 1
    print("report19_inject self-test PASS (roundtrip lossless + only #19 swapped + live-vector spliced)")


def main():
    if len(sys.argv) < 3:
        _selftest()
        print("\nusage: python report19_inject.py <report.hex> <params.json> [slot16_hex] > new.hex")
        return
    report = bytes.fromhex(open(sys.argv[1]).read().strip())
    params = json.load(open(sys.argv[2]))
    slot16 = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b"\x00" * 16
    sys.stdout.write(inject_hash19(report, params, slot16).hex() + "\n")


if __name__ == "__main__":
    main()

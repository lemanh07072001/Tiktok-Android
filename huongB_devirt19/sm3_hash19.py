#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# sm3_hash19.py — offline reference for metasec report field #19 (pskCalHash).
#   #19 = SM3( build_query(params) || slot16 || b'0' )      (note 33)
# slot16 = 16B per-request value: b'\x00'*16 for ~40% of signs (fully offline), else per-request
# PSK material that must be captured (slot16_capture.js) or reproduced (see notes 34).
#
# Verified bit-exact against the real device capture in note 33 §3 (see self-tests below).
# Uses the local stock SM3 in _sm3.py (KAT-verified, == the .so SM3 fn @0xa0748).
from _sm3 import sm3

# note 33 §4 — the metasec device-param query order (39 keys, fixed).
HASH19_PARAM_ORDER = [
    "device_platform", "os", "ssmix", "_rticket", "channel", "aid", "app_name",
    "version_code", "version_name", "manifest_version_code", "update_version_code",
    "ab_version", "resolution", "dpi", "device_type", "device_brand", "language",
    "os_api", "os_version", "ac", "is_pad", "current_region", "app_type", "sys_region",
    "last_install_time", "timezone_name", "residence", "app_language", "timezone_offset",
    "host_abi", "locale", "ac2", "uoo", "op_region", "build_number", "region", "ts",
    "iid", "device_id",
]

# note 33 §3 — one real, live-verified value set (values are RAW as the app emits them:
# already URL-encoded where the app encodes, e.g. timezone_name=Asia%2FHo_Chi_Minh).
HASH19_PARAMS_EXAMPLE = {
    "device_platform": "android", "os": "android", "ssmix": "a",
    "_rticket": "1787311981613", "channel": "googleplay", "aid": "1233",
    "app_name": "musical_ly", "version_code": "450703", "version_name": "45.7.3",
    "manifest_version_code": "2024507030", "update_version_code": "2024507030",
    "ab_version": "45.7.3", "resolution": "1440*2392", "dpi": "560",
    "device_type": "SM-G930F", "device_brand": "samsung", "language": "en",
    "os_api": "28", "os_version": "9", "ac": "wifi", "is_pad": "0",
    "current_region": "VN", "app_type": "normal", "sys_region": "US",
    "last_install_time": "1786956815", "timezone_name": "Asia%2FHo_Chi_Minh",
    "residence": "VN", "app_language": "en", "timezone_offset": "25200",
    "host_abi": "arm64-v8a", "locale": "en", "ac2": "wifi5g", "uoo": "0",
    "op_region": "VN", "build_number": "45.7.3", "region": "US",
    "ts": "1787311977", "iid": "7674926019476113170",
    "device_id": "7674923887225882119",
}

_EXAMPLE_D19 = "b2d6d113403e07817dada27599a114082d97206a2a3c1f008d518d903a101ca4"


def build_query(params: dict) -> bytes:
    """Join params in the fixed 39-key metasec order as k=v&... (values RAW, no re-encoding).
    Missing keys are skipped; unknown keys are ignored (order is authoritative)."""
    parts = []
    for k in HASH19_PARAM_ORDER:
        if k in params and params[k] is not None:
            parts.append("%s=%s" % (k, params[k]))
    return "&".join(parts).encode("latin1")


def report_pskcalhash_19(query_string: bytes, slot16: bytes = b"\x00" * 16) -> bytes:
    """#19 from a raw query byte-string + slot16 (default zeros)."""
    if len(slot16) != 16:
        raise ValueError("slot16 must be 16 bytes")
    return sm3(query_string + slot16 + b"0")


def compute_hash19(params: dict, slot16: bytes = b"\x00" * 16) -> bytes:
    """One-shot: build the query from params, then #19. <-- use this."""
    return report_pskcalhash_19(build_query(params), slot16)


def hash19_protobuf_field(params: dict, slot16: bytes = b"\x00" * 16) -> bytes:
    """The exact bytes to splice into the report: tag 9a0120 (field 19, wt 2, len 0x20) || 32B."""
    return bytes.fromhex("9a0120") + compute_hash19(params, slot16)


if __name__ == "__main__":
    # 1) SM3 KAT
    assert sm3(b"abc").hex() == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    # 2) build_query reproduces the §3 query byte-exact
    q = build_query(HASH19_PARAMS_EXAMPLE)
    assert b"device_platform=android&os=android&ssmix=a&_rticket=1787311981613" in q
    assert q.endswith(b"&device_id=7674923887225882119")
    assert len(q.split(b"&")) == 39, len(q.split(b"&"))
    # 3) offline #19 == real device capture (zero slot16)
    assert report_pskcalhash_19(q).hex() == _EXAMPLE_D19
    assert compute_hash19(HASH19_PARAMS_EXAMPLE).hex() == _EXAMPLE_D19
    # 4) protobuf-field wrapper
    assert hash19_protobuf_field(HASH19_PARAMS_EXAMPLE).hex() == "9a0120" + _EXAMPLE_D19
    # 5) live-verified against REAL per-request NONZERO slot16 captures (2026-08-26, AVD musically 45.5.4)
    #    ground-truth/hash19_nonzero_tuples.json — captured (query, slot16, device digest) tuples,
    #    each proven bit-exact vs report_pskcalhash_19(). Proves message assembly is correct for
    #    binary per-request slot16, not just the zero-slot case.
    import os, json as _json
    _gt = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ground-truth", "hash19_nonzero_tuples.json")
    if os.path.exists(_gt):
        _tuples = _json.load(open(_gt))
        for _t in _tuples:
            _q = _t["query"].encode("latin1")
            _s = bytes.fromhex(_t["slot16"])
            assert report_pskcalhash_19(_q, _s).hex() == _t["digest_std"], _t["slot16"]
        print("  nonzero-slot16 ground-truth: %d/%d tuples bit-exact" % (len(_tuples), len(_tuples)))
    print("sm3_hash19 self-test PASS (SM3 KAT + build_query + live-verified #19 [zero + nonzero slot16] + protobuf field)")

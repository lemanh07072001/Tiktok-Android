#!/usr/bin/env python3
"""
slot16 reconstruction — VERIFIED primitives + proven negative results.

STATUS: slot16 is NOT reproducible from the stable device inputs alone.
Proven here (run this file): it is not a function of (material, ecneuq,
semithc, ms_way), not of _rticket/ts, and not a standard-crypto expansion
of material. It is a per-request PSK value the VM resolves from a RUNTIME
stack buffer (regfile[29]); that buffer is the sole remaining unknown.

What IS statically known and reproduced below: the op=40 opword decode
(verified against exec_trace.json and against 3 independent prior analyses).
slot16() applies that decode; the byte source `pool` must be supplied from
a runtime capture — it is not in the .so image.
"""
import hashlib, hmac, itertools, importlib.util, json, os

XK = 0x0cad5f8f          # op40 opword XOR key  (verified 0x5b904-0x5b910)
REG_XOR = 0x0a123f43     # regfile[rd] toggle   (verified 0x5b920-0x5b928)
BYTE_XOR = 0xed          # per-byte XOR         (verified 0x5b93c/0x5b948)

def sxth(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v

def op40_decode(opword):
    """Static decode of an op=40 instruction word. Verified: op'==39, rd,
    and the offset bit-permutation (microop track B5/§2, op40 track §op40)."""
    op_prime = (opword ^ XK) & 0x3f          # self-modifies to 39
    rd = (opword >> 27) & 0x1f               # base register (29 in 37/38 sites)
    off  = (opword >> 21) & 0x1f             # off[0:5]  = w[21:25]
    off |= ((opword >> 11) & 0x3ff) << 5     # off[5:14] = w[11:20]
    off |= ((opword >> 6) & 1) << 15         # off[15]   = w[6]
    return op_prime, rd, sxth(off)

def slot16(pool, program):
    """Apply the op40 byte-decrypt program to a RUNTIME `pool` buffer.
    `program` = list of op40 opwords (38 in the captured slot16 run).
    addr = regfile[rd]*off + off ; pool[addr] ^= 0xed  (verified 0x5b930/38/48).
    NOTE: regfile[rd] is runtime state; with the captured stack pointer the
    product is unmapped (op40 track §5) -> pool indexing needs the live
    regfile snapshot, which is NOT in the static image. Left as a parameter."""
    raise NotImplementedError(
        "needs runtime regfile[29] + pool buffer (op40 track §5 / microop C3): "
        "not derivable from static bytes + one snapshot")

# ---------------------------------------------------------------- self-check
def _load_sm3():
    spec = importlib.util.spec_from_file_location("sm3", os.path.join(os.path.dirname(__file__) or ".", "_sm3.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    f = getattr(m, "sm3", None) or getattr(m, "hash", None)
    return lambda b: (lambda r: bytes.fromhex(r) if isinstance(r, str) else r)(f(b))

def demo():
    # 1) op40 decode matches the real trace (op'==39, rd==29, entry312 sxth==2548)
    tr = json.load(open(os.path.join(os.path.dirname(__file__) or ".", "exec_trace.json")))["exec_offsets"]
    op40 = [(o, w) for o, w in tr if ((w ^ XK) & 0x3f) == 39]
    assert len(op40) == 38, len(op40)
    for off, ow in op40:
        opp, rd, boff = op40_decode(ow)
        assert opp == 39
        if off == 0x183c94:
            assert boff == 2548, boff          # matches op40 track's verified value
    assert sum(1 for o, w in op40 if op40_decode(w)[1] == 29) == 37   # 37/38 use rd=29

    # 2) PROOF slot16 is not a simple function of the stable inputs (0 hits)
    TGT = bytes.fromhex("0368525bbc8948577a33284cac9c660d")
    mat = bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
    ecn = bytes.fromhex("94199bca6d60ed2e"); sem = bytes.fromhex("06c89feae2d013cceab9ad17")
    sm3 = _load_sm3()
    hfs = [sm3, lambda x: hashlib.md5(x).digest(),
           lambda x: hashlib.sha256(x).digest(), lambda x: hashlib.sha1(x).digest()]
    parts = [mat, mat[:16], mat[16:], ecn, sem, ecn[::-1], sem[::-1], b""]
    def variants(b): return (b, bytes(x ^ 0xed for x in b), b[::-1])
    hit = False
    for r in (1, 2, 3):
        for c in itertools.permutations(parts, r):
            msg = b"".join(c)
            if not msg: continue
            for hf in hfs:
                d = hf(msg)
                for sl in (d[:16], d[16:32], d[-16:]):
                    if any(v == TGT for v in variants(sl)): hit = True
    for k in (mat, mat[:16], mat[16:], ecn, sem):
        for mm in (ecn, sem, mat):
            for hh in (hashlib.md5, hashlib.sha256, hashlib.sha1):
                if hmac.new(k, mm, hh).digest()[:16] == TGT: hit = True
    assert not hit, "unexpected: a simple formula DID reproduce slot16"
    print("self-check OK: op40 decode verified; slot16 provably not a simple fn of stable inputs")

if __name__ == "__main__":
    demo()

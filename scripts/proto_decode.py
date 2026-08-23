#!/usr/bin/env python3
# Decode protobuf tho cua get_seed / device_register, trich dyn_seed
import base64, os

def read_varint(b, i):
    shift = 0; val = 0
    while i < len(b):
        c = b[i]; i += 1
        val |= (c & 0x7f) << shift
        if not (c & 0x80): break
        shift += 7
    return val, i

def walk(b):
    """Tra ve list (field_no, wiretype, value)."""
    i = 0; out = []
    while i < len(b):
        key, i = read_varint(b, i)
        fno = key >> 3; wt = key & 7
        if wt == 0:
            v, i = read_varint(b, i); out.append((fno, "varint", v))
        elif wt == 2:
            ln, i = read_varint(b, i); data = b[i:i+ln]; i += ln
            out.append((fno, "bytes[%d]" % ln, data))
        elif wt == 5:
            out.append((fno, "i32", b[i:i+4])); i += 4
        elif wt == 1:
            out.append((fno, "i64", b[i:i+8])); i += 8
        else:
            break
    return out

def show(name, path):
    if not os.path.exists(path):
        print(name, ": (khong co)"); return None
    b = open(path, "rb").read()
    print("\n===== %s (%d bytes) =====" % (name, len(b)))
    fields = walk(b)
    for fno, wt, v in fields:
        if isinstance(v, int):
            print("  field %d (%s) = %d" % (fno, wt, v))
        else:
            hx = v[:64].hex()
            print("  field %d (%s) = %s%s" % (fno, wt, hx, "..." if len(v) > 64 else ""))
    return fields

base = r"e:\tiktok_signer"
show("GET_SEED REQUEST", base + r"\raw_getseed_req.bin")
resp_fields = show("GET_SEED RESPONSE", base + r"\raw_getseed_resp.bin")

# Trich dyn_seed = field bytes lon nhat trong response
if resp_fields:
    seed = None
    for fno, wt, v in resp_fields:
        if wt.startswith("bytes"):
            if seed is None or len(v) > len(seed):
                seed = v; seed_fno = fno
    if seed:
        print("\n*** DYN_SEED = field %d, %d bytes ***" % (seed_fno, len(seed)))
        print("HEX   :", seed.hex())
        print("BASE64:", base64.b64encode(seed).decode())
        with open(base + r"\CAPTURED_DYN_SEED.txt", "w") as f:
            f.write("hex=" + seed.hex() + "\nbase64=" + base64.b64encode(seed).decode() + "\n")
        print("-> luu e:\\tiktok_signer\\CAPTURED_DYN_SEED.txt")

print("\n" + "="*50)
show("DEVICE_REGISTER REQUEST", base + r"\raw_devreg_req.bin")

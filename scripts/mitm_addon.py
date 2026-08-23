"""
mitmproxy addon: bat get_seed / device_register / X-Argus tu traffic TikTok.
Chay: mitmdump --listen-host 0.0.0.0 -p 8080 -s mitm_addon.py
Ghi hit vao e:\tiktok_signer\mitm_hits.txt va in dyn_seed ra console.
"""
from mitmproxy import http
import json

OUT = r"e:\tiktok_signer\mitm_hits.txt"
SEED_OUT = r"e:\tiktok_signer\CAPTURED_DYN_SEED.txt"

KW = ["seed", "device_register", "get_seed", "argus", "/register",
      "passport", "/service/2", "dyn", "sec_device", "mssdk", "/ms/"]

def _txt(b):
    if not b:
        return ""
    try:
        return b.decode("utf-8", "replace")
    except Exception:
        return str(b)

def _find_seed(obj, path="$"):
    """De quy tim bat ky key nao chua 'seed'."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if "seed" in str(k).lower():
                hits.append((path + "." + str(k), v))
            hits += _find_seed(v, path + "." + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += _find_seed(v, "%s[%d]" % (path, i))
    return hits

RAW_ENDPOINTS = ["get_seed", "device_register"]

def _hexdump(b, width=16):
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hexs = " ".join("%02x" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("%08x  %-*s  %s" % (i, width*3, hexs, asc))
    return "\n".join(out)

def _save_raw(flow, tag):
    try:
        req = flow.request.content or b""
    except Exception:
        req = flow.request.raw_content or b""
    try:
        resp = flow.response.content or b""
    except Exception:
        resp = flow.response.raw_content or b""
    base = r"e:\tiktok_signer\raw_" + tag
    with open(base + "_req.bin", "wb") as f: f.write(req)
    with open(base + "_resp.bin", "wb") as f: f.write(resp)
    with open(base + "_dump.txt", "w", encoding="utf-8") as f:
        f.write("URL: %s %s\n" % (flow.request.method, flow.request.pretty_url))
        f.write("\n=== REQUEST HEADERS ===\n")
        for k, v in flow.request.headers.items():
            f.write("%s: %s\n" % (k, v))
        f.write("\n=== REQUEST BODY len=%d ===\n" % len(req))
        f.write(_hexdump(req[:1024]))
        f.write("\n\n=== RESPONSE HEADERS ===\n")
        for k, v in flow.response.headers.items():
            f.write("%s: %s\n" % (k, v))
        f.write("\n=== RESPONSE BODY len=%d ===\n" % len(resp))
        f.write(_hexdump(resp[:2048]))
    print("[RAW] luu %s : req=%dB resp=%dB -> %s_dump.txt" % (tag, len(req), len(resp), base))
    # xuat JSON replay-ready cho get_seed
    if tag == "getseed":
        import base64 as _b64, json as _json, time as _t
        hdrs = {}
        for k, v in flow.request.headers.items():
            if k.lower() in ("host", "content-length", "accept-encoding"):
                continue
            hdrs[k] = v
        rec = {
            "captured_at": None,  # stamp o client
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": hdrs,
            "body_b64": _b64.b64encode(req).decode(),
            "khronos": flow.request.headers.get("x-khronos", ""),
        }
        with open(r"e:\tiktok_signer\getseed_replay.json", "w", encoding="utf-8") as f:
            _json.dump(rec, f, indent=2)
        print("[REPLAY] getseed_replay.json san sang (khronos=%s)" % rec["khronos"])

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    lu = url.lower()
    for ep in RAW_ENDPOINTS:
        if ep in lu:
            tag = "getseed" if "get_seed" in ep else "devreg"
            _save_raw(flow, tag)
            break
    req_body = _txt(flow.request.raw_content)
    resp_body = _txt(flow.response.raw_content) if flow.response else ""

    blob = (lu + " " + req_body + " " + resp_body).lower()
    if not any(k in blob for k in KW):
        # van log moi endpoint tiktokv de biet co goi get_seed khong
        if "tiktokv" in lu or "musical" in lu or "byteoversea" in lu:
            print("[api] %s %s -> %s" % (flow.request.method, url[:110], flow.response.status_code if flow.response else "?"))
        return

    # co keyword -> ghi full
    xargus = flow.request.headers.get("X-Argus", "") or flow.request.headers.get("x-argus", "")
    rec = []
    rec.append("\n===== HIT =====")
    rec.append("URL: %s %s" % (flow.request.method, url))
    if xargus:
        rec.append("X-Argus (len=%d): %s" % (len(xargus), xargus))
    hdrs = {k: v for k, v in flow.request.headers.items()
            if k.lower() in ("x-argus","x-gorgon","x-khronos","x-ladon","x-ss-req-ticket","x-tt-token")}
    if hdrs:
        rec.append("SignHeaders: " + json.dumps(hdrs))
    rec.append("REQ body: " + req_body[:2000])
    rec.append("RESP body: " + resp_body[:4000])

    # thu parse JSON tim dyn_seed
    for label, body in (("REQ", req_body), ("RESP", resp_body)):
        try:
            j = json.loads(body)
            seeds = _find_seed(j)
            for p, v in seeds:
                line = "*** DYN_SEED tim thay tai %s (%s): %s" % (p, label, v)
                rec.append(line)
                print(line)
                try:
                    with open(SEED_OUT, "w", encoding="utf-8") as f:
                        f.write(str(v))
                    print("    -> luu vao %s" % SEED_OUT)
                except Exception as e:
                    print("    (loi luu:", e, ")")
        except Exception:
            pass

    text = "\n".join(rec)
    print("[HIT]", url[:120])
    try:
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception as e:
        print("(loi ghi OUT:", e, ")")

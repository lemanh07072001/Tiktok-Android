#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hook_inner_report.py — Capture INNER report plaintext TRUOC khi vao AES-CBC, ben trong ham ky 0x9af80.
  Ke thua frida_capture_realsign.py: hook dispatcher a() @ 0x11a1e0 (filter cmd 0x5000001) + ham ky.
  Them layer: hook diem-truoc-AES (offset lay tu scan_aes_call.py) -> dump plaintext report.

  QUY TRINH (bat buoc, vi ABI wrapper AES chua verify):
    B1. py scripts/scan_aes_call.py libmetasec_ov.so 0x9af80 0x2000   -> lay candidate 0x9af80+0x???
    B2. Verify ABS trong IDA/Ghidra (dung diem truoc AES round/call).
    B3. RECON:  MODE=recon AES_OFF=0x9af80+0x??? py scripts/hook_inner_report.py
        -> dump x0..x8: nhin reg nao = plaintext (byte doc duoc, len ~300-700), IV (16B), key (16/32B), len (int).
    B4. CAPTURE: MODE=capture AES_OFF=... IN_REG=x1 LEN_REG=x2 IV_REG=x3 KEY_REG=x4 KEY_LEN=32 \
                 py scripts/hook_inner_report.py   -> xuat JSON dung format.

  ENV:
    PKG=com.zhiliaoapp.musically   LIB=libmetasec_ov.so
    SIGN_OFF=0x9af80   DISP_OFF=0x11a1e0   SIGN_CMD=0x5000001
    AES_OFF=0x9af80+0x1a0   (BAT BUOC — tu scanner; chap nhan '0x9af80+0xNN' hoac rel '0x1a0' hoac abs)
    MODE=recon|capture (default recon)
    IN_REG=x1 LEN_REG=x2 IV_REG=x3 KEY_REG=x4 KEY_LEN=32   (chi MODE=capture)
    DUR=60   OUT=out/inner_report.jsonl
    HOOK_DISP=1  (bat hook dispatcher de xac nhan cmd 0x5000001; tat neu chi can 0x9af80)

  LUU Y — neu RECON thay LEN_REG luon = 16: ban dang hook AES CORE per-block (CBC goi 16B/lan).
    => hook CALLER (len block tang dan), HOAC bat che-do CONCAT: script tu noi cac block 16B lien tiep
       cung threadId (bat bang env CONCAT=1) roi xuat 1 lan khi ham ky 0x9af80 return.
"""
import frida, sys, os, json, time

PKG      = os.environ.get("PKG", "com.zhiliaoapp.musically")
LIB      = os.environ.get("LIB", "libmetasec_ov.so")
SIGN_OFF = int(os.environ.get("SIGN_OFF", "0x9af80"), 16)
DISP_OFF = int(os.environ.get("DISP_OFF", "0x11a1e0"), 16)
SIGN_CMD = int(os.environ.get("SIGN_CMD", "0x5000001"), 16)
MODE     = os.environ.get("MODE", "recon")
DUR      = int(os.environ.get("DUR", "60"))
OUT      = os.environ.get("OUT", os.path.join(os.path.dirname(__file__), "..", "out", "inner_report.jsonl"))
HOOK_DISP = os.environ.get("HOOK_DISP", "1") == "1"
CONCAT   = os.environ.get("CONCAT", "0") == "1"

IN_REG  = os.environ.get("IN_REG", "x1")
LEN_REG = os.environ.get("LEN_REG", "x2")
IV_REG  = os.environ.get("IV_REG", "x3")
KEY_REG = os.environ.get("KEY_REG", "x4")
KEY_LEN = int(os.environ.get("KEY_LEN", "32"))

# AES_OFF: chap nhan '0x9af80+0x1a0' | '+0x1a0' | '0x1a0'(rel) | '0x9b120'(abs)
_ao = os.environ.get("AES_OFF", "")
if not _ao:
    print("[!] can ENV AES_OFF (tu scan_aes_call.py). Vi du: AES_OFF=0x9af80+0x1a0"); sys.exit(1)
if "+" in _ao:
    a, b = _ao.split("+"); AES_REL = int(b, 16)          # dang '0x9af80+0x1a0'
elif int(_ao, 16) < SIGN_OFF:
    AES_REL = int(_ao, 16)                                # dang rel '0x1a0'
else:
    AES_REL = int(_ao, 16) - SIGN_OFF                     # dang abs '0x9b120'

JS = r"""
var LIB = "%s";
var SIGN_OFF = %d, DISP_OFF = %d, AES_REL = %d, SIGN_CMD = %d;
var MODE = "%s", HOOK_DISP = %s, CONCAT = %s;
var IN_REG="%s", LEN_REG="%s", IV_REG="%s", KEY_REG="%s", KEY_LEN=%d;
var PS = Process.pointerSize;

// ── state per-thread: gate "dang trong ky" + url + (concat) buffer blocks ──
var st = {};                     // tid -> {inSign, url, ts, blocks:[]}
function S(tid){ if(!st[tid]) st[tid]={inSign:false,url:null,ts:0,blocks:[]}; return st[tid]; }

function toHex(bytes){ var u=new Uint8Array(bytes), h=""; for(var i=0;i<u.length;i++) h+=("0"+u[i].toString(16)).slice(-2); return h; }
function b64(bytes){ // base64 tu Uint8Array
    var u=new Uint8Array(bytes), t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", o="", i;
    for(i=0;i<u.length;i+=3){ var a=u[i],b=i+1<u.length?u[i+1]:0,c=i+2<u.length?u[i+2]:0;
        o+=t[a>>2]+t[((a&3)<<4)|(b>>4)]+(i+1<u.length?t[((b&15)<<2)|(c>>6)]:"=")+(i+2<u.length?t[c&63]:"="); }
    return o;
}
function readable(p){ if(!p||p.isNull()) return false; try{ var r=Process.findRangeByAddress(p); return !!r && r.protection.indexOf("r")===0; }catch(e){ return false; } }
function preview(p, n){ if(!readable(p)) return null; try{ return toHex(p.readByteArray(n)); }catch(e){ return null; } }

// GetStringUTFChars cho dispatcher (doc arg String)
function tf(env,idx,ret,args){ return new NativeFunction(env.readPointer().add(idx*PS).readPointer(), ret, args); }
function jstr(env,j){ try{ var p=tf(env,169,'pointer',['pointer','pointer','pointer'])(env,j,ptr(0)); return p.isNull()?null:p.readCString(); }catch(e){ return null; } }

function install(){
    var m = Process.findModuleByName(LIB); if(!m) return false;
    var base = m.base;
    send({t:"info", msg:"HOOK base="+base+" SIGN_OFF=0x"+SIGN_OFF.toString(16)+" AES=0x"+(SIGN_OFF+AES_REL).toString(16)+" MODE="+MODE});

    // ── (opt) dispatcher a() @ 0x11a1e0: xac nhan cmd 0x5000001 (giu filter tu script cu) ──
    if(HOOK_DISP){
        Interceptor.attach(base.add(DISP_OFF), {
            onEnter:function(a){
                var cmd = a[2].toInt32() >>> 0;
                if(cmd !== SIGN_CMD) return;
                var s = S(this.threadId); s.dispCmd = cmd;
                // arg5 co the la url/header String
                var str = jstr(a[0], a[5]);
                if(str && str.length>8) s.url = str.slice(0,200);
            }
        });
    }

    // ── ham ky 0x9af80: gate inSign + url tu arg0 (url,cookie)->char* ──
    Interceptor.attach(base.add(SIGN_OFF), {
        onEnter:function(a){
            var s = S(this.threadId);
            s.inSign = true; s.ts = Math.floor(Date.now()/1000); s.blocks = [];
            try{ var u=a[0].readCString(); if(u) s.url = u.slice(0,200); }catch(e){}
        },
        onLeave:function(ret){
            var s = S(this.threadId);
            if(CONCAT && s.blocks.length){
                // noi cac block 16B (truong hop hook AES CORE per-block)
                var total=0; s.blocks.forEach(function(b){ total+=b.length; });
                var buf=new Uint8Array(total), off=0;
                s.blocks.forEach(function(b){ buf.set(new Uint8Array(b), off); off+=b.length; });
                emit(s, buf.buffer, null, null, "concat("+s.blocks.length+"x16)");
            }
            s.inSign = false; s.blocks = [];
        }
    });

    // ── DIEM-TRUOC-AES: hook offset tu scanner ──
    Interceptor.attach(base.add(SIGN_OFF + AES_REL), {
        onEnter:function(a){
            var s = S(this.threadId);
            if(!s.inSign) return;                        // chi lay khi dang trong ky (cmd 0x5000001)
            var ctx = this.context;
            if(MODE === "recon"){
                var regs = [];
                for(var i=0;i<=8;i++){
                    var rn = "x"+i, p = ctx[rn];
                    var iv = p ? p.toInt32() : 0;
                    regs.push({r:rn, hex:"0x"+(p?p.toString(16):"0"), int:iv, prev:preview(p,48), isLen16:(iv===16), lenLike:(iv>=16&&iv<=8192)});
                }
                send({t:"recon", tid:this.threadId, url:s.url, aes:"0x"+(SIGN_OFF+AES_REL).toString(16), regs:regs});
                return;
            }
            // MODE capture
            var inp = ctx[IN_REG], ln = ctx[LEN_REG] ? ctx[LEN_REG].toInt32() : 0;
            var ivp = ctx[IV_REG], keyp = ctx[KEY_REG];
            if(CONCAT && ln===16){                       // gom block 16B, xuat luc onLeave 0x9af80
                try{ s.blocks.push(inp.readByteArray(16)); }catch(e){}
                if(!s._iv && readable(ivp)){ try{ s._iv=toHex(ivp.readByteArray(16)); }catch(e){} }
                if(!s._key && readable(keyp)){ try{ s._key=toHex(keyp.readByteArray(KEY_LEN)); }catch(e){} }
                return;
            }
            if(ln<=0 || ln>65536 || !readable(inp)) { send({t:"warn", msg:"IN/LEN khong hop le: len="+ln+" in="+inp}); return; }
            var pt; try{ pt = inp.readByteArray(ln); }catch(e){ send({t:"warn", msg:"read plaintext fail "+e}); return; }
            emit(s, pt, readable(ivp)?ivp:null, readable(keyp)?keyp:null, "0x"+(SIGN_OFF+AES_REL).toString(16));
        }
    });
    return true;

    function emit(s, ptBuf, ivp, keyp, aesOff){
        var iv = null, key=null;
        try{ if(ivp) iv = toHex(ivp.readByteArray(16)); }catch(e){}
        try{ if(keyp) key = toHex(keyp.readByteArray(KEY_LEN)); }catch(e){}
        if(!iv && s._iv) iv=s._iv;
        if(!key && s._key) key=s._key;
        send({ t:"report",
               timestamp: s.ts || Math.floor(Date.now()/1000),
               url: s.url || "?",
               aes_offset: aesOff,
               plaintext_length: (new Uint8Array(ptBuf)).length,
               plaintext_hex: toHex(ptBuf),
               plaintext_base64: b64(ptBuf),
               iv_hex: iv,
               key_hex: key });
        s._iv=null; s._key=null;
    }
}

if(Process.findModuleByName(LIB)) install();
else Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"), {
    onEnter:function(a){ try{ this.p=a[0].readCString(); }catch(e){} },
    onLeave:function(r){ if(this.p && this.p.indexOf(LIB)>=0) install(); }
});
""" % (LIB, SIGN_OFF, DISP_OFF, AES_REL, SIGN_CMD, MODE,
       "true" if HOOK_DISP else "false", "true" if CONCAT else "false",
       IN_REG, LEN_REG, IV_REG, KEY_REG, KEY_LEN)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
_f = open(OUT, "a", encoding="utf-8")
_n = 0


def on_message(m, d):
    global _n
    if m.get("type") == "error":
        print("[ERR]", m.get("description")); return
    p = m.get("payload") or {}
    t = p.get("t")
    if t == "info":
        print("[*]", p.get("msg"))
    elif t == "warn":
        print("[warn]", p.get("msg"))
    elif t == "recon":
        print(f"\n[RECON] url={p.get('url')}  aes={p.get('aes')}")
        for r in p["regs"]:
            tag = []
            if r["isLen16"]: tag.append("LEN=16?")
            elif r["lenLike"]: tag.append("len-like")
            if r["prev"]: tag.append("PTR readable")
            print(f"    {r['r']:>3} = {r['hex']:<14} int={r['int']:<8} {' '.join(tag)}"
                  + (f"\n            prev={r['prev']}" if r["prev"] else ""))
        print("    -> chon reg co prev doc duoc + do dai ~300-700 = plaintext; 16B = IV; 16/32B = key.")
    elif t == "report":
        _n += 1
        _f.write(json.dumps(p, ensure_ascii=False) + "\n"); _f.flush()
        print(f"\n[REPORT #{_n}] len={p['plaintext_length']} url={p['url']} aes={p['aes_offset']}")
        print(f"    iv={p['iv_hex']}  key={p['key_hex']}")
        print(f"    hex[0:64]={p['plaintext_hex'][:128]}...")


def main():
    dev = frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} — MODE={MODE} AES=0x{SIGN_OFF+AES_REL:x} ({DUR}s). Mo app + luot feed/login de trigger sign.")
    pid = dev.spawn([PKG]); s = dev.attach(pid)
    sc = s.create_script(JS); sc.on("message", on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except Exception: pass
    if _n:
        print(f"\n[*] saved {_n} report(s) -> {OUT}")
    else:
        print("\n[*] khong bat duoc report. Kiem tra: (a) AES_OFF dung? (b) MODE=recon truoc de chon reg? (c) da trigger sign chua?")


if __name__ == "__main__":
    main()

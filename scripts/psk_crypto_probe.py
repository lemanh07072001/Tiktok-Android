#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# psk_crypto_probe.py — hook HMAC/SHA256/MD5 (libcrypto+libttcrypto) + metasec oneshot + memcpy report,
#   gate trong sign; python matches digest outputs vs report #18/#19 -> lo PSK input + algorithm.
import frida,sys,os,json,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"; DUR=int(os.environ.get("DUR","55"))
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","_psk_crypto.json")
JS=r"""
const MSEC='libmetasec_ov.so';
const GATES=[0x9ecc0,0x9af80]; let SIGNING=0;
function hx(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
const ACC={}; // ctx -> {algo,hex,len,key}
function acc(ctx){const k=ctx.toString(); if(!ACC[k])ACC[k]={hex:'',len:0,key:null}; return ACC[k];}
function hookHash(lib){
  const m=Process.findModuleByName(lib); if(!m) return;
  function E(n){ try{return m.findExportByName(n);}catch(e){return null;} }
  [['SHA256',32],['MD5',16],['SHA1',20]].forEach(function(pr){
    const algo=pr[0],dl=pr[1];
    const up=E(algo+'_Update'),fin=E(algo+'_Final'),ini=E(algo+'_Init');
    if(ini)Interceptor.attach(ini,{onEnter(a){if(!SIGNING)return; const e=acc(a[0]);e.hex='';e.len=0;e.algo=algo.toLowerCase();}});
    if(up)Interceptor.attach(up,{onEnter(a){if(!SIGNING)return; const e=acc(a[0]);const n=a[2].toInt32(); if(n>0&&n<100000){try{if(e.hex.length<1024)e.hex+=hx(a[1].readByteArray(n));e.len+=n;}catch(_){}}}});
    if(fin)Interceptor.attach(fin,{onEnter(a){if(!SIGNING)return; const e=acc(a[1]); let dg=''; try{dg=hx(a[0].readByteArray(dl));}catch(_){} send({t:'hash',lib:lib,algo:algo,ilen:e.len,inhex:e.hex.slice(0,512),out:dg,key:e.key});}});
  });
  // HMAC — capture key (candidate PSK)
  const hi=E('HMAC_Init_ex')||E('HMAC_Init');
  const hu=E('HMAC_Update'), hf=E('HMAC_Final');
  if(hi)Interceptor.attach(hi,{onEnter(a){if(!SIGNING)return; const e=acc(a[0]);e.hex='';e.len=0; const kl=a[2]?a[2].toInt32():0; if(kl>0&&kl<256){try{e.key=hx(a[1].readByteArray(kl));}catch(_){}} e.algo='hmac';}});
  if(hu)Interceptor.attach(hu,{onEnter(a){if(!SIGNING)return; const e=acc(a[0]);const n=a[2].toInt32(); if(n>0&&n<100000){try{if(e.hex.length<1024)e.hex+=hx(a[1].readByteArray(n));e.len+=n;}catch(_){}}}});
  if(hf)Interceptor.attach(hf,{onEnter(a){if(!SIGNING)return; const e=acc(a[1]||a[0]); let dg=''; try{dg=hx(a[0].readByteArray(32));}catch(_){} send({t:'hash',lib:lib,algo:'HMAC',ilen:e.len,inhex:e.hex.slice(0,512),out:dg,key:e.key});}});
}
function install(){
  const m=Process.findModuleByName(MSEC); if(!m) return false; const base=m.base;
  GATES.forEach(o=>{try{Interceptor.attach(base.add(o),{onEnter(){SIGNING++;},onLeave(){if(SIGNING>0)SIGNING--;}});}catch(e){}});
  // metasec internal oneshot(data,len,out) @0x1539d0
  try{Interceptor.attach(base.add(0x1539d0),{onEnter(a){if(!SIGNING)return;this.d=a[0];this.n=a[1].toInt32();this.o=a[2];},onLeave(){if(!SIGNING||!this.o)return;let inp='',dg='';try{inp=hx(this.d.readByteArray(Math.min(this.n,256)));}catch(_){}try{dg=hx(this.o.readByteArray(32));}catch(_){}send({t:'hash',lib:'metasec',algo:'oneshot@1539d0',ilen:this.n,inhex:inp,out:dg,key:null});}});}catch(e){}
  // report via memcpy
  const memcpy=Module.findGlobalExportByName('memcpy');
  const seen={};
  Interceptor.attach(memcpy,{onEnter(a){if(!SIGNING)return;const n=a[2].toInt32();if(n<450||n>820)return;const s=a[1];let b0;try{b0=s.readU8();}catch(e){return;}if(b0!==0x08)return;let b1,b2;try{b1=s.add(1).readU8();b2=s.add(2).readU8();}catch(e){return;}if(b1!==0xd2||b2!==0xa4)return;let r;try{r=hx(s.readByteArray(n));}catch(e){return;}const k=r.slice(0,16)+n;if(seen[k])return;seen[k]=1;send({t:'report',len:n,hex:r});}});
  send({t:'info',msg:'installed base='+base});
  return true;
}
['libcrypto.so','libttcrypto.so'].forEach(hookHash);
if(Process.findModuleByName(MSEC)) install();
else {Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0){['libcrypto.so','libttcrypto.so'].forEach(hookHash);install();}}});}
"""
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG,"DUR=%ds"%DUR,flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
hashes=[];reports=[]
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="hash":hashes.append(p)
    elif p.get("t")=="report":reports.append(p);print("[REPORT] len=%d"%p["len"],flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump({"hashes":hashes,"reports":reports},open(OUT,"w"))
print("[*] hashes=%d reports=%d -> %s"%(len(hashes),len(reports),OUT),flush=True)

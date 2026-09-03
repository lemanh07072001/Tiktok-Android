// T10 (Mac): re-sign device-7677 request with FRESH ts via tt.Dump → POST → server verdict.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
const SIGNER='/Users/lemanh/Documents/Tiktok-Android/signer';
const JAVA_HOME='/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home';
const CP=fs.readFileSync('/tmp/tt_cp.txt','utf8').trim();

// 1) fresh timestamps into url.bin
const nowMs=Date.now(), nowS=Math.floor(nowMs/1000);
let url=fs.readFileSync(SIGNER+'/url.bin','utf8');
url=url.replace(/_rticket=\d+/,'_rticket='+nowMs).replace(/([&?])ts=\d+/,'$1ts='+nowS);
fs.writeFileSync(SIGNER+'/url.bin',url,'latin1');
console.log('[*] url ts updated ->',nowS,'; signing via tt.Dump (may take ~60s)...');

// 2) run tt.Dump
let out='';
try{ out=execFileSync(JAVA_HOME+'/bin/java',['-Djava.library.path=native','-cp',CP,'tt.Dump'],
  {cwd:SIGNER,env:{...process.env,JAVA_HOME},encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:256*1024*1024,timeout:180000}); }
catch(e){ out=(e.stdout||'')+(e.stderr||''); }

// 3) parse HEADER = X-Argus | val | X-Gorgon | val | ...
const hdrLine=(out.match(/HEADER = (.*)/)||[])[1]||'';
const parts=hdrLine.split(' | ');
const sig={};
for(let i=0;i+1<parts.length;i+=2){ if(parts[i].startsWith('X-')) sig[parts[i]]=parts[i+1]; }
console.log('[*] signed: X-Argus len=%d  X-Khronos=%s  X-Gorgon=%s',(sig['X-Argus']||'').length,sig['X-Khronos'],(sig['X-Gorgon']||'').slice(0,20));
if(!sig['X-Argus']){ console.log('[!] SIGN FAILED. tail:\n',out.slice(-600)); process.exit(1); }

// 4) real session cookie (cookie.bin line[1])
const ck=fs.readFileSync(SIGNER+'/cookie.bin','latin1').split('\r\n');
const cookieHeader=ck[1];
const UA='com.zhiliaoapp.musically/2024505040 (Linux; U; Android 14; en; SM-G930S; Build/UP1A.231005.007; Cronet/TTNetVersion:8e2f1a20 2024-01-01)';

// 5) POST + GET
for(const method of ['GET','POST']){
  try{
    const headers={'user-agent':UA,'accept-encoding':'gzip','x-ss-req-ticket':String(nowMs),'cookie':cookieHeader,...sig};
    const opt={method,headers};
    if(method==='POST'){ headers['content-type']='application/x-www-form-urlencoded; charset=UTF-8'; opt.body=''; }
    const r=await fetch(url,opt);
    const txt=await r.text();
    const sc=(txt.match(/"status_code"\s*:\s*(-?\d+)/)||[])[1];
    const msg=(txt.match(/"(status_msg|message|ec7|verify)"\s*:\s*"?([^",}]+)/)||[]);
    console.log(`\n=== ${method} HTTP ${r.status} | status_code=${sc||'?'} ===`);
    console.log('resp[:500]:',txt.slice(0,500).replace(/[^\x20-\x7e]/g,'.'));
  }catch(e){ console.log(`[${method}] ERR`,e.message); }
}

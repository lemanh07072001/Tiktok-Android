// win_probe.mjs — x-argus content-validation negative-control matrix (Windows).
// Reads signer/url.bin (target), signer/.lastsig.json (valid sig from win_sign.sh),
// signer/cookie.bin[1] (live session). Fires variants that isolate X-Argus CONTENT.
//   valid    : all signed headers valid                 (baseline: should PASS)
//   garbage  : X-Argus corrupted (same len/charset)     (isolates content — rest of sig valid)
//   absent   : X-Argus header removed                   (presence check)
//   nocookie : valid sig, NO session cookie             (auth baseline)
// Verdict rule: content-validated IFF garbage FAILS distinctly while valid PASSES,
//               AND nocookie's failure differs from garbage's (else auth is the gate).
import fs from 'node:fs';
const ROOT='d:/Tiktok-Android';
const argv=process.argv.slice(2);
const opt=Object.fromEntries(argv.filter(a=>a.startsWith('--')).map(a=>{const [k,...v]=a.slice(2).split('=');return [k,v.join('=')||true];}));
const METHODS = (opt.method==='POST')?['POST']:(opt.method==='BOTH'||opt.method==='both')?['GET','POST']:['GET'];
const BODY = (opt.body!==undefined && opt.body!==true)?String(opt.body):'';

const url=fs.readFileSync(ROOT+'/signer/url.bin','latin1').trim();
const sig=JSON.parse(fs.readFileSync(ROOT+'/signer/.lastsig.json','utf8'));
const cookie=fs.readFileSync(ROOT+'/signer/cookie.bin','latin1').split('\r\n')[1];
const UA='com.zhiliaoapp.musically/2024505040 (Linux; U; Android 14; en; SM-G930S; Build/UP1A.231005.007; Cronet/TTNetVersion:8e2f1a20 2024-01-01)';

function corrupt(s){ if(!s) return 'AAAAAAAA'; const a=s.split(''); for(let i=8;i<Math.min(40,a.length);i++){ a[i]= a[i]==='A'?'B':'A'; } return a.join(''); }
const path=(()=>{ try{ return new URL(url).pathname; }catch{ return url.slice(0,60);} })();

function buildHeaders(kind){
  const h={'user-agent':UA,'x-ss-req-ticket':String(Date.now())};
  // start from the full valid signed set
  for(const k of Object.keys(sig)) h[k]=sig[k];
  if(kind!=='nocookie') h['cookie']=cookie;
  if(kind==='garbage') h['X-Argus']=corrupt(sig['X-Argus']);
  if(kind==='absent') delete h['X-Argus'];
  return h;
}

function classify(txt){
  const sc=(txt.match(/"status_code"\s*:\s*(-?\d+)/)||[])[1];
  const desc=(txt.match(/"(status_msg|message|description|log_pb|verify_data|ec7)"\s*:\s*"?([^",}]{0,60})/)||[])[2];
  const flags=[];
  for(const w of ['verify','captcha','risk','ec7','frozen','forbidden','signature',' concheck','device_id']) if(new RegExp(w,'i').test(txt)) flags.push(w.trim());
  return {status_code:sc??'?', desc:desc||'', flags:[...new Set(flags)], len:txt.length};
}

const results={};
for(const method of METHODS){
  for(const kind of ['valid','garbage','absent','nocookie']){
    const headers=buildHeaders(kind);
    const o={method,headers};
    if(method==='POST'){ headers['content-type']='application/x-www-form-urlencoded; charset=UTF-8'; o.body=BODY; }
    let line;
    try{
      const r=await fetch(url,o);
      const txt=await r.text();
      const c=classify(txt);
      results[method+':'+kind]={http:r.status,...c,snippet:txt.slice(0,160).replace(/[^\x20-\x7e]/g,'.')};
      line=`  ${method} ${kind.padEnd(8)} HTTP=${r.status} status_code=${String(c.status_code).padEnd(6)} len=${String(c.len).padEnd(6)} flags=[${c.flags.join(',')}] ${c.desc?('desc="'+c.desc+'"'):''}`;
    }catch(e){ results[method+':'+kind]={err:e.message}; line=`  ${method} ${kind.padEnd(8)} ERR ${e.message}`; }
    console.log(line);
  }
}

// ---- verdict ----
function ok(r){ return r && !r.err && r.http>=200 && r.http<400 && (r.status_code==='0'|| r.status_code===0 || (r.status_code==='?'&&r.len>50)); }
const m=METHODS[0];
const V=results[m+':valid'], G=results[m+':garbage'], A=results[m+':absent'], N=results[m+':nocookie'];
let verdict;
if(!ok(V)) verdict='INCONCLUSIVE — valid signature did not PASS (endpoint/param/auth issue). Fix baseline first.';
else if(ok(G)) verdict='NOT content-validated — corrupted X-Argus still PASSED (presence-only or ignored).';
else if(!ok(N) && JSON.stringify([N.status_code,N.http])===JSON.stringify([G.status_code,G.http])) verdict='AMBIGUOUS — garbage-fail matches no-cookie-fail; AUTH may be the gate, not X-Argus content.';
else verdict='*** CONTENT-VALIDATED *** — valid PASSED, corrupted X-Argus FAILED distinctly. X-Argus content is checked here.';
console.log('\nENDPOINT '+path);
console.log('VERDICT: '+verdict);
console.log('JSON '+JSON.stringify({endpoint:path,method:m,results}));

// device_register OFFLINE test (Mac, self-contained) → sign via tt.Dump → POST → verdict.
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
const SIGNER='/Users/lemanh/Documents/Tiktok-Android/signer';
const JAVA_HOME='/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home';
const CP=fs.readFileSync('/tmp/tt_cp.txt','utf8').trim();
const P={model:'SM-G930F',brand:'samsung',mfr:'samsung',res:'1440*2560',resv2:'1440*2560',dpi:640,os_api:28,osv:'9',rom:'PPR1.180610.011',build:'PPR1.180610.011'};
const APP_VC='2024500030';
const UA=`com.zhiliaoapp.musically/${APP_VC} (Linux; U; Android ${P.osv}; en; ${P.model}; Build/${P.build}; Cronet/TTNetVersion:41c3dc2f 2026-04-08 QuicVersion:f9fda2ef 2026-03-10)`;
const APP={aid:1233,package:'com.zhiliaoapp.musically',app_name:'musical_ly',app_version:'45.0.3',version_code:2024500030,update_version_code:2024500030,manifest_version_code:2024500030,sig_hash:'194326e82c84a639a52e5c023116f12a',ab_version:'45.0.3',display_name:'TikTok'};
const md5U=s=>crypto.createHash('md5').update(s).digest('hex').toUpperCase();
const gunzip=b=>{for(const fn of [zlib.gunzipSync,zlib.brotliDecompressSync]){try{return fn(b).toString('utf8');}catch{}}return b.toString('utf8');};
const newIdentity=()=>({openudid:crypto.randomBytes(8).toString('hex'),cdid:crypto.randomUUID(),clientudid:crypto.randomUUID(),google_aid:crypto.randomUUID(),req_id:crypto.randomUUID()});
function buildHeader(id){return{os:'Android',os_version:P.osv,os_api:P.os_api,device_model:P.model,device_brand:P.brand,device_manufacturer:P.mfr,cpu_abi:'arm64-v8a',density_dpi:P.dpi,display_density:'mdpi',resolution:P.res.replace('*','x'),display_density_v2:'xxxhdpi',resolution_v2:P.resv2.replace('*','x'),access:'wifi',rom:P.rom,rom_version:P.build,language:'en',timezone:7,tz_name:'Asia/Ho_Chi_Minh',tz_offset:25200,clientudid:id.clientudid,openudid:id.openudid,cdid:id.cdid,google_aid:id.google_aid,req_id:id.req_id,device_platform:'android',channel:'googleplay',not_request_sender:1,gaid_limited:0,guest_mode:0,is_system_app:0,sdk_flavor:'i18nInner',sdk_target_version:30,sdk_version:'2.5.14.5',sdk_version_code:205140590,git_hash:'b53ca20',release_build:'348bf6c_20260618',custom:{ram_size:'4GB',dark_mode_setting_value:1,is_flip:false},apk_first_install_time:Date.now()-1000000,tweaked_channel:'googleplay',...APP,device_id:'0',install_id:'0'};}
const commonQ=(id,nowMs,nowS)=>new URLSearchParams({req_id:crypto.randomUUID(),device_platform:'android',os:'android',ssmix:'a',_rticket:String(nowMs),cdid:id.cdid,channel:'googleplay',aid:'1233',app_name:'musical_ly',version_code:'2024500030',version_name:'45.0.3',manifest_version_code:'2024500030',update_version_code:'2024500030',ab_version:'45.0.3',resolution:P.res,dpi:String(P.dpi),device_type:P.model,device_brand:P.brand,language:'en',os_api:String(P.os_api),os_version:P.osv,ac:'wifi',is_pad:'0',app_type:'normal',sys_region:'US',last_install_time:String(nowS-2),timezone_name:'Asia/Ho_Chi_Minh',app_language:'en',timezone_offset:'25200',host_abi:'arm64-v8a',locale:'en',ac2:'wifi',uoo:'1',op_region:'VN',build_number:'45.0.3',region:'US',ts:String(nowS),openudid:id.openudid,use_store_region_cookie:'1'});

const id=newIdentity();
const nowMs=Date.now(),nowS=Math.floor(nowMs/1000);
const body=JSON.stringify({header:buildHeader(id),magic_tag:'ss_app_log',_gen_time:nowMs});
const stub=md5U(body);
const url='https://api-boot.tiktokv.com/service/2/device_register/?'+commonQ(id,nowMs,nowS).toString();
const blk=['x-ss-stub',stub,'content-type','application/json; charset=utf-8','x-ss-req-ticket',String(nowMs),'x-tt-dm-status','login=0;ct=0;rt=7','sdk-version','2','passport-sdk-version','1','user-agent',UA].join('\r\n');
console.log('[*] register: openudid=%s device_id=0 stub=%s',id.openudid,stub.slice(0,8));
fs.writeFileSync(SIGNER+'/url.bin',url,'latin1'); fs.writeFileSync(SIGNER+'/cookie.bin',blk,'latin1');
console.log('[*] signing via tt.Dump (~90s)...');
let out=''; try{ out=execFileSync(JAVA_HOME+'/bin/java',['-Djava.library.path=native','-cp',CP,'tt.Dump'],{cwd:SIGNER,env:{...process.env,JAVA_HOME},encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:256*1024*1024,timeout:180000}); }catch(e){ out=(e.stdout||'')+(e.stderr||''); }
const parts=((out.match(/HEADER = (.*)/)||[])[1]||'').split(' | '); const sig={};
for(let i=0;i+1<parts.length;i+=2) if(parts[i].startsWith('X-')) sig[parts[i]]=parts[i+1];
console.log('[*] X-Argus len=%d X-Khronos=%s',(sig['X-Argus']||'').length,sig['X-Khronos']);
if(!sig['X-Argus']){ console.log('[!] SIGN FAIL:\n',out.slice(-400)); process.exit(1); }
const headers={'content-type':'application/json; charset=utf-8','x-ss-stub':stub,'x-ss-req-ticket':String(nowMs),'x-tt-dm-status':'login=0;ct=0;rt=7','sdk-version':'2','passport-sdk-version':'1','x-ss-dp':'1233','user-agent':UA,'accept-encoding':'gzip, deflate, br',...sig};
const resp=await fetch(url,{method:'POST',headers,body});
const raw=Buffer.from(await resp.arrayBuffer());
let j; try{ j=JSON.parse(gunzip(raw)); }catch{ j={_raw:raw.toString('latin1').slice(0,500)}; }
console.log('\n=== device_register HTTP %d ===',resp.status);
console.log('device_id_str=%s install_id_str=%s new_user=%s',j.device_id_str,j.install_id_str,j.new_user);
console.log('resp:',JSON.stringify(j).slice(0,800));

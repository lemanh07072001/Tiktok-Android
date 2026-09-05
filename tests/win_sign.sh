#!/usr/bin/env bash
# win_sign.sh — refresh url.bin timestamps, run tt.Dump (unidbg) via gradle, write signer/.lastsig.json
set -uo pipefail
export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-21.0.12.101-hotspot"
export PATH="$JAVA_HOME/bin:$PATH"
cd /d/Tiktok-Android/signer
node -e '
const fs=require("fs");
let u=fs.readFileSync("url.bin","latin1");
const ms=Date.now(), s=Math.floor(ms/1000);
u=u.replace(/_rticket=\d+/,"_rticket="+ms).replace(/([&?])ts=\d+/,"$1ts="+s).replace(/([&?])_ts=\d+/,"$1_ts="+s);
fs.writeFileSync("url.bin",u,"latin1");
process.stderr.write("[sign] url ts -> "+s+"\n");
'
echo "[sign] running tt.Dump (first run compiles; ~1-2 min)..." >&2
OUT="$(tools/gradle/bin/gradle -q --console=plain dump 2>/tmp/sign.err)"
printf '%s\n' "$OUT" > /tmp/sign.out
HDR="$(printf '%s\n' "$OUT" | grep -a 'HEADER = ' | head -1 | sed 's/^.*HEADER = //')"
if [ -z "$HDR" ]; then
  echo "[sign] FAILED — no HEADER line in output. stderr tail:" >&2
  tail -25 /tmp/sign.err >&2
  exit 1
fi
printf '%s' "$HDR" | node -e '
const fs=require("fs");
const line=fs.readFileSync(0,"utf8").trim();
const parts=line.split(" | ");
const sig={};
for(let i=0;i+1<parts.length;i+=2){ if(parts[i].startsWith("X-")) sig[parts[i]]=parts[i+1]; }
fs.writeFileSync(process.cwd()+"/.lastsig.json", JSON.stringify(sig));
process.stderr.write("[sign] OK  X-Argus.len="+((sig["X-Argus"]||"").length)+"  X-Gorgon="+((sig["X-Gorgon"]||"").slice(0,16))+"  X-Khronos="+(sig["X-Khronos"]||"")+"\n");
'
echo "[sign] wrote signer/.lastsig.json" >&2

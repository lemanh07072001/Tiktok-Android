'use strict';
var MOD='libmetasec_ov.so'; var META=null;
Process.enumerateModules().forEach(function(m){if(m.name===MOD)META=m.base;});
// adrp+add pairs seen: base pages + offsets. Compute absolute = page + off.
// From disasm: store-mgr 0xddb40 adrp 0x7c5579c000 +0x99d ; 0xddb6c adrp 0x7c5579b000 +0xb7e
//  dispatcher 0x12f9ec adrp 0x7c55791000 +0xe5f ; 0x12fabc +0xe69
// pages are relative to META (META=0x7c55600000 that run). Use page-META offsets:
//  0x19c000+0x99d, 0x19b000+0xb7e, 0x191000+0xe5f, 0x191000+0xe69, and store-mgr 0xddb7c adrp 0x7c557f4000(+0xb30 data)
var offs=[0x19c99d,0x19bb7e,0x191e5f,0x191e69,0x19d000+0x99d];
// also brute: read strings around 0x191000-0x19d000 region near these
var out=[];
offs.forEach(function(o){ try{ var s=META.add(o).readCString(64); out.push({off:'0x'+o.toString(16), s:s}); }catch(e){ out.push({off:'0x'+o.toString(16), s:null}); } });
send({k:'STR',out:out});

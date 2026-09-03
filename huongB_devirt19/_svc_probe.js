'use strict';
var MOD='libmetasec_ov.so'; var base=null,size=0;
Process.enumerateModules().forEach(function(m){if(m.name===MOD){base=m.base;size=m.size;}});
if(!base){send({k:'NOMOD'});} else {
  // count svc #0 sites (0xd4000001 = '01 00 00 d4')
  var sites=[];
  try{ Memory.scanSync(base,size,'01 00 00 d4').forEach(function(r){sites.push(r.address);}); }catch(e){send({k:'SCANERR',e:''+e});}
  // for each, decode preceding 4 insns to find mov w8/x8,#imm (syscall nr)
  var FILE_NR={56:'openat',57:'close',63:'read',64:'write',67:'pread64',68:'pwrite64',38:'renameat',276:'renameat2',79:'newfstatat',48:'faccessat'};
  var filesites=[];
  sites.forEach(function(addr){
    for(var i=1;i<=6;i++){
      try{
        var ins=Instruction.parse(addr.sub(4*i));
        if((ins.mnemonic==='movz'||ins.mnemonic==='mov')&&/w8|x8/.test(ins.opStr)){
          var m=ins.opStr.match(/#(0x[0-9a-f]+|\d+)/);
          if(m){ var nr=parseInt(m[1]); if(FILE_NR[nr]) filesites.push({a:'0x'+addr.sub(base).toString(16),nr:nr,fn:FILE_NR[nr]}); break; }
        }
      }catch(e){}
    }
  });
  send({k:'SVC', total:sites.length, filesites:filesites});
}
// also check libc syscall export presence
var sc=Module.findGlobalExportByName?Module.findGlobalExportByName('syscall'):null;
send({k:'LIBC_SYSCALL', present: sc?sc.toString():null});

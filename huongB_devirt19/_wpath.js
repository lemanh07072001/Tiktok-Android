'use strict';
// WRITE-PATH PROBE: disambiguate Java-vs-native, write-vs-mmap for the store.
// Fires a broad net; filters to .ms* store files. ATTACH-ONLY, no re-register.
var STORE_RE=/\.ms(s|p|f3|fs|f)?[_.]/;
var log=[]; var fdpath={};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function push(o){log.push(o); send(o);}

// ---------- NATIVE ----------
function gx(n){ try{return Module.findGlobalExportByName(n);}catch(e){return null;} }
var HOOKED=[], MISS=[];
function hookOpen(name){
  var p=gx(name); if(!p){MISS.push(name);return;}
  Interceptor.attach(p,{
    onEnter:function(a){ // openat(dirfd,path,..) or open(path,..)
      var pathArg = (name.indexOf('openat')>=0)?a[1]:a[0];
      try{this.path=pathArg.readUtf8String();}catch(e){this.path=null;}
    },
    onLeave:function(r){
      if(!this.path)return; var nm=this.path.split('/').pop();
      if(!STORE_RE.test(nm))return;
      var fd=r.toInt32(); if(fd>=0) fdpath[fd]=this.path;
      push({k:'OPEN',fn:name,fd:fd,path:this.path});
    }
  }); HOOKED.push(name);
}
['open','openat','open64','openat64','__openat','__openat_2'].forEach(hookOpen);

function hookW(name,fdIdx,bufIdx,lenIdx){
  var p=gx(name); if(!p){MISS.push(name);return;}
  Interceptor.attach(p,{
    onEnter:function(a){
      var fd=a[fdIdx].toInt32(); var path=fdpath[fd];
      if(!path)return;
      var len=0; try{len=a[lenIdx].toInt32();}catch(e){}
      var head=null; try{head=b2h(a[bufIdx].readByteArray(Math.min(len>0?len:32,64)));}catch(e){}
      push({k:'WRITE',fn:name,fd:fd,path:path,len:len,head:head});
    }
  }); HOOKED.push(name);
}
hookW('write',0,1,2); hookW('pwrite64',0,1,2); hookW('__write_chk',0,1,2);
// writev(fd, iov, iovcnt): decode first iov
(function(){var p=gx('writev'); if(!p){MISS.push('writev');return;}
 Interceptor.attach(p,{onEnter:function(a){var fd=a[0].toInt32();var path=fdpath[fd];if(!path)return;
   var iov=a[1]; var head=null,len=0; try{var base=iov.readPointer();len=iov.add(Process.pointerSize).readU64().toNumber();head=b2h(base.readByteArray(Math.min(len,64)));}catch(e){}
   push({k:'WRITEV',fn:'writev',fd:fd,path:path,len:len,head:head});}}); HOOKED.push('writev');})();

// mmap/msync/munmap: log only if any store fd currently open (hint at mmap-backed store)
(function(){var p=gx('mmap'); if(!p){MISS.push('mmap');return;}
 Interceptor.attach(p,{onEnter:function(a){this.fd=a[4].toInt32();},onLeave:function(r){
   var path=fdpath[this.fd]; if(!path)return; push({k:'MMAP',fd:this.fd,path:path,addr:r.toString()});}}); HOOKED.push('mmap');})();

// ---------- JAVA ----------
function javaHooks(){
  try{
    var FOS=Java.use('java.io.FileOutputStream');
    var File=Java.use('java.io.File');
    function fosPath(self){ try{return self.getFD?.().toString();}catch(e){return null;} }
    // hook the (File) ctor to map streams->path is complex; instead hook write with a path probe via reflection is hard.
    // Simpler: hook libcore.io.Linux.pwrite/write/open which ALL Java file IO funnels through.
    var Linux=Java.use('libcore.io.Linux');
    var Os=Java.use('android.system.Os');
    // Os.open(path,flags,mode) -> FileDescriptor
    Os.open.overload('java.lang.String','int','int').implementation=function(path,fl,mo){
      var fd=this.open(path,fl,mo);
      if(path && STORE_RE.test(path.split('/').pop())){ push({k:'JOPEN',path:path}); }
      return fd;
    };
    // Os.write(FileDescriptor, byte[], off, len)
    Os.write.overload('java.io.FileDescriptor','[B','int','int').implementation=function(fd,buf,off,len){
      try{
        // best-effort: we cannot easily get path from fd here; log size + head to spot 272/377/630
        if(len===272||len===271||len===377||len===378||len===630||len===132||len===32||len===16||len===8){
          var b=Java.array('byte',buf); var s=''; var n=Math.min(len,64);
          for(var i=0;i<n;i++){var v=b[off+i]&0xff;var h=v.toString(16);s+=(h.length<2?'0':'')+h;}
          push({k:'JWRITE',len:len,off:off,head:s});
        }
      }catch(e){}
      return this.write(fd,buf,off,len);
    };
    push({k:'JAVA_READY'});
  }catch(e){ push({k:'JAVA_ERR',msg:''+e}); }
}
if(Java && Java.available){ Java.perform(javaHooks); } else { push({k:'NO_JAVA'}); }

push({k:'READY', hooked:HOOKED, miss:MISS});
rpc.exports={status:function(){return {n:log.length};}, dump:function(){return log;}, clear:function(){log=[];fdpath={};return true;}};

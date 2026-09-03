'use strict';
function hd(bytes,n){ let h=''; const m=Math.min(bytes.length,n); for(let i=0;i<m;i++){ let v=bytes[i]&0xff; h+=('0'+v.toString(16)).slice(-2);} return h; }
Java.perform(function(){
  try{
    const ActivityThread=Java.use('android.app.ActivityThread');
    const app=ActivityThread.currentApplication();
    const ctx=app.getApplicationContext();
    const dataDir=ctx.getDataDir().getAbsolutePath();
    send({t:'root', dataDir:dataDir});
    const File=Java.use('java.io.File');
    const FIS=Java.use('java.io.FileInputStream');
    const results=[];
    function isMsp(name){ return name.indexOf('.msp_')===0||name.indexOf('.msfs_')===0||name.indexOf('.msf3_')===0
      || name.indexOf('.msp_')>=0||name.indexOf('.msfs_')>=0||name.indexOf('.msf3_')>=0; }
    function walk(f, depth){
      if(depth>6) return;
      let kids=null; try{ kids=f.listFiles(); }catch(e){ return; }
      if(kids===null) return;
      for(let i=0;i<kids.length;i++){
        const k=kids[i]; let nm=''; try{ nm=k.getName(); }catch(e){ continue; }
        let isDir=false; try{ isDir=k.isDirectory(); }catch(e){}
        if(isDir){ walk(k, depth+1); }
        else if(isMsp(nm)){
          let sz=0; try{ sz=k.length().valueOf(); }catch(e){}
          let head=''; 
          try{ const fis=FIS.$new(k); const buf=Java.array('byte', new Array(Math.min(64,sz)).fill(0));
               const rd=fis.read(buf); fis.close();
               head=hd(buf, 64); }catch(e){ head='ERR:'+e; }
          const path=k.getAbsolutePath();
          results.push({path:path, size:sz, head:head});
          send({t:'MSP', path:path, size:sz, head:head});
        }
      }
    }
    walk(File.$new(dataDir), 0);
    send({t:'done', count:results.length});
  }catch(e){ send({t:'err', e:''+e}); }
});

'use strict';
function rep(){
  const o={};
  o.frida = Frida.version;
  o.Process_setExceptionHandler = typeof Process.setExceptionHandler;
  o.Thread_setHW = typeof Thread.setHardwareWatchpoint;
  o.Thread_unsetHW = typeof Thread.unsetHardwareWatchpoint;
  try{
    const ths = Process.enumerateThreads();
    o.nThreads = ths.length;
    const t0 = ths[0];
    o.thread_keys = Object.keys(t0);
    o.thread_setHW = typeof t0.setHardwareWatchpoint;
    o.thread_id = t0.id;
  }catch(e){ o.thread_err = String(e); }
  send({t:'API', o:o});
}
setTimeout(rep, 800);

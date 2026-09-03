'use strict';
const out={};
out.fridaVer = Frida.version;
out.hasModule_findExportByName = (typeof Module.findExportByName);
out.hasModule_getGlobalExportByName = (typeof Module.getGlobalExportByName);
out.hasProcess_getModuleByName = (typeof Process.getModuleByName);
out.hasProcess_findModuleByName = (typeof Process.findModuleByName);
try{ const libc=Process.getModuleByName('libc.so'); out.libc=libc.base.toString();
  out.libc_findExportByName=(typeof libc.findExportByName);
  out.libc_getExportByName=(typeof libc.getExportByName);
  try{ out.openat = libc.findExportByName('openat')+''; }catch(e){ out.openat='ERR:'+e; }
}catch(e){ out.libcErr=''+e; }
send({t:'api', out:out});

import time,subprocess,frida
PKG='com.zhiliaoapp.musically'
ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
dev=frida.get_usb_device(timeout=5)
seen=[]
def on_spawn(s):
    print('SPAWN pid=%s ident=%s'%(s.pid, s.identifier), flush=True)
    seen.append((s.pid,s.identifier))
    try: dev.resume(s.pid)
    except Exception as e: print('resume exc',e,flush=True)
dev.on('spawn-added',on_spawn)
dev.enable_spawn_gating()
print('gating ON', flush=True)
subprocess.run([ADB,'shell','am','force-stop',PKG])
time.sleep(1.0)
subprocess.run([ADB,'shell','monkey','-p',PKG,'-c','android.intent.category.LAUNCHER','1'],
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print('launched, watching 15s', flush=True)
time.sleep(15)
print('SPAWNS SEEN:', seen, flush=True)
# also list pending spawns
try: print('pending:', [(p.pid,p.identifier) for p in dev.enumerate_pending_spawn()], flush=True)
except Exception as e: print('pend exc',e,flush=True)
dev.disable_spawn_gating()

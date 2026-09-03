import frida,sys,time,json
d=frida.get_usb_device()
pid=d.spawn(['com.zhiliaoapp.musically'])
s=d.attach(pid); sc=s.create_script(open('_apiprobe.js').read())
got={'v':False}
def om(m,dd):
    if m.get('type')=='send' and m['payload'].get('t')=='API':
        print("APIRESULT "+json.dumps(m['payload']['o'])); got['v']=True
    elif m.get('type')=='error': print("JSERR",m.get('description'))
sc.on('message',om); sc.load(); d.resume(pid)
dl=time.time()+10
while time.time()<dl and not got['v']: time.sleep(0.3)
try: s.detach()
except: pass
try: d.kill(pid)
except: pass
print("PROBE_DONE got=",got['v'])

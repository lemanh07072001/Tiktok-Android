import frida,sys,time,json
pid=int(sys.argv[1])
OLD=["8ca462427dbfb3f3d431621b14f496ff","46c03b52742b3f2615a3abdf1636b754","9a6b1808e00bd930275f06ee5b776c88","0e817e15c7f71685fd55d6a55d1c0c85","3b4fa8c4a2237be4399c294a2961825d"]
dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_scan2.js").read())
sc.on("message",lambda m,d: print("[*]",m["payload"]["msg"],flush=True) if m.get("type")=="send" else None)
sc.load()
print("[*] scanning for OLD pool values...",flush=True)
r=sc.exports_sync.scan(OLD)
print("[RESULT] hits=%d"%len(r),flush=True)
for h in r[:20]: print("   %s @ %s region=%s"%(h["slot"][:12],h["addr"],h["region"]),flush=True)
json.dump(r,open("_scan_out.json","w"),indent=1)

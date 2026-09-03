import frida, sys, time, json
ident = "com.zhiliaoapp.musically"
script_path = sys.argv[1]
dur = int(sys.argv[2]) if len(sys.argv) > 2 else 60
outjson = sys.argv[3] if len(sys.argv) > 3 else None
dev = frida.get_device_manager().add_remote_device("127.0.0.1:47119")
pid = dev.spawn([ident])
session = dev.attach(pid)
sc = session.create_script(open(script_path).read())
msgs = []; t0 = time.time()
def on(m, d):
    if m.get("type") != "send":
        print("[msg]", str(m)[:220], flush=True); return
    p = m["payload"]; msgs.append(p)
    print("[%ds]" % int(time.time() - t0), json.dumps(p)[:400], flush=True)
    if outjson: json.dump(msgs, open(outjson, "w"), indent=1)
sc.on("message", on); sc.load()
dev.resume(pid)
print("[*] SPAWNED pid=%d script=%s %ds" % (pid, script_path, dur), flush=True)
while time.time() - t0 < dur: time.sleep(1)
if outjson: json.dump(msgs, open(outjson, "w"), indent=1)
print("[DONE] msgs=%d" % len(msgs), flush=True)

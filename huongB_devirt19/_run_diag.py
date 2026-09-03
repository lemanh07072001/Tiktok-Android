import frida,sys,time
pid=int(sys.argv[1]); dev=frida.get_device_manager().add_remote_device("127.0.0.1:47119")
sc=dev.attach(pid).create_script(open("_diag.js").read())
sc.on("message",lambda m,d: print("[*]",m["payload"]["msg"],flush=True) if m.get("type")=="send" else None)
sc.load(); time.sleep(28)

import frida,sys,time
dev=frida.get_usb_device(); pid=dev.spawn(['com.zhiliaoapp.musically']); sess=dev.attach(pid)
sc=sess.create_script(open('_apichk.js').read())
sc.on('message',lambda m,d: print(m.get('payload') or m))
sc.load(); dev.resume(pid); time.sleep(3); sess.detach()

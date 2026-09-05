import frida, sys, time
JS=r"""
var m=Process.findModuleByName("libsscronet.so");
var pat=/OnReadCompleted|OnResponseStarted|OnSucceeded|Buffer_GetData|Buffer_GetSize|UploadDataProvider_Read|UrlResponseInfo_url_get|UrlResponseInfo_http_status|UrlRequest_InitWithParams|UrlRequestParams_http_method|UrlRequestParams_request_headers|OnRedirectReceived/;
var out=[];
m.enumerateExports().forEach(function(s){if(pat.test(s.name))out.push(s.name+" @"+s.address);});
send({tag:"info",msg:"callback/buffer exports ("+out.length+"):\n"+out.join("\n")});
"""
def on_message(mm,d):
    if mm.get("type")=="send":print(mm["payload"].get("msg",mm["payload"]),flush=True)
    elif mm.get("type")=="error":print("[ERR]",mm.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
s=dev.attach(int(sys.argv[1]))
sc=s.create_script(JS);sc.on("message",on_message);sc.load();time.sleep(4);s.detach()

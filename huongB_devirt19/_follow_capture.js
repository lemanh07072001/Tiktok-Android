'use strict';
// Capture the follow API request: full URL, query params, headers (X-Argus/Gorgon/Ladon), body.
// Hooks OkHttp Interceptor chain at the point the final Request is built.
Java.perform(function(){
  const seen={};
  function dumpRequest(req, tag){
    try{
      const url=req.url().toString();
      if(url.indexOf('/commit/follow')<0 && url.indexOf('/user/follow')<0 && url.indexOf('follow')<0) return;
      const key=url.split('?')[0];
      const method=req.method();
      // headers
      const headers=req.headers();
      const hnames=headers.names().toArray();
      let hdrs={};
      for(let i=0;i<hnames.length;i++){ const n=hnames[i]; hdrs[n]=headers.get(n); }
      // body
      let body='';
      try{
        const rb=req.body();
        if(rb){
          const Buffer=Java.use('okio.Buffer');
          const buf=Buffer.$new();
          rb.writeTo(buf);
          body=buf.readUtf8();
        }
      }catch(e){body='<'+e+'>';}
      send({t:'FOLLOW_REQ',tag:tag,method:method,url:url,headers:hdrs,body:body});
    }catch(e){}
  }
  // Hook OkHttpClient.newCall (entry) — but class name may be obfuscated. Try RealCall / Interceptor.
  // Most reliable: hook Request.Builder.build()
  try{
    const RB=Java.use('okhttp3.Request$Builder');
    RB.build.implementation=function(){
      const req=this.build();
      dumpRequest(req,'build');
      return req;
    };
    send({t:'info',msg:'hooked okhttp3.Request$Builder.build'});
  }catch(e){ send({t:'info',msg:'okhttp3 not found: '+e}); }
});

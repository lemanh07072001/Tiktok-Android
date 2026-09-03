'use strict';
send({t:'boot'});
setTimeout(function(){
  const out={
    setExceptionHandler: typeof Process.setExceptionHandler,
    hasThread: (typeof Thread!=='undefined'),
    setHWWP: (typeof Thread!=='undefined')? typeof Thread.setHardwareWatchpoint : 'noThread',
    unsetHWWP: (typeof Thread!=='undefined')? typeof Thread.unsetHardwareWatchpoint : 'noThread',
    getCurTid: typeof Process.getCurrentThreadId
  };
  send({t:'API',out:out});
},900);

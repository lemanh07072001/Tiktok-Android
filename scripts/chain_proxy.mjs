// chain_proxy.mjs — CONNECT proxy KHÔNG auth ở PORT, chuyển tiếp tới omoproxy CÓ auth (thêm Proxy-Authorization).
// Dùng làm upstream cho mitmdump (mitmdump không nhận auth nhúng trong --mode upstream ở bản này).
import net from 'node:net';
import { Buffer } from 'node:buffer';
const PORT = parseInt(process.argv[2] || '18088', 10);
const PH = 'lite.omoproxy.com', PPORT = 6969;
const USER = '26070808uc85zkx-session-30hyijpm-time-long', PASS = 'ppslbtjb5s22';
const AUTH = 'Basic ' + Buffer.from(USER + ':' + PASS).toString('base64');
net.createServer((client) => {
  client.once('data', (d) => {
    const s = d.toString('latin1');
    const m = s.match(/^CONNECT ([^:\s]+):(\d+)/);
    if (!m) { client.end(); return; }
    const host = m[1], port = parseInt(m[2], 10);
    const up = net.connect(PPORT, PH, () => {
      up.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\nProxy-Authorization: ${AUTH}\r\n\r\n`);
    });
    let buf = Buffer.alloc(0);
    const onData = (c) => {
      buf = Buffer.concat([buf, c]);
      const i = buf.indexOf('\r\n\r\n');
      if (i >= 0) {
        up.off('data', onData);
        const resp = buf.slice(0, i).toString('latin1');
        const rest = buf.slice(i + 4);
        if (/200/.test(resp)) {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (rest.length) up.write(rest);
          client.pipe(up); up.pipe(client);
        } else { client.end(); up.end(); }
      }
    };
    up.on('data', onData);
    up.on('error', () => client.end());
    client.on('error', () => up.end());
  });
}).listen(PORT, () => console.log('chain proxy listening', PORT, '-> omoproxy(auth)'));

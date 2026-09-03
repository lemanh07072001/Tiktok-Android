// proxy_chain.mjs — forward proxy NO-AUTH trên PC, chuỗi ra upstream proxy CÓ AUTH (omoproxy).
//  phone (không truyền được user:pass qua http_proxy) -> 127.0.0.1:PORT -> upstream(auth) -> egress sạch.
//  KHÔNG MITM (tunnel CONNECT end-to-end) -> phone không cần cert. Dùng cho register egress sạch.
//  Usage: UPSTREAM_PROXY=http://user:pass@host:port node proxy_chain.mjs [port]
import net from 'node:net';
import http from 'node:http';
const PORT = parseInt(process.argv[2] || '8088', 10);
const UP = process.env.UPSTREAM_PROXY;
if (!UP) { console.error('UPSTREAM_PROXY required'); process.exit(2); }
const u = new URL(UP);
const upHost = u.hostname, upPort = Number(u.port) || 8080;
const AUTH = 'Basic ' + Buffer.from(decodeURIComponent(u.username || '') + ':' + decodeURIComponent(u.password || '')).toString('base64');

const server = http.createServer((req, res) => {
  const up = http.request({ host: upHost, port: upPort, path: req.url, method: req.method, headers: { ...req.headers, 'proxy-authorization': AUTH } }, (r) => { res.writeHead(r.statusCode || 502, r.headers); r.pipe(res); });
  up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('upstream err'); });
  req.pipe(up);
});

server.on('connect', (req, clientSocket, head) => {
  console.error('[conn]', req.url, 'headlen=', head ? head.length : 0);
  const up = net.connect({ host: upHost, port: upPort });
  const kill = (w) => { console.error('[kill]', w); try { up.destroy(); } catch {} try { clientSocket.destroy(); } catch {} };
  up.on('error', (e) => kill('uperr:' + (e.code || e.message))); clientSocket.on('error', (e) => kill('cerr:' + (e.code || e.message)));
  up.on('end', () => console.error('[up end]')); clientSocket.on('end', () => console.error('[c end]'));
  up.on('connect', () => {
    console.error('[up tcp ok] -> send CONNECT');
    up.write(`CONNECT ${req.url} HTTP/1.1\r\nHost: ${req.url}\r\nProxy-Authorization: ${AUTH}\r\n\r\n`);
    let buf = Buffer.alloc(0);
    const onHdr = (d) => {
      buf = Buffer.concat([buf, d]);
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return;
      up.removeListener('data', onHdr);
      const status = buf.slice(0, buf.indexOf('\r\n')).toString();
      const ok = / 200 /.test(' ' + status + ' ');
      console.error('[up status]', JSON.stringify(status), 'ok=', ok, 'restlen=', buf.length - i - 4);
      clientSocket.write(ok ? 'HTTP/1.1 200 Connection Established\r\n\r\n' : 'HTTP/1.1 502 Bad Gateway\r\n\r\n');
      if (ok) { const rest = buf.slice(i + 4); if (rest.length) clientSocket.write(rest); clientSocket.pipe(up); up.pipe(clientSocket); console.error('[pipe set]'); }
      else kill('non200');
    };
    up.on('data', onHdr);
  });
});

server.listen(PORT, () => console.log('proxy_chain listen', PORT, '-> upstream', upHost + ':' + upPort));

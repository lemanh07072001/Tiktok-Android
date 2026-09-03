// http2socks.mjs — local HTTP-CONNECT proxy (NO-AUTH) that tunnels to an upstream SOCKS5 (auth) proxy.
// phone http_proxy=127.0.0.1:PORT (can't do SOCKS/auth) -> here -> SOCKS5(user:pass) -> egress.
// Env: SOCKS_HOST SOCKS_PORT SOCKS_USER SOCKS_PASS ; usage: node http2socks.mjs [port]
import net from 'node:net';
import http from 'node:http';
const PORT = parseInt(process.argv[2] || '8088', 10);
const SH = process.env.SOCKS_HOST, SP = Number(process.env.SOCKS_PORT);
const SU = process.env.SOCKS_USER || '', SPW = process.env.SOCKS_PASS || '';
if (!SH || !SP) { console.error('SOCKS_HOST/SOCKS_PORT required'); process.exit(2); }

function socks5Connect(host, port, cb) {
  const s = net.connect({ host: SH, port: SP });
  let stage = 0;
  const fail = (m) => { try { s.destroy(); } catch {} cb(new Error(m)); };
  s.on('error', (e) => fail('sock:' + (e.code || e.message)));
  s.on('connect', () => s.write(Buffer.from([0x05, 0x01, 0x02])));  // greet: user/pass method
  let buf = Buffer.alloc(0);
  s.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    if (stage === 0) {                       // method selection reply [05, method]
      if (buf.length < 2) return;
      if (buf[1] !== 0x02) return fail('no-userpass-auth method=' + buf[1]);
      buf = buf.slice(2); stage = 1;
      const u = Buffer.from(SU), p = Buffer.from(SPW);
      s.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
    }
    if (stage === 1) {                        // auth reply [01, status]
      if (buf.length < 2) return;
      if (buf[1] !== 0x00) return fail('auth-failed status=' + buf[1]);
      buf = buf.slice(2); stage = 2;
      const h = Buffer.from(host);
      const req = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]), h, Buffer.from([(port >> 8) & 0xff, port & 0xff])]);
      s.write(req);
    }
    if (stage === 2) {                        // connect reply [05, rep, 00, atyp, bnd..., port]
      if (buf.length < 4) return;
      if (buf[1] !== 0x00) return fail('connect-rep=' + buf[1]);
      const atyp = buf[3];
      const need = atyp === 1 ? 4 + 2 : atyp === 4 ? 16 + 2 : atyp === 3 ? 1 + buf[4] + 2 : 0;
      if (buf.length < 4 + need) return;
      const rest = buf.slice(4 + need);       // any early payload after reply
      stage = 3;
      s.removeAllListeners('data');
      cb(null, s, rest);
    }
  });
}

const server = http.createServer((req, res) => { res.writeHead(405); res.end('CONNECT only'); });
server.on('connect', (req, clientSocket, head) => {
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr, 10) || 443;
  socks5Connect(host, port, (err, up, early) => {
    if (err) { console.error('[fail]', req.url, err.message); try { clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); clientSocket.destroy(); } catch {} return; }
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) up.write(head);
    if (early && early.length) clientSocket.write(early);
    up.on('error', () => { try { clientSocket.destroy(); } catch {} });
    clientSocket.on('error', () => { try { up.destroy(); } catch {} });
    up.pipe(clientSocket); clientSocket.pipe(up);
  });
});
server.listen(PORT, () => console.log('http2socks listen', PORT, '-> SOCKS5', SH + ':' + SP, 'user=' + SU));

// re/src/net.mjs — route fetch qua proxy (đổi IP egress). import ở đầu script nếu cần proxy.
//   PROXY_URL=http://user:pass@host:port  hoặc  socks5://user:pass@host:port
import { ProxyAgent, Agent, setGlobalDispatcher } from 'undici';
const url = process.env.PROXY_URL;
const T = parseInt(process.env.PROXY_TIMEOUT_MS || '30000', 10);
const opts = { connect: { timeout: 15000 }, headersTimeout: T, bodyTimeout: T };
if (url && /^socks/i.test(url)) {
  const { socksDispatcher } = await import('fetch-socks');
  const u = new URL(url);
  setGlobalDispatcher(socksDispatcher({ type: /socks5/i.test(u.protocol) ? 5 : 4, host: u.hostname, port: Number(u.port) || 1080, userId: u.username ? decodeURIComponent(u.username) : undefined, password: u.password ? decodeURIComponent(u.password) : undefined }, opts));
  console.error('[net] SOCKS', u.hostname + ':' + u.port);
} else if (url) {
  setGlobalDispatcher(new ProxyAgent({ uri: url, ...opts }));
  console.error('[net] proxy', url.replace(/\/\/[^@]*@/, '//***@'));
} else setGlobalDispatcher(new Agent(opts));
export const PROXY_ON = !!url;

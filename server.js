import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { networkInterfaces } from 'node:os';

const random = () => randomBytes(32).toString('base64url');
const ttl = 15 * 60 * 1000;
const encode = value => new URLSearchParams({ v: value }).toString().slice(2);
const staticFiles = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'] };

function endpoint(value, label) {
  let url;
  try { url = new URL(value); } catch { throw new Error(`${label}: 올바른 URL을 입력해 주세요.`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error(`${label}: 인증 정보와 fragment가 없는 HTTP(S) URL이 필요합니다.`);
  return url;
}

export function inspectToken(data, session) {
  const checks = [
    { label: 'State 일치', ok: true },
    { label: 'Access Token 수신', ok: typeof data.access_token === 'string' && !!data.access_token },
    { label: 'Token Type 수신', ok: typeof data.token_type === 'string' && !!data.token_type },
    { label: 'ID Token 수신', ok: typeof data.id_token === 'string' && !!data.id_token },
  ];
  let decoded = null;
  if (data.id_token) {
    try {
      const parts = data.id_token.split('.');
      if (parts.length !== 3) throw new Error('JWT 형식이 아닙니다.');
      decoded = { header: JSON.parse(Buffer.from(parts[0], 'base64url')), payload: JSON.parse(Buffer.from(parts[1], 'base64url')) };
      const p = decoded.payload;
      if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error('잘못된 payload입니다.');
      checks.push(
        { label: 'Nonce 일치', ok: p.nonce === session.nonce },
        { label: 'Audience 일치', ok: (Array.isArray(p.aud) ? p.aud : [p.aud]).includes(session.config.clientId) && (!Array.isArray(p.aud) || p.aud.length <= 1 || p.azp === session.config.clientId) && (!p.azp || p.azp === session.config.clientId) },
        { label: '유효한 만료 시간', ok: typeof p.exp === 'number' && p.exp > Date.now() / 1000 },
        { label: '발급 시간 확인', ok: typeof p.iat === 'number' && p.iat <= Date.now() / 1000 + 60 },
        { label: 'Subject · Issuer 수신', ok: typeof p.sub === 'string' && !!p.sub && typeof p.iss === 'string' && !!p.iss },
      );
    } catch { decoded = null; checks.push({ label: 'ID Token 디코딩', ok: false }); }
  }
  return { checks, decoded };
}

export function createApp({ host = process.env.HOST || '127.0.0.1' } = {}) {
  const allowedHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
  if (host === '0.0.0.0' || host === '::') {
    for (const addresses of Object.values(networkInterfaces())) {
      for (const { address, family } of addresses || []) {
        if (!address.includes('%')) allowedHosts.add(family === 'IPv6' ? `[${address}]` : address);
      }
    }
  } else {
    allowedHosts.add(host.includes(':') ? `[${host}]` : host.toLowerCase());
  }
  const sessions = new Map();
  const sweep = setInterval(() => {
    for (const [id, s] of sessions) if (s.expires < Date.now()) sessions.delete(id);
  }, 60_000).unref();
  const server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const json = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); };
    const redirect = location => { res.writeHead(303, { Location: location }); res.end(); };
    try {
      const authority = req.headers.host || '';
      const address = new URL(`http://${authority}`);
      const validAuthority = address.host === authority.toLowerCase() || authority.toLowerCase() === `${address.hostname}:80`;
      if (!validAuthority || !allowedHosts.has(address.hostname) || Number(address.port || 80) !== req.socket.localPort) {
        return json(403, { error: '허용되지 않은 접속 주소입니다. 서버 실행 시 HOST에 접속할 IP를 지정해 주세요. 모든 PC IP를 허용하려면 HOST=0.0.0.0을 사용하세요.' });
      }
      const origin = address.origin;
      const url = new URL(req.url, origin);
      const id = req.headers.cookie?.split(';').map(v => v.trim()).find(v => v.startsWith('oidc_session='))?.slice(13);
      let session = sessions.get(id);
      if (session && session.expires < Date.now()) { sessions.delete(id); session = null; }

      if (req.method === 'POST') {
        if (req.headers.origin !== origin || !req.headers['content-type']?.startsWith('application/json')) return json(403, { error: '허용되지 않은 요청입니다.' });
        if (url.pathname === '/api/reset') {
          sessions.delete(id);
          res.setHeader('Set-Cookie', 'oidc_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
          return json(200, { ok: true });
        }
        if (url.pathname !== '/api/start') return json(404, { error: '경로를 찾을 수 없습니다.' });
        let body = '';
        for await (const chunk of req) { body += chunk; if (Buffer.byteLength(body) > 20_000) return json(413, { error: '입력값이 너무 큽니다.' }); }
        const input = JSON.parse(body);
        const config = {};
        for (const key of ['authorizationUrl', 'tokenUrl', 'clientId', 'clientSecret', 'scope', 'redirectUri', 'authMethod']) {
          config[key] = typeof input[key] === 'string' ? (key === 'clientSecret' ? input[key] : input[key].trim()) : '';
        }
        const authUrl = endpoint(config.authorizationUrl, 'Authorization URL');
        endpoint(config.tokenUrl, 'Token URL');
        const callback = endpoint(config.redirectUri, 'Redirect URI');
        if (callback.origin !== origin || callback.search || callback.pathname === '/' || callback.pathname.startsWith('/api/') || staticFiles[callback.pathname]) throw new Error(`Redirect URI는 ${origin}/callback처럼 이 앱의 별도 경로를 사용해 주세요. 쿼리는 지원하지 않습니다.`);
        if (!config.clientId) throw new Error('Client ID를 입력해 주세요.');
        config.scope = [...new Set(config.scope.split(/[\s,]+/).filter(Boolean))].join(' ');
        if (!config.scope.split(' ').includes('openid')) throw new Error('Scope에 openid를 포함해 주세요.');
        config.authMethod ||= 'client_secret_basic';
        if (!['client_secret_basic', 'client_secret_post', 'none'].includes(config.authMethod)) throw new Error('지원하지 않는 인증 방식입니다.');
        if (config.authMethod !== 'none' && !config.clientSecret) throw new Error('Client Secret을 입력하거나 고급 설정에서 공개 클라이언트를 선택해 주세요.');
        session = { config, state: random(), nonce: random(), verifier: random(), expires: Date.now() + ttl, result: null, used: false };
        for (const key of ['request', 'request_uri', 'response_mode', 'client_secret']) authUrl.searchParams.delete(key);
        for (const [key, value] of Object.entries({ response_type: 'code', client_id: config.clientId, redirect_uri: config.redirectUri, scope: config.scope, state: session.state, nonce: session.nonce, code_challenge: createHash('sha256').update(session.verifier).digest('base64url'), code_challenge_method: 'S256' })) authUrl.searchParams.set(key, value);
        session.requestUrl = authUrl.href;
        sessions.delete(id);
        const newId = random();
        sessions.set(newId, session);
        res.setHeader('Set-Cookie', `oidc_session=${newId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900`);
        return json(200, { authorizationUrl: authUrl.href });
      }

      if (req.method !== 'GET') return json(405, { error: '지원하지 않는 요청입니다.' });
      if (url.pathname === '/api/session') {
        if (!session) return json(200, { config: null, result: null });
        const { clientSecret, ...publicConfig } = session.config;
        return json(200, { config: publicConfig, requestUrl: session.requestUrl, result: session.result });
      }
      if (staticFiles[url.pathname]) {
        const [file, type] = staticFiles[url.pathname];
        res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
        return res.end(await readFile(new URL(`./public/${file}`, import.meta.url)));
      }
      if (!session || new URL(session.config.redirectUri).pathname !== url.pathname) return redirect('/?callback_error=expired');
      if (session.used) return redirect('/?callback_error=used');
      if (url.searchParams.getAll('state').length !== 1 || url.searchParams.get('state') !== session.state) return redirect('/?callback_error=state');
      session.used = true;
      const callbackParams = Object.fromEntries(url.searchParams);
      try {
        if (url.searchParams.has('error')) throw new Error(`${url.searchParams.get('error')}: ${url.searchParams.get('error_description') || '인증 제공자가 요청을 거절했습니다.'}`);
        const code = url.searchParams.get('code');
        if (!code || url.searchParams.getAll('code').length !== 1) throw new Error('Authorization Code가 없거나 중복되었습니다.');
        const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: session.config.redirectUri, code_verifier: session.verifier });
        const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
        const c = session.config;
        if (c.authMethod === 'client_secret_basic') headers.Authorization = `Basic ${Buffer.from(`${encode(c.clientId)}:${encode(c.clientSecret)}`).toString('base64')}`;
        else { form.set('client_id', c.clientId); if (c.authMethod === 'client_secret_post') form.set('client_secret', c.clientSecret); }
        const started = Date.now();
        const response = await fetch(c.tokenUrl, { method: 'POST', headers, body: form, redirect: 'error', signal: AbortSignal.timeout(15_000) });
        const raw = await response.text();
        let data;
        try { data = JSON.parse(raw); } catch { data = { raw }; }
        const valid = data && typeof data === 'object' && !Array.isArray(data);
        const result = { status: response.status, duration: Date.now() - started, receivedAt: new Date().toISOString(), callback: callbackParams, response: data, checks: [], decoded: null };
        if (!response.ok || !valid || data.error || 'raw' in data) result.error = `토큰 요청 실패 (HTTP ${response.status})${valid && data.error ? `: ${data.error}` : ''}`;
        else Object.assign(result, inspectToken(data, session));
        session.result = result;
      } catch (error) { session.result = { error: error.name === 'TimeoutError' ? '토큰 요청 시간이 초과되었습니다 (15초).' : error.message, callback: callbackParams, checks: [] }; }
      finally { session.config.clientSecret = ''; session.verifier = ''; }
      return redirect('/');
    } catch (error) { return json(400, { error: error.message }); }
  });
  server.on('close', () => clearInterval(sweep));
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || '127.0.0.1';
  createApp({ host }).listen(port, host, () => {
    const displayHost = host === '127.0.0.1' ? 'localhost' : host.includes(':') ? `[${host}]` : host;
    console.log(`OIDC Lab → http://${displayHost}:${port}`);
    if (host === '0.0.0.0' || host === '::') console.log('브라우저에서는 0.0.0.0 대신 이 PC의 IP 주소로 접속하세요.');
  });
}

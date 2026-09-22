import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { createApp, parseLaunchOptions } from '../server.js';
import { networkInterfaces } from 'node:os';

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
const jwt = payload => `${Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.test-signature`;

test('실행 옵션: CLI 우선 적용, npm 추가 인자 덮어쓰기 및 잘못된 포트 거절', () => {
  assert.deepEqual(parseLaunchOptions([], {}), { host: '127.0.0.1', port: 3000 });
  assert.deepEqual(parseLaunchOptions(['--host', '0.0.0.0', '--port', '8080'], { HOST: '127.0.0.1', PORT: '9000' }), { host: '0.0.0.0', port: 8080 });
  assert.deepEqual(parseLaunchOptions(['--port', '3000', '--port=8080', '--host=192.168.0.10'], {}), { host: '192.168.0.10', port: 8080 });
  for (const port of ['0', '65536', '-1', '3.5', 'abc', '']) assert.throws(() => parseLaunchOptions([`--port=${port}`], {}));
  assert.throws(() => parseLaunchOptions(['--host='], {}));
  assert.throws(() => parseLaunchOptions(['--port'], {}));
  assert.throws(() => parseLaunchOptions(['--unknown'], {}));
});

test('설정된 IP의 접속 및 요청은 허용하고 다른 Host와 Origin은 차단', async t => {
  const app = createApp({ host: '192.168.0.10' });
  t.after(() => app.close());
  const origin = await listen(app);
  const port = app.address().port;
  const address = `192.168.0.10:${port}`;
  const request = (host, requestOrigin = `http://${host}`) => new Promise((resolve, reject) => {
    const req = http.request(`${origin}/api/reset`, {
      method: 'POST', headers: { Host: host, Origin: requestOrigin, 'Content-Type': 'application/json' },
    }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end('{}');
  });
  assert.equal(await request(address), 200);
  assert.equal(await request(`localhost:${port}`), 200);
  assert.equal(await request(`untrusted.example:${port}`), 403);
  assert.equal(await request('192.168.0.10:1'), 403);
  assert.equal(await request(address, 'http://other.example'), 403);
});

test('전체 인터페이스 바인딩은 실제 PC IP를 허용', async t => {
  const app = createApp({ host: '0.0.0.0' });
  t.after(() => app.close());
  await new Promise(resolve => app.listen(0, '0.0.0.0', resolve));
  const addresses = Object.values(networkInterfaces()).flat().filter(item => item?.family === 'IPv4');
  for (const { address } of addresses) {
    const response = await fetch(`http://${address}:${app.address().port}/api/session`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { config: null, result: null });
  }
});

test('Authorization Code 흐름: PKCE, 인증 방식, 응답 점검 및 오류 처리', async t => {
  let currentAuth;
  let mode = 'success';
  let expectedMethod;
  let tokenCalls = 0;
  const provider = http.createServer(async (req, res) => {
    tokenCalls++;
    let body = '';
    for await (const chunk of req) body += chunk;
    const params = new URLSearchParams(body);
    assert.equal(params.get('grant_type'), 'authorization_code');
    assert.equal(params.get('code'), 'test-code');
    assert.equal(params.get('redirect_uri'), currentAuth.searchParams.get('redirect_uri'));
    assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), currentAuth.searchParams.get('code_challenge'));
    if (expectedMethod === 'client_secret_basic') assert.equal(req.headers.authorization, `Basic ${Buffer.from('test-client:my-secret').toString('base64')}`);
    else {
      assert.equal(req.headers.authorization, undefined);
      assert.equal(params.get('client_id'), 'test-client');
      assert.equal(params.get('client_secret'), expectedMethod === 'none' ? null : 'my-secret');
    }
    res.setHeader('Content-Type', 'application/json');
    if (mode === 'http-error') { res.writeHead(401); return res.end(JSON.stringify({ error: 'invalid_client' })); }
    if (mode === 'non-json') return res.end('<html>upstream error</html>');
    if (mode === 'missing-token') return res.end(JSON.stringify({ access_token: 'access', token_type: 'Bearer' }));
    const payload = { sub: 'user-123', iss: 'https://mock.example', aud: 'test-client', nonce: currentAuth.searchParams.get('nonce'), exp: Date.now() / 1000 + 3600, iat: Date.now() / 1000, name: '테스트 사용자', email: 'user@example.com' };
    if (mode === 'bad-claims') Object.assign(payload, { nonce: 'wrong', aud: 'other-client', exp: 1 });
    res.end(JSON.stringify({ access_token: 'test-access-token', token_type: 'Bearer', id_token: jwt(payload) }));
  });
  const app = createApp();
  t.after(() => { app.close(); provider.close(); });
  const providerOrigin = await listen(provider);
  const origin = await listen(app);
  const config = { authorizationUrl: `${providerOrigin}/authorize`, tokenUrl: `${providerOrigin}/token`, clientId: 'test-client', clientSecret: 'my-secret', scope: 'openid, profile, email', redirectUri: `${origin}/callback`, authMethod: 'client_secret_basic' };
  async function start(overrides = {}) {
    const response = await fetch(`${origin}/api/start`, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ ...config, ...overrides }) });
    const data = await response.json();
    return { response, data, cookie: response.headers.get('set-cookie')?.split(';')[0] };
  }
  async function callback(cookie, state = currentAuth.searchParams.get('state'), suffix = 'code=test-code') {
    return fetch(`${origin}/callback?state=${state}&${suffix}`, { headers: { Cookie: cookie }, redirect: 'manual' });
  }
  const session = async cookie => (await fetch(`${origin}/api/session`, { headers: { Cookie: cookie } })).json();

  for (const method of ['client_secret_basic', 'client_secret_post', 'none']) {
    await t.test(`성공: ${method}`, async () => {
      expectedMethod = method;
      const { response, data, cookie } = await start({ authMethod: method, clientSecret: method === 'none' ? '' : 'my-secret' });
      assert.equal(response.status, 200);
      assert.match(response.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/);
      currentAuth = new URL(data.authorizationUrl);
      assert.equal(currentAuth.searchParams.get('scope'), 'openid profile email');
      assert.equal(currentAuth.searchParams.get('code_challenge_method'), 'S256');
      assert.equal(currentAuth.searchParams.get('client_secret'), null);
      assert.equal((await callback(cookie)).status, 303);
      const saved = await session(cookie);
      assert.equal(saved.config.clientSecret, undefined);
      assert.equal(saved.result.decoded.payload.email, 'user@example.com');
      assert.ok(saved.result.checks.every(c => c.ok));
      const count = tokenCalls;
      assert.match((await callback(cookie)).headers.get('location'), /used/);
      assert.equal(tokenCalls, count);
    });
  }
  expectedMethod = 'client_secret_basic';
  await t.test('잘못된 state는 토큰 엔드포인트에 전달하지 않음', async () => {
    const { data, cookie } = await start(); currentAuth = new URL(data.authorizationUrl);
    const count = tokenCalls;
    assert.match((await callback(cookie, 'wrong-state')).headers.get('location'), /state/);
    assert.equal(tokenCalls, count);
    assert.equal((await session(cookie)).result, null);
  });
  for (const failure of ['http-error', 'non-json', 'missing-token', 'bad-claims']) {
    await t.test(`응답 실패 표시: ${failure}`, async () => {
      mode = failure;
      const { data, cookie } = await start(); currentAuth = new URL(data.authorizationUrl);
      await callback(cookie);
      const { result } = await session(cookie);
      if (['http-error', 'non-json'].includes(failure)) assert.ok(result.error);
      else assert.ok(result.checks.some(c => !c.ok));
      if (failure === 'non-json') assert.equal(result.response.raw, '<html>upstream error</html>');
    });
  }
  await t.test('사용자 거절 및 세션 초기화', async () => {
    const { data, cookie } = await start(); currentAuth = new URL(data.authorizationUrl);
    await callback(cookie, currentAuth.searchParams.get('state'), 'error=access_denied&error_description=Cancelled');
    assert.match((await session(cookie)).result.error, /access_denied/);
    await fetch(`${origin}/api/reset`, { method: 'POST', headers: { Origin: origin, Cookie: cookie, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal((await session(cookie)).result, null);
  });
  await t.test('잘못된 입력과 외부 요청 차단', async () => {
    assert.equal((await start({ redirectUri: 'https://other.example/callback' })).response.status, 400);
    assert.equal((await start({ scope: 'profile' })).response.status, 400);
    assert.equal((await start({ tokenUrl: 'file:///secret' })).response.status, 400);
    assert.equal((await start({ clientSecret: '' })).response.status, 400);
    assert.equal((await fetch(`${origin}/api/start`, { method: 'POST', headers: { Origin: 'https://other.example', 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
    assert.match((await fetch(`${origin}/callback?code=unknown`, { redirect: 'manual' })).headers.get('location'), /expired/);
  });
  await t.test('화면 및 정적 파일', async () => {
    for (const path of ['/', '/app.js', '/style.css']) assert.equal((await fetch(origin + path)).status, 200);
  });
});

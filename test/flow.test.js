import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildFlow } from '../public/flow-model.js';

const config = { authorizationUrl: 'https://login.example/realms/demo/protocol/openid-connect/auth?kc_idp_hint=company', tokenUrl: 'https://login.example/token', redirectUri: 'http://localhost:3000/callback' };
test('흐름 안내는 IdP 힌트를 표시하지만 외부 인증 성공을 추정하지 않음', () => {
  const flow = buildFlow(config, { requestUrl: 'https://login.example/auth' });
  assert.equal(flow.steps[1].title, 'Keycloak → company');
  assert.equal(flow.steps[1].status, 'external');
  assert.equal(flow.steps[2].status, 'waiting');
  assert.equal(flow.selected, 1);
  assert.equal(buildFlow({ authorizationUrl: 'invalid' }).steps[0].status, 'waiting');
});
test('인증 거절, 토큰 교환 실패, 클레임 점검 실패는 각각 해당 단계에 표시', () => {
  const denied = buildFlow(config, { result: { callback: { error: 'access_denied' }, error: '거절됨' } });
  assert.equal(denied.selected, 2);
  assert.equal(denied.steps[3].status, 'waiting');
  const timeout = buildFlow(config, { result: { callback: { code: 'code' }, error: '시간 초과' } });
  assert.equal(timeout.selected, 3);
  assert.equal(timeout.steps[3].status, 'error');
  const badClaims = buildFlow(config, { result: { callback: { code: 'code' }, status: 200, checks: [{ ok: false }] } });
  assert.equal(badClaims.selected, 4);
  assert.equal(badClaims.steps[4].status, 'error');
});
test('성공 결과에서도 외부 단계는 실측 완료로 표시하지 않음', () => {
  const flow = buildFlow(config, { requestUrl: 'url', result: { callback: { code: 'code' }, status: 200, checks: [{ ok: true }] } });
  assert.deepEqual(flow.steps.map(step => step.status), ['done', 'external', 'done', 'done', 'done']);
});

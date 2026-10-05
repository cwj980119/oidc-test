// Only callback and token results are observable by this app. IdP activity is explanatory.
export function buildFlow(config = {}, data = {}) {
  let auth;
  try { auth = new URL(config.authorizationUrl); } catch { /* Form may be incomplete. */ }
  const keycloak = !!auth?.pathname.includes('/protocol/openid-connect/auth');
  const provider = keycloak ? 'Keycloak' : '인증 서버';
  const hint = auth?.searchParams.get('kc_idp_hint');
  const result = data.result;
  const callback = result?.callback;
  const codeReceived = !!callback?.code && !callback?.error;
  const tokenReceived = !!result?.status;
  const checked = !!result?.checks?.length;
  const good = checked && !result.error && result.checks.every(check => check.ok);
  const urlLabel = value => {
    try { const url = new URL(value); return url.origin + url.pathname; } catch { return '연결 설정을 입력하세요.'; }
  };
  const steps = [
    { title: `앱 → ${provider}`, subtitle: '로그인 요청', status: data.requestUrl ? 'done' : 'waiting',
      description: '앱이 브라우저를 Authorization URL로 보냅니다. Client ID, Scope, Redirect URI와 state·nonce·PKCE를 함께 전달합니다.', detail: urlLabel(config.authorizationUrl) },
    { title: hint ? `${provider} → ${hint}` : `${provider}에서 인증`, subtitle: hint ? '외부 IdP로 이동' : '로그인 또는 SSO', status: 'external',
      description: hint ? `kc_idp_hint=${hint}를 지정한 요청입니다. Keycloak이 해당 별칭의 IdP로 인증을 위임하도록 요청합니다. IdP에서 로그인하거나 기존 SSO 세션을 사용합니다.` : '인증 서버가 로그인 또는 기존 SSO 세션을 확인합니다. Keycloak에 외부 IdP가 연결되어 있다면 선택하거나 기본 IdP로 이동할 수 있습니다.',
      detail: '외부 화면 내부의 진행 상태는 이 앱에서 직접 확인할 수 없습니다.' },
    { title: `${provider} → 앱`, subtitle: '콜백으로 돌아오기', status: callback ? (codeReceived ? 'done' : 'error') : 'waiting',
      description: '외부 IdP를 사용했다면 인증 결과가 먼저 Keycloak으로 돌아옵니다. 이후 인증 서버가 앱의 Redirect URI로 code를 보내고, 앱은 state가 요청과 같은지 확인합니다.',
      detail: callback ? (codeReceived ? 'Authorization Code 수신 · State 일치 확인' : `콜백 오류: ${callback.error || result.error || 'Code 없음'}`) : urlLabel(config.redirectUri) },
    { title: `앱 서버 ↔ ${provider}`, subtitle: '코드를 토큰으로 교환', status: tokenReceived ? (result.error ? 'error' : 'done') : codeReceived && result?.error ? 'error' : 'waiting',
      description: '앱 서버가 Token URL에 code와 PKCE 검증 값을 보냅니다. 설정한 방식으로 클라이언트를 인증하고 토큰 응답을 받습니다. Keycloak을 사용하면 토큰도 Keycloak에 요청합니다.',
      detail: tokenReceived ? `HTTP ${result.status} · ${result.duration} ms · ${urlLabel(config.tokenUrl)}` : codeReceived && result?.error ? result.error : urlLabel(config.tokenUrl) },
    { title: '앱에서 정보 확인', subtitle: '토큰과 사용자 정보', status: checked ? (good ? 'done' : 'error') : 'waiting',
      description: '응답 JSON과 ID Token의 사용자 정보를 표시합니다. nonce, audience, 만료 시간 등을 점검합니다. 서명 및 Issuer 신뢰성 검증은 포함하지 않습니다.',
      detail: checked ? `${result.checks.filter(check => check.ok).length}/${result.checks.length} 기본 점검 통과` : '토큰 응답을 받은 뒤 아래 응답 확인 영역에 표시됩니다.' },
  ];
  const failed = steps.findIndex(step => step.status === 'error');
  return { steps, selected: failed >= 0 ? failed : checked ? 4 : callback ? 2 : data.requestUrl ? 1 : 0 };
}

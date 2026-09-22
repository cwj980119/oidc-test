const $ = id => document.getElementById(id);
const form = $('config-form');
let result = null;
let activeTab = 'response';
$('redirectUri').value = `${location.origin}/callback`;
const fail = message => { $('form-error').textContent = message; $('form-error').hidden = false; };

function addScope(value = '') {
  const row = document.createElement('div');
  row.className = 'scope-row';
  const input = document.createElement('input');
  input.name = 'scopeItem';
  input.value = value;
  input.placeholder = '예: email 또는 offline_access';
  input.setAttribute('aria-label', 'Scope 항목');
  input.setAttribute('aria-describedby', 'scope-help');
  input.pattern = '[^\\s,]+';
  input.title = '공백이나 쉼표 없이 Scope 하나만 입력하세요.';
  input.autocomplete = 'off';
  row.append(input);
  if (value === 'openid') {
    input.readOnly = true;
    input.setAttribute('aria-label', '필수 Scope openid');
    const badge = document.createElement('span');
    badge.className = 'scope-required';
    badge.textContent = '필수';
    row.append(badge);
  } else {
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'text-button scope-remove';
    remove.textContent = '삭제';
    remove.setAttribute('aria-label', '이 Scope 항목 삭제');
    remove.addEventListener('click', () => {
      const next = row.nextElementSibling?.querySelector('input') || row.previousElementSibling?.querySelector('input');
      row.remove();
      (next || $('add-scope')).focus();
    });
    row.append(remove);
  }
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.isComposing) {
      event.preventDefault();
      if (input.reportValidity()) addScope().focus();
    }
  });
  $('scope-list').append(row);
  return input;
}

function setScopes(scope) {
  $('scope-list').replaceChildren();
  for (const value of new Set(['openid', ...scope.split(/[\s,]+/).filter(Boolean)])) addScope(value);
}
setScopes('openid profile email');
$('add-scope').addEventListener('click', () => addScope().focus());

function showTab(name) {
  activeTab = name;
  document.querySelectorAll('[data-tab]').forEach(button => {
    button.setAttribute('aria-selected', String(button.dataset.tab === name));
    button.tabIndex = button.dataset.tab === name ? 0 : -1;
  });
  $('payload-panel').setAttribute('aria-labelledby', `tab-${name}`);
  $('code-label').textContent = name === 'decoded' ? 'JWT · DECODED' : 'JSON';
  $('payload').textContent = JSON.stringify(result?.[name] ?? (name === 'decoded' ? { message: '디코딩할 수 있는 ID Token이 없습니다.' } : { message: '수신된 데이터가 없습니다.' }), null, 2);
}

function render(data) {
  result = data.result;
  $('request-details').hidden = !data.requestUrl;
  $('request-url').textContent = data.requestUrl || '';
  $('empty').hidden = !!result;
  $('result').hidden = !result;
  $('step-request').classList.toggle('done', !!data.requestUrl);
  $('step-callback').classList.toggle('done', !!result?.callback);
  $('step-token').classList.toggle('done', !!result?.status);
  $('flow-status').className = 'badge';
  $('flow-status').textContent = data.requestUrl ? '인증 진행 중' : '준비됨';
  if (!result) return;
  const good = !result.error && result.checks?.length && result.checks.every(check => check.ok);
  $('flow-status').textContent = good ? '응답 수신' : '확인 필요';
  $('flow-status').classList.add(good ? 'success' : 'failure');
  $('result-summary').className = good ? '' : 'failure';
  $('result-summary').textContent = result.error || `${good ? '✓ 응답을 받았고 기본 점검을 통과했습니다.' : '일부 기본 점검을 통과하지 못했습니다.'}  HTTP ${result.status} · ${result.duration} ms`;
  $('checks').replaceChildren(...(result.checks || []).map(check => {
    const span = document.createElement('span');
    span.className = `check${check.ok ? '' : ' bad'}`;
    span.textContent = `${check.ok ? '✓' : '×'} ${check.label}`;
    return span;
  }));
  showTab(activeTab);
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  $('form-error').hidden = true;
  $('start').disabled = true;
  $('start').textContent = '인증 화면으로 이동 중…';
  try {
    const fields = new FormData(form);
    const scope = [...new Set(fields.getAll('scopeItem').map(value => value.trim()).filter(Boolean))].join(' ');
    fields.delete('scopeItem');
    const response = await fetch('/api/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...Object.fromEntries(fields), scope }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error);
    $('clientSecret').value = '';
    location.assign(data.authorizationUrl);
  } catch (error) { fail(error.message); $('start').disabled = false; $('start').textContent = '로그인 테스트 시작 ↗'; }
});
$('toggle-secret').addEventListener('click', () => {
  const visible = $('clientSecret').type === 'password';
  $('clientSecret').type = visible ? 'text' : 'password';
  $('toggle-secret').textContent = visible ? '숨김' : '보기';
  $('toggle-secret').setAttribute('aria-pressed', String(visible));
  $('toggle-secret').setAttribute('aria-label', `Client Secret ${visible ? '숨기기' : '표시'}`);
});
document.querySelectorAll('[data-tab]').forEach(button => {
  button.addEventListener('click', () => showTab(button.dataset.tab));
  button.addEventListener('keydown', event => {
    const tabs = [...document.querySelectorAll('[data-tab]')];
    let index = tabs.indexOf(button);
    if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') index = (index + tabs.length - 1) % tabs.length;
    else if (event.key === 'Home') index = 0;
    else if (event.key === 'End') index = tabs.length - 1;
    else return;
    event.preventDefault(); showTab(tabs[index].dataset.tab); tabs[index].focus();
  });
});
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('payload').textContent); $('copy').textContent = '복사됨'; }
  catch { $('copy').textContent = '복사 실패'; }
  setTimeout(() => { $('copy').textContent = '복사'; }, 1800);
});
$('reset').addEventListener('click', async () => {
  try {
    const response = await fetch('/api/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (!response.ok) throw new Error('초기화하지 못했습니다. 다시 시도해 주세요.');
    $('clientSecret').value = ''; $('form-error').hidden = true; render({});
  } catch (error) { fail(error.message); }
});
async function load() {
  const callbackError = new URLSearchParams(location.search).get('callback_error');
  if (callbackError) {
    fail(({ expired: '세션이 만료되었거나 다른 주소로 돌아왔습니다. 처음 접속한 주소에서 다시 시작해 주세요.', used: '이미 처리한 콜백입니다. 새 테스트를 시작해 주세요.', state: 'State가 일치하지 않아 요청을 중단했습니다.' })[callbackError] || '콜백 처리에 실패했습니다.');
    history.replaceState(null, '', '/');
  }
  try {
    const response = await fetch('/api/session');
    if (!response.ok) throw new Error('세션을 불러오지 못했습니다.');
    const data = await response.json();
    if (data.config) for (const [key, value] of Object.entries(data.config)) {
      if (key === 'scope') setScopes(value);
      else if (form.elements[key]) form.elements[key].value = value;
    }
    render(data);
  } catch (error) { fail(error.message); }
}
load();
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });

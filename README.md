# OIDC Lab

OpenID Connect Authorization Code 흐름을 테스트하는 간단한 로컬 앱입니다. Node.js 22 이상만 있으면 됩니다. 패키지 설치, 데이터베이스, 빌드 과정이 없습니다.

## 실행

```sh
npm start
```

[http://localhost:3000](http://localhost:3000)으로 접속하세요.

1. 인증 제공자에 Redirect URI `http://localhost:3000/callback`을 등록합니다.
2. Authorization URL, Token URL, Client ID, Client Secret, Scope, Redirect URI를 입력합니다.
3. **로그인 테스트 시작**을 누르고 인증 제공자에서 로그인합니다.
4. 돌아온 화면에서 토큰 응답 JSON, ID Token의 header/payload, 콜백 파라미터, 기본 점검 결과를 확인합니다.

Scope는 항목별 입력칸에 하나씩 입력합니다. **+ 항목 추가** 또는 Enter로 입력칸을 추가하고 **삭제**로 제거할 수 있습니다. `openid`는 필수로 고정되며, 빈 항목은 무시하고 중복 항목은 한 번만 전송합니다. Redirect URI는 현재 앱과 같은 origin의 별도 경로를 사용해야 합니다. 예를 들어 `http://localhost:3000/callback` 또는 `http://localhost:3000/auth/callback`입니다. 쿼리가 있는 Redirect URI는 지원하지 않습니다. `localhost`와 `127.0.0.1`은 서로 다른 origin이므로 로그인 도중 바꾸지 마세요.

고급 설정에서 Token Endpoint 인증 방식을 선택할 수 있습니다. 기본은 `client_secret_basic`이며, `client_secret_post`와 공개 클라이언트용 `none`도 지원합니다. PKCE S256은 항상 사용합니다. 공개 클라이언트는 Secret을 비워 두세요.

## 동작과 범위

- 브라우저에서 인증 제공자로 이동한 뒤 서버가 콜백을 받아 Token URL로 코드를 교환합니다. 토큰 엔드포인트의 브라우저 CORS 설정은 필요하지 않습니다.
- state를 확인하고 콜백을 한 번만 처리합니다. ID Token의 nonce, audience, 만료·발급 시간, subject·issuer 존재 여부를 점검합니다.
- **JWT 서명, Issuer의 신뢰성은 검증하지 않습니다.** 응답을 살펴보는 개발 도구이며 실제 서비스의 로그인 검증 용도가 아닙니다. 별도의 Discovery/JWKS/UserInfo 요청은 하지 않습니다.
- 응답 원문에는 실제 토큰이 표시됩니다. Secret은 URL·파일·브라우저 저장소에 저장하지 않으며 교환 시도 후 서버 메모리에서도 비웁니다. 재시도할 때 다시 입력하세요.
- 세션은 서버 메모리에만 저장되고 시작 후 15분에 만료됩니다. 초기화 또는 서버 종료 시에도 삭제됩니다. 이미 화면에 표시된 응답은 초기화하거나 페이지를 새로고침할 때 사라집니다.
- 서버는 로컬 루프백(`127.0.0.1`)에만 바인딩됩니다. HTTP GET/query 방식의 콜백만 지원하며 HTTPS 프록시/배포용 구성은 포함하지 않습니다.
- 토큰 요청은 15초 제한이며 HTTP 오류와 비 JSON 응답도 화면에 표시합니다.

다른 포트를 쓰려면 PowerShell에서 `$env:PORT=3001`을 설정한 뒤 `npm start`를 실행하세요. Redirect URI도 해당 포트로 등록해야 합니다.

## 테스트

```sh
npm test
```

로컬 모의 토큰 서버로 PKCE, 3가지 클라이언트 인증 방식, 정상 응답, 잘못된 state, 콜백 재사용, 인증 거절, 토큰 오류 및 초기화를 검증합니다. 실제 제공자 테스트는 발급받은 클라이언트 설정이 필요합니다.

구현 참고: [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [PKCE · RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html).


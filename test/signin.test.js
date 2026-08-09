/**
 * EMS-185: the client half of a governed app's sign-in.
 *
 * WHAT THESE TESTS PROVE, AND WHAT THEY DO NOT. They drive this Worker's real
 * `fetch` handler with real `Request`s and assert on the requests it makes and
 * the cookies it sets. The emseapea control plane at the other end is a stub,
 * so what is proven here is that this app makes exactly the requests the
 * control plane's own end-to-end test (`app/test/app-signin-e2e.test.ts` in
 * the emseapea repo) proves the control plane answers — discovery, authorize
 * with PKCE S256 and `prompt=consent`, then a code-for-token exchange with the
 * verifier and no client secret. The two halves have never run in one process
 * and NOTHING here proves a deployed app signs a real person in.
 *
 * Node's built-in test runner, no dependencies: `npm test`.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { discoverEndpoints, signInConfigured } from '../src/index.js';

/** Obvious placeholders. Nothing here is, or resembles, a real credential. */
const ENV = {
  GATEWAY_URL: 'https://gateway.example/',
  CREDENTIAL_HANDLE: 'placeholder-app-handle-not-a-real-one',
  EMSEAPEA_URL: 'https://control-plane.example',
  EMSEAPEA_CLIENT_ID: 'emapp_placeholder-app-id',
};
/** An app deployed before sign-in existed: the two variables never arrived. */
const ENV_WITHOUT_SIGNIN = {
  GATEWAY_URL: ENV.GATEWAY_URL,
  CREDENTIAL_HANDLE: ENV.CREDENTIAL_HANDLE,
};

/**
 * Endpoints on a DIFFERENT host from EMSEAPEA_URL, on purpose. If this app
 * ever derived an endpoint instead of discovering it, every assertion that
 * names `endpoints.example` below would fail.
 */
const AUTHORIZE = 'https://endpoints.example/api/auth/mcp/authorize';
const TOKEN = 'https://endpoints.example/api/auth/mcp/token';
const REVOKE = 'https://endpoints.example/api/auth/oauth2/revoke';
const DISCOVERY = 'https://control-plane.example/.well-known/oauth-authorization-server';

const TOKEN_FOR_THE_PERSON = 'placeholder-person-token-not-a-real-one';
const APP = 'https://app.example';
const CALLBACK = `${APP}/auth/emseapea/callback`;

/** Every request the code under test made, in order. */
let calls = [];
const realFetch = globalThis.fetch;

const jsonResponse = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

/** A stub emseapea: a discovery document, a token endpoint, a revocation. */
function stubControlPlane({ token = () => jsonResponse({ access_token: TOKEN_FOR_THE_PERSON, token_type: 'Bearer', expires_in: 3600 }) } = {}) {
  globalThis.fetch = async (url, init) => {
    const href = String(url);
    const body = typeof init?.body === 'string' ? init.body : '';
    calls.push({ url: href, method: init?.method ?? 'GET', headers: new Headers(init?.headers), body });
    if (href === DISCOVERY) {
      return jsonResponse({
        issuer: ENV.EMSEAPEA_URL,
        authorization_endpoint: AUTHORIZE,
        token_endpoint: TOKEN,
        revocation_endpoint: REVOKE,
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (href === TOKEN) return token();
    if (href === REVOKE) return jsonResponse({});
    if (href.startsWith('https://gateway.example/')) return jsonResponse({ files: [] });
    throw new Error(`unexpected fetch to ${href}`);
  };
}

beforeEach(() => {
  calls = [];
  stubControlPlane();
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

const get = (path, headers) => new Request(`${APP}${path}`, { headers });
const gatewayCalls = () => calls.filter((c) => c.url.startsWith('https://gateway.example/'));

/** The cookie this response sets, by name, as the browser would store it. */
function setCookie(res, name) {
  return res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
}
function cookieValueOf(res, name) {
  const raw = setCookie(res, name);
  if (!raw) return undefined;
  return decodeURIComponent(raw.slice(name.length + 1).split(';')[0]);
}

async function s256(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  let binary = '';
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Sign in for real, through both routes, and return the browser's cookies. */
async function signInAndGetCookies() {
  const started = await worker.fetch(get('/auth/emseapea/signin'), ENV);
  const flow = new URLSearchParams(cookieValueOf(started, '__Host-emseapea_flow'));
  const state = new URL(started.headers.get('location')).searchParams.get('state');
  const back = await worker.fetch(
    new Request(`${CALLBACK}?code=an-authorization-code&state=${encodeURIComponent(state)}`, {
      headers: { cookie: `__Host-emseapea_flow=${encodeURIComponent(flow.toString())}` },
    }),
    ENV,
  );
  return { started, back, flow };
}

// ── Discovery ──────────────────────────────────────────────────────────────

test('endpoints are DISCOVERED at the well-known path, never derived', async () => {
  const endpoints = await discoverEndpoints(ENV);
  assert.equal(calls[0].url, DISCOVERY);
  // The proof that nothing is hard-coded: these are on a host EMSEAPEA_URL
  // does not name, and the app still finds them.
  assert.equal(endpoints.authorization, AUTHORIZE);
  assert.equal(endpoints.token, TOKEN);
  assert.equal(endpoints.revocation, REVOKE);
});

test('a discovery document with no endpoints is an error, not a guess', async () => {
  globalThis.fetch = async () => jsonResponse({ issuer: ENV.EMSEAPEA_URL });
  await assert.rejects(() => discoverEndpoints(ENV), /no authorization or token endpoint/);
});

// ── Authorize ──────────────────────────────────────────────────────────────

test('sign-in redirects to the discovered authorize endpoint with PKCE S256', async () => {
  const res = await worker.fetch(get('/auth/emseapea/signin'), ENV);
  assert.equal(res.status, 302);
  const to = new URL(res.headers.get('location'));
  assert.equal(`${to.origin}${to.pathname}`, AUTHORIZE);
  assert.equal(to.searchParams.get('response_type'), 'code');
  assert.equal(to.searchParams.get('client_id'), ENV.EMSEAPEA_CLIENT_ID);
  assert.equal(to.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(to.searchParams.get('state'));
  // The one redirect URI emseapea registers for this app: this path, at the
  // origin it deployed the app to.
  assert.equal(to.searchParams.get('redirect_uri'), CALLBACK);
});

test('the challenge really is SHA-256 of the verifier this app kept', async () => {
  const res = await worker.fetch(get('/auth/emseapea/signin'), ENV);
  const flow = new URLSearchParams(cookieValueOf(res, '__Host-emseapea_flow'));
  const sent = new URL(res.headers.get('location')).searchParams.get('code_challenge');
  assert.equal(sent, await s256(flow.get('verifier')));
  // And the verifier itself is never in the URL — that is the whole point.
  assert.ok(!res.headers.get('location').includes(flow.get('verifier')));
});

test('prompt=consent is sent, so the person is asked before anything is granted', async () => {
  const res = await worker.fetch(get('/auth/emseapea/signin'), ENV);
  assert.equal(new URL(res.headers.get('location')).searchParams.get('prompt'), 'consent');
});

test('the in-flight sign-in cookie is HttpOnly, Secure, SameSite=Lax and __Host-', async () => {
  const res = await worker.fetch(get('/auth/emseapea/signin'), ENV);
  const cookie = setCookie(res, '__Host-emseapea_flow');
  assert.ok(cookie.includes('HttpOnly'), cookie);
  assert.ok(cookie.includes('Secure'), cookie);
  // Lax and not Strict: the callback is a cross-site navigation from
  // emseapea, and Strict would withhold the cookie that proves it is ours.
  assert.ok(cookie.includes('SameSite=Lax'), cookie);
  assert.ok(cookie.includes('Path=/'), cookie);
  assert.ok(!cookie.includes('Domain='), cookie);
});

// ── Callback ───────────────────────────────────────────────────────────────

test('the code is exchanged with the verifier and NO client secret', async () => {
  const { back, flow } = await signInAndGetCookies();
  assert.equal(back.status, 302);
  const exchange = calls.find((c) => c.url === TOKEN);
  assert.ok(exchange, 'no code-for-token exchange was made');
  assert.equal(exchange.method, 'POST');
  const sent = new URLSearchParams(exchange.body);
  assert.equal(sent.get('grant_type'), 'authorization_code');
  assert.equal(sent.get('code'), 'an-authorization-code');
  assert.equal(sent.get('client_id'), ENV.EMSEAPEA_CLIENT_ID);
  assert.equal(sent.get('redirect_uri'), CALLBACK);
  assert.equal(sent.get('code_verifier'), flow.get('verifier'));
  // A public client has no secret. If one ever appears here, emseapea is
  // storing a plaintext credential for every governed app (D12/D16).
  assert.equal(sent.get('client_secret'), null);
});

test('the token is held in an HttpOnly cookie and never put in a URL', async () => {
  const { back } = await signInAndGetCookies();
  const cookie = setCookie(back, '__Host-emseapea_person');
  assert.ok(cookie.includes('HttpOnly'), cookie);
  assert.ok(cookie.includes('Secure'), cookie);
  assert.ok(cookie.includes('SameSite=Lax'), cookie);
  assert.equal(cookieValueOf(back, '__Host-emseapea_person'), TOKEN_FOR_THE_PERSON);
  // A token in a Location is a token in a browser history and a proxy log.
  assert.ok(!back.headers.get('location').includes(TOKEN_FOR_THE_PERSON));
  // The in-flight cookie is spent.
  assert.ok(setCookie(back, '__Host-emseapea_flow').includes('Max-Age=0'));
});

test('a code arriving with the wrong state is refused, and never exchanged', async () => {
  const started = await worker.fetch(get('/auth/emseapea/signin'), ENV);
  const flow = cookieValueOf(started, '__Host-emseapea_flow');
  const res = await worker.fetch(
    new Request(`${CALLBACK}?code=somebody-elses-code&state=not-the-state-we-issued`, {
      headers: { cookie: `__Host-emseapea_flow=${encodeURIComponent(flow)}` },
    }),
    ENV,
  );
  assert.equal(res.status, 400);
  assert.equal(calls.filter((c) => c.url === TOKEN).length, 0);
  assert.equal(setCookie(res, '__Host-emseapea_person'), undefined);
});

test('a code arriving with no in-flight sign-in at all is refused', async () => {
  const res = await worker.fetch(get('/auth/emseapea/callback?code=c&state=s'), ENV);
  assert.equal(res.status, 400);
  assert.equal(calls.filter((c) => c.url === TOKEN).length, 0);
});

test('emseapea refusing to issue a token leaves no session behind', async () => {
  stubControlPlane({ token: () => jsonResponse({ error: 'invalid_grant' }, 400) });
  const { back } = await signInAndGetCookies();
  assert.equal(back.status, 401);
  assert.equal(setCookie(back, '__Host-emseapea_person'), undefined);
});

test('return_to cannot be turned into an open redirect', async () => {
  for (const hostile of ['//evil.example', '/\\evil.example', 'https://evil.example']) {
    const started = await worker.fetch(
      get(`/auth/emseapea/signin?return_to=${encodeURIComponent(hostile)}`),
      ENV,
    );
    const flow = new URLSearchParams(cookieValueOf(started, '__Host-emseapea_flow'));
    const state = new URL(started.headers.get('location')).searchParams.get('state');
    const back = await worker.fetch(
      new Request(`${CALLBACK}?code=c&state=${encodeURIComponent(state)}`, {
        headers: { cookie: `__Host-emseapea_flow=${encodeURIComponent(flow.toString())}` },
      }),
      ENV,
    );
    assert.equal(back.headers.get('location'), '/', hostile);
  }
});

test('a same-origin return_to is honoured, so sign-in returns you where you were', async () => {
  const started = await worker.fetch(get('/auth/emseapea/signin?return_to=/me/google-files'), ENV);
  const flow = new URLSearchParams(cookieValueOf(started, '__Host-emseapea_flow'));
  const state = new URL(started.headers.get('location')).searchParams.get('state');
  const back = await worker.fetch(
    new Request(`${CALLBACK}?code=c&state=${encodeURIComponent(state)}`, {
      headers: { cookie: `__Host-emseapea_flow=${encodeURIComponent(flow.toString())}` },
    }),
    ENV,
  );
  assert.equal(back.headers.get('location'), '/me/google-files');
});

// ── What the session is FOR ────────────────────────────────────────────────

test('the held token becomes X-Emseapea-Person on the gateway call', async () => {
  const { back } = await signInAndGetCookies();
  const person = cookieValueOf(back, '__Host-emseapea_person');
  const res = await worker.fetch(
    get('/me/google-files', { cookie: `__Host-emseapea_person=${encodeURIComponent(person)}` }),
    ENV,
  );
  assert.equal(res.status, 200);
  const [call] = gatewayCalls();
  assert.ok(call, 'the gateway was never called');
  assert.equal(call.headers.get('x-emseapea-person'), TOKEN_FOR_THE_PERSON);
  // Still two headers, still not interchangeable.
  assert.equal(call.headers.get('authorization'), `Bearer ${ENV.CREDENTIAL_HANDLE}`);
});

test('an inbound header still wins, so EMS-181 callers are unaffected', async () => {
  const res = await worker.fetch(
    get('/me/google-files', {
      'x-emseapea-person': 'a-caller-that-already-held-one',
      cookie: `__Host-emseapea_person=${TOKEN_FOR_THE_PERSON}`,
    }),
    ENV,
  );
  assert.equal(res.status, 200);
  assert.equal(gatewayCalls()[0].headers.get('x-emseapea-person'), 'a-caller-that-already-held-one');
});

test('a browser with no session is sent to sign in — and the gateway is NOT called', async () => {
  const res = await worker.fetch(get('/me/google-files', { accept: 'text/html' }), ENV);
  assert.equal(res.status, 302);
  assert.equal(
    res.headers.get('location'),
    `${APP}/auth/emseapea/signin?return_to=%2Fme%2Fgoogle-files`,
  );
  // A redirect is not a weaker call. It is no call.
  assert.equal(gatewayCalls().length, 0);
});

test('a non-browser caller with no person is still refused, not redirected', async () => {
  const res = await worker.fetch(get('/me/google-files', { accept: 'application/json' }), ENV);
  assert.equal(res.status, 401);
  assert.equal(gatewayCalls().length, 0);
});

// ── Signing out ────────────────────────────────────────────────────────────

test('signing out clears the cookie and hands the token back', async () => {
  const res = await worker.fetch(
    get('/auth/emseapea/signout', {
      cookie: `__Host-emseapea_person=${TOKEN_FOR_THE_PERSON}`,
    }),
    ENV,
  );
  assert.equal(res.status, 302);
  assert.ok(setCookie(res, '__Host-emseapea_person').includes('Max-Age=0'));
  const revoked = calls.find((c) => c.url === REVOKE);
  assert.ok(revoked, 'the token was left live at the control plane');
  assert.equal(new URLSearchParams(revoked.body).get('token'), TOKEN_FOR_THE_PERSON);
});

test('signing out succeeds even when the control plane is unreachable', async () => {
  globalThis.fetch = async () => {
    throw new Error('the control plane is down');
  };
  const res = await worker.fetch(
    get('/auth/emseapea/signout', { cookie: `__Host-emseapea_person=${TOKEN_FOR_THE_PERSON}` }),
    ENV,
  );
  assert.equal(res.status, 302);
  assert.ok(setCookie(res, '__Host-emseapea_person').includes('Max-Age=0'));
});

// ── An app that was never given a client id (AC3) ──────────────────────────

test('an app with no bound client id still serves', async () => {
  assert.equal(signInConfigured(ENV_WITHOUT_SIGNIN), false);
  const res = await worker.fetch(get('/'), ENV_WITHOUT_SIGNIN);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /not configured/i);
  assert.equal(calls.length, 0, 'an unconfigured app must not call anything');
});

test('its sign-in routes explain themselves rather than failing', async () => {
  for (const path of [
    '/auth/emseapea/signin',
    '/auth/emseapea/callback?code=c&state=s',
    '/auth/emseapea/signout',
  ]) {
    const res = await worker.fetch(get(path), ENV_WITHOUT_SIGNIN);
    // Not a 500, and not a redirect into a flow that cannot complete.
    assert.equal(res.status, 503, path);
    assert.match(await res.text(), /not configured/i);
  }
  assert.equal(calls.length, 0);
});

test('and it still relays a person token that arrives on the request', async () => {
  const res = await worker.fetch(
    get('/me/google-files', { 'x-emseapea-person': TOKEN_FOR_THE_PERSON }),
    ENV_WITHOUT_SIGNIN,
  );
  assert.equal(res.status, 200);
  assert.equal(gatewayCalls()[0].headers.get('x-emseapea-person'), TOKEN_FOR_THE_PERSON);
});

test('a browser on an unconfigured app is refused, never redirected into nothing', async () => {
  const res = await worker.fetch(
    get('/me/google-files', { accept: 'text/html' }),
    ENV_WITHOUT_SIGNIN,
  );
  assert.equal(res.status, 401);
  assert.equal(gatewayCalls().length, 0);
});

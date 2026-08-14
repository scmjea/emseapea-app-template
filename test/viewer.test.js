/**
 * EMS-324: the front door, and the one line of curl that used to walk through
 * it.
 *
 * An app that reaches its system through an account its organisation prepared
 * shows the same organisation-wide data to everybody who opens it. It therefore
 * needs to check who is looking before it shows anything — and until this file
 * existed, nothing in this template did. Every route read the session cookie
 * and believed it:
 *
 *     curl -H 'Cookie: __Host-emseapea_person=anything' https://<the app>/
 *
 * `__Host-` and `HttpOnly` are instructions to a browser. An HTTP client sends
 * whatever cookie header it likes, and this app had no other check.
 *
 * WHAT THESE TESTS PROVE. They drive the real `fetch` handler with real
 * `Request`s against a stubbed emseapea, and assert on what it serves and what
 * it asks. What is proven is that this app refuses a session emseapea has not
 * confirmed, that it asks at the endpoint the DISCOVERY DOCUMENT names rather
 * than one assembled here, and that it tells "your sign-in is bad" apart from
 * "nobody could be asked".
 *
 * WHAT THEY DO NOT PROVE. emseapea is a stub. Nothing here shows a deployed app
 * talking to a real control plane, and nothing here can see whether a given app
 * reaches its system as the signed-in person or through a prepared account —
 * this file is copied into every app whatever it was approved for, which is why
 * the check is unconditional rather than switched on for one of them.
 *
 * Node's built-in test runner, no dependencies: `npm test`.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { verifyViewer } from '../src/index.js';

/** Obvious placeholders. Nothing here is, or resembles, a real credential. */
const ENV = {
  GATEWAY_URL: 'https://gateway.example/',
  CREDENTIAL_HANDLE: 'placeholder-app-handle-not-a-real-one',
  EMSEAPEA_URL: 'https://control-plane.example',
  EMSEAPEA_CLIENT_ID: 'emapp_placeholder-app-id',
};
const ENV_WITHOUT_SIGNIN = {
  GATEWAY_URL: ENV.GATEWAY_URL,
  CREDENTIAL_HANDLE: ENV.CREDENTIAL_HANDLE,
};

const DISCOVERY = 'https://control-plane.example/.well-known/oauth-authorization-server';
/** On a DIFFERENT host from EMSEAPEA_URL, so an app that assembled this path
 *  instead of reading it out of the document would fail every test below. */
const USERINFO = 'https://endpoints.example/api/auth/mcp/userinfo';

const APP = 'https://app.example';
const GOOD_TOKEN = 'placeholder-person-token-not-a-real-one';
const A_REAL_PERSON = { sub: 'usr_placeholder', email: 'someone@example.test', name: 'Someone' };

let calls = [];
const realFetch = globalThis.fetch;

const jsonResponse = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/**
 * A stub emseapea. `userinfo` decides what it says about whichever Bearer it
 * is given; by default it knows exactly one token and 401s everything else,
 * which is what a real one does.
 */
function stubControlPlane({
  userinfo = (token) => (token === GOOD_TOKEN ? jsonResponse(A_REAL_PERSON) : jsonResponse({ error: 'invalid_token' }, 401)),
  discovery = () =>
    jsonResponse({
      issuer: ENV.EMSEAPEA_URL,
      authorization_endpoint: 'https://endpoints.example/api/auth/mcp/authorize',
      token_endpoint: 'https://endpoints.example/api/auth/mcp/token',
      userinfo_endpoint: USERINFO,
    }),
} = {}) {
  globalThis.fetch = async (url, init) => {
    const href = String(url);
    const headers = new Headers(init?.headers);
    calls.push({ url: href, method: init?.method ?? 'GET', headers });
    if (href === DISCOVERY) return discovery();
    if (href === USERINFO) {
      return userinfo((headers.get('authorization') ?? '').replace(/^Bearer /, ''));
    }
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
const forged = (value) => ({ cookie: `__Host-emseapea_person=${value}` });

// ── The card's curl ────────────────────────────────────────────────────────

test('AC1: a made-up session cookie is refused, and nothing is served', async () => {
  // Literally the line in the report.
  const res = await worker.fetch(get('/', forged('anything')), ENV);
  assert.equal(res.status, 401);
  const body = await res.text();
  assert.match(body, /no longer good/i);
  // And it does not read as a signed-in home page.
  assert.doesNotMatch(body, /Signed in to emseapea/);
});

test('AC1: the same cookie on the data route reaches no gateway at all', async () => {
  const res = await worker.fetch(get('/me/google-files', forged('anything')), ENV);
  assert.equal(res.status, 401);
  assert.equal(gatewayCalls().length, 0, 'a forged session reached the gateway');
});

test('AC1: a made-up X-Emseapea-Person header is refused the same way', async () => {
  // The cookie is the reported route in; the header is the other one, and an
  // HTTP client can set either. A fix that only closed the cookie would have
  // closed the report and left the defect.
  const res = await worker.fetch(get('/', { 'x-emseapea-person': 'anything' }), ENV);
  assert.equal(res.status, 401);
  assert.equal(gatewayCalls().length, 0);
});

test('a refused session is cleared, so the browser stops presenting a dead one', async () => {
  const res = await worker.fetch(get('/', forged('anything')), ENV);
  const cleared = res.headers.getSetCookie().find((c) => c.startsWith('__Host-emseapea_person='));
  assert.ok(cleared, 'the dead cookie was left in place');
  assert.match(cleared, /Max-Age=0/);
});

// ── And a real one still works ─────────────────────────────────────────────

test('a session emseapea confirms is served, and the person comes back with it', async () => {
  const seen = await verifyViewer(get('/', forged(GOOD_TOKEN)), ENV);
  assert.equal(seen.outcome, 'verified');
  assert.equal(seen.token, GOOD_TOKEN);
  assert.equal(seen.person.sub, A_REAL_PERSON.sub);

  const res = await worker.fetch(get('/', forged(GOOD_TOKEN)), ENV);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Signed in to emseapea/);
});

test('the confirmed token is what reaches the gateway, unchanged', async () => {
  const res = await worker.fetch(get('/me/google-files', forged(GOOD_TOKEN)), ENV);
  assert.equal(res.status, 200);
  assert.equal(gatewayCalls()[0].headers.get('x-emseapea-person'), GOOD_TOKEN);
});

test('presenting nothing is not a refusal — a visitor still gets the front page', async () => {
  // A door that refused everybody who presented nothing would refuse its own
  // home page. What is refused is a session this app could not stand behind.
  const res = await worker.fetch(get('/'), ENV);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /to sign in with emseapea/i);
});

// ── AC3: the check does not go through the gateway ─────────────────────────

test('AC3: the viewer is checked at the endpoint the DOCUMENT names, not at the gateway', async () => {
  await worker.fetch(get('/', forged(GOOD_TOKEN)), ENV);
  const asked = calls.find((c) => c.url === USERINFO);
  assert.ok(asked, 'the viewer was never checked anywhere');
  // The token authenticates the call. That is what makes this usable from an
  // app with no client secret, and it is why userinfo and not introspection.
  assert.equal(asked.headers.get('authorization'), `Bearer ${GOOD_TOKEN}`);
  // Not derived from EMSEAPEA_URL: this host is not in it.
  assert.equal(calls[0].url, DISCOVERY);
  assert.equal(new URL(asked.url).origin, 'https://endpoints.example');
  // The gateway is not in this app's path for its own data, so it must not be
  // in the path of the check either.
  assert.equal(gatewayCalls().length, 0);
});

// ── The third answer ───────────────────────────────────────────────────────

test('an unreachable control plane is not a bad sign-in, and is not a pass either', async () => {
  globalThis.fetch = async () => {
    throw new Error('the control plane is down');
  };
  const res = await worker.fetch(get('/', forged(GOOD_TOKEN)), ENV);
  // Not 401: nobody established that this person's sign-in is bad.
  // Not 200: nobody established that it is good.
  assert.equal(res.status, 503);
  assert.match(await res.text(), /cannot check who is signed in/i);
});

test('emseapea answering 500 is read the same way — only 401 means "no"', async () => {
  stubControlPlane({ userinfo: () => jsonResponse({ error: 'boom' }, 500) });
  const res = await worker.fetch(get('/', forged(GOOD_TOKEN)), ENV);
  assert.equal(res.status, 503);
});

test('a discovery document naming no userinfo endpoint refuses rather than skipping the check', async () => {
  // The failure this catches is the tempting one: no endpoint, so no check, so
  // carry on. That is the defect with an extra step.
  stubControlPlane({
    discovery: () =>
      jsonResponse({
        issuer: ENV.EMSEAPEA_URL,
        authorization_endpoint: 'https://endpoints.example/api/auth/mcp/authorize',
        token_endpoint: 'https://endpoints.example/api/auth/mcp/token',
      }),
  });
  const res = await worker.fetch(get('/', forged(GOOD_TOKEN)), ENV);
  assert.equal(res.status, 503);
  assert.equal(gatewayCalls().length, 0);
});

test('an app with no EMSEAPEA_URL refuses a token rather than acting on one it cannot check', async () => {
  // A DELIBERATE behaviour change. This app used to relay a person token that
  // arrived on the request. It cannot tell whether that token is real, and it
  // cannot tell whether anything downstream will check — so it does not act.
  const res = await worker.fetch(
    get('/me/google-files', { 'x-emseapea-person': GOOD_TOKEN }),
    ENV_WITHOUT_SIGNIN,
  );
  assert.equal(res.status, 503);
  assert.match(await res.text(), /not given EMSEAPEA_URL/);
  assert.equal(gatewayCalls().length, 0);
  assert.equal(calls.length, 0, 'an app with no control plane address must not call one');
});

test('…and still SERVES: the home page answers and says what is missing', async () => {
  const res = await worker.fetch(get('/'), ENV_WITHOUT_SIGNIN);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /not configured/i);
});

// ── The check travels with the route a builder copies ──────────────────────

test('the worked example verifies for itself when called on its own', async () => {
  // A builder's first route is a copy of this one. A copy that only checks
  // because the handler remembered to is a copy that stops checking the moment
  // it is pasted somewhere new.
  const { myGoogleFiles } = await import('../src/index.js');
  const res = await myGoogleFiles(get('/me/google-files', forged('anything')), ENV);
  assert.equal(res.status, 401);
  assert.equal(gatewayCalls().length, 0);
});

/**
 * EMS-182: this app can sign a person in to emseapea, and holds their token
 * for the session.
 *
 * WHAT THESE COVER, AND WHAT THEY CANNOT. This is a separate repository from
 * emseapea's control plane, so nothing here talks to a real one — discovery
 * and the token endpoint are stubbed. What that leaves worth asserting is the
 * half that lives in THIS file and can be broken by an edit here: the request
 * this app makes, the checks it applies on the way back, and the things it
 * refuses. The other half — that emseapea issues a token for exactly these
 * parameters — is asserted in the control plane's own
 * `app/test/app-signin-e2e.test.ts`, which drives a real sign-in, a real
 * consent and a real code exchange.
 *
 * Node's built-in test runner, no dependencies: `npm test`.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { personTokenFrom, beginSignIn, completeSignIn } from '../src/index.js';

// Obvious placeholders. Nothing here is, or resembles, a real credential.
const ENV = {
  GATEWAY_URL: 'https://gateway.example/',
  CREDENTIAL_HANDLE: 'placeholder-app-handle-not-a-real-one',
  EMSEAPEA_URL: 'https://control-plane.example',
  EMSEAPEA_CLIENT_ID: 'emapp_placeholder-not-a-real-client',
};
const APP_ORIGIN = 'https://app.example';
const ISSUED = 'placeholder-issued-token-not-a-real-one';

const realFetch = globalThis.fetch;
/** Every outbound call the code under test made. */
let calls = [];

const DISCOVERY = {
  authorization_endpoint: 'https://control-plane.example/api/auth/mcp/authorize',
  token_endpoint: 'https://control-plane.example/api/auth/mcp/token',
};

function stub({ discovery = DISCOVERY, token = { access_token: ISSUED, expires_in: 3600 } } = {}) {
  globalThis.fetch = async (url, init) => {
    const href = String(url);
    calls.push({ href, method: init?.method ?? 'GET', body: init?.body });
    if (href.includes('.well-known')) {
      return new Response(JSON.stringify(discovery), {
        status: discovery ? 200 : 500,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (href.includes('/token')) {
      return new Response(JSON.stringify(token), {
        status: token ? 200 : 400,
        headers: { 'content-type': 'application/json' },
      });
    }
    throw new Error(`unexpected fetch to ${href}`);
  };
}

beforeEach(() => {
  calls = [];
  stub();
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** The `Set-Cookie` values off a response, as a list. */
function cookiesOf(res) {
  return typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : [res.headers.get('set-cookie')].filter(Boolean);
}

function cookieValue(res, name) {
  for (const c of cookiesOf(res)) {
    if (c.startsWith(`${name}=`)) return decodeURIComponent(c.slice(name.length + 1).split(';')[0]);
  }
  return undefined;
}

const get = (path, headers = {}) => new Request(`${APP_ORIGIN}${path}`, { headers });

test('sign-in sends the person to emseapea with PKCE S256 and prompt=consent', async () => {
  const res = await beginSignIn(get('/auth/emseapea/sign-in'), ENV);
  assert.equal(res.status, 302);
  const to = new URL(res.headers.get('location'));

  assert.equal(to.origin + to.pathname, DISCOVERY.authorization_endpoint);
  assert.equal(to.searchParams.get('response_type'), 'code');
  assert.equal(to.searchParams.get('client_id'), ENV.EMSEAPEA_CLIENT_ID);
  assert.equal(to.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(to.searchParams.get('code_challenge'));
  // THE ASSERTION THAT MATTERS MOST HERE. Without prompt=consent, emseapea
  // mints the code and redirects straight back, skipping the screen that
  // tells the person what they are connecting. Dropping this parameter is a
  // one-word edit that silently removes a governance control, so it is
  // asserted rather than trusted.
  assert.equal(to.searchParams.get('prompt'), 'consent');
  // Exactly the redirect emseapea registered — anything else is refused there.
  assert.equal(to.searchParams.get('redirect_uri'), `${APP_ORIGIN}/auth/emseapea/callback`);
});

test('the PKCE verifier is set as an HttpOnly cookie and never put in the URL', async () => {
  const res = await beginSignIn(get('/auth/emseapea/sign-in'), ENV);
  const raw = cookiesOf(res).find((c) => c.startsWith('emseapea_pkce='));
  assert.ok(raw, 'no PKCE cookie was set');
  assert.match(raw, /HttpOnly/);
  assert.match(raw, /Secure/);
  assert.match(raw, /SameSite=Lax/);

  const verifier = cookieValue(res, 'emseapea_pkce').split('.')[1];
  assert.ok(verifier);
  // The verifier is the proof; putting it in the authorize URL would hand it
  // to anyone who can read a Referer header or a browser history entry.
  assert.ok(!res.headers.get('location').includes(verifier));
});

test('the endpoints are DISCOVERED, not hard-coded — a repo cannot be updated in place', async () => {
  stub({
    discovery: {
      authorization_endpoint: 'https://control-plane.example/somewhere/else/authorize',
      token_endpoint: 'https://control-plane.example/somewhere/else/token',
    },
  });
  const res = await beginSignIn(get('/auth/emseapea/sign-in'), ENV);
  assert.ok(res.headers.get('location').startsWith('https://control-plane.example/somewhere/else/'));
  assert.ok(calls[0].href.endsWith('/.well-known/oauth-authorization-server'));
});

/** A full sign-in, carrying the cookie from step 1 into step 2. */
async function roundTrip({ stateOverride, codeOverride } = {}) {
  const started = await beginSignIn(get('/auth/emseapea/sign-in'), ENV);
  const pkce = cookieValue(started, 'emseapea_pkce');
  const state = stateOverride ?? pkce.split('.')[0];
  const code = codeOverride ?? 'placeholder-authorization-code';
  return completeSignIn(
    get(`/auth/emseapea/callback?code=${code}&state=${encodeURIComponent(state)}`, {
      cookie: `emseapea_pkce=${encodeURIComponent(pkce)}`,
    }),
    ENV,
  );
}

test('the callback exchanges the code with the verifier and NO client secret', async () => {
  const res = await roundTrip();
  assert.equal(res.status, 302);

  const exchange = calls.find((c) => c.href.includes('/token'));
  const sent = new URLSearchParams(exchange.body);
  assert.equal(sent.get('grant_type'), 'authorization_code');
  assert.equal(sent.get('client_id'), ENV.EMSEAPEA_CLIENT_ID);
  assert.equal(sent.get('redirect_uri'), `${APP_ORIGIN}/auth/emseapea/callback`);
  assert.ok(sent.get('code_verifier'), 'the verifier is this public client’s only proof');
  // There is no secret to send, by design. If one ever appears here it means
  // the app stopped being a public client and started holding a credential.
  assert.equal(sent.get('client_secret'), null);
});

test('the person’s token is kept HttpOnly, and the spent PKCE cookie is cleared', async () => {
  const res = await roundTrip();
  const session = cookiesOf(res).find((c) => c.startsWith('emseapea_person='));
  assert.ok(session);
  assert.match(session, /HttpOnly/);
  assert.equal(cookieValue(res, 'emseapea_person'), ISSUED);
  // Spent codes must not be redeemable twice.
  assert.ok(cookiesOf(res).some((c) => c.startsWith('emseapea_pkce=') && /Max-Age=0/.test(c)));
});

test('a callback whose state does not match the cookie is REFUSED, and no code is redeemed', async () => {
  const res = await roundTrip({ stateOverride: 'a-state-this-app-never-issued' });
  assert.equal(res.status, 400);
  // The load-bearing half: not merely "an error", but that the token endpoint
  // was never called. A refusal that still redeemed the code would have let
  // somebody else's code be exchanged into this app's session.
  assert.equal(
    calls.filter((c) => c.href.includes('/token')).length,
    0,
    'a code was redeemed despite the state check failing',
  );
  assert.equal(cookieValue(res, 'emseapea_person'), undefined);
});

test('a callback with no PKCE cookie at all is refused — an unsolicited code is not a sign-in', async () => {
  const res = await completeSignIn(get('/auth/emseapea/callback?code=abc&state=xyz'), ENV);
  assert.equal(res.status, 400);
  assert.equal(calls.filter((c) => c.href.includes('/token')).length, 0);
});

test('an error handed back by emseapea is reported, not exchanged', async () => {
  const res = await completeSignIn(get('/auth/emseapea/callback?error=access_denied'), ENV);
  assert.equal(res.status, 400);
  assert.equal(calls.filter((c) => c.href.includes('/token')).length, 0);
});

test('a session cookie makes the person available to the gateway call', async () => {
  const req = get('/me/google-files', { cookie: `emseapea_person=${ISSUED}` });
  assert.equal(personTokenFrom(req), ISSUED);
});

test('an inbound header WINS over the cookie — a relayed caller is not answered as whoever last signed in', async () => {
  const relayed = 'placeholder-relayed-person-token';
  const req = get('/me/google-files', {
    cookie: `emseapea_person=${ISSUED}`,
    'x-emseapea-person': relayed,
  });
  assert.equal(personTokenFrom(req), relayed);
});

test('a browser with no person is sent to sign in; a script gets a 401 it can act on', async () => {
  const browser = await worker.fetch(get('/me/google-files', { accept: 'text/html' }), ENV);
  assert.equal(browser.status, 302);
  assert.equal(browser.headers.get('location'), '/auth/emseapea/sign-in');

  const script = await worker.fetch(get('/me/google-files', { accept: 'application/json' }), ENV);
  assert.equal(script.status, 401);
  // Never a redirect into HTML for something that asked for JSON, and never a
  // call to the gateway without a person.
  assert.equal(calls.length, 0);
});

test('an app emseapea never registered says so, instead of half-starting a sign-in', async () => {
  const res = await worker.fetch(get('/auth/emseapea/sign-in'), {
    GATEWAY_URL: ENV.GATEWAY_URL,
    CREDENTIAL_HANDLE: ENV.CREDENTIAL_HANDLE,
  });
  assert.equal(res.status, 500);
  const body = await res.json();
  assert.match(body.error, /EMSEAPEA_URL and EMSEAPEA_CLIENT_ID/);
  assert.equal(calls.length, 0);
});

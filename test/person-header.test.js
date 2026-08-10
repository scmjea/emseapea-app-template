/**
 * The one behaviour a governed app must not lose while someone is editing it:
 * a request that does not say who is signed in is REFUSED, not quietly
 * downgraded into a call as somebody else.
 *
 * Node's built-in test runner, no dependencies: `npm test`.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { personTokenFrom, callGateway, connectUrl } from '../src/index.js';

// Obvious placeholders. Nothing here is, or resembles, a real credential.
const ENV = {
  GATEWAY_URL: 'https://gateway.example/',
  CREDENTIAL_HANDLE: 'placeholder-app-handle-not-a-real-one',
};
const PERSON = 'placeholder-person-token-not-a-real-one';

/** Every gateway call the code under test made. */
let calls = [];
const realFetch = globalThis.fetch;

function stubGateway(response) {
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), headers: new Headers(init?.headers) });
    return response();
  };
}

const jsonResponse = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

beforeEach(() => {
  calls = [];
  stubGateway(() => jsonResponse({ files: [] }));
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

const get = (path, headers) => new Request(`https://app.example${path}`, { headers });

test('no X-Emseapea-Person: refused, and the gateway is never called', async () => {
  const res = await worker.fetch(get('/me/google-files'), ENV);
  assert.equal(res.status, 401);
  // The point of the test. A downgraded call would still have been a call.
  assert.equal(calls.length, 0, 'a request with no person must not reach the gateway');
});

test('an empty X-Emseapea-Person is treated as no person, not as a person', async () => {
  const res = await worker.fetch(get('/me/google-files', { 'x-emseapea-person': '   ' }), ENV);
  assert.equal(res.status, 401);
  assert.equal(calls.length, 0);
});

test('with a person: the handle and the person go to the gateway, in their own headers', async () => {
  const res = await worker.fetch(get('/me/google-files', { 'x-emseapea-person': PERSON }), ENV);
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  const [call] = calls;
  // Addressed to the gateway, not to Google.
  assert.ok(call.url.startsWith('https://gateway.example/u/google/'), call.url);
  assert.equal(call.headers.get('authorization'), `Bearer ${ENV.CREDENTIAL_HANDLE}`);
  assert.equal(call.headers.get('x-emseapea-person'), PERSON);
  // The two must never be conflated: the person's token is not an app handle.
  assert.notEqual(call.headers.get('authorization'), `Bearer ${PERSON}`);
});

test('callGateway has no call-as-nobody path at all', async () => {
  await assert.rejects(() => callGateway(ENV, '/u/google/drive/v3/files', undefined));
  assert.equal(calls.length, 0);
});

test('no account in the system is rendered, not raised as an error', async () => {
  stubGateway(() =>
    jsonResponse({
      ok: false,
      outcome: 'no_account',
      system: 'google',
      message: 'You do not have a Google Workspace account yet.',
    }),
  );
  const res = await worker.fetch(get('/me/google-files', { 'x-emseapea-person': PERSON }), ENV);
  assert.equal(res.status, 200);
  assert.equal((await res.json()).message, 'You do not have a Google Workspace account yet.');
});

// ── The step that message cannot know about ───────────────────────────────
//
// "Ask your IT team" is the right advice for somebody with no account at all,
// and the wrong advice for somebody who HAS one and has never linked it to
// emseapea — which is the common case and one they can fix themselves. The
// gateway cannot tell the two apart: it knows there is nothing to act as, not
// why. So the app offers both readings, and the gateway's sentence is kept.

/** The two variables an app is given when emseapea can sign people in. */
const WITH_CONTROL_PLANE = {
  ...ENV,
  EMSEAPEA_URL: 'https://control-plane.example',
  EMSEAPEA_CLIENT_ID: 'placeholder-client-id-not-a-real-one',
};

test('a Microsoft no-account answer keeps the sentence and adds the link', async () => {
  const message = 'You need a Microsoft 365 account to see this. Ask your IT team.';
  stubGateway(() => jsonResponse({ ok: false, outcome: 'no_account', system: 'msgraph', message }));
  const res = await worker.fetch(
    get('/me/google-files', { 'x-emseapea-person': PERSON }),
    WITH_CONTROL_PLANE,
  );
  const body = await res.json();
  assert.equal(res.status, 200);
  // Verbatim and unreworded. Rewording somebody else's account status is not
  // this app's to do.
  assert.equal(body.message, message);
  // ON THE CONTROL PLANE, not here: this app never runs a vendor OAuth flow
  // and must never look as though it does.
  const link = new URL(body.connect.url);
  assert.equal(link.origin, 'https://control-plane.example');
  assert.equal(link.pathname, '/api/connect/msgraph/start');
  // And it asks to be sent back to the page the person was actually on.
  assert.equal(link.searchParams.get('return_to'), 'https://app.example/me/google-files');
  // It promises nothing about the link working — a 503 there means the
  // organisation has not finished its registration, and it says so.
  assert.match(body.connect.why, /not set up yet/);
});

test('an app never told where emseapea is builds no link at all', async () => {
  // A link that goes somewhere wrong is worse than no link: the person reports
  // a broken link instead of the missing configuration behind it.
  const message = 'You need a Microsoft 365 account to see this. Ask your IT team.';
  stubGateway(() => jsonResponse({ ok: false, outcome: 'no_account', system: 'msgraph', message }));
  const res = await worker.fetch(get('/me/google-files', { 'x-emseapea-person': PERSON }), ENV);
  const body = await res.json();
  assert.equal(body.message, message);
  assert.equal(body.connect, undefined);
  assert.ok(!JSON.stringify(body).includes('/api/connect/'), 'a half-built URL reached the answer');
});

test('no link for a system a person cannot link themselves', () => {
  // Google's person-scoped access is a domain-wide delegation an administrator
  // sets up. There is nothing for a person to press, and emseapea's connect
  // route refuses anything but Microsoft — so a link here would fail, and
  // offering one would be this app inventing a control.
  assert.equal(connectUrl(WITH_CONTROL_PLANE, 'google'), undefined);
  assert.equal(connectUrl(WITH_CONTROL_PLANE, undefined), undefined);
  assert.equal(connectUrl({}, 'msgraph'), undefined);
  assert.equal(connectUrl(undefined, 'msgraph'), undefined);
  assert.equal(connectUrl({ EMSEAPEA_URL: '' }, 'msgraph'), undefined);
});

test('a trailing slash on EMSEAPEA_URL does not become a doubled one', () => {
  const url = connectUrl({ EMSEAPEA_URL: 'https://control-plane.example/' }, 'msgraph');
  assert.equal(url, 'https://control-plane.example/api/connect/msgraph/start');
  assert.ok(!url.includes('example//'), 'a doubled slash reached the URL');
});

test('personTokenFrom reads the header, and only when it has content', () => {
  assert.equal(personTokenFrom(get('/', { 'x-emseapea-person': PERSON })), PERSON);
  assert.equal(personTokenFrom(get('/')), undefined);
  assert.equal(personTokenFrom(get('/', { 'x-emseapea-person': '' })), undefined);
});

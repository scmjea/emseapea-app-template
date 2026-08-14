/**
 * The one behaviour a governed app must not lose while someone is editing it:
 * a request that does not say who is signed in is REFUSED, not quietly
 * downgraded into a call as somebody else.
 *
 * Node's built-in test runner, no dependencies: `npm test`.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, {
  personTokenFrom,
  callGateway,
  connectUrl,
  noAccountAnswer,
} from '../src/index.js';

// Obvious placeholders. Nothing here is, or resembles, a real credential.
const ENV = {
  GATEWAY_URL: 'https://gateway.example/',
  CREDENTIAL_HANDLE: 'placeholder-app-handle-not-a-real-one',
  /**
   * EMS-324. These two are here now, and every test below that expects a
   * gateway call needs them: this app no longer acts on a person token until
   * emseapea has confirmed it, and an app with no `EMSEAPEA_URL` has nowhere to
   * ask. That is deliberate — *we could not check* is not *it is fine* — and it
   * means the version of this file that ran before the front door existed was
   * proving the gateway call shape on a person nothing had ever verified.
   */
  EMSEAPEA_URL: 'https://control-plane.example',
  EMSEAPEA_CLIENT_ID: 'placeholder-client-id-not-a-real-one',
};
const PERSON = 'placeholder-person-token-not-a-real-one';

const DISCOVERY = 'https://control-plane.example/.well-known/oauth-authorization-server';
const USERINFO = 'https://endpoints.example/api/auth/mcp/userinfo';

/** Every gateway call the code under test made. The viewer check is not one —
 *  it goes to emseapea, not to the gateway, which is EMS-324 AC3 — so it is
 *  deliberately not counted here and the assertions below are unchanged. */
let calls = [];
const realFetch = globalThis.fetch;

/**
 * The gateway, and behind it just enough of emseapea for the front door to get
 * an answer: a discovery document naming `userinfo`, and a `userinfo` that
 * knows exactly one token.
 */
function stubGateway(response) {
  globalThis.fetch = async (url, init) => {
    const href = String(url);
    const headers = new Headers(init?.headers);
    if (href === DISCOVERY) {
      return jsonResponse({
        issuer: ENV.EMSEAPEA_URL,
        authorization_endpoint: 'https://endpoints.example/api/auth/mcp/authorize',
        token_endpoint: 'https://endpoints.example/api/auth/mcp/token',
        userinfo_endpoint: USERINFO,
      });
    }
    if (href === USERINFO) {
      return (headers.get('authorization') ?? '') === `Bearer ${PERSON}`
        ? jsonResponse({ sub: 'usr_placeholder', email: 'someone@example.test' })
        : jsonResponse({ error: 'invalid_token' }, 401);
    }
    calls.push({ url: href, headers });
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

/**
 * The two variables an app is given when emseapea can sign people in. They are
 * in `ENV` itself since EMS-324 — the front door needs somewhere to ask — so
 * this is now the same object, kept under its own name because the tests below
 * are about what having a control plane MEANS for the connect link, and reading
 * `WITH_CONTROL_PLANE` at the call site is the point being made.
 */
const WITH_CONTROL_PLANE = { ...ENV };

/** An app that was never given emseapea's address. */
const WITHOUT_CONTROL_PLANE = {
  GATEWAY_URL: ENV.GATEWAY_URL,
  CREDENTIAL_HANDLE: ENV.CREDENTIAL_HANDLE,
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

test('an app never told where emseapea is builds no link at all', () => {
  // A link that goes somewhere wrong is worse than no link: the person reports
  // a broken link instead of the missing configuration behind it.
  //
  // EMS-324 MOVED THIS OFF THE HANDLER, and the reason is worth reading rather
  // than skipping. It used to drive `worker.fetch` with an env that had no
  // `EMSEAPEA_URL`. Such an app can no longer reach the gateway at all — it has
  // nowhere to check the viewer, so it refuses before it gets there — which
  // means the route can no longer produce the answer this test is about. The
  // subject is `noAccountAnswer`, so the subject is what it now calls.
  const message = 'You need a Microsoft 365 account to see this. Ask your IT team.';
  const body = noAccountAnswer(
    { ok: false, outcome: 'no_account', system: 'msgraph', message },
    get('/me/google-files'),
    WITHOUT_CONTROL_PLANE,
  );
  assert.equal(body.message, message);
  assert.equal(body.connect, undefined);
  assert.ok(!JSON.stringify(body).includes('/api/connect/'), 'a half-built URL reached the answer');
});

test('and that app refuses rather than acting on a person it cannot check', async () => {
  // The other half of what changed above, asserted rather than left implied.
  stubGateway(() => jsonResponse({ files: [] }));
  const res = await worker.fetch(
    get('/me/google-files', { 'x-emseapea-person': PERSON }),
    WITHOUT_CONTROL_PLANE,
  );
  assert.equal(res.status, 503);
  assert.equal(calls.length, 0, 'a person nothing verified reached the gateway');
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

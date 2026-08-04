/**
 * The one behaviour a governed app must not lose while someone is editing it:
 * a request that does not say who is signed in is REFUSED, not quietly
 * downgraded into a call as somebody else.
 *
 * Node's built-in test runner, no dependencies: `npm test`.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { personTokenFrom, callGateway } from '../src/index.js';

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

test('personTokenFrom reads the header, and only when it has content', () => {
  assert.equal(personTokenFrom(get('/', { 'x-emseapea-person': PERSON })), PERSON);
  assert.equal(personTokenFrom(get('/')), undefined);
  assert.equal(personTokenFrom(get('/', { 'x-emseapea-person': '' })), undefined);
});

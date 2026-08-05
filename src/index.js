/**
 * A governed emseapea app. Minimal on purpose — replace the routes with your
 * own, but keep the shape of the gateway call, because that shape is the
 * governance.
 *
 * TWO things identify a call, and they are not interchangeable:
 *
 *   Authorization: Bearer <CREDENTIAL_HANDLE>   which APP is calling
 *   X-Emseapea-Person: <the person's token>     which PERSON it is calling for
 *
 * The handle says which app. It is not a vendor token and it never reaches
 * the vendor: address GATEWAY_URL, never the vendor's own host, and the
 * gateway swaps the handle for real vendor credentials this app never sees.
 * Vendor documentation will tell you to do something different; it is
 * describing ungoverned access.
 *
 * The person token says who is signed in, and for a system reached "only what
 * the person using it can already see" it is not optional. On Google
 * Workspace it decides whose Drive, mail and directory view come back — the
 * gateway signs an assertion naming that person — so with nothing forwarded
 * there is nobody to act as and the gateway REFUSES rather than substituting
 * somebody. See docs/architecture.md D13 in the emseapea repo.
 *
 * Treat the person token as opaque cargo: do not decode it, do not log it, do
 * not store it, and do not send it anywhere except GATEWAY_URL.
 *
 * ---------------------------------------------------------------------------
 * WHERE THE PERSON TOKEN COMES FROM. Read this before you ship.
 * ---------------------------------------------------------------------------
 * The token is an OAuth access token issued by the emseapea control plane's
 * own sign-in — the same kind of token an MCP client carries. The control
 * plane resolves it to a person and REJECTS it when that person's
 * organisation is not the one this app's handle belongs to, so forwarding a
 * borrowed token from another org buys nothing.
 *
 * There are TWO ways this app gets one, and both are wired up below:
 *
 *   1. RELAYED. Your caller already holds a token — an agent or MCP client
 *      that has signed in to emseapea — and sends it to this app as
 *      `X-Emseapea-Person`. Nothing more is needed.
 *
 *   2. SIGNED IN HERE (EMS-182). Send the person to `/auth/emseapea/sign-in`.
 *      This app discovers emseapea's OAuth endpoints, runs authorization-code
 *      + PKCE against them, and keeps the resulting token in an HttpOnly
 *      cookie for their session. This is the route a PERSON opening the app
 *      in a browser needs — Alice builds the dashboard, Bob opens it, Bob
 *      sees BOB's data.
 *
 * Route 2 needs two variables that emseapea sets when it deploys you:
 *
 *   EMSEAPEA_URL        where the control plane lives
 *   EMSEAPEA_CLIENT_ID  this app's own OAuth client id
 *
 * There is deliberately NO client secret. Emseapea registers this app as a
 * PUBLIC OAuth client and PKCE is its proof of identity, so there is nothing
 * here that leaking would cost you. It also registers exactly ONE permitted
 * redirect — `/auth/emseapea/callback` on this app's own origin — so a code
 * cannot be redirected anywhere else even by a caller who asks for it.
 *
 * This app still cannot MINT a token, and neither can you. With neither route
 * satisfied the example below refuses rather than calling as nobody in
 * particular. That refusal is the feature.
 *
 * Treat everything about the flow as security-relevant: the `state` value is
 * checked on the way back, the PKCE verifier never leaves this app, and the
 * person's token is stored HttpOnly so page scripts cannot read it.
 */

/** Lower-case because `Headers` lookups are case-insensitive either way, and
 *  this is the one name both ends of the contract have to agree on. */
const PERSON_HEADER = 'x-emseapea-person';

/** The cookie this app keeps a signed-in person's token in. */
const SESSION_COOKIE = 'emseapea_person';
/** The cookie holding the in-flight PKCE verifier and state, for ~10 minutes. */
const PKCE_COOKIE = 'emseapea_pkce';
/** The ONE redirect emseapea registers for this app. Changing it here without
 *  changing it there breaks the flow with `Invalid redirect URI`. */
const CALLBACK_PATH = '/auth/emseapea/callback';
const SIGN_IN_PATH = '/auth/emseapea/sign-in';

/**
 * The signed-in person's token: the inbound header first, this app's own
 * session cookie second.
 *
 * Header first on purpose. A caller that went to the trouble of forwarding a
 * person is making a more specific claim than a cookie left over in a
 * browser, and an agent calling this app on behalf of somebody must not be
 * silently answered with whoever last signed in on this device.
 */
export function personTokenFrom(request) {
  const header = (request.headers.get(PERSON_HEADER) ?? '').trim();
  if (header !== '') return header;
  const cookie = readCookie(request, SESSION_COOKIE);
  return cookie === '' ? undefined : cookie;
}

/** One cookie by name. Workers give us the raw header and nothing else. */
function readCookie(request, name) {
  const raw = request.headers.get('cookie') ?? '';
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return '';
}

function setCookie(name, value, maxAgeSeconds) {
  // HttpOnly so page scripts cannot read the person's token; SameSite=Lax so
  // it survives the top-level redirect back from emseapea but is not sent on
  // cross-site subrequests; Secure because this app is served over HTTPS.
  return (
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; ` +
    `Max-Age=${maxAgeSeconds}`
  );
}

function base64url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomToken() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * Emseapea's OAuth endpoints, asked for rather than hard-coded.
 *
 * This is the one thing standing between a repository generated today and a
 * control plane that moves a path in a year. A repo does not track the
 * template it came from, so anything frozen in here is frozen forever —
 * discovery is how that risk is kept to the part a standard already pins
 * (RFC 8414).
 */
async function discover(env) {
  const base = String(env.EMSEAPEA_URL ?? '').replace(/\/+$/, '');
  if (!base || !env.EMSEAPEA_CLIENT_ID) {
    throw new Error(
      'This app was not set up to sign people in: EMSEAPEA_URL and EMSEAPEA_CLIENT_ID are not ' +
        'set. Emseapea sets both when it deploys the app. Until then, a caller has to forward ' +
        'the person with an X-Emseapea-Person header.',
    );
  }
  const res = await fetch(`${base}/.well-known/oauth-authorization-server`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`Could not reach emseapea's sign-in (${res.status}).`);
  const meta = await res.json();
  if (!meta?.authorization_endpoint || !meta?.token_endpoint) {
    throw new Error('Emseapea did not describe its sign-in endpoints.');
  }
  return meta;
}

/**
 * Step 1: send the person to emseapea to sign in.
 *
 * `prompt=consent` is NOT optional and NOT cosmetic. Emseapea's provider mints
 * the code and redirects straight back without it, skipping the screen that
 * tells the person what they are connecting and to whom. An app asking an
 * organisation's people to authenticate must not be able to do that quietly.
 */
export async function beginSignIn(request, env) {
  const meta = await discover(env);
  const verifier = randomToken();
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = base64url(new Uint8Array(digest));
  const state = randomToken();

  const authorize = new URL(meta.authorization_endpoint);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', String(env.EMSEAPEA_CLIENT_ID));
  authorize.searchParams.set('redirect_uri', callbackUri(request));
  authorize.searchParams.set('scope', 'openid profile email');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('prompt', 'consent');

  return new Response(null, {
    status: 302,
    headers: {
      location: authorize.toString(),
      // The verifier never leaves this app and never reaches the browser's
      // scripts. It is what proves, at the token endpoint, that the code
      // being redeemed was requested by this app and not intercepted.
      'set-cookie': setCookie(PKCE_COOKIE, `${state}.${verifier}`, 600),
    },
  });
}

/** This app's own callback, which is the only redirect emseapea permits it. */
function callbackUri(request) {
  return `${new URL(request.url).origin}${CALLBACK_PATH}`;
}

/**
 * Step 2: emseapea sends the person back with a code. Swap it for their token.
 *
 * The `state` check is the reason this cannot be driven by somebody else: a
 * code delivered to this callback that this app did not ask for has no
 * matching cookie, and is refused rather than redeemed.
 */
export async function completeSignIn(request, env) {
  const url = new URL(request.url);
  const refused = url.searchParams.get('error');
  if (refused) return html(`Emseapea refused the sign-in (${escapeHtml(refused)}).`, 400);

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const stored = readCookie(request, PKCE_COOKIE);
  const separator = stored.indexOf('.');
  const expectedState = separator === -1 ? '' : stored.slice(0, separator);
  const verifier = separator === -1 ? '' : stored.slice(separator + 1);

  if (!code || !state || !verifier || state !== expectedState) {
    // Deliberately not specific about WHICH part failed. This branch is
    // reached by an expired sign-in and by a forged one, and only one of
    // those deserves a diagnostic.
    return html('That sign-in did not complete. Please start again.', 400);
  }

  const meta = await discover(env);
  const res = await fetch(meta.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    // No client secret: this app is a PUBLIC client and `code_verifier` is
    // its proof. There is nothing here to keep out of a log.
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUri(request),
      client_id: String(env.EMSEAPEA_CLIENT_ID),
      code_verifier: verifier,
    }).toString(),
  });
  if (!res.ok) return html('Emseapea would not complete the sign-in. Please try again.', 502);
  const token = await res.json().catch(() => undefined);
  if (!token?.access_token) return html('Emseapea did not return a sign-in.', 502);

  const headers = new Headers({ location: '/' });
  // The cookie expires when the token does, so a stale cookie cannot keep
  // sending a dead token to the gateway on every request.
  headers.append(
    'set-cookie',
    setCookie(SESSION_COOKIE, token.access_token, Number(token.expires_in) || 3600),
  );
  // Spent, and no longer able to authorise a second exchange.
  headers.append(
    'set-cookie',
    `${PKCE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  );
  return new Response(null, { status: 302, headers });
}

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
}

function html(message, status) {
  return new Response(`<!doctype html><meta charset="utf-8"><p>${message}</p>`, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

/**
 * One call through the gateway, on behalf of one person.
 *
 * `personToken` is a required argument rather than an optional one on
 * purpose: there is deliberately no call-as-nobody path through this
 * function, so a route with no person has to decide what to do about that
 * instead of quietly getting a weaker call.
 */
export async function callGateway(env, path, personToken) {
  if (!personToken) throw new Error('callGateway needs the signed-in person');
  if (!env.GATEWAY_URL || !env.CREDENTIAL_HANDLE) {
    throw new Error('GATEWAY_URL and CREDENTIAL_HANDLE are not set for this app');
  }
  return fetch(`${String(env.GATEWAY_URL).replace(/\/+$/, '')}${path}`, {
    headers: {
      authorization: `Bearer ${env.CREDENTIAL_HANDLE}`,
      [PERSON_HEADER]: personToken,
      accept: 'application/json',
    },
  });
}

/**
 * Worked example: a person reading their OWN Google Drive files.
 *
 * This is the delegated-identity claim in one route. The app holds no Google
 * credential; the gateway signs as the person this request names; Google
 * decides what that person may see. Swap `google` and the path for any other
 * system listed in this repo's CONNECTORS.md.
 */
export async function myGoogleFiles(request, env) {
  const personToken = personTokenFrom(request);
  if (!personToken) {
    // Refused, not downgraded. The gateway is not called at all: there is no
    // weaker version of this request worth making, because a call that
    // reached Google as somebody else would answer the wrong question
    // convincingly.
    //
    // A PERSON gets sent to sign in; a MACHINE gets a 401 it can act on. The
    // difference is worth making: redirecting an API client into an HTML
    // sign-in page turns a clear failure into a confusing one, and answering
    // a browser with JSON leaves somebody staring at an error for a problem
    // they could have fixed by signing in.
    if (wantsHtml(request) && env.EMSEAPEA_CLIENT_ID) {
      return new Response(null, { status: 302, headers: { location: SIGN_IN_PATH } });
    }
    return json(
      {
        error:
          "This reads the signed-in person's own files, so the request has to say who that " +
          `is. Forward their emseapea token as the X-Emseapea-Person header, or open ${SIGN_IN_PATH} ` +
          'in a browser to sign in.',
      },
      401,
    );
  }

  const res = await callGateway(
    env,
    '/u/google/drive/v3/files?pageSize=10&fields=files(id,name,mimeType)',
    personToken,
  );
  const body = await res.json().catch(() => undefined);

  // Not everyone has an account in every system. The gateway answers that
  // with a 200 and something to render — a fact about the person, not an
  // error — so show the message as it is rather than making it a 403.
  if (body?.ok === false && body.outcome === 'no_account') {
    return json({ message: body.message }, 200);
  }
  if (!res.ok) {
    return json({ error: 'Could not read from Google right now.' }, res.status);
  }
  return json(body ?? {}, 200);
}

function json(value, status) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** A browser asking for a page, as opposed to something calling an API. */
function wantsHtml(request) {
  return (request.headers.get('accept') ?? '').includes('text/html');
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    try {
      // The two sign-in routes (EMS-182). They are the app's, not emseapea's:
      // emseapea registered `/auth/emseapea/callback` on THIS origin as the
      // one place it will send an authorization code.
      if (pathname === SIGN_IN_PATH) return await beginSignIn(request, env);
      if (pathname === CALLBACK_PATH) return await completeSignIn(request, env);
      if (pathname === '/me/google-files') return await myGoogleFiles(request, env);
    } catch (e) {
      return json({ error: e instanceof Error ? e.message : 'Something went wrong.' }, 500);
    }
    return new Response(
      'Hello from a governed emseapea app. Try GET /me/google-files — in a browser you will be ' +
        `sent to ${SIGN_IN_PATH} to sign in; from a script, forward the person's emseapea token ` +
        'as an X-Emseapea-Person header.',
    );
  },
};

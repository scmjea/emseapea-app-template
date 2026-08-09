/**
 * A governed emseapea app. Minimal on purpose — replace the routes with your
 * own, but keep the shape of the gateway call and of the sign-in, because that
 * shape is the governance.
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
 * not put it in a URL, and do not send it anywhere except GATEWAY_URL.
 *
 * ---------------------------------------------------------------------------
 * WHERE THE PERSON TOKEN COMES FROM. Read this before you ship.
 * ---------------------------------------------------------------------------
 * Either of two ways, and this file does both:
 *
 *   1. **A caller already holds one.** An agent or MCP client that has signed
 *      in to emseapea sends its token to this app in the same
 *      `X-Emseapea-Person` header. Relayed as-is.
 *   2. **This app signs the person in itself.** A browser has no such header,
 *      so the app runs the OAuth authorization-code flow against emseapea and
 *      keeps the resulting token for the session. That is the block below.
 *
 * Either way the token is an OAuth access token issued by the emseapea control
 * plane's own sign-in — the same kind of token an MCP client carries. The
 * control plane resolves it to a person and REJECTS it when that person's
 * organisation is not the one this app's handle belongs to, so a borrowed
 * token from another org buys nothing.
 *
 * ---------------------------------------------------------------------------
 * SIGNING A PERSON IN (EMS-182 registered this app; EMS-185 is this half)
 * ---------------------------------------------------------------------------
 * NOTHING HERE NEEDS EDITING and very little of it should be. Two variables
 * arrive from the deploy, set by emseapea and not by you:
 *
 *   EMSEAPEA_URL        where the control plane lives — an ORIGIN, not an
 *                       endpoint. Endpoints are DISCOVERED at
 *                       `${EMSEAPEA_URL}/.well-known/oauth-authorization-server`
 *                       (RFC 8414) rather than written down here, because this
 *                       repository is a copy that does not track the template:
 *                       a URL frozen into it can never be corrected, and a
 *                       discovery document can.
 *   EMSEAPEA_CLIENT_ID  this app's own OAuth client id.
 *
 * There is deliberately no client secret. The app is registered as a PUBLIC
 * OAuth client and proves itself with **PKCE** — it invents a random
 * `code_verifier`, sends only its SHA-256 hash when it asks for a code, and
 * presents the original when it trades that code for a token. Whoever
 * intercepts the code cannot use it without the verifier, which never left
 * this Worker. That is the whole idea, and it is why an app with no secret is
 * still safe to trust with an authorization code.
 *
 * If those variables are absent — an app deployed before this existed, or into
 * an environment with no control plane address — this app STILL SERVES. It
 * says sign-in is not configured and carries on relaying a person token that
 * arrives on the request. Nothing here fails closed on a binding it never got.
 *
 * WHERE THE SESSION LIVES, AND WHY THERE. A governed app is uploaded as a
 * single ES module with plain-text variables: no KV, no Durable Object, no
 * disk, no second file. The only place left to keep anything between requests
 * is the person's own browser, so the token rides in an `HttpOnly; Secure;
 * SameSite=Lax` cookie on this app's own origin, and the app holds no session
 * store at all. The trade-offs, stated rather than assumed:
 *
 *   - **The cookie is NOT signed, and does not need to be.** A signature would
 *     prove we issued the value; the value is a bearer token the control plane
 *     validates on every use, so a forged one is simply an invalid token and
 *     is refused upstream. There is also no secret to sign with — every
 *     binding this app gets is plain text — so a "signed" cookie here would
 *     have meant inventing a key with nowhere to keep it.
 *   - **The token is in the browser.** Anything that can read cookies on this
 *     origin can act as the person for up to an hour. `HttpOnly` keeps script
 *     out, `Secure` keeps it off plaintext HTTP, and the `__Host-` prefix stops
 *     a neighbouring host on the same parent domain from writing it.
 *   - **No refresh token.** We do not ask for `offline_access`, so nothing
 *     long-lived is stored anywhere. The cookie expires when the token does
 *     (about an hour) and the person signs in again — one redirect.
 *   - **Sessions do not survive a token expiry, and cannot be revoked from
 *     here.** Signing out clears the cookie and hands the token back to the
 *     control plane's revocation endpoint, which is as close to a server-side
 *     session as an app with no storage can get.
 */

/** Lower-case because `Headers` lookups are case-insensitive either way, and
 *  this is the one name both ends of the contract have to agree on. */
const PERSON_HEADER = 'x-emseapea-person';

/**
 * The callback path. Fixed by emseapea, NOT chosen here: the control plane
 * registers exactly one redirect URI for this app — this path at the origin it
 * deployed the app to — and refuses an authorization request naming any other.
 * Change this string and sign-in stops working.
 */
const CALLBACK_PATH = '/auth/emseapea/callback';
const SIGNIN_PATH = '/auth/emseapea/signin';
const SIGNOUT_PATH = '/auth/emseapea/signout';

/**
 * `__Host-` is a browser-enforced prefix: the cookie is only accepted if it is
 * `Secure`, `Path=/`, and carries no `Domain` — which means no other host can
 * write it. That matters on shared parent domains like `workers.dev`, where a
 * neighbour would otherwise be able to plant a session on this app.
 */
const PERSON_COOKIE = '__Host-emseapea_person';
/**
 * The in-flight sign-in: the PKCE verifier and the CSRF state. Short-lived.
 *
 * ONE at a time, which is the cost of having nowhere but a cookie to keep it:
 * starting a second sign-in in another tab overwrites the first, and the first
 * tab's callback is then refused as not having come from here. The person
 * signs in again. Storing several would mean a store this app does not have.
 */
const FLOW_COOKIE = '__Host-emseapea_flow';
const FLOW_TTL_SECONDS = 600;

/** True when emseapea gave this app what it needs to sign anybody in. */
export function signInConfigured(env) {
  return Boolean(env?.EMSEAPEA_URL && env?.EMSEAPEA_CLIENT_ID);
}

/**
 * The signed-in person's token: the inbound header first, then this app's own
 * session cookie.
 *
 * Header first so an agent or MCP client that already holds a token keeps
 * working exactly as it did before this app could sign anyone in — an explicit
 * caller saying who it is for should not be overruled by whoever last used a
 * browser here. A browser cannot set this header cross-origin, so there is no
 * way for a third-party page to smuggle one in.
 */
export function personTokenFrom(request) {
  const header = (request.headers.get(PERSON_HEADER) ?? '').trim();
  if (header !== '') return header;
  const cookie = (cookieValue(request, PERSON_COOKIE) ?? '').trim();
  return cookie === '' ? undefined : cookie;
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

// ───────────────────────────────────────────────────────────────────────────
// The sign-in itself
// ───────────────────────────────────────────────────────────────────────────

/**
 * Ask emseapea where its OAuth endpoints are (RFC 8414).
 *
 * Deliberately NOT cached. The two requests a sign-in makes are the only ones
 * that need this — not one per page view — and a cache would be a second,
 * staler copy of the one fact this file exists to avoid freezing in.
 */
export async function discoverEndpoints(env, fetchImpl = fetch) {
  const issuer = String(env.EMSEAPEA_URL).replace(/\/+$/, '');
  const res = await fetchImpl(`${issuer}/.well-known/oauth-authorization-server`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`Emseapea sign-in discovery failed (${res.status}).`);
  const meta = (await res.json().catch(() => undefined)) ?? {};
  if (!meta.authorization_endpoint || !meta.token_endpoint) {
    throw new Error('Emseapea sign-in discovery named no authorization or token endpoint.');
  }
  return {
    authorization: String(meta.authorization_endpoint),
    token: String(meta.token_endpoint),
    // Optional (RFC 7009). Used on sign-out when the control plane offers it.
    revocation: meta.revocation_endpoint ? String(meta.revocation_endpoint) : undefined,
  };
}

/**
 * Step 1: send the person to emseapea to sign in.
 *
 * `prompt=consent` IS sent, and that is a decision rather than boilerplate.
 * Better Auth only shows the consent screen when a client asks for it;
 * without it a code is minted and returned with nothing shown to the person.
 * The control plane also adds it server-side on a first authorization, so this
 * is belt and braces — but this file is a copy that can never be updated, and
 * "an organisation's person is told before an app can act as them" is too
 * important to make conditional on code in another repository. The price is
 * that the consent screen appears on every sign-in, including the hourly one
 * after a token expires. That is the trade we are making, on purpose.
 */
export async function startSignIn(request, env, fetchImpl = fetch) {
  const endpoints = await discoverEndpoints(env, fetchImpl);
  const verifier = randomToken(32);
  const challenge = await s256(verifier);
  // Ties the callback to THIS browser's sign-in: a code delivered without the
  // matching cookie is somebody else's, and is refused below.
  const state = randomToken(16);
  const returnTo = safeReturnTo(new URL(request.url).searchParams.get('return_to'));

  const authorize = new URL(endpoints.authorization);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', String(env.EMSEAPEA_CLIENT_ID));
  authorize.searchParams.set('redirect_uri', callbackUriFor(request));
  authorize.searchParams.set('scope', 'openid profile email');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('prompt', 'consent');

  const headers = new Headers({ location: authorize.toString() });
  // Only the verifier and the state — never the token, which does not exist
  // yet, and nothing about the person, whom we have not met.
  setCookie(
    headers,
    FLOW_COOKIE,
    new URLSearchParams({ state, verifier, returnTo }).toString(),
    FLOW_TTL_SECONDS,
  );
  return new Response(null, { status: 302, headers });
}

/**
 * Step 2: emseapea sent the person back with a code. Trade it for a token.
 */
export async function completeSignIn(request, env, fetchImpl = fetch) {
  const url = new URL(request.url);
  const headers = new Headers();
  // Whatever happens next, this sign-in attempt is over.
  clearCookie(headers, FLOW_COOKIE);

  const error = url.searchParams.get('error');
  if (error) {
    // `error_description` is attacker-influencable text; it is not rendered.
    return page(headers, 400, 'Sign-in was not completed. Nothing was granted.');
  }

  const flow = new URLSearchParams(cookieValue(request, FLOW_COOKIE) ?? '');
  const expectedState = flow.get('state');
  const verifier = flow.get('verifier');
  const code = url.searchParams.get('code');
  if (!expectedState || !verifier) {
    return page(headers, 400, 'This sign-in has expired. Start it again.');
  }
  // The CSRF check. Without it, somebody could hand this app a code they
  // obtained themselves and sign the person in as THEM.
  if (url.searchParams.get('state') !== expectedState || !code) {
    return page(headers, 400, 'This sign-in did not come from here. Nothing was granted.');
  }

  const endpoints = await discoverEndpoints(env, fetchImpl);
  // Server to server, no cookie, no client secret — the verifier is the proof.
  const res = await fetchImpl(endpoints.token, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUriFor(request),
      client_id: String(env.EMSEAPEA_CLIENT_ID),
      code_verifier: verifier,
    }).toString(),
  });
  const body = (await res.json().catch(() => undefined)) ?? {};
  if (!res.ok || !body.access_token) {
    // Deliberately not repeating the provider's message: it can carry detail
    // about somebody else's account.
    return page(headers, 401, 'Emseapea would not issue a token for this sign-in.');
  }

  // The cookie outlives the token by nothing: when it goes, the person signs
  // in again rather than making a call that is refused upstream.
  const lifetime = Math.min(Math.max(Number(body.expires_in) || 3600, 60), 86_400);
  setCookie(headers, PERSON_COOKIE, String(body.access_token), lifetime);
  headers.set('location', safeReturnTo(flow.get('returnTo')));
  return new Response(null, { status: 302, headers });
}

/**
 * Sign out: drop the cookie, and hand the token back.
 *
 * Revocation is best-effort by design — the person is signed out of this app
 * the moment the cookie goes, whatever the control plane says. But leaving a
 * live token behind on every sign-out is exactly the sort of thing an app with
 * no session store gets wrong, and emseapea advertises a revocation endpoint
 * so that it does not have to be.
 */
export async function signOut(request, env, fetchImpl = fetch) {
  const token = cookieValue(request, PERSON_COOKIE);
  const headers = new Headers({ location: '/' });
  clearCookie(headers, PERSON_COOKIE);
  if (token && signInConfigured(env)) {
    try {
      const endpoints = await discoverEndpoints(env, fetchImpl);
      if (endpoints.revocation) {
        await fetchImpl(endpoints.revocation, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            token,
            token_type_hint: 'access_token',
            client_id: String(env.EMSEAPEA_CLIENT_ID),
          }).toString(),
        });
      }
    } catch {
      // Signing out must not fail because the control plane is unreachable.
    }
  }
  return new Response(null, { status: 302, headers });
}

// ───────────────────────────────────────────────────────────────────────────
// Small helpers. No dependencies: a governed app is one file.
// ───────────────────────────────────────────────────────────────────────────

/**
 * This app's own callback URL, built from the request rather than written
 * down, so it always names the origin the person actually reached.
 *
 * A forged `Host` header would produce a redirect URI emseapea has not
 * registered, and emseapea refuses those — so the worst a forged host achieves
 * is a failed sign-in, never a code delivered somewhere else.
 */
function callbackUriFor(request) {
  return new URL(CALLBACK_PATH, request.url).toString();
}

/** Where to go after signing in. Never off-site, and never to another host. */
function safeReturnTo(value) {
  const path = String(value ?? '');
  // A single leading slash only: `//evil.example` and `/\evil.example` are
  // both read by browsers as another host.
  if (!/^\/[^/\\]/.test(path)) return '/';
  return path;
}

/** URL-safe random, from the platform CSPRNG — never `Math.random`. */
function randomToken(bytes) {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** The PKCE challenge: base64url(SHA-256(verifier)), as `S256` means. */
async function s256(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function cookieValue(request, name) {
  const header = request.headers.get('cookie') ?? '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** `__Host-` requires exactly this shape: Secure, Path=/, and no Domain. */
function setCookie(headers, name, value, maxAgeSeconds) {
  headers.append(
    'set-cookie',
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; ` +
      `Max-Age=${maxAgeSeconds}`,
  );
}

function clearCookie(headers, name) {
  setCookie(headers, name, '', 0);
}

function json(value, status, headers = new Headers()) {
  headers.set('content-type', 'application/json');
  return new Response(JSON.stringify(value), { status, headers });
}

/** A plain page. Only ever given text this file wrote — never a query value. */
function page(headers, status, text) {
  headers.set('content-type', 'text/plain; charset=utf-8');
  return new Response(text, { status, headers });
}

/** A top-level browser navigation, as opposed to an API client or an agent. */
function wantsHtml(request) {
  return (request.headers.get('accept') ?? '').includes('text/html');
}

// ───────────────────────────────────────────────────────────────────────────
// Worked example
// ───────────────────────────────────────────────────────────────────────────

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
    // A browser that has not signed in is SENT to sign in. The gateway is
    // still not called — a redirect is not a weaker request, it is no request.
    if (signInConfigured(env) && wantsHtml(request)) {
      const to = new URL(SIGNIN_PATH, request.url);
      to.searchParams.set('return_to', new URL(request.url).pathname);
      return new Response(null, { status: 302, headers: { location: to.toString() } });
    }
    // Anything else is refused, not downgraded. There is no weaker version of
    // this request worth making, because a call that reached Google as
    // somebody else would answer the wrong question convincingly.
    return json(
      {
        error:
          "This reads the signed-in person's own files, so the request has to say who that " +
          'is. Forward their emseapea token as the X-Emseapea-Person header, or open ' +
          `${SIGNIN_PATH} in a browser to sign in.`,
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

/** The front page: whichever of the three states this app is actually in. */
function home(request, env) {
  const signedIn = Boolean(cookieValue(request, PERSON_COOKIE));
  if (!signInConfigured(env)) {
    // AC3: an app deployed before sign-in existed, or into an environment with
    // no control plane, SERVES. It just cannot sign anybody in.
    return page(
      new Headers(),
      200,
      'Hello from a governed emseapea app.\n\n' +
        'Signing people in is not configured here: this app was not given ' +
        'EMSEAPEA_URL and EMSEAPEA_CLIENT_ID. Redeploy it through emseapea to get them. ' +
        'Until then, GET /me/google-files still works for a caller that forwards an ' +
        'X-Emseapea-Person header.',
    );
  }
  if (signedIn) {
    return page(
      new Headers(),
      200,
      'Signed in to emseapea.\n\n' +
        'GET /me/google-files reads your own Google Drive files.\n' +
        `GET ${SIGNOUT_PATH} signs you out.`,
    );
  }
  return page(
    new Headers(),
    200,
    'Hello from a governed emseapea app.\n\n' +
      `GET ${SIGNIN_PATH} to sign in with emseapea, then GET /me/google-files.`,
  );
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    try {
      if (pathname === SIGNIN_PATH || pathname === CALLBACK_PATH || pathname === SIGNOUT_PATH) {
        if (!signInConfigured(env)) {
          // Explained, not crashed. This app was never given a client id.
          return page(
            new Headers(),
            503,
            'Signing in with emseapea is not configured for this app: it has no ' +
              'EMSEAPEA_URL and EMSEAPEA_CLIENT_ID. Redeploy it through emseapea.',
          );
        }
        if (pathname === SIGNIN_PATH) return await startSignIn(request, env);
        if (pathname === CALLBACK_PATH) return await completeSignIn(request, env);
        return await signOut(request, env);
      }
      if (pathname === '/me/google-files') return await myGoogleFiles(request, env);
      return home(request, env);
    } catch (e) {
      return json({ error: e instanceof Error ? e.message : 'Something went wrong.' }, 500);
    }
  },
};

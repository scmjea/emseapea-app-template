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
 * This template RELAYS a person token that arrives on the inbound request in
 * the same `X-Emseapea-Person` header. It cannot mint one, and neither can
 * you without doing the work below: a Worker has no session, and provisioning
 * does not register a governed app as a sign-in client anywhere.
 *
 * The token is an OAuth access token issued by the emseapea control plane's
 * own sign-in — the same kind of token an MCP client carries. The control
 * plane resolves it to a person and REJECTS it when that person's
 * organisation is not the one this app's handle belongs to, so forwarding a
 * borrowed token from another org buys nothing.
 *
 * For this header to carry a real person, ONE of these has to be true, and
 * neither becomes true on its own:
 *
 *   1. Your caller already holds one — an agent or MCP client that has signed
 *      in to emseapea — and sends it to this app as `X-Emseapea-Person`.
 *      Then this template is all you need.
 *
 *   2. Your app signs people in to emseapea itself: discover the endpoints at
 *      `<control plane>/.well-known/oauth-authorization-server`, register as
 *      a client, run the OAuth authorization-code + PKCE flow, and hold the
 *      resulting access token for the signed-in person. That flow is NOT in
 *      this template and nothing in emseapea sets it up for you today.
 *
 * Until one of them is true, the example below answers 401. It does not fall
 * back to calling as nobody in particular. That refusal is the feature.
 */

/** Lower-case because `Headers` lookups are case-insensitive either way, and
 *  this is the one name both ends of the contract have to agree on. */
const PERSON_HEADER = 'x-emseapea-person';

/** The signed-in person's token off the inbound request, or `undefined`. */
export function personTokenFrom(request) {
  const raw = request.headers.get(PERSON_HEADER) ?? '';
  const token = raw.trim();
  return token === '' ? undefined : token;
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
    return json(
      {
        error:
          "This reads the signed-in person's own files, so the request has to say who that " +
          'is. Forward their emseapea token as the X-Emseapea-Person header.',
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

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === '/me/google-files') {
      try {
        return await myGoogleFiles(request, env);
      } catch (e) {
        return json({ error: e instanceof Error ? e.message : 'Something went wrong.' }, 500);
      }
    }
    return new Response(
      'Hello from a governed emseapea app. Try GET /me/google-files with an ' +
        'X-Emseapea-Person header.',
    );
  },
};

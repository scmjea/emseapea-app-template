# A governed emseapea app

<!--
  NO PLACEHOLDERS IN THIS FILE — not in the heading, and not in here either.

  The heading used to name the app through a double-brace token, and nothing
  ever substituted it, so every repository provisioned from this template
  shipped with the literal braces as the first line of the first file a builder
  opens.

  The token is DESCRIBED rather than shown, on purpose. Emseapea's template
  check reads this whole file and fails on the shape, wherever it appears —
  including inside a comment like this one. It found the first draft of this
  comment, which quoted the token it was warning about, and it was right to.

  Nothing CAN substitute it, and that is the part worth keeping in mind before
  reintroducing one. A generated repository is created with GitHub's
  `POST /generate`, which copies this tree verbatim; the provisioning broker
  then WRITES `CONNECTORS.md` and `emseapea.json` into it. Those two carry the
  app's name because they are written from scratch. This file is not written,
  it is copied — and the broker's `writeFile` sends no blob `sha`, so it cannot
  update a path that already exists here even if somebody taught it to try.

  So: this file describes the TEMPLATE, in words that are true of every app
  generated from it. Anything that has to name one app belongs in
  `CONNECTORS.md`, which already opens with it.
-->

This repository was created from your organization's approved template by the
emseapea provisioning broker. It comes with:

- CI that runs the SAME checks the deploy gate enforces (gitleaks + Semgrep) —
  green here means green at the gate. Semgrep checks the code against a set of
  known insecure patterns; it is not exhaustive and a green check is not a
  guarantee the code is secure — write safe code regardless of what the scan
  finds.
- A credential handle (never a raw secret) delivered via `get_workspace`;
  redeem it through your organization's gateway (`/u/<system>/...`).
- A worked example of an on-behalf-of call — a person reading their own Google
  Drive files — in `src/index.js`, and tests for it in `test/`. Run them with
  `npm test` (Node's own test runner; there are no dependencies to install).
- **Sign-in with emseapea, already wired.** A person opens the app, signs in to
  your organization's emseapea, and the app calls the gateway as *them*.

Build whatever the approved intent describes. Every deploy goes through the
emseapea deploy gate.

## Two headers, and they are not interchangeable

```http
GET {GATEWAY_URL}/u/google/drive/v3/files?pageSize=10
Authorization: Bearer {CREDENTIAL_HANDLE}
X-Emseapea-Person: {the signed-in person's emseapea token}
```

`Authorization` says which **app** is calling. It is not a vendor token, it
never reaches the vendor, and it goes to `GATEWAY_URL` — never to the vendor's
own host, whatever the vendor's documentation says.

`X-Emseapea-Person` says which **person** the app is calling for. Systems your
org reaches "only what the person using it can already see" need it: on Google
Workspace it decides whose Drive, mail and directory view come back, so with
nothing forwarded the gateway has nobody to act as and refuses the call rather
than substituting someone. Treat the token as opaque cargo — do not decode,
log, store, or send it anywhere except `GATEWAY_URL`.

## Where the person's token comes from — two ways, and both are built

The token is an OAuth access token issued by the emseapea control plane's own
sign-in — the same kind an MCP client carries. The control plane rejects it if
the person's organization is not the one this app's handle belongs to, so a
borrowed token from another org buys nothing.

1. **Your caller already holds one.** An agent or MCP client that has signed in
   to emseapea sends its token to this app as `X-Emseapea-Person`. Forwarded
   as-is; nothing to build.
2. **This app signs the person in.** A browser has no such header, so the app
   runs the OAuth authorization-code + PKCE flow against emseapea itself and
   keeps the token for the session. Three routes, and none of them need
   editing:

   | Route | What it does |
   | --- | --- |
   | `GET /auth/emseapea/signin` | Starts the flow. `?return_to=/some/path` comes back here afterwards. |
   | `GET /auth/emseapea/callback` | Where emseapea returns the person. **Fixed by emseapea** — it is the only redirect URI registered for this app. Do not change the path. |
   | `GET /auth/emseapea/signout` | Clears the session and hands the token back. |

If a person has not signed in, a browser hitting `/me/google-files` is sent to
sign in; anything else gets a 401. Neither ever falls back to calling as nobody
in particular, and neither should anything you add.

### How it works, in the order it happens

1. **Discovery.** The app asks
   `${EMSEAPEA_URL}/.well-known/oauth-authorization-server` where emseapea's
   OAuth endpoints are. They are never written down in this repo, because this
   repo is a copy that does not track the template — a frozen URL could never
   be corrected; a discovery document can.
2. **Authorize with PKCE.** The app invents a random `code_verifier`, sends
   only its SHA-256 hash, and redirects the person to emseapea. It sends
   `prompt=consent`, so the person is shown what they are agreeing to before
   anything is granted — on every sign-in, deliberately.
3. **Exchange.** emseapea returns an authorization code; the app trades it for
   a token, presenting the original verifier. **There is no client secret**:
   this app is registered as a *public* OAuth client and PKCE is its proof.
   Whoever intercepts the code cannot use it without the verifier, which never
   left the Worker.

### Where the session lives, and the trade-offs

A governed app is uploaded as a single ES module with plain-text variables —
no KV, no Durable Object, no disk, no second file. The only place left to keep
anything between requests is the person's own browser, so the token rides in a
`__Host-`-prefixed `HttpOnly; Secure; SameSite=Lax` cookie on this app's own
origin. What that costs:

- **The cookie is not signed, and does not need to be.** A signature proves we
  issued the value; the value is a bearer token emseapea validates on every
  use, so a forged one is simply refused upstream. There is also no secret to
  sign with — every variable this app gets is plain text.
- **The token is in the browser** for as long as it is valid (about an hour).
  `HttpOnly` keeps script out, `Secure` keeps it off plaintext HTTP, and
  `__Host-` stops a neighbouring host on the same parent domain writing it.
- **No refresh token.** Nothing long-lived is stored anywhere; when the token
  expires the person signs in again — one redirect, and one consent screen.
- **No server-side session, so no way to end one from here** beyond clearing
  the cookie and revoking the token at sign-out.

## "You need a … account to see this. Ask your IT team."

Signing in to emseapea is **not** the same as linking a vendor account, and
this is the step almost everyone misses first.

This app never sees a vendor password. emseapea runs the vendor's OAuth flow,
keeps the refresh token, and the gateway mints from it — so somebody who has
signed in to emseapea but never linked their Microsoft account has nothing for
the gateway to act as, and it answers `no_account`. That is what the message
above means, and it is why `noAccountAnswer` keeps the gateway's sentence
verbatim and adds the one thing that sentence cannot know: whether this is a
person with no account, or a person who has one and never linked it.

The link goes to `{EMSEAPEA_URL}/api/connect/msgraph/start`, with
`?return_to=` set to the page they were on, so they come back here rather than
being left in emseapea. emseapea checks that address against the origins it has
deployed your organization's apps to and refuses anything else.

Two things it deliberately does not do:

- **It builds no link at all without `EMSEAPEA_URL`.** A link that goes
  somewhere wrong gets reported as a broken link instead of as the missing
  configuration behind it.
- **It promises nothing about the link working.** If your organization has not
  finished its Microsoft app registration, that page says so — and *that* is
  the case where "ask your IT team" was right after all, with something
  specific to ask for.

Only Microsoft is offered, because it is the only system where linking is a
person's own one-time step. Google Workspace access comes from a domain-wide
delegation an administrator sets up: there is nothing there for a person to
press, and emseapea's connect route refuses any other system.

## An app with no `EMSEAPEA_CLIENT_ID` still serves

Sign-in needs two variables that arrive from the deploy: `EMSEAPEA_URL` and
`EMSEAPEA_CLIENT_ID`. An app deployed before they existed, or into an
environment with no control plane address, does not get them — and still
serves. It says sign-in is not configured, and carries on relaying a person
token that arrives on the request. Nothing here fails closed on a variable it
never got.

## This applies to repositories created from here on

A repository generated from this template gets a copy of these files; it does
not track them. Changes made here do not reach a repo that already exists — if
this app was created before this section appeared, `src/index.js` will not sign
anybody in, and you will need to copy the current template by hand.
